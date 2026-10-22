import queue
import threading
import time
import types
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from backend.capture_telemetry import flow_packet_metadata, packet_metadata
from backend.capture_worker import CaptureController, _put_bounded, scapy_capture
from backend.capture_routes import get_flows, controller
from backend.flow_telemetry import ExperimentalFlowTracker


def wait_until(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate(): return True
        time.sleep(0.01)
    return predicate()


class FakeValue:
    def __init__(self, value=0): self.value = value; self.lock = threading.Lock()
    def get_lock(self): return self.lock


class FakeEvent:
    def set(self): self.is_set = True
    def is_set(self): return getattr(self, "is_set", False)


class FakeProcess:
    def __init__(self, **kwargs): self.alive = False
    def start(self): self.alive = True
    def is_alive(self): return self.alive
    def join(self, timeout=None): self.alive = False
    def terminate(self): self.alive = False
    def close(self): pass


class FakeQueue(queue.Queue):
    def __init__(self, maxsize): super().__init__(maxsize)
    def cancel_join_thread(self): pass
    def close(self): pass
    def join_thread(self): pass


class FakeContext:
    Queue = staticmethod(lambda maxsize: FakeQueue(maxsize))
    Event = staticmethod(FakeEvent)
    Value = staticmethod(lambda kind, value: FakeValue(value))
    Process = staticmethod(lambda **kwargs: FakeProcess())


class Request:
    headers = {"origin": "http://localhost:5173", "x-capture-token": "flow-token"}
    client = types.SimpleNamespace(host="127.0.0.1")
    url = types.SimpleNamespace(hostname="localhost")


class Layer:
    def __init__(self, **values): self.__dict__.update(values)


class Packet:
    def __init__(self, layers, timestamp=None, size=60):
        self.layers, self.time, self.size = layers, time.time() if timestamp is None else timestamp, size
    @property
    def payload(self): raise AssertionError("payload accessed")
    def haslayer(self, kind): return kind in self.layers
    def __getitem__(self, kind): return self.layers[kind]
    def __len__(self): return self.size


def fake_scapy_modules():
    scapy = types.ModuleType("scapy")
    layers = types.ModuleType("scapy.layers")
    inet = types.ModuleType("scapy.layers.inet")
    inet6 = types.ModuleType("scapy.layers.inet6")
    for name in ("IP", "TCP", "UDP", "ICMP"):
        setattr(inet, name, type(name, (), {}))
    inet6.IPv6 = type("IPv6", (), {})
    return scapy, layers, inet, inet6


class FlowCaptureIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.scapy, self.layers, self.inet, self.inet6 = fake_scapy_modules()

    def test_extract_allowlisted_tcp_metadata_without_payload(self):
        ip, tcp = self.inet.IP, self.inet.TCP
        packet = Packet({ip: Layer(src="192.0.2.1", dst="198.51.100.2", proto=6),
                         tcp: Layer(sport=1234, dport=80, flags=18)}, timestamp=100.5)
        modules = {"scapy": self.scapy, "scapy.layers": self.layers,
                   "scapy.layers.inet": self.inet, "scapy.layers.inet6": self.inet6}
        with patch.dict("sys.modules", modules):
            result = flow_packet_metadata(packet, 60)
            packet_event = packet_metadata(packet)
        self.assertEqual(result, {"timestamp": 100.5, "protocol": "TCP",
            "src_ip": "192.0.2.1", "src_port": 1234, "dst_ip": "198.51.100.2",
            "dst_port": 80, "packet_length": 60, "tcp_flags": 18})
        self.assertEqual(packet_event["bytes"], 60)
        self.assertNotIn("payload", result)

    def test_udp_ipv6_and_unsupported_or_malformed_packets(self):
        ipv6, udp = self.inet6.IPv6, self.inet.UDP
        good = Packet({ipv6: Layer(src="2001:db8::1", dst="2001:db8::2", nh=17),
                       udp: Layer(sport=53, dport=40000)})
        modules = {"scapy": self.scapy, "scapy.layers": self.layers,
                   "scapy.layers.inet": self.inet, "scapy.layers.inet6": self.inet6}
        with patch.dict("sys.modules", modules):
            self.assertEqual(flow_packet_metadata(good)["protocol"], "UDP")
            unknown = Packet({ipv6: Layer(src="2001:db8::1", dst="2001:db8::2", nh=58)})
            self.assertIsNone(flow_packet_metadata(unknown))
            malformed = Packet({ipv6: Layer(src="bad-ip", dst="2001:db8::2", nh=17), udp: Layer(sport=1, dport=2)})
            self.assertIsNone(flow_packet_metadata(malformed))

    def test_worker_dispatch_batches_and_flow_endpoint_keeps_packet_contract(self):
        c = CaptureController(interface_provider=lambda: ["if0"], context=FakeContext)
        c.start("if0")
        now = time.time()
        c.events.put_nowait({"type": "capture_batch", "events": [
            {"type": "packet", "data": {"timestamp": "t", "protocol": "TCP", "src": "a", "dst": "b", "bytes": 60}},
            {"type": "flow", "data": {"timestamp": now, "protocol": "TCP", "src_ip": "192.0.2.1", "src_port": 1,
                "dst_ip": "198.51.100.2", "dst_port": 2, "packet_length": 60, "tcp_flags": 2}},
        ]})
        def processed():
            with c.telemetry_lock:
                return c.telemetry.packets == 1 and len(c.flow_telemetry.flows) == 1
        self.assertTrue(wait_until(processed))
        packet_snapshot = c.snapshot()
        self.assertEqual(set(packet_snapshot), {"packets", "bytes", "dropped", "protocols", "endpoints", "recent"})
        self.assertEqual(packet_snapshot["packets"], 1)
        flow_snapshot = c.flow_snapshot()
        self.assertEqual(flow_snapshot["flows"][0]["packets"], 1)
        self.assertEqual(flow_snapshot["flows"][0]["bytes"], 60)
        self.assertEqual(flow_snapshot["flows"][0]["started_at_seconds"], now)
        self.assertEqual(flow_snapshot["label"], "Experimental flow telemetry; not a V2 prediction")
        for forbidden in ("prediction", "attack", "risk_score", "features"):
            self.assertNotIn(forbidden, flow_snapshot)
        c.stop()
        self.assertEqual(c.flow_snapshot()["flows"], [])
        c.start("if0")
        self.assertEqual(c.flow_snapshot()["flows"], [])
        self.assertEqual(c.snapshot()["packets"], 1)  # existing packet telemetry remains cumulative
        c.shutdown()

    def test_queue_drop_is_atomic_per_capture_batch(self):
        q = queue.Queue(maxsize=1); dropped = FakeValue()
        batch = {"type": "capture_batch", "events": [{"type": "packet", "data": {}}, {"type": "flow", "data": {}}]}
        _put_bounded(q, batch, dropped); _put_bounded(q, batch, dropped)
        self.assertEqual(dropped.value, 1)
        self.assertEqual(q.get_nowait(), batch)
        self.assertTrue(q.empty())

    def test_controller_reports_dropped_batches_without_partial_flow_data(self):
        c = CaptureController(interface_provider=lambda: ["if0"], context=FakeContext)
        c.start("if0")
        q = queue.Queue(maxsize=1); dropped = FakeValue()
        batch = {"type": "capture_batch", "events": [
            {"type": "packet", "data": {"timestamp": "t", "protocol": "UDP", "src": "a", "dst": "b", "bytes": 30}},
            {"type": "flow", "data": {"timestamp": time.time(), "protocol": "UDP", "src_ip": "192.0.2.1", "src_port": 1,
                "dst_ip": "198.51.100.2", "dst_port": 2, "packet_length": 30}},
        ]}
        _put_bounded(q, batch, dropped); _put_bounded(q, batch, dropped)
        self.assertEqual(dropped.value, 1)
        c.dropped_counter.value = dropped.value
        flow_snapshot = c.flow_snapshot()
        self.assertEqual(flow_snapshot["capture_dropped_events"], 1)
        self.assertEqual(flow_snapshot["flows"], [])
        self.assertEqual(c.snapshot()["dropped"], 1)
        c.shutdown()

    def test_consumer_processes_batches_without_snapshot_polling(self):
        c = CaptureController(interface_provider=lambda: ["if0"], context=FakeContext)
        c.start("if0")
        now = time.time()
        c.events.put_nowait({"type": "capture_batch", "events": [
            {"type": "packet", "data": {"timestamp": "t", "protocol": "UDP", "src": "a", "dst": "b", "bytes": 30}},
            {"type": "flow", "data": {"timestamp": now, "protocol": "UDP", "src_ip": "192.0.2.1", "src_port": 1,
                "dst_ip": "198.51.100.2", "dst_port": 2, "packet_length": 30}},
        ]})
        def processed():
            with c.telemetry_lock:
                return c.telemetry.packets == 1 and len(c.flow_telemetry.flows) == 1
        self.assertTrue(wait_until(processed))
        c.stop(); c.shutdown()

    def test_stop_drains_accepted_batches_before_returning(self):
        c = CaptureController(interface_provider=lambda: ["if0"], context=FakeContext)
        c.start("if0")
        now = time.time()
        c.events.put_nowait({"type": "capture_batch", "events": [
            {"type": "packet", "data": {"timestamp": "t", "protocol": "UDP", "src": "a", "dst": "b", "bytes": 30}},
            {"type": "flow", "data": {"timestamp": now, "protocol": "UDP", "src_ip": "192.0.2.1", "src_port": 1,
                "dst_ip": "198.51.100.2", "dst_port": 2, "packet_length": 30}},
        ]})
        self.assertEqual(c.stop()["state"], "stopped")
        self.assertEqual(c.snapshot()["packets"], 1)
        self.assertEqual(c.flow_snapshot()["flows"], [])  # flows reset only after drain
        self.assertIsNone(c.events)

    def test_consumer_timeout_retains_resources_until_retry(self):
        c = CaptureController(interface_provider=lambda: ["if0"], context=FakeContext)
        c.start("if0")
        entered = threading.Event(); release = threading.Event()
        original_add = c.telemetry.add
        def blocked_add(record):
            entered.set()
            release.wait(4)
            original_add(record)
        c.telemetry.add = blocked_add
        c.events.put_nowait({"type": "packet", "timestamp": "t", "protocol": "UDP", "src": "a", "dst": "b", "bytes": 1})
        self.assertTrue(entered.wait(1))
        self.assertEqual(c.stop()["state"], "error")
        self.assertIsNotNone(c.events)
        with self.assertRaises(ValueError): c.start("if0")
        release.set()
        self.assertEqual(c.stop()["state"], "stopped")
        self.assertEqual(c.snapshot()["packets"], 1)
        c.telemetry.add = original_add

    def test_failed_consumer_retains_resources_and_blocks_restart(self):
        c = CaptureController(interface_provider=lambda: ["if0"], context=FakeContext)
        c.start("if0")
        original_add = c.telemetry.add
        calls = {"count": 0}
        def fail_once(record):
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("private detail")
            original_add(record)
        c.telemetry.add = fail_once
        c.events.put_nowait({"type": "packet", "timestamp": "t", "protocol": "UDP", "src": "a", "dst": "b", "bytes": 1})
        self.assertTrue(wait_until(lambda: c.consumer_failed))
        self.assertEqual(c.stop()["state"], "error")
        self.assertIsNotNone(c.events)
        self.assertIsNotNone(c.consumer)
        with self.assertRaises(ValueError): c.start("if0")
        self.assertEqual(c.dropped, 0)
        self.assertNotIn("private detail", c.error or "")

    def test_snapshot_waits_for_atomic_batch_application(self):
        c = CaptureController(interface_provider=lambda: ["if0"], context=FakeContext)
        c.start("if0")
        entered = threading.Event(); release = threading.Event()
        original_add = c.telemetry.add
        def paused_add(record):
            original_add(record)
            entered.set()
            release.wait(1)
        now = time.time()
        c.telemetry.add = paused_add
        c.events.put_nowait({"type": "capture_batch", "events": [
            {"type": "packet", "data": {"timestamp": "t", "protocol": "TCP", "src": "a", "dst": "b", "bytes": 60}},
            {"type": "flow", "data": {"timestamp": now, "protocol": "TCP", "src_ip": "192.0.2.1", "src_port": 1,
                "dst_ip": "198.51.100.2", "dst_port": 2, "packet_length": 60}},
        ]})
        self.assertTrue(entered.wait(1))
        done = threading.Event(); snapshots = []
        reader = threading.Thread(target=lambda: (snapshots.append((c.snapshot(), c.flow_snapshot())), done.set()))
        reader.start()
        self.assertFalse(done.wait(0.05))
        release.set(); self.assertTrue(done.wait(1)); reader.join(1)
        self.assertEqual(snapshots[0][0]["packets"], 1)
        self.assertEqual(snapshots[0][1]["flows"][0]["packets"], 1)
        c.telemetry.add = original_add
        c.stop(); c.shutdown()

    def test_simultaneous_snapshots_and_stop_do_not_deadlock(self):
        c = CaptureController(interface_provider=lambda: ["if0"], context=FakeContext)
        c.start("if0")
        started = threading.Barrier(3); errors = []
        def reader():
            try:
                started.wait(); c.snapshot(); c.flow_snapshot()
            except Exception as exc: errors.append(exc)
        def stopper():
            try:
                started.wait(); c.stop()
            except Exception as exc: errors.append(exc)
        threads = [threading.Thread(target=reader), threading.Thread(target=stopper)]
        for thread in threads: thread.start()
        started.wait()
        for thread in threads: thread.join(2)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(c.state, "stopped")
        c.shutdown()

    def test_scapy_adapter_emits_typed_batch_and_keeps_packet_event(self):
        ip, tcp = self.inet.IP, self.inet.TCP
        packet = Packet({ip: Layer(src="192.0.2.1", dst="198.51.100.2", proto=6), tcp: Layer(sport=5, dport=6, flags=16)})
        scapy_all = types.ModuleType("scapy.all")
        def sniff(**kwargs): kwargs["prn"](packet)
        scapy_all.sniff = sniff
        self.scapy.all = scapy_all
        modules = {"scapy": self.scapy, "scapy.all": scapy_all, "scapy.layers": self.layers,
                   "scapy.layers.inet": self.inet, "scapy.layers.inet6": self.inet6}
        emitted = []
        stop = FakeEvent()
        stop.is_set = True  # run one sniff iteration, then stop
        # Adapter checks the stop flag before sniffing; use a flag that flips after first call.
        class OneShot:
            calls = 0
            def is_set(self):
                self.calls += 1
                return self.calls > 1
        with patch.dict("sys.modules", modules):
            scapy_capture("if0", emitted.append, OneShot())
        self.assertEqual(emitted[0]["type"], "capture_batch")
        self.assertEqual([event["type"] for event in emitted[0]["events"]], ["packet", "flow"])

    def test_flow_route_requires_origin_and_session_token(self):
        original_token = controller.token
        original_state = controller.state
        try:
            controller.token = "flow-token"
            controller.state = "running"
            self.assertEqual(get_flows(Request())["flows"], [])
            Request.headers = {"origin": "http://localhost:5173"}
            with self.assertRaises(HTTPException): get_flows(Request())
            Request.headers = {"origin": "http://localhost:5173", "x-capture-token": "wrong-token"}
            with self.assertRaises(HTTPException): get_flows(Request())
            Request.headers = {"origin": "https://evil.invalid", "x-capture-token": "flow-token"}
            with self.assertRaises(HTTPException): get_flows(Request())
            Request.headers = {"origin": "http://localhost:5173", "x-capture-token": "flow-token"}
            controller.state = "stopped"
            with self.assertRaises(HTTPException) as stopped:
                get_flows(Request())
            self.assertEqual(stopped.exception.status_code, 409)
            controller.state = "running"
            Request.client = types.SimpleNamespace(host="192.168.1.25")
            with self.assertRaises(HTTPException): get_flows(Request())
        finally:
            controller.token = original_token
            controller.state = original_state
            Request.client = types.SimpleNamespace(host="127.0.0.1")
            Request.headers = {"origin": "http://localhost:5173", "x-capture-token": "flow-token"}

    def test_flow_state_resets_after_worker_failure_before_restart(self):
        c = CaptureController(interface_provider=lambda: ["if0"], context=FakeContext)
        c.start("if0")
        now = time.time()
        event = {"timestamp": now, "protocol": "UDP", "src_ip": "192.0.2.1", "src_port": 1,
                 "dst_ip": "198.51.100.2", "dst_port": 2, "packet_length": 30}
        c.events.put_nowait({"type": "capture_batch", "events":[{"type":"flow", "data":event}]})
        self.assertTrue(wait_until(lambda: bool(c.flow_snapshot()["flows"])))
        self.assertEqual(c.flow_snapshot()["flows"][0]["packets"], 1)
        c.events.put_nowait({"_error": "Capture worker failed (OSError)"})
        c.process.alive = False
        self.assertEqual(c.status()["state"], "error")
        self.assertEqual(c.flow_snapshot()["flows"], [])
        c.stop()
        c.start("if0")
        self.assertEqual(c.flow_snapshot()["flows"], [])
        c.shutdown()

    def test_tracker_direction_expiry_and_malformed_input_are_separate(self):
        tracker = ExperimentalFlowTracker(idle_timeout_seconds=5)
        base = {"protocol": "UDP", "src_ip": "192.0.2.1", "src_port": 1,
                "dst_ip": "198.51.100.2", "dst_port": 2, "packet_length": 30}
        self.assertEqual(tracker.add_packet({**base, "timestamp": 10}), "forward")
        reverse = {**base, "src_ip": base["dst_ip"], "src_port": base["dst_port"],
                   "dst_ip": base["src_ip"], "dst_port": base["src_port"], "timestamp": 11}
        self.assertEqual(tracker.add_packet(reverse), "backward")
        self.assertIsNone(tracker.add_packet({**base, "timestamp": "invalid"}))
        self.assertEqual(tracker.snapshot(now=20)["flows"], [])
        self.assertEqual(tracker.snapshot()["malformed_packets"], 1)


if __name__ == "__main__": unittest.main()
