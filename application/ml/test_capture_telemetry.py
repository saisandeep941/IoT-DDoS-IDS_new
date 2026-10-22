import queue
import sys
import threading
import types
import unittest
from unittest.mock import patch

from backend.capture_telemetry import Telemetry, packet_metadata
from backend.capture_worker import CaptureController, CaptureSetupError, _put_bounded, _child
from backend.capture_routes import _local_request, _guard, validate_start_body, get_status, get_capture_session, start_capture, controller, csrf_token
from backend.main import app
from fastapi import HTTPException


class Packet:
    protocol, src, dst = "UDP", "192.0.2.1", "198.51.100.2"
    def __len__(self): return 72
    def haslayer(self, _layer): return False


class FakeEvent:
    def set(self): self.is_set = True


class FakeValue:
    def __init__(self, kind, value): self.value = value; self.lock = threading.Lock()
    def get_lock(self): return self.lock


class FakeProcess:
    def __init__(self, **kwargs): self.alive = False
    def start(self): self.alive = True
    def is_alive(self): return self.alive
    def join(self, timeout=None): self.alive = False
    def terminate(self): self.alive = False
    def close(self): self.closed = True


class FailedStartProcess(FakeProcess):
    def start(self): raise OSError("spawn denied")


class FakeQueue(queue.Queue):
    def __init__(self, maxsize):
        super().__init__(maxsize)
        self.closed = self.joined = self.cancelled = False
    def close(self): self.closed = True
    def join_thread(self): self.joined = True
    def cancel_join_thread(self): self.cancelled = True


class FakeContext:
    Queue = staticmethod(lambda maxsize: FakeQueue(maxsize))
    Event = staticmethod(FakeEvent)
    Value = staticmethod(FakeValue)
    Process = staticmethod(lambda target, args, daemon: FakeProcess())


class Request:
    headers = {"host": "localhost:8000", "origin": "http://localhost:5173"}
    client = type("Client", (), {"host": "127.0.0.1"})()
    url = type("URL", (), {"hostname": "localhost"})()
    body = {"interface": "if0"}
    async def json(self):
        if self.body == "invalid-json": raise ValueError("invalid JSON")
        return self.body


def run_immediate_coroutine(coroutine):
    """Run request mocks whose async methods complete without yielding I/O."""
    try:
        coroutine.send(None)
    except StopIteration as result:
        return result.value
    finally:
        coroutine.close()
    raise AssertionError("mock endpoint unexpectedly awaited external I/O")


class CaptureTests(unittest.TestCase):
    def test_metadata_has_no_payload(self):
        with patch.dict(sys.modules, {"scapy.layers.inet": None, "scapy.layers.inet6": None}), \
             patch("backend.capture_telemetry.datetime") as dt:
            dt.now.return_value.isoformat.return_value = "2026-01-01T00:00:00+00:00"
            event = packet_metadata(Packet())
        self.assertEqual((event["protocol"], event["src"], event["bytes"]), ("UDP", "192.0.2.1", 72))
        self.assertNotIn("payload", event)

    def test_history_and_endpoint_bounds(self):
        t = Telemetry(history_limit=2, endpoint_limit=2)
        for i in range(5): t.add({"timestamp": str(i), "protocol": "TCP", "src": f"s{i}", "dst": f"d{i}", "bytes": 1, "payload": "secret"})
        snap = t.snapshot()
        self.assertEqual(len(snap["recent"]), 2); self.assertLessEqual(len(snap["endpoints"]), 2)
        self.assertNotIn("payload", str(snap))

    def test_queue_limit_counts_drops_and_api_body_validation(self):
        q = queue.Queue(maxsize=1); dropped = FakeValue("L", 0)
        _put_bounded(q, {"one": 1}, dropped); _put_bounded(q, {"two": 2}, dropped)
        self.assertEqual(dropped.value, 1)
        self.assertEqual(validate_start_body({"interface": "if0"}), "if0")
        for bad in ({"interface": "if0", "command": "anything"}, [], None):
            with self.assertRaises(HTTPException): validate_start_body(bad)
        with self.assertRaises(ValueError): CaptureController(interface_provider=lambda: ["if0"], context=FakeContext).start("C:\\")

    def test_import_is_inert_worker_errors_do_not_leak_messages_and_status_hides_token(self):
        self.assertIsNone(controller.process)
        self.assertEqual(controller.state, "stopped")
        events = queue.Queue()
        errors = queue.Queue(maxsize=1); dropped = FakeValue("L", 0)
        _child("if0", events, FakeEvent(), dropped, lambda *args: (_ for _ in ()).throw(OSError("SECRET PAYLOAD")), errors)
        self.assertNotIn("SECRET PAYLOAD", errors.get_nowait()["_error"])
        self.assertEqual(dropped.value, 0)
        with patch.object(controller, "status", return_value={"state": "stopped", "token": "secret"}):
            self.assertNotIn("token", get_status(Request()))

    def test_interface_validation_and_lifecycle(self):
        c = CaptureController(interface_provider=lambda: ["if0"], context=FakeContext)
        with self.assertRaises(ValueError): c.start("arbitrary")
        self.assertEqual(c.start("if0")["state"], "running")
        with self.assertRaises(ValueError): c.start("if0")
        self.assertEqual(c.stop()["state"], "stopped")
        with self.assertRaises(ValueError): c.stop()
        c.shutdown()
        self.assertIsNone(c.process)

    def test_shutdown_and_failed_start(self):
        c = CaptureController(interface_provider=lambda: ["if0"], context=FakeContext)
        c.start("if0"); c.shutdown(); self.assertEqual(c.state, "stopped")
        class BrokenContext(FakeContext):
            Process = staticmethod(lambda **kwargs: FailedStartProcess())
        broken = CaptureController(interface_provider=lambda: ["if0"], context=BrokenContext)
        with self.assertRaises(RuntimeError): broken.start("if0")
        self.assertEqual(broken.state, "stopped")
        self.assertIsNone(broken.process); self.assertIsNone(broken.events)
        self.assertIsNone(broken.stop_event); self.assertIsNone(broken.dropped_counter)
        self.assertIsNone(broken.token); self.assertIsNone(broken.interface)
        self.assertIn("Capture setup failed (OSError)", broken.error or "")
        broken.shutdown(); self.assertEqual(broken.state, "stopped")

    def test_start_failure_closes_allocated_resources(self):
        created = {}
        starts = {"count": 0}
        class BrokenContext(FakeContext):
            @staticmethod
            def Queue(maxsize):
                created["queue"] = FakeQueue(maxsize); return created["queue"]
            @staticmethod
            def Process(**kwargs):
                starts["count"] += 1
                if starts["count"] == 1:
                    return FailedStartProcess()
                return FakeProcess()
        c = CaptureController(interface_provider=lambda: ["if0"], context=BrokenContext)
        with self.assertRaises(RuntimeError): c.start("if0")
        self.assertTrue(created["queue"].closed)
        self.assertTrue(created["queue"].joined)
        self.assertTrue(created["queue"].cancelled)
        self.assertIsNone(c.events); self.assertIsNone(c.stop_event)
        self.assertEqual(c.start("if0")["state"], "running")
        c.shutdown()

    def test_partial_start_failure_stops_child_before_releasing_resources(self):
        created = {}
        class PartialProcess(FakeProcess):
            def start(self):
                self.alive = True
                raise OSError("spawn failed after child creation")
        class PartialContext(FakeContext):
            @staticmethod
            def Queue(maxsize):
                created["queue"] = FakeQueue(maxsize); return created["queue"]
            @staticmethod
            def Event():
                created["event"] = FakeEvent(); return created["event"]
            @staticmethod
            def Process(**kwargs):
                created["count"] = created.get("count", 0) + 1
                if created["count"] > 1: return FakeProcess()
                created["process"] = PartialProcess(); return created["process"]
        c = CaptureController(interface_provider=lambda: ["if0"], context=PartialContext)
        with self.assertRaises(RuntimeError): c.start("if0")
        self.assertTrue(created["event"].is_set)
        self.assertFalse(created["process"].alive)
        self.assertTrue(created["queue"].closed)
        self.assertIsNone(c.process); self.assertIsNone(c.events)
        self.assertEqual(c.state, "stopped")
        self.assertEqual(c.start("if0")["state"], "running")
        c.shutdown()

    def test_interface_diagnostics_are_distinct_and_sanitized(self):
        from backend.capture_worker import interfaces
        scapy = types.ModuleType("scapy")
        scapy_all = types.ModuleType("scapy.all")
        scapy.all = scapy_all
        with patch.dict(sys.modules, {"scapy": None, "scapy.all": None}):
            with self.assertRaises(CaptureSetupError) as missing:
                interfaces()
        self.assertIn("Scapy is not installed", str(missing.exception))

        for failure, expected in (
            (PermissionError("private path detail"), "access was denied"),
            (OSError("Npcap driver unavailable"), "Npcap is unavailable"),
        ):
            scapy_all.get_if_list = unittest.mock.Mock(side_effect=failure)
            with patch.dict(sys.modules, {"scapy": scapy, "scapy.all": scapy_all}):
                with self.assertRaises(CaptureSetupError) as result:
                    interfaces()
            self.assertIn(expected, str(result.exception))
            self.assertNotIn("private path detail", str(result.exception))

        scapy_all.get_if_list = lambda: []
        with patch.dict(sys.modules, {"scapy": scapy, "scapy.all": scapy_all}):
            with self.assertRaises(CaptureSetupError) as empty:
                interfaces()
        self.assertIn("No capture interfaces", str(empty.exception))

    def test_crashed_worker_can_be_stopped_and_restarted(self):
        c = CaptureController(interface_provider=lambda: ["if0"], context=FakeContext)
        c.start("if0")
        _child("if0", c.events, FakeEvent(), c.dropped_counter,
               lambda *args: (_ for _ in ()).throw(OSError("SECRET PAYLOAD")), c.error_events)
        c.process.alive = False
        self.assertEqual(c.status()["state"], "error")
        self.assertEqual(c.dropped, 0)
        self.assertEqual(c.stop()["state"], "stopped")
        self.assertEqual(c.start("if0")["state"], "running")
        c.shutdown()

    def test_unstopped_worker_handle_is_preserved_and_blocks_restart(self):
        class StubbornProcess(FakeProcess):
            def start(self): self.alive = True
            def join(self, timeout=None): pass
            def terminate(self): pass
        class StubbornContext(FakeContext):
            Process = staticmethod(lambda **kwargs: StubbornProcess())
        c = CaptureController(interface_provider=lambda: ["if0"], context=StubbornContext)
        c.start("if0")
        self.assertEqual(c.stop()["state"], "error")
        self.assertIsNotNone(c.process)
        with self.assertRaises(ValueError): c.start("if0")
        c.process.alive = False
        self.assertEqual(c.stop()["state"], "stopped")
        c.shutdown()
        self.assertIsNone(c.process)

    def test_local_origin_guards(self):
        _local_request(Request())
        Request.headers = {"host": "192.168.1.10:8000", "origin": "http://localhost:5173"}
        Request.url = type("URL", (), {"hostname": "192.168.1.10"})()
        with self.assertRaises(HTTPException): _local_request(Request())
        Request.headers = {"host": "localhost:8000", "origin": "http://localhost:5173"}
        Request.url = type("URL", (), {"hostname": "localhost"})()
        Request.client = type("Client", (), {"host": "192.168.1.10"})()
        with self.assertRaises(HTTPException): _local_request(Request())
        Request.client = type("Client", (), {"host": "127.0.0.1"})()
        Request.headers = {"host": "localhost:8000", "origin": "https://evil.invalid"}
        with self.assertRaises(HTTPException): _guard(Request())

    def test_missing_and_invalid_capture_tokens_are_rejected(self):
        Request.headers = {"host": "localhost:8000", "origin": "http://localhost:5173"}
        Request.url = type("URL", (), {"hostname": "localhost"})()
        with patch.object(controller, "token", "expected-token"):
            with self.assertRaises(HTTPException): _guard(Request(), token=True)
            Request.headers["x-capture-token"] = "wrong-token"
            with self.assertRaises(HTTPException): _guard(Request(), token=True)
            Request.headers["x-capture-token"] = "expected-token"
            _guard(Request(), token=True)

    def test_start_route_rejects_missing_invalid_and_malformed_requests(self):
        Request.url = type("URL", (), {"hostname": "localhost"})()
        Request.headers = {"host": "localhost:8000", "origin": "http://localhost:5173"}
        with self.assertRaises(HTTPException) as missing:
            run_immediate_coroutine(start_capture(Request()))
        self.assertEqual(missing.exception.status_code, 403)
        Request.headers["x-capture-token"] = "invalid"
        with self.assertRaises(HTTPException) as invalid:
            run_immediate_coroutine(start_capture(Request()))
        self.assertEqual(invalid.exception.status_code, 403)
        Request.headers["x-capture-token"] = csrf_token
        Request.body = {"interface": "if0", "command": "arbitrary"}
        with self.assertRaises(HTTPException) as malformed:
            run_immediate_coroutine(start_capture(Request()))
        self.assertEqual(malformed.exception.status_code, 422)
        Request.body = "invalid-json"
        with self.assertRaises(HTTPException) as invalid_json:
            run_immediate_coroutine(start_capture(Request()))
        self.assertEqual(invalid_json.exception.status_code, 400)

    def test_session_resume_requires_csrf_token_and_only_returns_active_session_token(self):
        Request.url = type("URL", (), {"hostname": "localhost"})()
        Request.headers = {"host": "localhost:8000", "origin": "http://localhost:5173"}
        with self.assertRaises(HTTPException): get_capture_session(Request())
        Request.headers["x-capture-token"] = "invalid"
        with self.assertRaises(HTTPException): get_capture_session(Request())
        Request.headers["x-capture-token"] = csrf_token
        with patch.object(controller, "status", return_value={"state": "running"}), patch.object(controller, "token", "active-token"):
            self.assertEqual(get_capture_session(Request()), {"token": "active-token"})


if __name__ == "__main__": unittest.main()
