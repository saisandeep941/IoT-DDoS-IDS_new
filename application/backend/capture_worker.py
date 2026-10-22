"""Isolated process controller. Scapy is loaded only after an explicit start."""
import multiprocessing as mp
import queue
import secrets
import sys
import threading
import time

from backend.capture_telemetry import Telemetry, packet_metadata, flow_packet_metadata
from backend.flow_telemetry import ExperimentalFlowTracker


class CaptureSetupError(RuntimeError):
    """A sanitized, user-actionable capture setup failure."""


def _capture_error(exc):
    if isinstance(exc, ModuleNotFoundError) and exc.name and exc.name.split(".", 1)[0] == "scapy":
        return "Scapy is not installed in this Python environment. Install the optional capture requirements."
    if isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5:
        return "Packet capture access was denied. Check Npcap permissions or run with the required privileges."
    message = str(exc).lower()
    if any(text in message for text in ("npcap", "winpcap", "wpcap.dll", "packet.dll", "libpcap", "pcap_open")):
        return "Npcap is unavailable or could not open the capture interface. Install or repair Npcap and check its service."
    if sys.platform == "win32" and isinstance(exc, OSError) and getattr(exc, "winerror", None) in (2, 3, 126):
        return "Npcap is unavailable. Install or repair the Npcap driver before capturing."
    return f"Capture setup failed ({type(exc).__name__}). Check the optional capture setup and selected interface."


def interfaces():
    try:
        from scapy.all import get_if_list
    except (ImportError, ModuleNotFoundError) as exc:
        raise CaptureSetupError(_capture_error(exc)) from None
    try:
        result = list(get_if_list())
    except Exception as exc:
        raise CaptureSetupError(_capture_error(exc)) from None
    if not result:
        raise CaptureSetupError("No capture interfaces are available. Check Npcap installation and enabled network adapters.")
    return result


def scapy_capture(interface, emit, stop_event):
    from scapy.all import sniff
    def capture_event(packet):
        packet_event = packet_metadata(packet)
        events = [{"type": "packet", "data": packet_event}]
        try:
            flow_event = flow_packet_metadata(packet, packet_event["bytes"])
        except Exception:
            flow_event = None
        if flow_event is not None:
            events.append({"type": "flow", "data": flow_event})
        emit({"type": "capture_batch", "events": events})
    # store=False: Scapy does not retain packet objects in a capture list.
    while not stop_event.is_set():
        sniff(iface=interface, prn=capture_event, store=False,
              promisc=False, timeout=0.5, stop_filter=lambda _: stop_event.is_set())


def _child(interface, events, stop_event, dropped, adapter, errors=None):
    try:
        adapter(interface, lambda item: _put_bounded(events, item, dropped), stop_event)
    except BaseException as exc:
        # Keep control-plane failures out of the capture-batch drop counter.
        if errors is not None:
            try: errors.put_nowait({"_error": _capture_error(exc)})
            except (queue.Full, OSError, ValueError): pass


def _put_bounded(events, item, dropped=None):
    try: events.put_nowait(item)
    except queue.Full:
        if dropped is not None:
            with dropped.get_lock(): dropped.value += 1


class CaptureController:
    def __init__(self, interface_provider=interfaces, adapter=scapy_capture, context=None):
        self.interface_provider, self.adapter = interface_provider, adapter
        self.context = context or mp.get_context("spawn")
        # Lock order is lifecycle_lock -> telemetry_lock. The queue consumer
        # only takes telemetry_lock and never lifecycle_lock, so lifecycle
        # code can join it without holding a lock it needs.
        self.lifecycle_lock = threading.RLock()
        self.telemetry_lock = threading.RLock()
        self.lock = self.lifecycle_lock  # compatibility for existing callers
        self.telemetry = Telemetry()
        self.flow_telemetry = ExperimentalFlowTracker()
        self.state = "stopped"; self.error = None; self.interface = None
        self.process = self.events = self.error_events = self.stop_event = self.token = None
        self.consumer = self.consumer_done = self.producer_done = None
        self.consumer_failed = False
        self.dropped = 0; self.dropped_counter = None

    def status(self):
        with self.lifecycle_lock:
            if self.state == "running" and self.process and not self.process.is_alive():
                try: self.process.join(timeout=0)
                except Exception: pass
                self._finish_producer_locked()
                if not self._drain_consumer_locked(timeout=2):
                    self.state = "error"
                    with self.telemetry_lock:
                        self.error = "Capture queue consumer could not drain safely. Session resources are retained; retry stop before restarting."
                else:
                    with self.telemetry_lock:
                        self.state = "error" if self.error else "stopped"
                        self.flow_telemetry = ExperimentalFlowTracker()
                    self._release()
            return self._status_locked()

    def start(self, interface):
        with self.lifecycle_lock:
            if self.state != "stopped": raise ValueError("Capture can start only from stopped state")
            if self.process is not None or self.events is not None or self.consumer is not None:
                raise ValueError("Previous capture resources have not been safely released")
            available = self.interface_provider()
            if not isinstance(interface, str) or interface not in available:
                raise ValueError("Unknown capture interface")
            self.events = self.context.Queue(maxsize=512)
            self.error_events = self.context.Queue(maxsize=1)
            # Flow summaries are scoped to a capture session; legacy packet
            # telemetry intentionally retains its existing cumulative behavior.
            with self.telemetry_lock:
                self.flow_telemetry = ExperimentalFlowTracker()
                self.error = None
            self.stop_event = self.context.Event()
            self.producer_done = threading.Event()
            self.consumer_done = threading.Event()
            self.consumer_failed = False
            self.dropped_counter = self.context.Value("L", 0); self.interface = interface
            self.dropped = 0; self.token = secrets.token_urlsafe(24)
            self.consumer = threading.Thread(
                target=self._consume_queue,
                args=(self.events, self.error_events, self.producer_done, self.consumer_done),
                name="capture-queue-consumer", daemon=True,
            )
            try:
                self.consumer.start()
            except Exception as exc:
                self.producer_done.set()
                self._set_error(f"Capture queue consumer failed to start ({type(exc).__name__}).")
                if self._join_consumer_locked(timeout=1):
                    self._release()
                    self.interface = None; self.token = None; self.state = "stopped"
                else:
                    self.state = "error"
                    self._set_error("Capture queue consumer did not stop after startup failure. Retry stop before starting another session.")
                raise RuntimeError("Capture queue consumer failed to start") from exc
            try:
                self.process = self.context.Process(
                    target=_child,
                    args=(interface, self.events, self.stop_event, self.dropped_counter, self.adapter, self.error_events),
                    daemon=True,
                )
                self.process.start(); self.state = "running"
            except Exception as exc:
                with self.telemetry_lock: self.error = _capture_error(exc)
                # A start failure can happen after a child was partially created.
                # Give that child a chance to stop before releasing its IPC handles.
                if self.stop_event is not None:
                    try: self.stop_event.set()
                    except Exception: pass
                alive = False
                if self.process is not None:
                    try:
                        alive = self.process.is_alive()
                        if alive:
                            self.process.join(timeout=1)
                            alive = self.process.is_alive()
                        if alive:
                            self.process.terminate(); self.process.join(timeout=2)
                            alive = self.process.is_alive()
                    except Exception:
                        alive = True
                if alive:
                    self.state = "error"
                    self._set_error("Capture worker did not exit after a startup failure. Stop it before retrying.")
                else:
                    self._finish_producer_locked()
                    if self._join_consumer_locked(timeout=2):
                        self._refresh_dropped()
                        self._release()
                        self.state = "stopped"
                        self.interface = None; self.token = None
                    else:
                        self.state = "error"
                        self._set_error("Capture queue consumer did not stop after startup failure. Retry stop before starting another session.")
                raise RuntimeError("Capture worker failed to start") from exc
            return {**self.status(), "token": self.token}

    def _apply_item(self, item):
        with self.telemetry_lock:
            if isinstance(item, dict) and "_error" in item:
                self.error = str(item["_error"])[:240]
                self.flow_telemetry = ExperimentalFlowTracker()
            elif isinstance(item, dict) and item.get("type") == "capture_batch":
                records = item.get("events")
                if not isinstance(records, list): return
                # Apply each packet/flow pair under one lock so snapshots
                # cannot observe only one half of an accepted batch.
                for record in records:
                    if not isinstance(record, dict) or not isinstance(record.get("data"), dict): continue
                    if record.get("type") == "packet":
                        try: self.telemetry.add(record["data"])
                        except (TypeError, ValueError, OverflowError): pass
                    elif record.get("type") == "flow":
                        self.flow_telemetry.add_packet(record["data"])
            else:
                # Preserve adapters that emit the original packet event shape.
                try: self.telemetry.add(item)
                except (TypeError, ValueError, OverflowError): pass

    def _consume_queue(self, events, errors, producer_done, consumer_done):
        try:
            while True:
                try: control = errors.get_nowait()
                except (queue.Empty, EOFError, OSError, ValueError): control = None
                if isinstance(control, dict) and "_error" in control:
                    self._apply_item(control)
                try:
                    item = events.get(timeout=0.1)
                except queue.Empty:
                    if producer_done.is_set():
                        # Producer join precedes this signal, so its queue
                        # feeder has finished and an empty read means drained.
                        try: control = errors.get_nowait()
                        except (queue.Empty, EOFError, OSError, ValueError): control = None
                        if isinstance(control, dict) and "_error" in control:
                            self._apply_item(control)
                        break
                    continue
                self._apply_item(item)
        except Exception as exc:
            with self.telemetry_lock:
                self.error = f"Capture queue consumer failed ({type(exc).__name__})."
                self.consumer_failed = True
        finally:
            consumer_done.set()

    def _finish_producer_locked(self):
        if self.producer_done is not None:
            self.producer_done.set()

    def _join_consumer_locked(self, timeout):
        consumer = self.consumer
        if consumer is None: return True
        if consumer is threading.current_thread(): return False
        consumer.join(timeout=timeout)
        return not consumer.is_alive()

    def _drain_consumer_locked(self, timeout):
        if not self._join_consumer_locked(timeout):
            return False
        with self.telemetry_lock:
            return not self.consumer_failed

    def _refresh_dropped(self):
        counter = self.dropped_counter
        if counter is not None:
            try: self.dropped = int(counter.value)
            except (AttributeError, OSError, ValueError): pass

    def _set_error(self, message):
        with self.telemetry_lock:
            self.error = message

    def _status_locked(self):
        self._refresh_dropped()
        with self.telemetry_lock:
            error = self.error
        return {"state": self.state, "interface": self.interface, "error": error,
                "dropped": self.dropped}

    def snapshot(self):
        with self.lifecycle_lock:
            with self.telemetry_lock:
                data = self.telemetry.snapshot()
                counter = self.dropped_counter
                data["dropped"] = int(counter.value) if counter is not None else self.dropped
                return data

    def flow_snapshot(self):
        with self.lifecycle_lock:
            with self.telemetry_lock:
                data = self.flow_telemetry.snapshot(now=time.time())
                counter = self.dropped_counter
                data["capture_dropped_events"] = int(counter.value) if counter is not None else self.dropped
                return data

    def stop(self):
        with self.lifecycle_lock:
            if self.state not in ("running", "error", "stopping"): raise ValueError("Capture is not running")
            self.state = "stopping"
            if self.stop_event: self.stop_event.set()
            if self.process:
                try:
                    self.process.join(timeout=3)
                    if self.process.is_alive():
                        self.process.terminate(); self.process.join(timeout=2)
                    if self.process.is_alive():
                        self._set_error("Capture worker did not exit after termination")
                        self.state = "error"
                        return self._status_locked()
                except Exception as exc:
                    self._set_error(f"Capture worker shutdown failed ({type(exc).__name__})")
                    self.state = "error"
                    return self._status_locked()
            self._finish_producer_locked()
            # Do not release an unexpectedly failed consumer's session: it may
            # have dequeued a batch before the aggregation error occurred.
            if not self._drain_consumer_locked(timeout=2):
                self._set_error("Capture queue consumer could not drain safely. Session resources are retained; retry stop before restarting.")
                self.state = "error"
                return self._status_locked()
            self._refresh_dropped()
            with self.telemetry_lock:
                self.flow_telemetry = ExperimentalFlowTracker()
            self.state = "stopped"
            self._release()
            return self._status_locked()

    def _release(self):
        # Resource release is safe only after producer death and consumer join.
        events, errors, process = self.events, self.error_events, self.process
        with self.telemetry_lock:
            self._refresh_dropped()
            self.process = self.events = self.error_events = self.stop_event = self.dropped_counter = None
            self.consumer = self.consumer_done = self.producer_done = None
        for channel in (events, errors):
            if channel is None: continue
            try: channel.cancel_join_thread()
            except Exception: pass
            try: channel.close()
            except Exception: pass
            try: channel.join_thread()
            except Exception: pass
        if process is not None:
            try: process.close()
            except Exception: pass

    def shutdown(self):
        with self.lifecycle_lock:
            if self.state in ("running", "error"):
                self.stop()
            if self.process is None and self.consumer is None:
                self._release()

