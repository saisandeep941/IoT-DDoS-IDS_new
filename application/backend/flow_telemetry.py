"""Experimental, bounded TCP/UDP flow summaries from packet metadata only.

The capture worker feeds this module and the capture API exposes its summaries.
It does not perform model inference. Direction and timeout policies below are
provisional and are not claimed to match CICFlowMeter or Random Forest V2.
"""

from collections import deque
import ipaddress
import math
import time


class ExperimentalFlowTracker:
    """Aggregate allowlisted metadata records without accepting packet objects.

    Provisional policies:
    * the first observed endpoint pair is called forward; the reverse is backward;
    * a flow expires after ``idle_timeout_seconds`` since its latest timestamp;
    * input timestamps and reported durations/IATs use seconds.

    Only TCP and UDP records with valid IP addresses, ports, timestamps, and
    packet lengths are accepted. TCP flags are retained as raw numeric masks;
    individual flag names are deliberately not interpreted.
    """

    MAX_PACKET_LENGTH = 16 * 1024 * 1024
    MAX_FLOW_CAPACITY = 4096
    MAX_HISTORY_CAPACITY = 4096
    MAX_COUNTER_VALUE = (1 << 63) - 1

    def __init__(self, max_flows=1024, event_history_limit=256,
                 idle_timeout_seconds=60.0):
        if (isinstance(max_flows, bool) or not isinstance(max_flows, int) or
                not 1 <= max_flows <= self.MAX_FLOW_CAPACITY):
            raise ValueError(f"max_flows must be between 1 and {self.MAX_FLOW_CAPACITY}")
        if (isinstance(event_history_limit, bool) or
                not isinstance(event_history_limit, int) or
                not 1 <= event_history_limit <= self.MAX_HISTORY_CAPACITY):
            raise ValueError(f"event_history_limit must be between 1 and {self.MAX_HISTORY_CAPACITY}")
        if (isinstance(idle_timeout_seconds, bool) or
                not isinstance(idle_timeout_seconds, (int, float))):
            raise ValueError("idle_timeout_seconds must be a positive finite number")
        try:
            idle_timeout_seconds = float(idle_timeout_seconds)
        except (OverflowError, TypeError, ValueError):
            raise ValueError("idle_timeout_seconds must be a positive finite number") from None
        if not math.isfinite(idle_timeout_seconds) or idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be a positive finite number")

        self.max_flows = max_flows
        self.event_history_limit = event_history_limit
        self.idle_timeout_seconds = float(idle_timeout_seconds)
        self.flows = {}
        self.event_history = deque(maxlen=event_history_limit)
        self._next_flow_id = 1
        self.malformed_packets = 0
        self.unsupported_packets = 0
        self.expired_flows = 0
        self.evicted_flows = 0

    @staticmethod
    def _endpoint(address, port):
        if not isinstance(address, str):
            raise ValueError("invalid address")
        canonical = ipaddress.ip_address(address).compressed
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError("invalid port")
        return canonical, port

    @staticmethod
    def _finite_timestamp(value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("invalid timestamp")
        try:
            timestamp = float(value)
        except (OverflowError, TypeError, ValueError):
            raise ValueError("invalid timestamp") from None
        if not math.isfinite(timestamp):
            raise ValueError("invalid timestamp")
        return timestamp

    @classmethod
    def _normalize(cls, event):
        if not isinstance(event, dict):
            raise ValueError("metadata record must be a dict")
        protocol = event.get("protocol")
        if protocol not in ("TCP", "UDP"):
            return None
        timestamp = cls._finite_timestamp(event.get("timestamp"))
        source = cls._endpoint(event.get("src_ip"), event.get("src_port"))
        destination = cls._endpoint(event.get("dst_ip"), event.get("dst_port"))
        length = event.get("packet_length")
        if (isinstance(length, bool) or not isinstance(length, int) or
                not 0 <= length <= cls.MAX_PACKET_LENGTH):
            raise ValueError("invalid packet length")
        flags = event.get("tcp_flags")
        if protocol == "TCP" and flags is not None:
            if isinstance(flags, bool) or not isinstance(flags, int) or not 0 <= flags <= 0x1FF:
                raise ValueError("invalid TCP flags")
        else:
            flags = None
        # Return only validated, bounded scalar metadata. Other keys, including
        # any payload-like value, are never read or copied.
        return {
            "timestamp": timestamp, "protocol": protocol,
            "src": source, "dst": destination,
            "packet_length": length, "tcp_flags": flags,
        }

    def _expire(self, now):
        stale = [key for key, flow in self.flows.items()
                 if now - flow["last_seen_at"] >= self.idle_timeout_seconds]
        for key in stale:
            del self.flows[key]
        self.expired_flows = self._increment(self.expired_flows, len(stale))
        return len(stale)

    @classmethod
    def _increment(cls, value, amount=1):
        return min(cls.MAX_COUNTER_VALUE, value + amount)

    def expire(self, now=None):
        """Expire idle flows; ``now`` is seconds in the input timestamp domain."""
        if now is None:
            now = time.time()
        now = self._finite_timestamp(now)
        return self._expire(now)

    @staticmethod
    def _new_direction():
        return {
            "packets": 0, "bytes": 0,
            "packet_length_min": None, "packet_length_max": None,
            "packet_length_mean": 0.0,
            "iat_count": 0, "iat_min_seconds": None,
            "iat_max_seconds": None, "iat_mean_seconds": 0.0,
            "tcp_packets_with_flags": 0, "tcp_flags_or": 0,
            "_last_seen_at": None,
        }

    def _new_flow(self, metadata):
        if len(self.flows) >= self.max_flows:
            oldest_key = min(self.flows, key=lambda key: (
                self.flows[key]["last_seen_at"], self.flows[key]["flow_id"]))
            del self.flows[oldest_key]
            self.evicted_flows = self._increment(self.evicted_flows)
        flow_id = self._next_flow_id
        active_ids = {flow["flow_id"] for flow in self.flows.values()}
        while flow_id in active_ids:
            flow_id = 1 if flow_id >= self.MAX_COUNTER_VALUE else flow_id + 1
        self._next_flow_id = 1 if flow_id >= self.MAX_COUNTER_VALUE else flow_id + 1
        return {
            "flow_id": flow_id,
            "protocol": metadata["protocol"],
            "forward_src": metadata["src"],
            "forward_dst": metadata["dst"],
            "started_at": metadata["timestamp"],
            "last_seen_at": metadata["timestamp"],
            "packets": 0, "bytes": 0,
            "packet_length_min": None, "packet_length_max": None,
            "packet_length_mean": 0.0,
            "iat_count": 0, "iat_min_seconds": None,
            "iat_max_seconds": None, "iat_mean_seconds": 0.0,
            "out_of_order_timestamps": 0,
            "forward": self._new_direction(),
            "backward": self._new_direction(),
        }

    @staticmethod
    def _update_length(stats, length):
        stats["packets"] = ExperimentalFlowTracker._increment(stats["packets"])
        stats["bytes"] = ExperimentalFlowTracker._increment(stats["bytes"], length)
        stats["packet_length_min"] = length if stats["packet_length_min"] is None else min(stats["packet_length_min"], length)
        stats["packet_length_max"] = length if stats["packet_length_max"] is None else max(stats["packet_length_max"], length)
        stats["packet_length_mean"] += (length - stats["packet_length_mean"]) / stats["packets"]

    @staticmethod
    def _update_iat(stats, timestamp):
        previous = stats.get("_last_seen_at")
        if previous is not None:
            interval = timestamp - previous
            if interval >= 0:
                count = ExperimentalFlowTracker._increment(stats["iat_count"])
                stats["iat_count"] = count
                stats["iat_mean_seconds"] += (interval - stats["iat_mean_seconds"]) / count
                stats["iat_min_seconds"] = interval if stats["iat_min_seconds"] is None else min(stats["iat_min_seconds"], interval)
                stats["iat_max_seconds"] = interval if stats["iat_max_seconds"] is None else max(stats["iat_max_seconds"], interval)
        # Keep the watermark so an out-of-order packet cannot create negative IATs.
        stats["_last_seen_at"] = timestamp if previous is None else max(previous, timestamp)

    def add_packet(self, event):
        """Add one metadata dict. Return its assigned direction, or None if rejected."""
        try:
            metadata = self._normalize(event)
        except (ValueError, TypeError, OverflowError):
            self.malformed_packets = self._increment(self.malformed_packets)
            return None
        if metadata is None:
            self.unsupported_packets = self._increment(self.unsupported_packets)
            return None

        timestamp = metadata["timestamp"]
        # Expiration and the new packet use the same timestamp domain.
        self._expire(timestamp)
        endpoint_a, endpoint_b = metadata["src"], metadata["dst"]
        low, high = sorted((endpoint_a, endpoint_b))
        key = (metadata["protocol"], low, high)
        flow = self.flows.get(key)
        if flow is not None and (
                not math.isfinite(timestamp - flow["started_at"]) or
                not math.isfinite(timestamp - flow["last_seen_at"])):
            self.malformed_packets = self._increment(self.malformed_packets)
            return None
        if flow is None:
            flow = self._new_flow(metadata)
            self.flows[key] = flow
        direction_name = "forward" if endpoint_a == flow["forward_src"] else "backward"

        length = metadata["packet_length"]
        self._update_length(flow, length)
        self._update_length(flow[direction_name], length)
        self._update_iat(flow, timestamp)
        self._update_iat(flow[direction_name], timestamp)
        previous_last_seen = flow["last_seen_at"]
        flow["last_seen_at"] = max(previous_last_seen, timestamp)
        flow["started_at"] = min(flow["started_at"], timestamp)
        flow["out_of_order_timestamps"] = self._increment(
            flow["out_of_order_timestamps"], int(timestamp < previous_last_seen))

        flags = metadata["tcp_flags"]
        if flags is not None:
            flow[direction_name]["tcp_packets_with_flags"] = self._increment(
                flow[direction_name]["tcp_packets_with_flags"])
            flow[direction_name]["tcp_flags_or"] |= flags

        self.event_history.append({
            "flow_id": flow["flow_id"], "timestamp": timestamp,
            "protocol": metadata["protocol"], "direction": direction_name,
            "src_ip": endpoint_a[0], "src_port": endpoint_a[1],
            "dst_ip": endpoint_b[0], "dst_port": endpoint_b[1],
            "packet_length": length, "tcp_flags": flags,
        })
        return direction_name

    @staticmethod
    def _public_direction(stats):
        return {key: value for key, value in stats.items() if not key.startswith("_")}

    def snapshot(self, now=None):
        """Return bounded summaries; optionally expire using supplied event time."""
        if now is not None:
            self.expire(now)
        summaries = []
        for flow in sorted(self.flows.values(), key=lambda item: item["flow_id"]):
            summaries.append({
                "flow_id": flow["flow_id"], "protocol": flow["protocol"],
                "forward_src": {"ip": flow["forward_src"][0], "port": flow["forward_src"][1]},
                "forward_dst": {"ip": flow["forward_dst"][0], "port": flow["forward_dst"][1]},
                "direction_rule": "first_observed_endpoint_pair_is_forward (provisional)",
                "started_at_seconds": flow["started_at"],
                "last_seen_at_seconds": flow["last_seen_at"],
                "duration_seconds": flow["last_seen_at"] - flow["started_at"],
                "packets": flow["packets"], "bytes": flow["bytes"],
                "packet_length_min": flow["packet_length_min"],
                "packet_length_max": flow["packet_length_max"],
                "packet_length_mean": flow["packet_length_mean"],
                "iat_count": flow["iat_count"],
                "iat_min_seconds": flow["iat_min_seconds"],
                "iat_max_seconds": flow["iat_max_seconds"],
                "iat_mean_seconds": flow["iat_mean_seconds"],
                "out_of_order_timestamps": flow["out_of_order_timestamps"],
                "forward": self._public_direction(flow["forward"]),
                "backward": self._public_direction(flow["backward"]),
            })
        return {
            "label": "Experimental flow telemetry; not a V2 prediction",
            "idle_timeout_seconds": self.idle_timeout_seconds,
            "timeout_policy": "idle-time expiration; provisional",
            "timestamp_unit": "seconds; provisional",
            "flows": summaries,
            "recent_events": list(self.event_history),
            "malformed_packets": self.malformed_packets,
            "unsupported_packets": self.unsupported_packets,
            "expired_flows": self.expired_flows,
            "evicted_flows": self.evicted_flows,
        }
