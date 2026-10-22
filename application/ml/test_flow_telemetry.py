"""Synthetic tests for the isolated experimental flow tracker."""

import math
import unittest

from backend.flow_telemetry import ExperimentalFlowTracker


def packet(timestamp, protocol="TCP", src_ip="192.0.2.10", src_port=1234,
           dst_ip="198.51.100.20", dst_port=443, length=60,
           tcp_flags=None, **extra):
    # extra keys let tests prove payload-like values are ignored.
    return {
        "timestamp": timestamp, "protocol": protocol,
        "src_ip": src_ip, "src_port": src_port,
        "dst_ip": dst_ip, "dst_port": dst_port,
        "packet_length": length, "tcp_flags": tcp_flags, **extra,
    }


class ExperimentalFlowTests(unittest.TestCase):
    def test_tcp_bidirectional_counts_lengths_iats_and_raw_flags(self):
        tracker = ExperimentalFlowTracker()
        self.assertEqual(tracker.add_packet(packet(100, length=60, tcp_flags=0x02)), "forward")
        self.assertEqual(tracker.add_packet(packet(101, length=100, tcp_flags=0x10)), "forward")
        self.assertEqual(tracker.add_packet(packet(
            102, src_ip="198.51.100.20", src_port=443,
            dst_ip="192.0.2.10", dst_port=1234, length=80, tcp_flags=0x10,
        )), "backward")

        flow = tracker.snapshot()["flows"][0]
        self.assertEqual((flow["packets"], flow["bytes"], flow["duration_seconds"]), (3, 240, 2))
        self.assertEqual((flow["packet_length_min"], flow["packet_length_max"], flow["packet_length_mean"]), (60, 100, 80))
        self.assertEqual((flow["iat_count"], flow["iat_mean_seconds"]), (2, 1))
        self.assertEqual(flow["forward"]["packets"], 2)
        self.assertEqual(flow["forward"]["tcp_flags_or"], 0x12)
        self.assertEqual(flow["forward"]["tcp_packets_with_flags"], 2)
        self.assertEqual(flow["backward"]["tcp_flags_or"], 0x10)
        self.assertIn("provisional", flow["direction_rule"])

    def test_udp_reverse_direction_shares_one_flow_without_tcp_flags(self):
        tracker = ExperimentalFlowTracker()
        tracker.add_packet(packet(10, protocol="UDP", length=72))
        tracker.add_packet(packet(
            11, protocol="UDP", src_ip="198.51.100.20", src_port=443,
            dst_ip="192.0.2.10", dst_port=1234, length=40,
        ))
        snapshot = tracker.snapshot()
        self.assertEqual(len(snapshot["flows"]), 1)
        self.assertEqual(snapshot["flows"][0]["backward"]["packets"], 1)
        self.assertEqual(snapshot["flows"][0]["forward"]["tcp_packets_with_flags"], 0)
        self.assertEqual(snapshot["flows"][0]["bytes"], 112)

    def test_tcp_flag_mask_is_preserved_without_interpreting_flag_names(self):
        tracker = ExperimentalFlowTracker()
        tracker.add_packet(packet(1, tcp_flags=0x100))
        flow = tracker.snapshot()["flows"][0]
        self.assertEqual(flow["forward"]["tcp_flags_or"], 0x100)
        self.assertEqual(flow["forward"]["tcp_packets_with_flags"], 1)

    def test_distinct_ports_and_protocols_create_separate_flows(self):
        tracker = ExperimentalFlowTracker()
        tracker.add_packet(packet(1, protocol="TCP"))
        tracker.add_packet(packet(1, protocol="UDP"))
        tracker.add_packet(packet(1, protocol="TCP", dst_port=444))
        self.assertEqual(len(tracker.snapshot()["flows"]), 3)

    def test_out_of_order_timestamps_never_produce_negative_iat(self):
        tracker = ExperimentalFlowTracker()
        tracker.add_packet(packet(5))
        tracker.add_packet(packet(7))
        tracker.add_packet(packet(6))
        flow = tracker.snapshot()["flows"][0]
        self.assertEqual(flow["out_of_order_timestamps"], 1)
        self.assertEqual(flow["last_seen_at_seconds"], 7)
        self.assertEqual(flow["duration_seconds"], 2)
        self.assertEqual(flow["iat_count"], 1)
        self.assertEqual(flow["iat_min_seconds"], 2)

    def test_idle_expiry_is_provisional_and_uses_supplied_time_domain(self):
        tracker = ExperimentalFlowTracker(idle_timeout_seconds=10)
        tracker.add_packet(packet(100))
        self.assertEqual(tracker.expire(109.99), 0)
        self.assertEqual(tracker.expire(110), 1)
        snapshot = tracker.snapshot()
        self.assertEqual(snapshot["flows"], [])
        self.assertEqual(snapshot["expired_flows"], 1)
        self.assertIn("provisional", snapshot["timeout_policy"])

    def test_flow_and_event_history_bounds_and_oldest_flow_eviction(self):
        tracker = ExperimentalFlowTracker(max_flows=2, event_history_limit=2)
        tracker.add_packet(packet(1, src_ip="192.0.2.1"))
        tracker.add_packet(packet(2, src_ip="192.0.2.2"))
        tracker.add_packet(packet(3, src_ip="192.0.2.3"))
        tracker.add_packet(packet(4, src_ip="192.0.2.4"))
        snapshot = tracker.snapshot()
        self.assertEqual(len(snapshot["flows"]), 2)
        self.assertEqual(len(snapshot["recent_events"]), 2)
        self.assertEqual(snapshot["evicted_flows"], 2)
        self.assertLessEqual(len(tracker.flows), tracker.max_flows)

    def test_malformed_and_unsupported_packets_are_rejected_safely(self):
        tracker = ExperimentalFlowTracker()
        malformed = (
            packet(float("nan")), packet(10 ** 10000), packet(1, src_ip="not-an-ip"),
            packet(1, src_port=-1), packet(1, length=-1),
            packet(1, length=ExperimentalFlowTracker.MAX_PACKET_LENGTH + 1),
            packet(1, tcp_flags=512), packet(1, dst_port=True),
            None, "not a metadata record",
        )
        for item in malformed:
            self.assertIsNone(tracker.add_packet(item))
        self.assertIsNone(tracker.add_packet(packet(1, protocol="ICMP")))
        snapshot = tracker.snapshot()
        self.assertEqual(snapshot["malformed_packets"], len(malformed))
        self.assertEqual(snapshot["unsupported_packets"], 1)
        self.assertEqual(snapshot["flows"], [])

    def test_extreme_time_delta_is_rejected_without_corrupting_existing_flow(self):
        tracker = ExperimentalFlowTracker()
        tracker.add_packet(packet(1e308))
        self.assertIsNone(tracker.add_packet(packet(-1e308)))
        flow = tracker.snapshot()["flows"][0]
        self.assertEqual(flow["packets"], 1)
        self.assertEqual(flow["duration_seconds"], 0)
        self.assertEqual(tracker.snapshot()["malformed_packets"], 1)

    def test_payload_like_fields_are_never_returned_or_retained(self):
        tracker = ExperimentalFlowTracker()
        tracker.add_packet(packet(1, tcp_flags=0x08, payload="PRIVATE BODY", raw=b"secret"))
        serialized = repr(tracker.snapshot())
        self.assertNotIn("PRIVATE BODY", serialized)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("payload", serialized)
        self.assertNotIn("raw", serialized)

    def test_no_guessing_of_unresolved_schema_fields_or_model_input(self):
        tracker = ExperimentalFlowTracker()
        tracker.add_packet(packet(1, tcp_flags=0x80))
        snapshot = tracker.snapshot()
        self.assertNotIn("SimillarHTTP", snapshot)
        self.assertNotIn("Inbound", snapshot)
        self.assertNotIn("Fwd Header Length.1", snapshot)
        self.assertNotIn("CWE Flag Count", snapshot)
        self.assertNotIn("CWR Flag Count", snapshot)
        self.assertNotIn("features", snapshot)

    def test_constructor_rejects_unbounded_or_invalid_limits(self):
        with self.assertRaises(ValueError): ExperimentalFlowTracker(max_flows=0)
        with self.assertRaises(ValueError): ExperimentalFlowTracker(max_flows=4097)
        with self.assertRaises(ValueError): ExperimentalFlowTracker(event_history_limit=0)
        with self.assertRaises(ValueError): ExperimentalFlowTracker(event_history_limit=math.inf)
        with self.assertRaises(ValueError): ExperimentalFlowTracker(idle_timeout_seconds=0)
        with self.assertRaises(ValueError): ExperimentalFlowTracker(idle_timeout_seconds=10 ** 10000)

    def test_lifetime_counters_and_flow_ids_remain_bounded(self):
        tracker = ExperimentalFlowTracker(max_flows=2)
        tracker.malformed_packets = tracker.MAX_COUNTER_VALUE - 1
        tracker.add_packet(None)
        tracker.add_packet(None)
        self.assertEqual(tracker.malformed_packets, tracker.MAX_COUNTER_VALUE)
        tracker._next_flow_id = tracker.MAX_COUNTER_VALUE
        tracker.add_packet(packet(1, src_ip="192.0.2.1"))
        tracker.add_packet(packet(1, src_ip="192.0.2.2"))
        ids = {flow["flow_id"] for flow in tracker.snapshot()["flows"]}
        self.assertEqual(ids, {1, tracker.MAX_COUNTER_VALUE})


if __name__ == "__main__":
    unittest.main()
