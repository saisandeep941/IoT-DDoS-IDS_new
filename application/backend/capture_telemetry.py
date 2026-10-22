"""Metadata-only telemetry helpers. This module never stores packet objects."""
from collections import Counter, deque
from datetime import datetime, timezone
import ipaddress
import math


def packet_metadata(packet):
    """Extract minimal metadata from a Scapy-like packet; safe for mock packets."""
    proto = "OTHER"
    src = dst = ""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
        if packet.haslayer(IP):
            layer = packet[IP]
            src, dst = layer.src, layer.dst
            proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(int(layer.proto), "IP")
        elif packet.haslayer(IPv6):
            layer = packet[IPv6]
            src, dst = layer.src, layer.dst
            proto = {6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(int(layer.nh), "IPv6")
        elif packet.haslayer(TCP): proto = "TCP"
        elif packet.haslayer(UDP): proto = "UDP"
        elif packet.haslayer(ICMP): proto = "ICMP"
    except ImportError:
        # Unit tests may supply a metadata-like fake without Scapy installed.
        proto = getattr(packet, "protocol", "OTHER")
        src, dst = getattr(packet, "src", ""), getattr(packet, "dst", "")
    packet_time = getattr(packet, "time", None)
    try: timestamp = datetime.fromtimestamp(float(packet_time), timezone.utc).isoformat() if packet_time is not None else datetime.now(timezone.utc).isoformat()
    except (TypeError, ValueError, OSError): timestamp = datetime.now(timezone.utc).isoformat()
    return {"timestamp": timestamp, "protocol": str(proto),
            "src": str(src), "dst": str(dst), "bytes": int(len(packet))}


def flow_packet_metadata(packet, packet_length=None):
    """Extract allowlisted IP/TCP/UDP headers for experimental flow summaries.

    Packet payloads are never accessed. Unsupported or malformed packets are
    omitted from flow telemetry while remaining available to packet telemetry.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        if packet.haslayer(IP):
            network = packet[IP]
            protocol_number = int(network.proto)
        elif packet.haslayer(IPv6):
            network = packet[IPv6]
            protocol_number = int(network.nh)
        else:
            return None
        if protocol_number == 6 and packet.haslayer(TCP):
            transport = packet[TCP]
            protocol = "TCP"
            flags = int(transport.flags)
        elif protocol_number == 17 and packet.haslayer(UDP):
            transport = packet[UDP]
            protocol = "UDP"
            flags = None
        else:
            return None
        stamp = float(packet.time)
        if not math.isfinite(stamp):
            return None
        length = int(len(packet) if packet_length is None else packet_length)
        result = {
            "timestamp": stamp, "protocol": protocol,
            "src_ip": ipaddress.ip_address(str(network.src)).compressed,
            "src_port": int(transport.sport),
            "dst_ip": ipaddress.ip_address(str(network.dst)).compressed,
            "dst_port": int(transport.dport),
            "packet_length": length,
        }
        if not (0 <= result["src_port"] <= 65535 and 0 <= result["dst_port"] <= 65535):
            return None
        if flags is not None:
            result["tcp_flags"] = flags
        return result
    except Exception:
        return None


class Telemetry:
    def __init__(self, history_limit=200, endpoint_limit=64):
        self.history = deque(maxlen=history_limit)
        self.endpoint_limit = endpoint_limit
        self.endpoints = Counter()
        self.protocols = Counter()
        self.packets = self.bytes = self.dropped = 0

    def add(self, event):
        # Whitelist fields so queue messages cannot smuggle payload data.
        clean = {k: event[k] for k in ("timestamp", "protocol", "src", "dst", "bytes") if k in event}
        clean["timestamp"] = str(clean.get("timestamp", ""))[:64]
        clean["src"] = str(clean.get("src", ""))[:128]
        clean["dst"] = str(clean.get("dst", ""))[:128]
        clean["protocol"] = str(clean.get("protocol", "OTHER"))[:16]
        clean["bytes"] = max(0, int(clean.get("bytes", 0)))
        self.packets += 1; self.bytes += clean["bytes"]
        if clean["protocol"] in self.protocols or len(self.protocols) < 16:
            self.protocols[clean["protocol"]] += 1
        for endpoint in (clean["src"], clean["dst"]):
            if endpoint and (endpoint in self.endpoints or len(self.endpoints) < self.endpoint_limit): self.endpoints[endpoint] += 1
        self.history.append(clean)

    def snapshot(self):
        return {"packets": self.packets, "bytes": self.bytes, "dropped": self.dropped,
                "protocols": dict(self.protocols), "endpoints": dict(self.endpoints),
                "recent": list(self.history)}
