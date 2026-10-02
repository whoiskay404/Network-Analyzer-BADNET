"""Capture-level statistics."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ProtocolCount:
    """One row of the protocol hierarchy."""

    name: str
    packets: int
    bytes: int

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {"name": self.name, "packets": self.packets, "bytes": self.bytes}


@dataclass(slots=True)
class EndpointCount:
    """An address tally (source, destination or port)."""

    value: str
    count: int
    packets: int
    bytes: int

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {
            "value": self.value,
            "count": self.count,
            "packets": self.packets,
            "bytes": self.bytes,
        }


@dataclass(slots=True)
class PcapInfo:
    """Everything ``badnet info`` needs.

    Fields that capinfos/tshark could not supply stay ``None`` and the analyzer
    records a warning rather than inventing a value.
    """

    path: str
    file_size: int
    capture_format: str
    """pcap / pcapng / unknown - detected from magic bytes, never the extension."""
    file_format_detail: str | None = None
    packet_count: int | None = None
    first_ts: float | None = None
    last_ts: float | None = None
    duration: float | None = None
    avg_rate: float | None = None
    """Average packets per second over the capture duration."""
    data_bit_rate: float | None = None
    snaplen: int | None = None
    link_type: str | None = None
    protocols: list[ProtocolCount] = field(default_factory=list)
    ipv4_packets: int = 0
    ipv6_packets: int = 0
    arp_packets: int = 0
    malformed_packets: int = 0
    top_sources: list[EndpointCount] = field(default_factory=list)
    top_destinations: list[EndpointCount] = field(default_factory=list)
    top_ports: list[EndpointCount] = field(default_factory=list)
    readers: list[str] = field(default_factory=list)
    """Which tools/parsers produced the numbers (``capinfos``, ``tshark``, ``scapy``)."""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Serialise for JSON reports and metadata.json."""
        return {
            "path": self.path,
            "file_size": self.file_size,
            "capture_format": self.capture_format,
            "file_format_detail": self.file_format_detail,
            "packet_count": self.packet_count,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "duration": self.duration,
            "avg_rate": self.avg_rate,
            "data_bit_rate": self.data_bit_rate,
            "snaplen": self.snaplen,
            "link_type": self.link_type,
            "protocols": [p.to_dict() for p in self.protocols],
            "ipv4_packets": self.ipv4_packets,
            "ipv6_packets": self.ipv6_packets,
            "arp_packets": self.arp_packets,
            "malformed_packets": self.malformed_packets,
            "top_sources": [e.to_dict() for e in self.top_sources],
            "top_destinations": [e.to_dict() for e in self.top_destinations],
            "top_ports": [e.to_dict() for e in self.top_ports],
            "readers": list(self.readers),
            "warnings": list(self.warnings),
        }

    @property
    def malformed(self) -> bool:
        """True when at least one packet could not be decoded cleanly."""
        return self.malformed_packets > 0
