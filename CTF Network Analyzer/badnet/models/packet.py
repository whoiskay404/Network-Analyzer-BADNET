"""The normalised packet row produced by both readers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

#: Transport protocol values used across the data model.
IPV4 = "IPv4"
IPV6 = "IPv6"
ARP = "ARP"
TCP = "TCP"
UDP = "UDP"
ICMP = "ICMP"

_TRANSPORT_BY_PROTO_NUM = {"6": TCP, "17": UDP, "1": ICMP}


@dataclass(slots=True)
class NormalizedPacket:
    """One packet, flattened into scalars both readers can produce.

    A single flat row (rather than a per-protocol object tree) keeps memory
    bounded and makes it trivial to stream to NDJSON.  Fields that a given
    reader cannot populate are left at their defaults.
    """

    number: int
    ts: float
    """Unix epoch seconds (float, fractional)."""
    frame_len: int
    cap_len: int
    protocols: str = ""
    """``_ws.col.Protocol`` / frame.protocols, e.g. ``eth:ethertype:ip:tcp:http``."""
    src: str | None = None
    dst: str | None = None
    ip_version: int | None = None
    transport: str | None = None
    """TCP / UDP / ICMP / None."""
    src_port: int | None = None
    dst_port: int | None = None
    tcp_stream: int | None = None
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_len: int | None = None
    tcp_flags: str | None = None
    tcp_retransmission: bool = False
    tcp_out_of_order: bool = False
    tcp_syn: bool = False
    tcp_fin: bool = False
    tcp_rst: bool = False
    udp_length: int | None = None
    icmp_type: int | None = None
    malformed: bool = False
    malformed_reason: str | None = None
    info: str | None = None
    """Dissector summary line; used for display only."""
    payload_hex: str | None = None
    """Hex payload of the innermost data, capped by the reader."""

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON storage."""
        return asdict(self)

    @property
    def service_ports(self) -> tuple[str, str]:
        """``(src, dst)`` as ``ip:port`` strings (ports omitted when absent)."""
        s = f"{self.src}:{self.src_port}" if self.src_port else (self.src or "?")
        d = f"{self.dst}:{self.dst_port}" if self.dst_port else (self.dst or "?")
        return s, d

    @property
    def flow_key(self) -> str:
        """Direction-independent key identifying the bidirectional conversation."""
        left, right = sorted(
            [(self.src or "", self.src_port or 0), (self.dst or "", self.dst_port or 0)]
        )
        proto = self.transport or IPV4
        return f"{left[0]}:{left[1]}-{right[0]}:{right[1]}-{proto}"


def transport_from_ip_proto(value: str | None) -> str | None:
    """Map an IP protocol number to a symbolic transport name."""
    if not value:
        return None
    return _TRANSPORT_BY_PROTO_NUM.get(str(value).strip())


@dataclass(slots=True)
class ReadStats:
    """Counters returned alongside a stream of :class:`NormalizedPacket`."""

    total_packets: int = 0
    malformed: int = 0
    bytes_on_wire: int = 0
    bytes_captured: int = 0
    reader: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Serialise for metadata.json."""
        return {
            "total_packets": self.total_packets,
            "malformed": self.malformed,
            "bytes_on_wire": self.bytes_on_wire,
            "bytes_captured": self.bytes_captured,
            "reader": self.reader,
            "warnings": list(self.warnings),
        }
