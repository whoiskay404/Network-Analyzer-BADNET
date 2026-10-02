"""TCP stream / UDP flow models and reassembly containers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class StreamDirection(StrEnum):
    """Direction of a reconstructed stream half."""

    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"


@dataclass(slots=True)
class StreamInfo:
    """Metadata for one TCP stream (or UDP flow) in the capture."""

    stream_id: int
    proto: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    packets: int = 0
    bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    app_protocol: str = ""
    """Short protocol label (``http``, ``tls``, ``dns``...) - never a dissector stack."""
    protocols: str = ""
    """Raw dissector layer stack, e.g. ``eth:ethertype:ip:tcp:http``."""
    tcp_flags: list[str] = field(default_factory=list)
    has_syn: bool = False
    has_fin: bool = False
    has_rst: bool = False
    interesting_port: bool = False

    @property
    def duration(self) -> float:
        """Seconds between first and last packet of the stream."""
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def client_label(self) -> str:
        """``ip:port`` of the client side."""
        return f"{self.client_ip}:{self.client_port}"

    @property
    def server_label(self) -> str:
        """``ip:port`` of the server side."""
        return f"{self.server_ip}:{self.server_port}"

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {
            "stream_id": self.stream_id,
            "proto": self.proto,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "server_ip": self.server_ip,
            "server_port": self.server_port,
            "client": self.client_label,
            "server": self.server_label,
            "packets": self.packets,
            "bytes": self.bytes,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": self.duration,
            "app_protocol": self.app_protocol,
            "protocols": self.protocols,
            "tcp_flags": self.tcp_flags,
            "has_syn": self.has_syn,
            "has_fin": self.has_fin,
            "has_rst": self.has_rst,
            "interesting_port": self.interesting_port,
        }


@dataclass(slots=True)
class Segment:
    """One reassembly record: raw payload with its TCP sequence number."""

    seq: int
    data: bytes
    ts: float
    packet_no: int

    def __len__(self) -> int:
        """Payload length in bytes."""
        return len(self.data)


@dataclass(slots=True)
class DirectionalData:
    """Per-direction reassembly result for one stream."""

    stream_id: int
    src: str
    src_port: int
    dst: str
    dst_port: int
    packets: int = 0
    bytes: int = 0
    first_seq: int | None = None
    next_seq: int | None = None
    retransmissions: int = 0
    out_of_order: int = 0
    overlaps: int = 0
    gaps: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def missing_bytes(self) -> int:
        """Bytes never observed between the lowest and highest sequence number."""
        if self.first_seq is None or self.next_seq is None:
            return 0
        return max(0, self.next_seq - self.first_seq - self.bytes)

    def to_dict(self) -> dict[str, object]:
        """Serialise for JSON reports."""
        return {
            "stream_id": self.stream_id,
            "src": self.src,
            "src_port": self.src_port,
            "dst": self.dst,
            "dst_port": self.dst_port,
            "packets": self.packets,
            "bytes": self.bytes,
            "first_seq": self.first_seq,
            "next_seq": self.next_seq,
            "retransmissions": self.retransmissions,
            "out_of_order": self.out_of_order,
            "overlaps": self.overlaps,
            "gaps": self.gaps,
            "missing_bytes": self.missing_bytes,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass(slots=True)
class StreamData:
    """Fully reconstructed bidirectional stream payload."""

    stream_id: int
    client_to_server: bytes
    server_to_client: bytes
    client: DirectionalData
    server: DirectionalData

    @property
    def total_bytes(self) -> int:
        """Combined payload size of both directions."""
        return len(self.client_to_server) + len(self.server_to_client)

    def to_dict(self) -> dict[str, object]:
        """Serialise for JSON reports."""
        return {
            "stream_id": self.stream_id,
            "client_to_server_bytes": len(self.client_to_server),
            "server_to_client_bytes": len(self.server_to_client),
            "client": self.client.to_dict(),
            "server": self.server.to_dict(),
            "missing_bytes": self.client.missing_bytes + self.server.missing_bytes,
        }
