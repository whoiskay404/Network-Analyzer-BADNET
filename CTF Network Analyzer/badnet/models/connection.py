"""Normalised bidirectional connection records."""

from __future__ import annotations

from dataclasses import dataclass, field

#: Layers that carry no protocol identity.  tshark appends these whenever it has
#: finished decoding a payload, so the tail of ``frame.protocols`` is never a
#: service name.
_PSEUDO_LAYERS = frozenset(
    {
        "data",
        "data-text-lines",
        "data-data",
        "tcp",
        "udp",
        "ip",
        "ipv4",
        "ipv6",
        "eth",
        "ethertype",
        "arp",
        "frame",
        "media",
        "multiple",
        "fragment",
        "icmp",
        "igmp",
        "sll",
    }
)


def _most_specific_layer(protocols: str) -> str:
    """Return the most specific real dissector layer in a ``frame.protocols`` value.

    Returns ``""`` when the stack contains nothing but transport/payload layers.
    """
    for layer in reversed(protocols.split(":")):
        name = layer.strip().lower()
        if name and not name.startswith(("data", "x509")) and name not in _PSEUDO_LAYERS:
            return layer.strip()
    return ""


@dataclass(slots=True)
class Connection:
    """One 5-tuple conversation, normalised to client -> server orientation.

    ``proto`` is TCP or UDP.  ``endpoint_a``/``endpoint_b`` are the canonical
    orientation (lowest address first) while ``client``/``server`` follow the
    observed direction of first data transfer, which is what a human expects to
    see in a report.
    """

    proto: str
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    packets: int = 0
    bytes: int = 0
    a_to_b_packets: int = 0
    a_to_b_bytes: int = 0
    b_to_a_packets: int = 0
    b_to_a_bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    stream_id: int | None = None
    """tshark TCP stream index when known."""
    protocols: str = ""
    """Application protocol hint from the dissector (e.g. ``http``, ``tls``)."""
    interesting_port: bool = False
    tcp_flags_seen: set[str] = field(default_factory=set)
    service_name: str = ""
    """Resolved service name, e.g. ``http``. Empty means "not resolved"."""

    @property
    def duration(self) -> float:
        """Seconds between first and last packet of the conversation."""
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def key(self) -> str:
        """Canonical direction-independent key."""
        return f"{self.a_ip}:{self.a_port}-{self.b_ip}:{self.b_port}-{self.proto}"

    @property
    def client_label(self) -> str:
        """``ip:port`` of the client side."""
        return f"{self.client_ip}:{self.client_port}"

    @property
    def server_label(self) -> str:
        """``ip:port`` of the server side."""
        return f"{self.server_ip}:{self.server_port}"

    @property
    def service(self) -> str:
        """Best-effort application protocol name.

        Preference order:

        1. The port→service table from ``signatures/interesting_ports.yaml``,
           applied to the server port (falling back to the client port for
           captures with no recognisable server).
        2. The most specific real dissector layer, ignoring transport layers and
           the ``data*``/``media``/``x509*`` pseudo-layers tshark appends.

        Deliberately *not* "the last layer of ``frame.protocols``": for an HTTP
        stream that stack ends in ``data-text-lines``, which would label every web
        connection with a payload dissector's internal name.
        """
        if self.service_name:
            return self.service_name
        layer = _most_specific_layer(self.protocols)
        return layer.upper() if layer else self.proto

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {
            "proto": self.proto,
            "a_ip": self.a_ip,
            "a_port": self.a_port,
            "b_ip": self.b_ip,
            "b_port": self.b_port,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "server_ip": self.server_ip,
            "server_port": self.server_port,
            "packets": self.packets,
            "bytes": self.bytes,
            "a_to_b_packets": self.a_to_b_packets,
            "a_to_b_bytes": self.a_to_b_bytes,
            "b_to_a_packets": self.b_to_a_packets,
            "b_to_a_bytes": self.b_to_a_bytes,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": self.duration,
            "stream_id": self.stream_id,
            "protocols": self.protocols,
            "interesting_port": self.interesting_port,
            "service": self.service,
            "tcp_flags_seen": sorted(self.tcp_flags_seen),
        }
