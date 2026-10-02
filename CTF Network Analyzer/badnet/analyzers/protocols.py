"""Protocol summary: counts for each application protocol present.

Only protocols actually observed are reported.  Malformed packets are counted
and surfaced rather than silently dropped.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field

from badnet.analyzers.pipeline import PipelineContext

log = logging.getLogger("badnet.analyzers.protocols")


@dataclass(slots=True)
class ProtocolSummary:
    """Protocol counts for the whole capture."""

    counts: dict[str, int] = field(default_factory=dict)
    packets: int = 0
    malformed: int = 0
    bytes_by_protocol: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Serialise for JSON reports."""
        return {
            "counts": self.counts,
            "packets": self.packets,
            "malformed": self.malformed,
            "bytes_by_protocol": self.bytes_by_protocol,
            "warnings": list(self.warnings),
        }

    @property
    def present(self) -> dict[str, int]:
        """Only the protocols that were seen, in descending count order."""
        return {k: v for k, v in sorted(self.counts.items(), key=lambda kv: -kv[1]) if v > 0}


#: Order used for display (protocols BADNET understands).
DISPLAY_ORDER = (
    "IPv4",
    "IPv6",
    "ARP",
    "ICMP",
    "TCP",
    "UDP",
    "DNS",
    "HTTP",
    "TLS",
    "FTP",
    "SMTP",
    "SMB",
    "SSH",
    "DHCP",
    "NTP",
    "SNMP",
    "Telnet",
    "POP3",
    "IMAP",
)

#: Which frame-protocol tokens map to which display name.
ALIASES: dict[str, tuple[str, ...]] = {
    "IPv4": ("ip",),
    "IPv6": ("ipv6", "ip6"),
    "ARP": ("arp",),
    "ICMP": ("icmp", "icmpv6"),
    "TCP": ("tcp",),
    "UDP": ("udp",),
    "DNS": ("dns",),
    "HTTP": ("http",),
    "TLS": ("tls", "ssl"),
    "FTP": ("ftp", "ftp-data"),
    "SMTP": ("smtp",),
    "SMB": ("smb", "smb2", "netbios", "nbns"),
    "SSH": ("ssh",),
    "DHCP": ("dhcp", "bootp"),
    "NTP": ("ntp",),
    "SNMP": ("snmp",),
    "Telnet": ("telnet",),
    "POP3": ("pop",),
    "IMAP": ("imap",),
}


def analyze(ctx: PipelineContext, *, counts: dict[str, int] | None = None) -> ProtocolSummary:
    """Compute protocol counts from the packet stream.

    Parameters
    ----------
    counts:
        Optional pre-computed counts (from a prior pass) to merge, so the
        summary can be assembled without a second pass when the caller already
        walked the capture.
    """
    summary = ProtocolSummary()
    counter: Counter[str] = Counter()
    bytes_counter: Counter[str] = Counter()

    if counts:
        counter.update(counts)

    for packet in ctx.iter_packets():
        summary.packets += 1
        if packet.malformed:
            summary.malformed += 1
        for name, matched in _match(packet).items():
            if matched:
                counter[name] += 1
                bytes_counter[name] += packet.frame_len

    summary.counts = {name: counter.get(name, 0) for name in DISPLAY_ORDER}
    summary.bytes_by_protocol = {name: bytes_counter.get(name, 0) for name in DISPLAY_ORDER}
    if summary.malformed:
        summary.warnings.append(
            f"{summary.malformed} packet(s) were not decoded cleanly "
            "(truncated capture or malformed frames)"
        )
    if summary.packets == 0:
        summary.warnings.append("no packets were decoded from this capture")
    return summary


def _match(packet) -> dict[str, bool]:
    """Which display protocols this packet belongs to."""
    stack = (packet.protocols or "").lower()
    out: dict[str, bool] = {}
    for name, aliases in ALIASES.items():
        if name == "IPv4":
            out[name] = packet.ip_version == 4
            continue
        if name == "IPv6":
            out[name] = packet.ip_version == 6
            continue
        out[name] = any(alias in stack for alias in aliases)
    return out
