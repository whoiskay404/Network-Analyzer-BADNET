"""Capture format detection from magic bytes (never from the file extension)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

#: Little-endian classic pcap.
PCAP_LE = b"\xd4\xc3\xb2\xa1"
#: Big-endian classic pcap.
PCAP_BE = b"\xa1\xb2\xc3\xd4"
#: Little-endian pcap with nanosecond timestamps.
PCAP_LE_NS = b"\x4d\x3c\xb2\xa1"
#: Big-endian pcap with nanosecond timestamps.
PCAP_BE_NS = b"\xa1\xb2\x3c\x4d"
#: pcapng section header block (byte-order agnostic prefix).
PCAPNG = b"\x0a\x0d\x0d\x0a"

_HEADER_SIZE = 24


@dataclass(frozen=True, slots=True)
class CaptureFormat:
    """Result of format sniffing."""

    kind: str
    """``pcap``, ``pcapng`` or ``unknown``."""
    endianness: str = "little"
    nanosecond: bool = False
    detail: str = ""

    @property
    def supported(self) -> bool:
        """True when BADNET knows how to read this format."""
        return self.kind in ("pcap", "pcapng")


def sniff(path: str | Path, *, head_size: int = 4096) -> CaptureFormat:
    """Identify the capture format from the first bytes of *path*.

    ``pcap`` vs ``pcapng`` and byte order are taken from the magic, so a
    ``.pcap`` file that is really pcapng (and vice versa) is handled correctly.
    """
    p = Path(path)
    try:
        with p.open("rb") as fh:
            head = fh.read(head_size)
    except OSError as exc:
        from badnet.errors import InputError

        raise InputError(f"cannot read {p}: {exc}") from exc

    if len(head) < 4:
        return CaptureFormat(kind="unknown", detail="file is shorter than 4 bytes")

    magic = head[:4]
    if magic == PCAP_LE:
        return CaptureFormat("pcap", "little", False, "classic pcap, little-endian")
    if magic == PCAP_BE:
        return CaptureFormat("pcap", "big", False, "classic pcap, big-endian")
    if magic == PCAP_LE_NS:
        return CaptureFormat("pcap", "little", True, "classic pcap, little-endian, nanosecond")
    if magic == PCAP_BE_NS:
        return CaptureFormat("pcap", "big", True, "classic pcap, big-endian, nanosecond")
    if magic == PCAPNG:
        # Byte-order magic follows the block type: 0x1A2B3C4D (big) or 0x4D3C2B1A (little).
        if len(head) >= 8:
            bom = int.from_bytes(head[8:12], "big")
            if bom == 0x1A2B3C4D:
                return CaptureFormat("pcapng", "big", False, "pcapng, big-endian block format")
            if bom == 0x4D3C2B1A:
                return CaptureFormat(
                    "pcapng", "little", False, "pcapng, little-endian block format"
                )
        return CaptureFormat("pcapng", "little", False, "pcapng")

    if len(head) >= _HEADER_SIZE:
        # Some writers emit a slightly different magic; fall back to structure.
        version_major = int.from_bytes(head[4:6], "little")
        link_type = int.from_bytes(head[20:24], "little")
        if version_major in (2, 3, 4) and link_type < 300:
            return CaptureFormat(
                "pcap",
                "little",
                False,
                f"classic pcap (version {version_major}, linktype {link_type})",
            )
        version_major = int.from_bytes(head[4:6], "big")
        link_type = int.from_bytes(head[20:24], "big")
        if version_major in (2, 3, 4) and link_type < 300:
            return CaptureFormat(
                "pcap",
                "big",
                False,
                f"classic pcap (version {version_major}, linktype {link_type})",
            )

    return CaptureFormat(kind="unknown", detail="no known capture magic found")


def describe(path: str | Path) -> str:
    """One-line format description used in reports."""
    fmt = sniff(path)
    return fmt.detail or f"unknown format ({fmt.kind})"
