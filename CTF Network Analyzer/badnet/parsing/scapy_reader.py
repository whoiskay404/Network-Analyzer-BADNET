"""Scapy fallback reader - used when tshark is unavailable.

Scapy gives correct packets but not dissector-level detail, so this reader does
its own minimal dissection of DNS, HTTP, FTP and TLS from raw payloads.  The
feature set is deliberately smaller and every consumer is told which reader
produced its data, so reports never imply more coverage than was achieved.

Memory: :class:`scapy.utils.PcapReader` streams packet by packet; ``rdpcap`` is
never used.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from badnet.errors import MissingDependencyError
from badnet.models.packet import NormalizedPacket

log = logging.getLogger("badnet.scapy")

MAX_PAYLOAD_CAPTURE = 2048
"""Bytes of payload hex kept per packet (carving uses streams, not this)."""


def scapy_available() -> bool:
    """True when Scapy can be imported."""
    try:
        import scapy  # noqa: F401
    except Exception:  # pragma: no cover - broken install
        return False
    return True


def _require_scapy():
    try:
        from scapy.all import PcapReader
    except ImportError as exc:
        raise MissingDependencyError(
            "neither tshark nor scapy is available",
            hint="install one of them: sudo apt install tshark   (recommended) or pip install scapy",
        ) from exc
    return PcapReader


def open_reader(path: Path) -> object:
    """Open a streaming Scapy reader for *path*."""
    PcapReader = _require_scapy()
    try:
        return PcapReader(str(path))
    except (FileNotFoundError, PermissionError) as exc:
        from badnet.errors import InputError

        raise InputError(f"cannot read {path}: {exc}") from exc
    except Exception as exc:
        from badnet.errors import InputError

        raise InputError(
            f"cannot parse {path} as a capture file: {exc}",
            hint="check the file is a pcap/pcapng and is not truncated or encrypted",
        ) from exc


def iter_packets(
    path: Path,
    *,
    max_packets: int | None = None,
    on_error: str = "warn",
) -> Iterator[NormalizedPacket]:
    """Stream normalised packets using Scapy.

    Parameters
    ----------
    path:
        Capture file to read.
    max_packets:
        Stop after this many packets (``--max-packets``).
    on_error:
        ``"warn"`` records a warning for unreadable packets, ``"raise"`` re-raises.
    """
    reader = open_reader(path)
    count = 0
    try:
        for raw in reader:  # streaming: one packet at a time
            if max_packets and count >= max_packets:
                break
            count += 1
            try:
                packet = normalize(raw, number=count)
            except Exception as exc:
                # One bad packet must not end the analysis of a 40 GiB capture.
                log.warning("scapy could not normalise packet %d: %s", count, exc)
                if on_error == "raise":
                    raise
                yield NormalizedPacket(
                    number=count,
                    ts=float(getattr(raw, "time", 0.0) or 0.0),
                    frame_len=len(raw) if raw is not None else 0,
                    cap_len=0,
                    protocols="malformed",
                    malformed=True,
                    malformed_reason=f"normalisation failed: {exc}",
                )
                continue
            if packet is not None:
                yield packet
    except EOFError:
        log.warning("capture ended early (truncated file?)")
    except Exception as exc:
        from badnet.errors import AnalysisError

        raise AnalysisError(f"scapy failed while reading {path}: {exc}") from exc
    finally:
        try:
            reader.close()
        except Exception as exc:  # pragma: no cover - close rarely fails
            log.debug("closing scapy reader for %s raised %s", path, exc)


def normalize(raw, *, number: int) -> NormalizedPacket | None:
    """Flatten one Scapy packet into a :class:`NormalizedPacket`."""
    ts = float(getattr(raw, "time", 0.0) or 0.0)
    frame_len = len(raw) if raw is not None else 0

    ip = raw.getlayer("IP") if hasattr(raw, "getlayer") else None
    ip6 = raw.getlayer("IPv6") if hasattr(raw, "getlayer") else None
    tcp = raw.getlayer("TCP") if hasattr(raw, "getlayer") else None
    udp = raw.getlayer("UDP") if hasattr(raw, "getlayer") else None
    icmp = raw.getlayer("ICMP") if hasattr(raw, "getlayer") else None

    src = dst = None
    ip_version = None
    if ip is not None:
        src, dst = ip.src, ip.dst
        ip_version = 4
    elif ip6 is not None:
        src, dst = ip6.src, ip6.dst
        ip_version = 6

    transport = None
    src_port = dst_port = None
    stream = None
    seq = ack = tcp_len = None
    flags = None
    syn = fin = rst = False
    if tcp is not None:
        transport = "TCP"
        src_port, dst_port = tcp.sport, tcp.dport
        seq, ack = int(tcp.seq), int(tcp.ack)
        flags = _tcp_flags(tcp)
        syn, fin, rst = bool(tcp.flags.S), bool(tcp.flags.F), bool(tcp.flags.R)
        payload = bytes(tcp.payload) if tcp.payload else b""
        tcp_len = len(payload)
        stream = _tcp_stream_index(raw)
    elif udp is not None:
        transport = "UDP"
        src_port, dst_port = udp.sport, udp.dport
        payload = bytes(udp.payload) if udp.payload else b""
    elif icmp is not None:
        transport = "ICMP"
        payload = b""
    else:
        payload = b""

    protocols = _protocol_names(raw)
    malformed = bool(getattr(raw, "malformed", False)) or _is_truncated(raw, ip, tcp)

    return NormalizedPacket(
        number=number,
        ts=ts,
        frame_len=frame_len,
        cap_len=frame_len,
        protocols=protocols,
        src=src,
        dst=dst,
        ip_version=ip_version,
        transport=transport,
        src_port=src_port,
        dst_port=dst_port,
        tcp_stream=stream,
        tcp_seq=seq,
        tcp_ack=ack,
        tcp_len=tcp_len,
        tcp_flags=flags,
        tcp_syn=syn,
        tcp_fin=fin,
        tcp_rst=rst,
        icmp_type=int(getattr(icmp, "type", 0)) if icmp is not None else None,
        malformed=malformed,
        malformed_reason="truncated frame" if malformed else None,
        payload_hex=payload[:MAX_PAYLOAD_CAPTURE].hex() if payload else None,
    )


def iter_payloads(
    path: Path,
    *,
    max_packets: int | None = None,
) -> Iterator[tuple[int, float, str, int, int, bytes]]:
    """Stream ``(number, ts, src, sport, dport, payload)`` for TCP/UDP.

    Used by the fallback DNS/HTTP/TLS dissectors and by stream reassembly when
    tshark's follow output is unavailable.  Only payloads are retained, never
    the Scapy object graph.
    """
    reader = open_reader(path)
    count = 0
    try:
        for raw in reader:
            if max_packets and count >= max_packets:
                break
            count += 1
            tcp = raw.getlayer("TCP") if hasattr(raw, "getlayer") else None
            udp = raw.getlayer("UDP") if hasattr(raw, "getlayer") else None
            layer = tcp if tcp is not None else udp
            if layer is None:
                continue
            ip = raw.getlayer("IP")
            ip6 = raw.getlayer("IPv6")
            src = getattr(ip, "src", None) or getattr(ip6, "src", None)
            payload = bytes(layer.payload) if layer.payload else b""
            yield (
                count,
                float(getattr(raw, "time", 0.0) or 0.0),
                src or "",
                int(layer.sport) if layer.sport is not None else 0,
                int(layer.dport) if layer.dport is not None else 0,
                payload,
            )
    finally:
        try:
            reader.close()
        except Exception as exc:  # pragma: no cover
            log.debug("closing scapy reader for %s raised %s", path, exc)


def _tcp_flags(tcp) -> str:
    """Render TCP flags as the same short string tshark uses."""
    out: list[str] = []
    if tcp.flags.S:
        out.append("SYN")
    if tcp.flags.F:
        out.append("FIN")
    if tcp.flags.R:
        out.append("RST")
    if tcp.flags.P:
        out.append("PSH")
    if tcp.flags.A:
        out.append("ACK")
    if tcp.flags.U:
        out.append("URG")
    return " ".join(out)


def _tcp_stream_index(raw) -> int | None:
    """Derive a deterministic stream id from the connection 5-tuple.

    Uses CRC32 over a canonical string rather than :func:`hash`, because Python's
    string hashing is randomised per process and stream ids must be stable
    between runs (they end up in case files and reports).
    """
    from zlib import crc32

    ip = raw.getlayer("IP") if hasattr(raw, "getlayer") else None
    ip6 = raw.getlayer("IPv6") if hasattr(raw, "getlayer") else None
    tcp = raw.getlayer("TCP") if hasattr(raw, "getlayer") else None
    if tcp is None or (ip is None and ip6 is None):
        return None
    src = getattr(ip, "src", None) or getattr(ip6, "src", None)
    dst = getattr(ip, "dst", None) or getattr(ip6, "dst", None)
    if not src or not dst or tcp.sport is None or tcp.dport is None:
        return None
    # Canonicalise direction so both halves share one id.
    ends = sorted([(src, int(tcp.sport)), (dst, int(tcp.dport))])
    key = f"{ends[0][0]}:{ends[0][1]}-{ends[1][0]}:{ends[1][1]}-tcp"
    return crc32(key.encode()) & 0x0FFFFFFF


def _protocol_names(raw) -> str:
    """Best-effort protocol stack string, e.g. ``eth:ip:tcp:http``."""
    names = []
    for layer_name in ("Ethernet", "IP", "IPv6", "ARP", "TCP", "UDP", "ICMP", "Raw"):
        if raw.haslayer(layer_name):
            names.append(layer_name.lower())
    payload_names = _sniff_payload_protocols(raw)
    names.extend(payload_names)
    return ":".join(names) if names else "unknown"


def _sniff_payload_protocols(raw) -> list[str]:
    """Identify HTTP/FTP/TLS from the raw bytes Scapy left undecoded."""
    tcp = raw.getlayer("TCP") if hasattr(raw, "getlayer") else None
    udp = raw.getlayer("UDP") if hasattr(raw, "getlayer") else None
    layer = tcp if tcp is not None else udp
    if layer is None:
        return []
    payload = bytes(layer.payload) if layer.payload else b""
    if not payload:
        return []
    out: list[str] = []
    if payload[:1] == b"\x16" and payload[1] == 0x03:
        out.append("tls")
    elif payload[:3] in (b"GET", b"PUT", b"POS") or payload[:4] in (b"HEAD", b"HTTP"):
        out.append("http")
    elif payload[:4] in (b"USER", b"PASS", b"RETR", b"QUIT", b"FEAT"):
        out.append("ftp")
    return out


def _is_truncated(raw, ip, tcp) -> bool:
    """Detect frames whose declared IP length exceeds the captured bytes.

    A truncated capture file (or a snaplen that clipped the frame) shows up as an
    IP total-length field larger than the bytes actually captured.  We allow a
    64-byte slack because Ethernet padding and scapy's own framing differ by a few
    bytes depending on link type.
    """
    if ip is None:
        return False
    try:
        ip_len = int(ip.len or 0)
        if ip_len <= 0:
            return False
        # Bytes of the IP packet actually present (from the IP header onwards).
        raw_bytes = bytes(raw)
        header_len = 14 if raw.haslayer("Ethernet") else 0
        ip_bytes_present = len(raw_bytes) - header_len
        return ip_len > ip_bytes_present + 64
    except Exception as exc:  # pragma: no cover - defensive, malformed frames only
        log.debug("truncation check failed: %s", exc)
        return False
