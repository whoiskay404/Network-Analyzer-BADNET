"""Capture-level analysis: statistics for ``badnet info``.

Counters come from capinfos/tshark wherever possible (that is the whole point
of the orchestrator: do not re-implement dissectors), and fall back to the
packet stream only for numbers those tools do not expose.
"""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path

from badnet.analyzers.pipeline import PipelineContext
from badnet.integrations import tshark
from badnet.models.packet import NormalizedPacket
from badnet.models.pcapinfo import EndpointCount, PcapInfo, ProtocolCount
from badnet.utils.hashing import hash_file

log = logging.getLogger("badnet.analyzers.pcap")

#: Layers reported in the protocol summary, in display order.
SUMMARY_PROTOCOLS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("IPv4", ("ip",)),
    ("IPv6", ("ipv6", "ip6")),
    ("ARP", ("arp",)),
    ("ICMP", ("icmp", "icmpv6", "igmp")),
    ("TCP", ("tcp",)),
    ("UDP", ("udp",)),
    ("DNS", ("dns",)),
    ("HTTP", ("http",)),
    ("TLS", ("tls", "ssl")),
    ("FTP", ("ftp", "ftp-data")),
    ("SMTP", ("smtp",)),
    ("SMB", ("smb", "smb2", "netbios")),
    ("SSH", ("ssh",)),
    ("DHCP", ("dhcp", "bootp")),
    ("NTP", ("ntp",)),
    ("SNMP", ("snmp",)),
    ("Telnet", ("telnet",)),
    ("POP3", ("pop",)),
    ("IMAP", ("imap",)),
)

_TOP_N = 10


def analyze(ctx: PipelineContext, *, deep: bool = True) -> PcapInfo:
    """Build a :class:`PcapInfo` for the capture in *ctx*.

    Parameters
    ----------
    deep:
        When False only file-level facts are collected (no second pass over the
        packets), which is what ``badnet info --fast`` uses.
    """
    path: Path = ctx.pcap_path
    stat = path.stat()
    fmt = _format_of(path)
    info = PcapInfo(
        path=str(path),
        file_size=stat.st_size,
        capture_format=fmt[0],
        file_format_detail=fmt[1],
        readers=[ctx.reader],
    )

    _fill_from_capinfos(ctx, info)
    if deep:
        _fill_from_packets(ctx, info)
    else:
        if info.packet_count is None:
            info.warnings.append("packet counts require the deep pass (--fast skips it)")
    return info


def _format_of(path: Path) -> tuple[str, str]:
    from badnet.parsing import pcap_format

    fmt = pcap_format.sniff(path)
    return fmt.kind, fmt.detail


def _fill_from_capinfos(ctx: PipelineContext, info: PcapInfo) -> None:
    """Use capinfos for counts/timestamps/rates instead of recomputing them."""
    assert ctx.tshark_info is not None
    try:
        raw = tshark.capinfos_facts(ctx.tshark_info, ctx.pcap_path)
    except Exception as exc:
        info.warnings.append(f"capinfos unavailable ({exc}); falling back to packet scan")
        return

    info.readers.append("capinfos")

    if ctx.max_packets is not None:
        # capinfos always reports the whole file.  With --max-packets the analysed
        # subset is smaller, so these figures would contradict the packet scan.
        info.warnings.append(
            f"capinfos describes the whole file; this run was limited to "
            f"{ctx.max_packets} packet(s) so the numbers below come from the packet scan"
        )
        return

    count = _first_int(raw, "packet_count")
    if count is not None:
        info.packet_count = count
    size = _first_int(raw, "file_size")
    if size is not None:
        info.file_size = size
    if info.first_ts is None and raw.get("start_time"):
        info.first_ts = _epoch_of(raw["start_time"])
    if info.last_ts is None and raw.get("end_time"):
        info.last_ts = _epoch_of(raw["end_time"])
    if info.first_ts is not None and info.last_ts is not None and info.duration is None:
        info.duration = max(0.0, info.last_ts - info.first_ts)
    duration_field = _first_float(raw, "capture_duration")
    if duration_field is not None and duration_field > 0:
        info.duration = duration_field
    rate = _first_float(raw, "average_packet_rate")
    if rate is not None:
        info.avg_rate = rate
    elif info.duration and info.packet_count:
        info.avg_rate = info.packet_count / info.duration
    bitrate = _first_float(raw, "data_bit_rate")
    if bitrate is not None:
        info.data_bit_rate = bitrate
    snap = _first_float(raw, "snaplen")
    if snap is not None and snap > 0:
        info.snaplen = int(snap)
    link = raw.get("encapsulation")
    if isinstance(link, str) and link:
        info.link_type = link
    if not info.protocols and ctx.has_tshark():
        _fill_protocols_from_tshark(ctx, info)


def _fill_protocols_from_tshark(ctx: PipelineContext, info: PcapInfo) -> None:
    """Ask tshark for its protocol hierarchy (``-z io,phs``)."""
    assert ctx.tshark_info is not None
    tshark_bin = ctx.tshark_info.tshark
    if not tshark_bin:
        return
    from badnet.utils.subprocess import ToolError, iter_lines

    args = [tshark_bin, "-r", str(ctx.pcap_path), "-n", "-q", "-z", "io,phs"]
    try:
        stack: list[tuple[int, ProtocolCount]] = []
        for line in iter_lines(args, timeout=600, max_output=32 * 1024 * 1024):
            stripped = line.strip()
            if not stripped or "frames:" not in stripped:
                continue
            indent = (len(line) - len(line.lstrip())) // 2
            name, _, tail = stripped.partition("frames:")
            pkts, _, byts = tail.partition("bytes:")
            try:
                count = int(pkts.strip())
                size = int(byts.strip())
            except ValueError:
                continue
            name = name.strip()
            if not name:
                continue
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack.append((indent, ProtocolCount(name=name, packets=count, bytes=size)))
            # Only top-level and its direct children are interesting for a summary.
            if indent <= 1:
                info.protocols.append(ProtocolCount(name=name, packets=count, bytes=size))
    except ToolError as exc:
        info.warnings.append(f"protocol hierarchy unavailable: {exc}")


def _fill_from_packets(ctx: PipelineContext, info: PcapInfo) -> None:
    """Single streaming pass filling counts, endpoints and malformed stats."""
    src_counter: Counter[str] = Counter()
    dst_counter: Counter[str] = Counter()
    port_counter: Counter[str] = Counter()
    proto_counter: Counter[str] = Counter()
    proto_bytes: Counter[str] = Counter()
    layers = {name: 0 for name, _ in SUMMARY_PROTOCOLS}
    total = 0
    malformed = 0
    first_ts: float | None = None
    last_ts: float | None = None

    for packet in ctx.iter_packets():
        total += 1
        if packet.malformed:
            malformed += 1
        if first_ts is None or packet.ts < first_ts:
            first_ts = packet.ts
        if last_ts is None or packet.ts > last_ts:
            last_ts = packet.ts
        if packet.src:
            src_counter[packet.src] += 1
        if packet.dst:
            dst_counter[packet.dst] += 1
        for port in (packet.src_port, packet.dst_port):
            if port:
                port_counter[str(port)] += 1
        for name in _matched_layers(packet):
            if name in layers:
                layers[name] += 1
            proto_counter[name] += 1
            proto_bytes[name] += packet.frame_len
        if packet.ip_version == 6:
            info.ipv6_packets += 1
        elif packet.ip_version == 4:
            info.ipv4_packets += 1
        if "arp" in _matched_layers(packet):
            info.arp_packets += 1

    if info.packet_count is None:
        info.packet_count = total
    if first_ts is not None and info.first_ts is None:
        info.first_ts = first_ts
    if last_ts is not None and info.last_ts is None:
        info.last_ts = last_ts
    if info.duration is None and first_ts is not None and last_ts is not None:
        info.duration = max(0.0, last_ts - first_ts)
    if info.avg_rate is None and info.duration and total:
        info.avg_rate = total / info.duration
    info.malformed_packets = malformed
    if malformed:
        info.warnings.append(
            f"{malformed} packet(s) could not be decoded cleanly; "
            "the capture may be truncated or contain malformed frames"
        )
    if total == 0:
        info.warnings.append("no packets decoded from the capture")

    info.top_sources = _endpoint_rows(src_counter)
    info.top_destinations = _endpoint_rows(dst_counter)
    info.top_ports = _endpoint_rows(port_counter)
    # Protocol hierarchy: keep capinfos/tshark's own when available, else ours.
    if not info.protocols:
        for name, count in proto_counter.most_common():
            info.protocols.append(ProtocolCount(name=name, packets=count, bytes=proto_bytes[name]))


def _matched_layers(packet: NormalizedPacket) -> tuple[str, ...]:
    """Which summary protocols this packet belongs to."""
    out: list[str] = []
    stack = packet.protocols.lower() if packet.protocols else ""
    for name, aliases in SUMMARY_PROTOCOLS:
        if name == "IPv4":
            if packet.ip_version == 4:
                out.append(name)
            continue
        if name == "IPv6":
            if packet.ip_version == 6:
                out.append(name)
            continue
        if any(alias in stack for alias in aliases):
            out.append(name)
    return tuple(out)


def _endpoint_rows(counter: Counter[str]) -> list[EndpointCount]:
    return [
        EndpointCount(value=value, count=count, packets=count, bytes=0)
        for value, count in counter.most_common(_TOP_N)
    ]


def _as_int(value: object) -> int | None:
    """Coerce a capinfos string column to ``int`` (``"65535"`` -> ``65535``)."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if not text or text in ("n/a", "-"):
            return None
        try:
            return int(float(text))
        except ValueError:
            return None
    return None


def _as_float(value: object) -> float | None:
    """Coerce a capinfos string column to ``float`` (``"9.109098"`` -> float)."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if not text or text in ("n/a", "-"):
            return None
        try:
            return float(text)
        except ValueError:
            return None
    return None


def _first_int(raw: dict, *keys: str) -> int | None:
    for key in keys:
        parsed = _as_int(raw.get(key))
        if parsed is not None:
            return parsed
    return None


def _first_float(raw: dict, *keys: str) -> float | None:
    for key in keys:
        parsed = _as_float(raw.get(key))
        if parsed is not None:
            return parsed
    return None


def _epoch_of(value: float | str) -> float | None:
    """Normalise capinfos timestamps (epoch seconds or ISO-8601) to epoch."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        from datetime import datetime

        text = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed.timestamp()
    return None


def input_hashes(path: Path) -> dict[str, str]:
    """All three digests of the input capture, for evidence integrity."""
    return hash_file(path).to_dict()
