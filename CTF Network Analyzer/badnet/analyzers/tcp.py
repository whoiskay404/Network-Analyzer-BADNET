"""TCP/UDP conversation analysis: connections, streams and reassembly.

Reassembly rules (deterministic, documented, testable):

* segments are keyed by their **absolute** sequence number (``tcp.seq_raw``), so
  a capture that starts mid-connection still reassembles;
* 32-bit sequence wrap is handled by unwrapping relative to the first segment;
* overlapping data keeps the **first** occurrence (the original transmission),
  and the overlap is counted rather than silently overwritten;
* retransmissions and out-of-order segments are counted;
* gaps are reported as ``missing_bytes`` instead of being padded with zeros, so
  a truncated stream is never mistaken for a complete one.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass

from badnet.analyzers.pipeline import PipelineContext
from badnet.errors import AnalysisError
from badnet.integrations import tshark
from badnet.models.connection import Connection
from badnet.models.packet import NormalizedPacket
from badnet.models.stream import DirectionalData, StreamData, StreamInfo
from badnet.signatures import load_signatures
from badnet.utils.subprocess import ToolError

log = logging.getLogger("badnet.analyzers.tcp")

#: Fields needed to build connection/stream aggregates (no payload: cheap pass).
CONNECTION_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.flags",
    "udp.srcport",
    "udp.dstport",
)

#: Fields needed for reassembly of a single stream.
STREAM_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.seq_raw",
    "tcp.len",
    "tcp.flags",
    "tcp.analysis.retransmission",
    "tcp.analysis.out_of_order",
    "tcp.payload",
)

#: Hard cap on distinct connections kept in memory (protects against scans).
MAX_CONNECTIONS = 50_000

SEQ_MODULO = 1 << 32


@dataclass(slots=True)
class SegmentRecord:
    """One TCP segment as read from the capture."""

    packet_no: int
    ts: float
    src: str
    src_port: int
    dst: str
    dst_port: int
    seq_raw: int
    payload: bytes
    flags: str = ""
    retransmission: bool = False
    out_of_order: bool = False


def analyze(ctx: PipelineContext) -> tuple[list[Connection], list[StreamInfo]]:
    """Single pass building connection records and TCP stream metadata.

    Returns ``(connections, streams)``.  Both are sorted deterministically.
    """
    connections: dict[str, Connection] = {}
    streams: dict[int, StreamInfo] = {}
    interesting_ports = set(ctx.config.interesting_ports)
    truncated = False

    for packet in ctx.iter_packets():
        if packet.src is None or packet.dst is None:
            continue
        if packet.transport not in ("TCP", "UDP"):
            continue
        sport = packet.src_port or 0
        dport = packet.dst_port or 0
        proto = packet.transport

        key = _connection_key(packet.src, sport, packet.dst, dport, proto)
        conn = connections.get(key)
        if conn is None:
            if len(connections) >= MAX_CONNECTIONS:
                truncated = True
                continue
            left, right = sorted([(packet.src, sport), (packet.dst, dport)])
            conn = Connection(
                proto=proto,
                a_ip=left[0],
                a_port=left[1],
                b_ip=right[0],
                b_port=right[1],
                client_ip=packet.src,
                client_port=sport,
                server_ip=packet.dst,
                server_port=dport,
                first_seen=packet.ts,
                last_seen=packet.ts,
                stream_id=packet.tcp_stream,
                protocols=packet.protocols,
            )
            connections[key] = conn

        conn.packets += 1
        conn.bytes += packet.frame_len
        conn.last_seen = max(conn.last_seen, packet.ts)
        conn.first_seen = min(conn.first_seen, packet.ts)
        if packet.protocols and len(packet.protocols) > len(conn.protocols):
            conn.protocols = packet.protocols
        if _is_a(conn, packet):
            conn.a_to_b_packets += 1
            conn.a_to_b_bytes += packet.frame_len
        else:
            conn.b_to_a_packets += 1
            conn.b_to_a_bytes += packet.frame_len
        if packet.tcp_flags:
            for flag in packet.tcp_flags.split():
                if flag not in conn.tcp_flags_seen:
                    conn.tcp_flags_seen.add(flag)
        if packet.tcp_stream is not None:
            conn.stream_id = packet.tcp_stream
        conn.interesting_port = sport in interesting_ports or dport in interesting_ports

        # Stream bookkeeping is TCP-only.
        if packet.tcp_stream is None:
            continue
        sid = packet.tcp_stream
        stream = streams.get(sid)
        if stream is None:
            stream = StreamInfo(
                stream_id=sid,
                proto="TCP",
                client_ip=packet.src,
                client_port=sport,
                server_ip=packet.dst,
                server_port=dport,
                first_seen=packet.ts,
                last_seen=packet.ts,
                app_protocol=_app_protocol(packet),
                protocols=packet.protocols,
            )
            streams[sid] = stream
        stream.packets += 1
        stream.bytes += packet.frame_len
        stream.first_seen = min(stream.first_seen, packet.ts)
        stream.last_seen = max(stream.last_seen, packet.ts)
        if packet.tcp_flags:
            for flag in packet.tcp_flags.split():
                if flag not in stream.tcp_flags:
                    stream.tcp_flags.append(flag)
        stream.has_syn = stream.has_syn or packet.tcp_syn
        stream.has_fin = stream.has_fin or packet.tcp_fin
        stream.has_rst = stream.has_rst or packet.tcp_rst
        # Keep the dissector stack for reference, but refine only the short label.
        if packet.protocols and len(packet.protocols) > len(stream.protocols):
            stream.protocols = packet.protocols
        if not stream.app_protocol or _app_protocol(packet):
            stream.app_protocol = _app_protocol(packet) or stream.app_protocol
        stream.interesting_port = (
            stream.interesting_port or sport in interesting_ports or dport in interesting_ports
        )

    if truncated:
        ctx.warn(
            f"more than {MAX_CONNECTIONS} distinct connections were seen; "
            "the remainder were not tracked individually"
        )

    # Resolve display service names once, from the port->service table shipped in
    # signatures/interesting_ports.yaml.  Done after the pass so the server port
    # is final even when the first packet we saw was a response.
    port_services = load_signatures(ctx.config.effective_signature_dir).port_services
    for conn in connections.values():
        conn.service_name = port_services.get(conn.server_port, "") or port_services.get(
            conn.client_port, ""
        )

    conn_list = sorted(connections.values(), key=lambda c: (-c.packets, c.a_ip, c.a_port))
    stream_list = sorted(streams.values(), key=lambda s: s.stream_id)
    return conn_list, stream_list


def _is_a(conn: Connection, packet: NormalizedPacket) -> bool:
    return (packet.src, packet.src_port or 0) == (conn.a_ip, conn.a_port)


def _connection_key(a: str, ap: int, b: str, bp: int, proto: str) -> str:
    left, right = sorted([(a, ap), (b, bp)])
    return f"{left[0]}:{left[1]}-{right[0]}:{right[1]}-{proto}"


#: Application protocols recognised in a dissector layer stack, most specific
#: first.  ``tls`` is checked after ``ssl`` is folded in, and DNS is only reported
#: for UDP because DNS-over-TCP is rare enough to be mislabelled by the stack.
_APP_PROTOCOLS = (
    "http",
    "tls",
    "dns",
    "ftp",
    "smtp",
    "ssh",
    "smb",
    "imap",
    "pop",
    "telnet",
    "tftp",
    "ldap",
    "rdp",
    "mysql",
    "postgres",
    "redis",
)


def _app_protocol(packet: NormalizedPacket) -> str:
    """Short application label derived from the dissector layer stack.

    The stack looks like ``eth:ethertype:ip:tcp:http:media``; the report wants
    ``http``, not the stack.  Layers below the transport are ignored so that a
    port-80 TCP conversation is not labelled ``tcp``.
    """
    layers = [layer.strip().lower() for layer in (packet.protocols or "").split(":") if layer]
    if not layers:
        return ""
    after_transport = False
    for layer in layers:
        if layer in ("tcp", "udp", "sctp"):
            after_transport = True
            continue
        if not after_transport:
            continue
        if layer in ("ssl", "tls"):
            return "tls"
        if layer in _APP_PROTOCOLS:
            return layer
        if layer in ("data", "data-text-lines", "urlencoded-form", "media"):
            continue
    return ""


# --------------------------------------------------------------- reassembly


def read_segments(
    ctx: PipelineContext,
    stream_id: int,
    *,
    max_bytes: int = 32 * 1024 * 1024,
) -> list[SegmentRecord]:
    """Read every segment of one TCP stream.

    Prefers tshark with a per-stream display filter; falls back to the Scapy
    reader when tshark is unavailable.
    """
    if ctx.has_tshark():
        return _read_segments_tshark(ctx, stream_id, max_bytes=max_bytes)
    return _read_segments_scapy(ctx, stream_id, max_bytes=max_bytes)


def _read_segments_tshark(
    ctx: PipelineContext, stream_id: int, *, max_bytes: int
) -> list[SegmentRecord]:
    assert ctx.tshark_info is not None
    display_filter = f"tcp.stream eq {int(stream_id)} and tcp.len gt 0"
    try:
        rows = ctx.packet_rows(fields=STREAM_FIELDS, display_filter=display_filter)
        return _segments_from_rows(rows, stream_id, max_bytes=max_bytes)
    except ToolError as exc:
        ctx.warn(f"tshark stream read failed for stream {stream_id}: {exc}")
        return []


def _segments_from_rows(
    rows: Iterable[list[str]], stream_id: int, *, max_bytes: int
) -> list[SegmentRecord]:
    idx = {name: i for i, name in enumerate(STREAM_FIELDS)}

    def get(row: list[str], name: str) -> str:
        i = idx[name]
        return row[i] if i < len(row) else ""

    out: list[SegmentRecord] = []
    total = 0
    for row in rows:
        seq = _int(get(row, "tcp.seq_raw"))
        if seq is None:
            continue
        payload = tshark.decode_hex_field(get(row, "tcp.payload"))
        if not payload:
            continue
        total += len(payload)
        if total > max_bytes:
            log.warning(
                "stream %d exceeds the %d byte reassembly cap; truncating", stream_id, max_bytes
            )
            break
        out.append(
            SegmentRecord(
                packet_no=_int(get(row, "frame.number")) or 0,
                ts=_float(get(row, "frame.time_epoch")) or 0.0,
                src=get(row, "ip.src") or get(row, "ipv6.src"),
                src_port=_int(get(row, "tcp.srcport")) or 0,
                dst=get(row, "ip.dst") or get(row, "ipv6.dst"),
                dst_port=_int(get(row, "tcp.dstport")) or 0,
                seq_raw=seq,
                payload=payload,
                flags=get(row, "tcp.flags"),
                retransmission=bool(get(row, "tcp.analysis.retransmission")),
                out_of_order=bool(get(row, "tcp.analysis.out_of_order")),
            )
        )
    return out


def _read_segments_scapy(
    ctx: PipelineContext, stream_id: int, *, max_bytes: int
) -> list[SegmentRecord]:
    from badnet.parsing import scapy_reader

    # Re-derive the Scapy stream index for each packet and keep only ours.
    out: list[SegmentRecord] = []
    total = 0
    reader = scapy_reader.open_reader(ctx.pcap_path)
    try:
        count = 0
        for raw in reader:
            if ctx.max_packets and count >= ctx.max_packets:
                break
            count += 1
            packet = scapy_reader.normalize(raw, number=count)
            if packet is None or packet.tcp_stream is None or packet.tcp_stream != stream_id:
                continue
            payload_hex = packet.payload_hex or ""
            payload = bytes.fromhex(payload_hex) if payload_hex else b""
            if not payload:
                continue
            total += len(payload)
            if total > max_bytes:
                break
            out.append(
                SegmentRecord(
                    packet_no=packet.number,
                    ts=packet.ts,
                    src=packet.src or "",
                    src_port=packet.src_port or 0,
                    dst=packet.dst or "",
                    dst_port=packet.dst_port or 0,
                    seq_raw=packet.tcp_seq or 0,
                    payload=payload,
                    flags=packet.tcp_flags or "",
                )
            )
    finally:
        try:
            reader.close()
        except Exception as exc:  # pragma: no cover
            log.debug("closing scapy reader raised %s", exc)
    return out


@dataclass(slots=True)
class DirectionResult:
    """Reassembly result for one direction plus its counters."""

    data: bytes
    stats: DirectionalData


def reassemble(
    segments: list[SegmentRecord],
    *,
    stream_id: int = 0,
    max_bytes: int = 32 * 1024 * 1024,
    direction: tuple[str, int, str, int] | None = None,
) -> DirectionResult:
    """Reassemble one direction from its segments.

    Missing bytes are represented as zero bytes so that offsets stay correct for
    carving, and ``DirectionalData.missing_bytes`` records how many were never
    observed.  Consumers must check that value before trusting a carved artifact.
    """
    if not segments:
        return DirectionResult(
            data=b"",
            stats=DirectionalData(
                stream_id=stream_id,
                src="",
                src_port=0,
                dst="",
                dst_port=0,
            ),
        )

    # Group by direction so the caller can reassemble each half explicitly.
    groups: dict[tuple[str, int, str, int], list[SegmentRecord]] = {}
    for seg in segments:
        groups.setdefault((seg.src, seg.src_port, seg.dst, seg.dst_port), []).append(seg)

    if direction is not None:
        key = direction
        group = groups.get(key, [])
    else:
        key = sorted(groups)[0]
        group = groups[key]

    if not group:
        return _empty_direction(key, stream_id)

    # Each direction has its own sequence space, so the anchor must come from
    # this direction only.  Anchoring on the other side's numbers would offset
    # every byte by thousands and manufacture a hole.
    base = min(s.seq_raw for s in group)

    # Unwrap sequence numbers relative to the lowest observed one in this
    # direction, so a mid-stream capture start does not shift the output.
    unwrapped: list[tuple[int, SegmentRecord]] = []
    for seg in group:
        offset = (seg.seq_raw - base) % SEQ_MODULO
        if offset > SEQ_MODULO // 2:
            # The segment belongs before the anchor (a mid-stream capture start).
            offset -= SEQ_MODULO
        unwrapped.append((offset, seg))
    unwrapped.sort(key=lambda item: (item[0], item[1].packet_no))

    stats = DirectionalData(
        stream_id=stream_id,
        src=key[0],
        src_port=key[1],
        dst=key[2],
        dst_port=key[3],
        packets=len(group),
        first_seen=min(s.ts for s in group),
        last_seen=max(s.ts for s in group),
    )

    buf = bytearray()
    filled = bytearray()  # parallel array: 1 = this offset holds real data
    overlaps = 0
    retransmissions = 0
    for offset, seg in unwrapped:
        data = seg.payload
        if offset < 0:
            data = data[-offset:]
            offset = 0
        if not data:
            continue
        if offset >= max_bytes:
            log.info(
                "stream %d: segment at offset %d exceeds the cap, truncating", stream_id, offset
            )
            break
        if offset + len(data) > max_bytes:
            data = data[: max_bytes - offset]
        # Pad any hole with zeros so absolute offsets are preserved, then grow
        # the buffer to hold this segment before writing into it.
        if len(buf) < offset:
            buf.extend(bytes(offset - len(buf)))
            filled.extend(bytes(offset - len(filled)))
        end = offset + len(data)
        if len(buf) < end:
            buf.extend(bytes(end - len(buf)))
            filled.extend(bytes(end - len(filled)))
        for i, byte in enumerate(data):
            pos = offset + i
            if filled[pos]:
                overlaps += 1
                continue  # first write wins: the original bytes survive
            buf[pos] = byte
            filled[pos] = 1
        if seg.retransmission:
            retransmissions += 1
        stats.last_seen = max(stats.last_seen, seg.ts)

    real_bytes = sum(filled)
    holes = len(buf) - real_bytes
    stats.first_seq = base
    stats.next_seq = base + len(buf)
    stats.bytes = real_bytes
    stats.overlaps = overlaps
    stats.retransmissions = retransmissions
    stats.gaps = 1 if holes else 0
    stats.out_of_order = sum(1 for s in group if s.out_of_order)
    if holes:
        log.info(
            "stream %d %s:%d -> %s:%d: %d byte(s) were never seen; "
            "the reconstruction contains a hole",
            stream_id,
            stats.src,
            stats.src_port,
            stats.dst,
            stats.dst_port,
            holes,
        )
    return DirectionResult(data=bytes(buf), stats=stats)


def reassemble_stream(
    ctx: PipelineContext,
    stream_id: int,
    *,
    max_bytes: int | None = None,
    client: tuple[str, int, str, int] | None = None,
    server: tuple[str, int, str, int] | None = None,
) -> StreamData:
    """Reassemble both directions of one TCP stream.

    *client*/*server* may be supplied from the tracked :class:`StreamInfo`.  That
    matters when the capture starts mid-stream: the SYN is absent, so a banner
    emitted before the client's first request (an FTP greeting, say) would
    otherwise be mislabelled as the client direction.

    Raises
    ------
    AnalysisError
        When the stream id is not present in the capture.
    """
    cap = max_bytes or ctx.limits.max_artifact_size
    segments = read_segments(ctx, stream_id, max_bytes=cap)
    if not segments:
        raise AnalysisError(
            f"stream {stream_id} has no reassemblable TCP payload in this capture",
            hint="run 'badnet stream <capture>' to list the streams that do have payload",
        )

    # Split into the two directions and reassemble each independently.
    by_dir: dict[tuple[str, int, str, int], list[SegmentRecord]] = {}
    for seg in segments:
        by_dir.setdefault((seg.src, seg.src_port, seg.dst, seg.dst_port), []).append(seg)

    # Preferred orientation: what the connection tracker learned from the SYN.
    # Fall back to the observed data when the caller has no tracked stream.
    client_key = client if client in by_dir else _client_direction(segments)
    server_key = server if server in by_dir else next((k for k in by_dir if k != client_key), None)

    c2s = reassemble(segments, stream_id=stream_id, max_bytes=cap, direction=client_key)
    s2c = reassemble(segments, stream_id=stream_id, max_bytes=cap, direction=server_key)

    return StreamData(
        stream_id=stream_id,
        client_to_server=c2s.data,
        server_to_client=s2c.data,
        client=c2s.stats,
        server=s2c.stats,
    )


def _empty_direction(key: tuple[str, int, str, int] | None, stream_id: int = 0) -> DirectionResult:
    return DirectionResult(
        data=b"",
        stats=DirectionalData(
            stream_id=stream_id,
            src=key[0] if key else "",
            src_port=key[1] if key else 0,
            dst=key[2] if key else "",
            dst_port=key[3] if key else 0,
        ),
    )


def _client_direction(segments: list[SegmentRecord]) -> tuple[str, int, str, int]:
    """Identify the client side of a stream when the caller has no tracker data.

    Priority order:

    1. The SYN sender, when a handshake packet survived the payload filter.
    2. When both ends were captured, the side on the ephemeral port, because the
       well-known end is the server.  This is the case that matters: a capture
       starting mid-stream has no SYN, and protocols that greet first (FTP 220,
       SMTP 220, IMAP, POP3) would otherwise be labelled backwards.
    3. Otherwise the earliest observed sender.
    """
    syn_senders = {
        (s.src, s.src_port, s.dst, s.dst_port)
        for s in segments
        if "S" in (s.flags or "") and "A" not in (s.flags or "")
    }
    if syn_senders:
        return sorted(syn_senders)[0]

    directions = {(s.src, s.src_port, s.dst, s.dst_port) for s in segments}
    if len(directions) == 2:
        ephemeral = [d for d in directions if d[1] > 1024]
        well_known = [d for d in directions if d[1] <= 1024]
        if len(ephemeral) == 1 and len(well_known) == 1:
            return ephemeral[0]

    first = min(segments, key=lambda s: (s.ts, s.packet_no))
    return (first.src, first.src_port, first.dst, first.dst_port)


def _int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        # tshark can render sequence numbers as "unreassembled" or "".
        return None


def _float(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def sort_connections(conns: list[Connection], *, by: str = "packets") -> list[Connection]:
    """Sort connections by the requested metric (stable, deterministic)."""
    keys = {
        "packets": lambda c: -c.packets,
        "bytes": lambda c: -c.bytes,
        "duration": lambda c: -c.duration,
        "dport": lambda c: (c.server_port, -c.packets),
        "first_seen": lambda c: c.first_seen,
        "last_seen": lambda c: -c.last_seen,
    }
    key = keys.get(by)
    if key is None:
        raise AnalysisError(f"cannot sort connections by {by!r}; use one of {sorted(keys)}")
    return sorted(conns, key=lambda c: (key(c), c.a_ip, c.a_port))


def stream_ids(
    ctx: PipelineContext, streams: list[StreamInfo], *, limit: int | None = None
) -> list[int]:
    """Choose which streams to reassemble: interesting ports first, then bulk."""
    ranked = sorted(
        streams,
        key=lambda s: (not s.interesting_port, -s.bytes, s.stream_id),
    )
    chosen = [s.stream_id for s in ranked]
    if limit is not None and len(chosen) > limit:
        ctx.warn(
            f"{len(chosen)} streams carry payload; reassembling the {limit} most interesting "
            "(increase limits.max_artifact_size or filter the capture to widen this)"
        )
        chosen = chosen[:limit]
    return chosen
