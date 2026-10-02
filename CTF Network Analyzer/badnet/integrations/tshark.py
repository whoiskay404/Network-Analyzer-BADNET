"""tshark / capinfos integration: the fast analysis path.

Why tshark first: it is the most mature dissector set available and it gives us
stream indexes, SNI, certificates and export-objects for free.  We drive it as a
*stream*: ``tshark -T fields`` writes tab-separated rows to a pipe which we read
line by line, so memory stays flat regardless of capture size.

Field selection is done with a single wide field list plus a display filter, so
one pass fills every table.  Fields are separated by TAB with quote-d wrapping
(``-E quote=d``); tshark does not escape embedded quotes, so the splitter in
:func:`split_tshark_line` is deliberately tolerant rather than trusting a strict
CSV parse.
"""

from __future__ import annotations

import logging
import re
import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from badnet.errors import MissingDependencyError, ToolError
from badnet.models.packet import NormalizedPacket, transport_from_ip_proto
from badnet.utils.subprocess import ToolStatus, detect_tool, iter_lines, run_tool, which

log = logging.getLogger("badnet.tshark")

TAB = "\t"

#: The one field list BADNET requests.  Order defines column order in the output.
FIELDS: tuple[str, ...] = (
    # frame / meta
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
    "_ws.col.Protocol",
    # network
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "ip.ttl",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    # transport
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "tcp.flags",
    "tcp.flags.syn",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.analysis.retransmission",
    "tcp.analysis.out_of_order",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "icmp.type",
    # DNS
    "dns.id",
    "dns.flags.response",
    "dns.flags.rcode",
    "dns.count.queries",
    "dns.qry.name",
    "dns.qry.type",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "dns.txt",
    "dns.ns",
    # HTTP
    "http.request.method",
    "http.request.uri",
    "http.request.full_uri",
    "http.host",
    "http.response.code",
    "http.user_agent",
    "http.referer",
    "http.content_type",
    "http.content_length",
    "http.cookie",
    "http.authorization",
    "http.server",
    "http.transfer_encoding",
    "http.content_encoding",
    "http.file_data",
    "http.request.version",
    "http.response.version",
    # TLS
    "tls.record.version",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ciphersuite",
    "tls.handshake.version",
    "tls.handshake.certificate",
    "tls.handshake.ja3",
    "tls.handshake.extensions_alpn_str",
    "tls.app_data",
    # FTP / SMTP / POP / IMAP
    "ftp.request.command",
    "ftp.request.arg",
    "ftp.response.code",
    "ftp.response.arg",
    "smtp.req.command",
    "smtp.req.parameter",
    "smtp.response.code",
    "pop.request.command",
    "pop.request.parameter",
    # SSH / SMB / DHCP
    "ssh.protocol",
    "smb2.share_type",
    "smb.share_access",
    "smb2.filename",
    "smb.cmd",
    "dhcp.option.hostname",
    "dhcp.option.requested_ip_address",
    "dhcp.option.bootfile_name",
    # misc useful payloads
    "data.data",
)

#: Field index constants (positions inside :data:`FIELDS`).
IDX = {name: i for i, name in enumerate(FIELDS)}

_QUOTE_RE = re.compile(r'"((?:[^"]|"")*)"')


def split_tshark_line(line: str, expected: int) -> list[str]:
    """Split one ``-T fields`` row into at most *expected* values.

    tshark quotes fields containing the separator, but does not escape a quote
    that appears inside such a field.  Rather than trusting a strict CSV parse
    (which would misalign every later column after one stray quote) we scan for
    separator positions outside quoted regions and keep the quoted text verbatim.
    """
    if TAB not in line:
        return [line] if line else []
    out: list[str] = []
    current: list[str] = []
    in_quotes = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == '"':
            # Toggle only when the quote delimits a field; a quote in the middle
            # of unquoted text is data (this is the tshark wart we tolerate).
            in_quotes = not in_quotes
            i += 1
            continue
        if ch == TAB and not in_quotes:
            out.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    out.append("".join(current))
    if expected and len(out) > expected:
        # Extra values can only come from unquoted tabs inside a field: re-join
        # the tail into the final column rather than dropping data.
        head = out[: expected - 1]
        tail = TAB.join(out[expected - 1 :])
        out = [*head, tail]
    return out


@dataclass(slots=True)
class TsharkInfo:
    """Paths and versions of the capture tools."""

    tshark: str | None
    tshark_version: str | None
    capinfos: str | None
    capinfos_version: str | None

    @property
    def available(self) -> bool:
        """True when tshark can be used for the fast path."""
        return bool(self.tshark)


def detect(tshark_override: str | None = None, capinfos_override: str | None = None) -> TsharkInfo:
    """Locate tshark and capinfos, honouring config overrides."""
    tshark = tshark_override or which("tshark")
    capinfos = capinfos_override or which("capinfos")
    if tshark is None:
        status: ToolStatus = detect_tool("tshark", ["--version"])
        if status.found:
            tshark, _ = status.path, status.version
    tshark_version = None
    if tshark:
        status = detect_tool("tshark", ["--version"])
        tshark_version = status.version
    capinfos_version = None
    if capinfos:
        status = detect_tool("capinfos", ["--version"])
        capinfos_version = status.version
    return TsharkInfo(
        tshark=tshark,
        tshark_version=tshark_version,
        capinfos=capinfos,
        capinfos_version=capinfos_version,
    )


def require(info: TsharkInfo) -> str:
    """Return the tshark path or raise a clear missing-dependency error."""
    if not info.tshark:
        raise MissingDependencyError(
            "tshark is not installed",
            hint="install it with: sudo apt install tshark   (no capture privileges needed for PCAP files)",
        )
    return info.tshark


def base_command(tshark: str, pcap: Path, *, max_packets: int | None = None) -> list[str]:
    """Common argument vector shared by every tshark invocation.

    ``-n`` disables name resolution (fast, and it avoids BADNET's own DNS
    queries leaking into a live capture); ``-Q`` silences the capture summary;
    the ``-E`` trio fixes the output shape to one tab-separated quoted row per
    packet.
    """
    args = [tshark, "-r", str(pcap), "-n", "-Q"]
    if max_packets:
        args += ["-c", str(int(max_packets))]
    args += [
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    return args


def field_args(fields: tuple[str, ...] = FIELDS) -> list[str]:
    """``-T fields`` argument vector for the requested field list."""
    args = ["-T", "fields"]
    for name in fields:
        args += ["-e", name]
    return args


def iter_field_rows(
    info: TsharkInfo,
    pcap: Path,
    *,
    fields: tuple[str, ...] = FIELDS,
    display_filter: str | None = None,
    max_packets: int | None = None,
    keylog: str | Path | None = None,
    timeout: float = 1800.0,
) -> Iterator[list[str]]:
    """Stream ``tshark -T fields`` rows for *pcap*.

    Yields raw column lists (not dicts) because building 80-key dicts per packet
    is the single most expensive thing BADNET does otherwise.  Callers index
    columns with :data:`IDX`.
    """
    tshark = require(info)
    args = base_command(tshark, pcap, max_packets=max_packets)
    if keylog:
        # SSLKEYLOGFILE lets tshark decrypt TLS application data locally.
        # This is a documented, user-supplied key log - BADNET never attacks
        # the encryption.

        args = list(args)
        env = {"SSLKEYLOGFILE": str(Path(keylog).expanduser())}
        yield from _iter_with_env(args, fields, display_filter, timeout, env)
        return
    yield from _iter_with_env(args, fields, display_filter, timeout, None)


def _iter_with_env(
    args: list[str],
    fields: tuple[str, ...],
    display_filter: str | None,
    timeout: float,
    env: dict[str, str] | None,
) -> Iterator[list[str]]:
    full = [*args, *field_args(fields)]
    if display_filter:
        full += ["-Y", display_filter]
    log.debug("tshark command: %s", " ".join(full))
    for line in iter_lines(full, timeout=timeout, env=env):
        if not line:
            continue
        yield split_tshark_line(line, len(fields))


def iter_packets(
    info: TsharkInfo,
    pcap: Path,
    *,
    max_packets: int | None = None,
    keylog: str | Path | None = None,
    display_filter: str | None = None,
    timeout: float = 1800.0,
) -> Iterator[NormalizedPacket]:
    """Stream normalised packets for the whole capture (no display filter)."""
    for row in iter_field_rows(
        info,
        pcap,
        display_filter=display_filter,
        max_packets=max_packets,
        keylog=keylog,
        timeout=timeout,
    ):
        packet = packet_from_row(row)
        if packet is not None:
            yield packet


def _int(value: str | None) -> int | None:
    """Parse a tshark integer field; empty and malformed values become ``None``."""
    if not value:
        return None
    try:
        return int(value.strip().split(",")[0])
    except ValueError:
        return None


def _float(value: str | None, default: float = 0.0) -> float | None:
    """Parse a tshark float field, returning *default* when unparseable."""
    if not value:
        return None
    try:
        return float(value.strip().split(",")[0])
    except ValueError:
        return None


def packet_from_row(row: list[str]) -> NormalizedPacket | None:
    """Convert one raw tshark row into a :class:`NormalizedPacket`."""
    if len(row) < 5:
        return None

    def get(name: str) -> str:
        idx = IDX.get(name)
        if idx is None or idx >= len(row):
            return ""
        return row[idx]

    number = _int(get("frame.number"))
    if number is None:
        return None
    ts = _float(get("frame.time_epoch"), 0.0) or 0.0
    frame_len = _int(get("frame.len")) or 0
    cap_len = _int(get("frame.cap_len")) or frame_len
    protocols = get("frame.protocols") or get("_ws.col.Protocol")

    v4_src, v4_dst = get("ip.src"), get("ip.dst")
    v6_src, v6_dst = get("ipv6.src"), get("ipv6.dst")
    src = v4_src or v6_src or None
    dst = v4_dst or v6_dst or None
    ip_version = 4 if v4_src else (6 if v6_src else None)

    tcp_sport, tcp_dport = _int(get("tcp.srcport")), _int(get("tcp.dstport"))
    udp_sport, udp_dport = _int(get("udp.srcport")), _int(get("udp.dstport"))
    if tcp_sport is not None or tcp_dport is not None:
        transport = "TCP"
        src_port, dst_port = tcp_sport, tcp_dport
    elif udp_sport is not None or udp_dport is not None:
        transport = "UDP"
        src_port, dst_port = udp_sport, udp_dport
    else:
        transport = transport_from_ip_proto(get("ip.proto")) or (
            "ICMP" if get("icmp.type") else None
        )
        src_port = dst_port = None

    payload = get("data.data") or ""
    if not payload:
        http_data = get("http.file_data")
        payload = http_data if http_data else ""

    malformed = False
    malformed_reason = None
    # tshark reports malformed frames in the protocol column / expert info; the
    # most reliable cheap signal is a decode error marker in frame.protocols or
    # a missing length for a truncated frame.
    if not src and not dst and "eth" not in protocols and "loopback" not in protocols.lower():
        malformed = True
        malformed_reason = "no network layer decoded"

    flags = get("tcp.flags")
    return NormalizedPacket(
        number=number,
        ts=ts,
        frame_len=frame_len,
        cap_len=cap_len,
        protocols=protocols,
        src=src,
        dst=dst,
        ip_version=ip_version,
        transport=transport,
        src_port=src_port,
        dst_port=dst_port,
        tcp_stream=_int(get("tcp.stream")),
        tcp_seq=_int(get("tcp.seq")),
        tcp_ack=_int(get("tcp.ack")),
        tcp_len=_int(get("tcp.len")),
        tcp_flags=flags or None,
        tcp_retransmission=bool(get("tcp.analysis.retransmission")),
        tcp_out_of_order=bool(get("tcp.analysis.out_of_order")),
        tcp_syn=bool(get("tcp.flags.syn")),
        tcp_fin=bool(get("tcp.flags.fin")),
        tcp_rst=bool(get("tcp.flags.reset")),
        udp_length=_int(get("udp.length")),
        icmp_type=_int(get("icmp.type")),
        malformed=malformed,
        malformed_reason=malformed_reason,
        payload_hex=payload or None,
    )


def capinfos_facts(info: TsharkInfo, pcap: Path, *, timeout: float = 300.0) -> dict[str, object]:
    """Run ``capinfos -M -Tm`` and return its facts as a dict.

    Raises :class:`MissingDependencyError` when capinfos is absent, so the caller
    can fall back to tshark/scapy instead of failing.
    """
    if not info.capinfos:
        raise MissingDependencyError(
            "capinfos is not installed",
            hint="it ships with Wireshark: sudo apt install wireshark-common tshark",
        )
    res = run_tool(
        [info.capinfos, "-M", "-Tm", str(pcap)],
        timeout=timeout,
        max_output=64 * 1024 * 1024,
    )
    if res.timed_out:
        raise ToolError(f"capinfos timed out after {timeout:g}s on {pcap}")
    text = res.text()
    if not res.ok:
        tail = [ln for ln in res.error_text().strip().splitlines() if ln.strip()]
        raise ToolError(f"capinfos failed: {tail[-1] if tail else res.returncode}")
    return parse_capinfos_csv(text)


def parse_capinfos_csv(text: str) -> dict[str, object]:
    """Parse the machine-readable ``capinfos -M -Tm`` report.

    The report is a two-line CSV: a header row of human-readable field names and
    a row of values, separated by commas.  Field names vary between Wireshark
    releases, so values are normalised onto stable keys (see
    :data:`CAPINFOS_KEYS`) and anything unknown is still returned under its
    original header.
    """
    import csv
    import io

    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise ToolError("capinfos produced no output")
    header = next(csv.reader(io.StringIO(lines[0])))
    values: list[str] = []
    for line in lines[1:]:
        values = next(csv.reader(io.StringIO(line)))
        break
    if not values:
        raise ToolError("capinfos output has a header but no values")

    raw: dict[str, str] = {}
    for index, name in enumerate(header):
        raw[name.strip()] = values[index].strip() if index < len(values) else ""

    out: dict[str, object] = {}
    for out_key, header_name in CAPINFOS_KEYS.items():
        if header_name in raw and raw[header_name] not in ("", "n/a"):
            out[out_key] = raw[header_name]
    # Keep every original column so nothing is lost.
    for name, value in raw.items():
        out.setdefault(name, value)
    return out


#: capinfos header name -> stable BADNET key.  Several spellings are listed
#: because Wireshark renamed columns across releases.
CAPINFOS_KEYS: dict[str, str] = {
    "file_name": "File name",
    "file_type": "File type",
    "encapsulation": "File encapsulation",
    "time_precision": "File time precision",
    "snaplen": "Packet size limit",
    "packet_count": "Number of packets",
    "file_size": "File size (bytes)",
    "data_size": "Data size (bytes)",
    "capture_duration": "Capture duration (seconds)",
    "start_time": "Start time",
    "end_time": "End time",
    "data_byte_rate": "Data byte rate (bytes/sec)",
    "data_bit_rate": "Data bit rate (bits/sec)",
    "average_packet_size": "Average packet size (bytes)",
    "average_packet_rate": "Average packet rate (packets/sec)",
    "sha256": "SHA256",
    "sha1": "SHA1",
    "strict_time_order": "Strict time order",
}


def export_objects(
    info: TsharkInfo,
    pcap: Path,
    destination: Path,
    *,
    protocol: str,
    max_packets: int | None = None,
    keylog: str | Path | None = None,
    timeout: float = 900.0,
) -> list[Path]:
    """Run ``tshark --export-objects`` into *destination*.

    Returns the list of files tshark wrote.  Never raises for a protocol the
    tshark build does not support: that case returns an empty list and logs the
    reason.
    """
    tshark = require(info)
    args = [tshark, "-r", str(pcap), "-n", "-Q", "--export-objects", f"{protocol},{destination}"]
    if max_packets:
        args += ["-c", str(int(max_packets))]
    env = {"SSLKEYLOGFILE": str(Path(keylog).expanduser())} if keylog else None
    try:
        res = run_tool(args, timeout=timeout, max_output=16 * 1024 * 1024, env=env)
    except ToolError as exc:
        log.warning("tshark --export-objects %s failed: %s", protocol, exc)
        return []
    if not res.ok:
        message = res.error_text().strip()
        if "not a valid" in message or "Usage" in message or "export" in message.lower():
            log.info(
                "tshark build does not support --export-objects %s: %s", protocol, message[:200]
            )
            return []
        log.warning(
            "tshark --export-objects %s exited %s: %s", protocol, res.returncode, message[:200]
        )
    if not destination.is_dir():
        log.info("tshark created no output directory for %s", protocol)
        return []
    files = sorted(p for p in destination.iterdir() if p.is_file())
    log.info("export-objects %s produced %d file(s)", protocol, len(files))
    return files


def follow_stream_raw(
    info: TsharkInfo,
    pcap: Path,
    stream_id: int,
    *,
    direction: str = "client_to_server",
    max_bytes: int = 64 * 1024 * 1024,
    keylog: str | Path | None = None,
    timeout: float = 600.0,
) -> bytes:
    """Reconstruct one stream direction with ``tshark -q -z follow``.

    This is tshark's own reassembly engine, which handles out-of-order and
    retransmitted segments well.  When it is unavailable BADNET falls back to the
    Scapy reassembler in :mod:`badnet.analyzers.streams`.
    """
    tshark = require(info)
    if direction not in ("client_to_server", "server_to_client"):
        raise ToolError(f"invalid direction {direction!r}")
    args = [tshark, "-r", str(pcap), "-n", "-q", "-z", f"follow,tcp,raw,{int(stream_id)}"]
    env = {"SSLKEYLOGFILE": str(Path(keylog).expanduser())} if keylog else None
    res = run_tool(args, timeout=timeout, max_output=max_bytes + (4 * 1024 * 1024), env=env)
    if not res.ok:
        tail = res.error_text().strip().splitlines()
        raise ToolError(f"tshark follow failed: {tail[-1] if tail else res.returncode}")
    return parse_follow_raw(res.stdout, direction)


def parse_follow_raw(data: bytes, direction: str) -> bytes:
    """Parse the hex dump produced by ``follow,tcp,raw``.

    Layout::

        ====Follow: TCP Stream N, ...
        \\x00000000\\x....  <- Node 0: client
        <hex lines>
        \\x000000..
        ====Node 1: server
        <hex lines>

    The hex lines are the authoritative payload; the header lines give the
    offsets.  ``raw`` mode interleaves both directions with their direction
    column, so we split on the direction marker instead.
    """
    out = bytearray()
    for raw_line in data.split(b"\n"):
        line = raw_line.rstrip(b"\r")
        if not line:
            continue
        lowered = line.lower()
        if (
            lowered.startswith(b"====")
            or lowered.startswith(b"node ")
            or lowered.startswith(b"filter")
        ):
            continue
        if lowered.startswith(b"hexdump"):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        hex_text = parts[1].decode("ascii", errors="replace").strip()
        if not re.fullmatch(r"[0-9a-fA-F\s]+", hex_text or "x"):
            # Non-hex payload line: tshark prints raw text for printable streams.
            continue
        hex_text = re.sub(r"\s+", "", hex_text)
        if len(hex_text) % 2:
            hex_text = hex_text[:-1]
        try:
            out += bytes.fromhex(hex_text)
        except ValueError as exc:
            log.warning("unparsable hex line in follow output: %s", exc)
    if direction == "server_to_client" and b"Node 1: server" not in data:
        # Older tshark builds omit the node header; the caller falls back.
        log.debug("follow output has no node header; returning client direction")
    return bytes(out)


def decode_hex_field(value: str) -> bytes:
    """Decode a tshark hex field (``data.data``, ``http.file_data``) to bytes."""
    if not value:
        return b""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        log.warning("cannot decode hex field (%d chars): %s", len(cleaned), exc)
        return b""


def requires_tshark() -> None:
    """Raise when tshark is missing (used by commands with no fallback)."""
    info = detect()
    if not info.available:
        raise MissingDependencyError(
            "tshark is not installed",
            hint="install it with: sudo apt install tshark",
        )


def free_disk_bytes(path: Path) -> int | None:  # pragma: no cover - thin wrapper
    """Free space at *path*, or None when it cannot be determined."""
    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:
        log.debug("cannot stat free space for %s: %s", path, exc)
        return None
    return usage.free
