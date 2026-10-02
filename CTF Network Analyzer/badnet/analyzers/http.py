"""HTTP/1.x request/response extraction from reassembled TCP streams.

The parser is deliberately small and defensive, because everything it reads is
attacker-controlled:

* it never trusts ``Content-Length`` or chunk sizes for memory: bodies are
  previewed up to ``limits.max_body_preview`` and the remainder is skipped by
  advancing the cursor, not by allocating;
* a malformed start line or header block ends parsing of that direction instead
  of raising, so one broken message cannot hide the rest of the capture;
* gzip/deflate bodies are decoded only for the bounded preview, under a size cap;
* no HTTP field is ever evaluated, executed or resolved over the network.

Messages are paired per stream by observation order to form
:class:`~badnet.models.http.HttpExchange`.  HTTP is not multiplexed on a
connection, so the Nth request belongs with the Nth response.
"""

from __future__ import annotations

import gzip
import zlib
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from badnet.analyzers import tcp as tcp_analyzer
from badnet.analyzers.pipeline import PipelineContext
from badnet.errors import AnalysisError
from badnet.models.http import HttpExchange, HttpRequest, HttpResponse, HttpStats
from badnet.models.stream import StreamInfo
from badnet.utils.logging import get_logger
from badnet.utils.textutil import safe_text_preview

log = get_logger("analyzers.http")

#: Ports where an unlabelled stream is still worth attempting to parse as HTTP.
DEFAULT_HTTP_PORTS: frozenset[int] = frozenset({80, 8000, 8008, 8080, 8081, 8888})

#: Upper bound on streams reassembled for HTTP parsing in one run.
MAX_HTTP_STREAMS = 2000

#: Upper bound on messages parsed from one direction (guards a byte loop).
MAX_MESSAGES_PER_STREAM = 5000

#: Response statuses that never carry a message body.
_BODYLESS_STATUSES = frozenset({204, 304})


@dataclass(slots=True)
class HttpAnalysis:
    """Result of the HTTP phase: parsed exchanges plus aggregate counters."""

    exchanges: list[HttpExchange] = field(default_factory=list)
    stats: HttpStats = field(default_factory=HttpStats)
    warnings: list[str] = field(default_factory=list)

    @property
    def requests(self) -> int:
        """Number of parsed requests (equal to the number of exchanges)."""
        return len(self.exchanges)


def analyze(
    ctx: PipelineContext, streams: list[StreamInfo], *, limit: int | None = None
) -> HttpAnalysis:
    """Parse HTTP out of every HTTP-looking TCP stream.

    Streams are selected by the dissector's ``http`` label, falling back to a
    small set of well-known ports when the label is absent (for example a capture
    with no tshark dissector).  Reassembly reuses the tracked client/server
    orientation so requests and responses are not swapped.
    """
    analysis = HttpAnalysis()
    candidates = _http_streams(streams)
    cap = limit if limit is not None else MAX_HTTP_STREAMS
    if len(candidates) > cap:
        ctx.warn(
            f"{len(candidates)} HTTP streams present; parsing the first {cap} "
            "(raise limits or filter the capture to widen this)"
        )
        candidates = candidates[:cap]

    host_counter: Counter[str] = Counter()
    path_counter: Counter[str] = Counter()
    status_counter: Counter[str] = Counter()
    method_counter: Counter[str] = Counter()
    max_preview = ctx.limits.max_body_preview

    for stream in candidates:
        client = (stream.client_ip, stream.client_port, stream.server_ip, stream.server_port)
        server = (stream.server_ip, stream.server_port, stream.client_ip, stream.client_port)
        try:
            data = tcp_analyzer.reassemble_stream(
                ctx, stream.stream_id, client=client, server=server
            )
        except AnalysisError as exc:
            analysis.warnings.append(f"stream {stream.stream_id}: {exc}")
            ctx.warn(f"HTTP stream {stream.stream_id} could not be reassembled: {exc}")
            continue

        requests = parse_requests(
            data.client_to_server,
            stream=stream,
            src=stream.client_ip,
            dst=stream.server_ip,
            ts=stream.first_seen,
            max_body_preview=max_preview,
        )
        responses = parse_responses(
            data.server_to_client,
            stream=stream,
            src=stream.server_ip,
            dst=stream.client_ip,
            ts=stream.first_seen,
            max_body_preview=max_preview,
        )

        for index, request in enumerate(requests):
            response = responses[index] if index < len(responses) else None
            analysis.exchanges.append(
                HttpExchange(request=request, response=response, stream_id=stream.stream_id)
            )
            method_counter[request.method] += 1
            if request.host:
                host_counter[request.host] += 1
            if request.path:
                path_counter[request.path] += 1
            if response and response.status_code is not None:
                status_counter[str(response.status_code)] += 1

    stats = analysis.stats
    stats.requests = len(analysis.exchanges)
    stats.responses = sum(1 for e in analysis.exchanges if e.response is not None)
    stats.unique_hosts = len(host_counter)
    stats.unique_paths = len(path_counter)
    stats.top_hosts = host_counter.most_common(20)
    stats.top_paths = path_counter.most_common(20)
    stats.status_counts = dict(status_counter.most_common())
    stats.methods = dict(method_counter.most_common())
    return analysis


def _http_streams(streams: list[StreamInfo]) -> list[StreamInfo]:
    """HTTP-labelled streams first, then well-known ports, both deduplicated."""
    chosen: list[StreamInfo] = []
    seen: set[int] = set()
    for stream in streams:
        is_http = stream.app_protocol == "http" or (
            not stream.app_protocol and stream.server_port in DEFAULT_HTTP_PORTS
        )
        if is_http and stream.stream_id not in seen:
            seen.add(stream.stream_id)
            chosen.append(stream)
    return chosen


# ------------------------------------------------------------------- parsing


@dataclass(slots=True)
class _Body:
    """Bounded body preview plus the cursor position after the real body."""

    preview: bytes
    next_pos: int
    declared_size: int


def parse_requests(
    data: bytes,
    *,
    stream: StreamInfo,
    src: str | None = None,
    dst: str | None = None,
    ts: float = 0.0,
    max_body_preview: int = 4096,
    max_messages: int = MAX_MESSAGES_PER_STREAM,
) -> list[HttpRequest]:
    """Parse the client-to-server bytes of one stream into requests."""
    messages = _parse_messages(data, max_body_preview=max_body_preview, max_messages=max_messages)
    out: list[HttpRequest] = []
    for message in messages:
        if isinstance(message, HttpRequest):
            message.stream_id = stream.stream_id
            message.src = src
            message.dst = dst
            message.ts = ts
            out.append(message)
    return out


def parse_responses(
    data: bytes,
    *,
    stream: StreamInfo,
    src: str | None = None,
    dst: str | None = None,
    ts: float = 0.0,
    max_body_preview: int = 4096,
    max_messages: int = MAX_MESSAGES_PER_STREAM,
) -> list[HttpResponse]:
    """Parse the server-to-client bytes of one stream into responses."""
    messages = _parse_messages(data, max_body_preview=max_body_preview, max_messages=max_messages)
    out: list[HttpResponse] = []
    for message in messages:
        if isinstance(message, HttpResponse):
            message.stream_id = stream.stream_id
            message.src = src
            message.dst = dst
            message.ts = ts
            out.append(message)
    return out


def _parse_messages(
    data: bytes, *, max_body_preview: int, max_messages: int
) -> list[HttpRequest | HttpResponse]:
    """Parse a byte stream into a sequence of requests and responses.

    The message kind is detected from the start line, so a stream whose
    orientation was guessed wrong still parses correctly.
    """
    out: list[HttpRequest | HttpResponse] = []
    pos = 0
    length = len(data)

    while pos < length and len(out) < max_messages:
        line = _read_line(data, pos)
        if line is None:
            break
        raw_line, pos = line
        start_line = raw_line.decode("latin-1").strip()
        if not start_line:
            continue

        headers, pos, complete = _read_headers(data, pos)
        if not complete:
            break

        lower = {key.lower(): value for key, value in headers.items()}
        is_response = start_line.startswith("HTTP/")
        status = _status_from_start_line(start_line) if is_response else None
        preview, pos, size = _read_body(
            data,
            pos,
            lower,
            is_response=is_response,
            status=status,
            max_preview=max_body_preview,
        )
        preview = _decode_body(preview, lower.get("content-encoding"), max_body_preview)
        body_text = safe_text_preview(preview, max_len=max_body_preview) if preview else None

        if is_response:
            message = _build_response(start_line, headers, lower, body_text, size)
        else:
            message = _build_request(start_line, headers, lower, body_text, size)
        if message is not None:
            out.append(message)

    return out


def _read_line(data: bytes, pos: int) -> tuple[bytes, int] | None:
    """Return ``(line_without_terminator, next_pos)`` or ``None`` at end."""
    crlf = data.find(b"\r\n", pos)
    lf = data.find(b"\n", pos)
    if crlf == -1 and lf == -1:
        return None
    if crlf != -1 and (lf == -1 or crlf <= lf):
        return data[pos:crlf], crlf + 2
    return data[pos:lf], lf + 1


def _read_headers(data: bytes, pos: int) -> tuple[dict[str, str], int, bool]:
    """Read a header block.  Returns ``(headers, next_pos, complete)``."""
    headers: dict[str, str] = {}
    last_key: str | None = None
    while True:
        line = _read_line(data, pos)
        if line is None:
            return headers, pos, False
        raw, pos = line
        if raw == b"":
            return headers, pos, True
        # Obsolete line folding: a leading space continues the previous value.
        if raw[:1] in (b" ", b"\t") and last_key is not None:
            headers[last_key] = f"{headers[last_key]} {raw.strip().decode('latin-1')}".strip()
            continue
        if b":" not in raw:
            last_key = None
            continue
        name, _, value = raw.partition(b":")
        key = name.decode("latin-1").strip()
        if not key:
            last_key = None
            continue
        headers[key] = value.decode("latin-1").strip()
        last_key = key


def _read_body(
    data: bytes,
    pos: int,
    headers: dict[str, str],
    *,
    is_response: bool,
    status: int | None,
    max_preview: int,
) -> tuple[bytes, int, int]:
    """Return ``(preview, next_pos, declared_size)`` without over-allocating."""
    transfer = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer:
        return _read_chunked(data, pos, max_preview)

    declared = _int(headers.get("content-length"))
    if declared is None:
        if is_response and status is not None and not _bodyless(status):
            # HTTP/1.0-style: body runs to the end of the connection.
            preview = data[pos : pos + max_preview]
            return preview, len(data), len(data) - pos
        return b"", pos, 0

    if declared <= 0:
        return b"", pos, max(0, declared)
    preview = data[pos : pos + min(declared, max_preview)]
    next_pos = min(pos + declared, len(data))
    return preview, next_pos, declared


def _read_chunked(data: bytes, pos: int, max_preview: int) -> tuple[bytes, int, int]:
    """Decode a chunked body for preview and return its end position."""
    chunks: list[bytes] = []
    total = 0
    remaining = max_preview
    length = len(data)

    while pos < length:
        line = _read_line(data, pos)
        if line is None:
            break
        size_line, pos = line
        token = size_line.split(b";", 1)[0].strip()
        size = _hex(token)
        if size is None:
            break
        if size == 0:
            # Consume the trailer section up to the terminating blank line.
            while True:
                trailer = _read_line(data, pos)
                if trailer is None:
                    break
                raw, pos = trailer
                if raw == b"":
                    break
            break
        end = min(pos + size, length)
        if remaining > 0:
            chunks.append(data[pos:end][:remaining])
            remaining -= min(size, remaining)
        total += size
        pos = end
        crlf = _read_line(data, pos)
        if crlf is not None:
            _, pos = crlf

    return b"".join(chunks), pos, total


def _decode_body(preview: bytes, encoding: str | None, cap: int) -> bytes:
    """Best-effort gzip/deflate decode of a bounded preview."""
    enc = (encoding or "").lower()
    if not preview:
        return preview
    try:
        if "gzip" in enc:
            return gzip.decompress(preview)[:cap]
        if "deflate" in enc:
            return zlib.decompress(preview)[:cap]
    except (OSError, zlib.error, EOFError):
        # A partial preview cannot be decompressed; show the raw bytes instead.
        return preview
    return preview


def _build_request(
    start_line: str,
    headers: dict[str, str],
    lower: dict[str, str],
    body_text: str | None,
    body_size: int,
) -> HttpRequest | None:
    method, _, rest = start_line.partition(" ")
    target, _, version = rest.rpartition(" ")
    method = method.strip()
    target = target.strip() or "/"
    if not method:
        return None
    split = urlsplit(target)
    return HttpRequest(
        ts=0.0,
        packet_no=0,
        method=method,
        uri=target,
        host=lower.get("host"),
        path=split.path or "/",
        query_string=split.query or None,
        version=version or None,
        headers=headers,
        user_agent=lower.get("user-agent"),
        referer=lower.get("referer"),
        content_type=lower.get("content-type"),
        content_length=_int(lower.get("content-length")),
        authorization=lower.get("authorization"),
        cookie=lower.get("cookie"),
        body_preview=body_text,
        body_size=body_size,
    )


def _build_response(
    start_line: str,
    headers: dict[str, str],
    lower: dict[str, str],
    body_text: str | None,
    body_size: int,
) -> HttpResponse | None:
    parts = start_line.split(" ", 2)
    if len(parts) < 2:
        return None
    version = parts[0]
    status = _int(parts[1])
    reason = parts[2].strip() if len(parts) > 2 else None
    return HttpResponse(
        ts=0.0,
        packet_no=0,
        version=version,
        status_code=status,
        reason=reason,
        headers=headers,
        content_type=lower.get("content-type"),
        content_length=_int(lower.get("content-length")),
        server=lower.get("server"),
        set_cookie=lower.get("set-cookie"),
        body_preview=body_text,
        body_size=body_size,
    )


def _status_from_start_line(start_line: str) -> int | None:
    parts = start_line.split(" ", 2)
    return _int(parts[1]) if len(parts) > 1 else None


def _bodyless(status: int) -> bool:
    return status in _BODYLESS_STATUSES or 100 <= status < 200


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return None


def _hex(value: bytes) -> int | None:
    try:
        return int(value, 16)
    except ValueError:
        return None
