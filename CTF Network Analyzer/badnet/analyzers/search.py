"""Regex sweep across reassembled capture data.

The standard library :mod:`re` has no timeout, so a user-supplied pattern such as
``(a+)+$`` can pin a CPU indefinitely (ReDoS).  BADNET mitigates this in three
ways rather than pretending a timeout exists:

1. patterns matching the classic nested-quantifier shape are refused up front
   with :class:`~badnet.errors.ReDoSGuardError`;
2. every search is bounded by number of hits and a wall-clock budget that
   measures **regex execution only** - time spent reassembling streams is not
   charged against it;
3. ``--literal`` bypasses the regex engine entirely and uses ``bytes.find``,
   which cannot backtrack at all.  It is the recommended mode for hostile input.

The budget is a mitigation, not a proof: a single ``finditer`` call on one
window is not interruptible portably.  ``--literal`` is the only guarantee.
"""

from __future__ import annotations

import re

from badnet.analyzers.pipeline import PipelineContext
from badnet.errors import ReDoSGuardError, UsageError
from badnet.models.search import SearchHit
from badnet.utils.logging import get_logger

log = get_logger("analyzer.search")

#: A quantified group that is itself quantified: ``(a+)+``, ``(.*)*``, ``(x{2,})+``.
#: Alternation-overlap ReDoS (``(a|a)+``) is not caught; the wall-clock budget and
#: ``--literal`` cover the rest.
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]")


def looks_catastrophic(pattern: str) -> bool:
    """Heuristically detect a pattern prone to catastrophic backtracking."""
    return bool(_NESTED_QUANTIFIER.search(pattern))


def compile_search(
    regex: str,
    *,
    literal: bool = False,
    ignore_case: bool = False,
    guard: bool = True,
) -> re.Pattern[bytes]:
    """Compile *regex* into a bytes pattern.

    Raises
    ------
    UsageError
        The pattern is empty or not valid regex syntax.
    ReDoSGuardError
        The pattern looks prone to catastrophic backtracking and *guard* is on.
    """
    if regex == "":
        raise UsageError("--regex must not be empty", hint="pass a literal string or a pattern")

    if literal:
        source = re.escape(regex)
    else:
        if guard and looks_catastrophic(regex):
            raise ReDoSGuardError(
                "the regex has nested quantifiers and could hang the analysis",
                hint="use --literal to search for the text as-is, or simplify the pattern",
            )
        source = regex

    flags = re.IGNORECASE if ignore_case else 0
    try:
        return re.compile(source.encode("utf-8"), flags)
    except re.error as exc:
        raise UsageError(f"invalid regular expression: {exc}") from exc


def search_blob(
    data: bytes,
    pattern: re.Pattern[bytes],
    *,
    stream_id: int = 0,
    direction: str = "",
    source: str = "",
    context_bytes: int = 40,
    max_hits: int = 1000,
    max_match_bytes: int = 512,
) -> list[SearchHit]:
    """Find every match of *pattern* in one reassembled direction.

    Offsets are byte offsets into *data*, so they line up with a hexdump of the
    reassembled stream.  A match longer than *max_match_bytes* is stored
    truncated and flagged.
    """
    hits: list[SearchHit] = []
    if not data:
        return hits

    for match in pattern.finditer(data):
        if len(hits) >= max_hits:
            log.info("stream %d %s: stopping at %d hit(s)", stream_id, direction, max_hits)
            break
        start, end = match.span()
        raw = match.group(0)
        truncated = len(raw) > max_match_bytes
        if truncated:
            raw = raw[:max_match_bytes]

        ctx_start = max(0, start - context_bytes)
        ctx_end = min(len(data), end + context_bytes)
        hits.append(
            SearchHit(
                stream_id=stream_id,
                direction=direction,
                offset=start,
                length=end - start,
                match=raw.decode("utf-8", errors="replace"),
                context=data[ctx_start:ctx_end].decode("utf-8", errors="replace"),
                context_offset=ctx_start,
                source=source,
                truncated=truncated,
            )
        )
    return hits


def iter_stream_payloads(
    ctx: PipelineContext,
    streams,
    *,
    limit: int | None = None,
    ranked: bool = True,
):
    """Yield ``(stream_id, direction, data, source)`` for reassemblable streams.

    Uses the same reassembler as ``badnet analyze``, so a search result and a
    dumped stream always agree byte for byte.  Streams are visited most
    interesting first, matching :func:`badnet.analyzers.tcp.stream_ids`.
    """
    from badnet.analyzers.tcp import reassemble_stream

    chosen = list(streams)
    if ranked:
        chosen.sort(key=lambda s: (not s.interesting_port, -s.bytes, s.stream_id))
    if limit is not None:
        chosen = chosen[:limit]

    for stream in chosen:
        client = (stream.client_ip, stream.client_port, stream.server_ip, stream.server_port)
        server = (stream.server_ip, stream.server_port, stream.client_ip, stream.client_port)
        try:
            data = reassemble_stream(ctx, stream.stream_id, client=client, server=server)
        except Exception as exc:  # a stream with no payload must not abort the sweep
            log.debug("stream %d could not be reassembled: %s", stream.stream_id, exc)
            continue
        if data.client_to_server:
            yield (
                stream.stream_id,
                "client_to_server",
                data.client_to_server,
                f"tcp-stream-{stream.stream_id}",
            )
        if data.server_to_client:
            yield (
                stream.stream_id,
                "server_to_client",
                data.server_to_client,
                f"tcp-stream-{stream.stream_id}",
            )


def iter_datagram_payloads(
    ctx: PipelineContext,
    *,
    limit: int | None = None,
):
    """Yield ``(packet_no, direction, data, source)`` for UDP/ICMP payloads.

    TCP is covered by stream reassembly, where an offset is meaningful.  UDP and
    ICMP have no byte stream to reassemble, so each datagram is searched on its
    own: the offset is relative to that packet's payload and the source label
    (``udp-packet-N`` / ``icmp-packet-N``) says exactly which one.  This is what
    makes DNS tunnelling and custom UDP protocols searchable at all.
    """
    yielded = 0
    for packet in ctx.iter_packets():
        if limit is not None and yielded >= limit:
            return
        transport = (packet.transport or "").lower()
        if transport not in ("udp", "icmp"):
            continue
        payload_hex = packet.payload_hex or ""
        if not payload_hex:
            continue
        try:
            data = bytes.fromhex(payload_hex)
        except ValueError:
            continue
        if not data:
            continue
        yielded += 1
        yield packet.number, transport, data, f"{transport}-packet-{packet.number}"
