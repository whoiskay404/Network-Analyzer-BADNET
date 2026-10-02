"""Generic payload sweep: look at every unencrypted byte, not just HTTP/DNS.

HTTP and DNS get their own parsers and detectors, but a flag does not have to
travel over either.  It may arrive over FTP, a raw TCP stream, IRC, a bespoke
protocol, or a UDP flow on a non-standard port.  This analyzer feeds every
reassembled TCP stream direction and every UDP/ICMP datagram to the payload
detector, so ``badnet auto`` finds those flags without the investigator having
to guess a regex for ``badnet search``.

The whole capture is read once (see
:func:`badnet.analyzers.tcp.read_stream_segments_bulk`) and reassembled stream by
stream, most-interesting first, under explicit memory budgets.
"""

from __future__ import annotations

from dataclasses import dataclass

from badnet.analyzers import tcp as tcp_analyzer
from badnet.analyzers.pipeline import PipelineContext
from badnet.analyzers.search import iter_datagram_payloads
from badnet.errors import AnalysisError
from badnet.utils.logging import get_logger

log = get_logger("analyzer.payload")

#: TCP streams reassembled for the sweep.  Ranked most-interesting-first, so a
#: flag on an unusual port or in the largest flow is reached well before the cap.
DEFAULT_MAX_STREAMS = 2000
#: UDP/ICMP datagrams examined (each is searched on its own, no reassembly).
DEFAULT_MAX_DATAGRAMS = 20000
#: Per-stream/datagram byte cap for the text handed to the scanner.
DEFAULT_MAX_BLOB_BYTES = 8 * 1024 * 1024
#: Global byte budget across the whole sweep.
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024


@dataclass(slots=True)
class PayloadBlob:
    """One block of reassembled bytes and where it came from."""

    source: str
    text: str


def sweep(
    ctx: PipelineContext,
    streams,
    *,
    max_streams: int | None = DEFAULT_MAX_STREAMS,
    max_datagrams: int = DEFAULT_MAX_DATAGRAMS,
    max_blob_bytes: int = DEFAULT_MAX_BLOB_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> list[PayloadBlob]:
    """Return every TCP stream direction and datagram worth signature-scanning."""
    blobs: list[PayloadBlob] = []
    total = 0

    by_stream = tcp_analyzer.read_stream_segments_bulk(
        ctx,
        max_bytes_per_stream=max_blob_bytes,
        max_total_bytes=max_total_bytes,
    )

    ranked = sorted(streams, key=lambda s: (not s.interesting_port, -s.bytes, s.stream_id))
    if max_streams is not None:
        ranked = ranked[:max_streams]

    for stream in ranked:
        segments = by_stream.get(stream.stream_id)
        if not segments:
            continue
        client = (stream.client_ip, stream.client_port, stream.server_ip, stream.server_port)
        server = (stream.server_ip, stream.server_port, stream.client_ip, stream.client_port)
        try:
            data = tcp_analyzer.reassemble_from_segments(
                segments,
                stream.stream_id,
                max_bytes=max_blob_bytes,
                client=client,
                server=server,
            )
        except AnalysisError:
            continue
        label = f"tcp-stream-{stream.stream_id}"
        if data.client_to_server:
            blobs.append(
                PayloadBlob(
                    source=f"{label} client_to_server", text=_to_text(data.client_to_server)
                )
            )
            total += len(data.client_to_server)
        if data.server_to_client:
            blobs.append(
                PayloadBlob(
                    source=f"{label} server_to_client", text=_to_text(data.server_to_client)
                )
            )
            total += len(data.server_to_client)
        if total >= max_total_bytes:
            log.info("payload sweep reached its %d-byte budget; stopping", max_total_bytes)
            return blobs

    for _packet_no, _transport, data, label in iter_datagram_payloads(ctx, limit=max_datagrams):
        chunk = data[:max_blob_bytes]
        if not chunk:
            continue
        blobs.append(PayloadBlob(source=label, text=_to_text(chunk)))
        total += len(chunk)
        if total >= max_total_bytes:
            break

    return blobs


def _to_text(data: bytes) -> str:
    """Decode payload bytes for the scanners without ever failing on binary."""
    return data.decode("utf-8", errors="replace")
