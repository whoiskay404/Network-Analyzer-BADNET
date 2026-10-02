"""DNS query/response extraction and tunnelling heuristics.

The parser works on the DNS wire format (RFC 1035) rather than on dissector
fields, so both readers produce identical records and a capture whose DNS was
never dissected - or deliberately shaped to dodge a dissector - is still
analysed.  Everything here reads attacker-controlled bytes, so:

* every length is bounds-checked against the buffer before it is used;
* name-compression pointers must strictly move backwards and are capped, which
  makes a pointer loop a parse failure instead of a hang;
* record counts and stored messages are capped, so a flood cannot exhaust memory.

No DNS name, answer or TXT value is ever resolved, executed or evaluated.
"""

from __future__ import annotations

import ipaddress
import math
import string
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from badnet.analyzers.pipeline import PipelineContext
from badnet.config import DnsThresholds
from badnet.models.dns import QTYPE, RCODE, DnsRecord, DnsStats, DnsTunnelCandidate
from badnet.utils.logging import get_logger

log = get_logger("analyzers.dns")

#: A DNS header is a fixed 12 bytes.
_HEADER_LEN = 12

#: Hard caps on the counts a header may claim.  The fields are 16-bit on the
#: wire; refusing absurd values keeps a crafted header from driving a long loop.
_MAX_QUESTIONS = 64
_MAX_RESOURCE_RECORDS = 512

#: Resource records decoded from one message before the rest are skipped.
_MAX_RRS = 1024

#: Stored records for one run (bounds memory on a flood).
MAX_DNS_RECORDS = 20000

#: Name/pointer limits (RFC 1035 plus a loop guard).
_MAX_NAME_LEN = 255
_MAX_LABEL_LEN = 63
_MAX_POINTER_HOPS = 16

_TYPE_A = 1
_TYPE_NS = 2
_TYPE_CNAME = 5
_TYPE_PTR = 12
_TYPE_MX = 15
_TYPE_TXT = 16
_TYPE_AAAA = 28

#: Characters that appear in base32/base64/base64url/hex payloads.
_ENCODED_CHARS = frozenset(string.ascii_letters + string.digits + "_-+/=")


@dataclass(slots=True)
class DnsAnalysis:
    """Result of the DNS phase: records, aggregate stats and tunnel candidates."""

    records: list[DnsRecord] = field(default_factory=list)
    stats: DnsStats = field(default_factory=DnsStats)
    tunnels: list[DnsTunnelCandidate] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def analyze(ctx: PipelineContext, *, limit: int | None = None) -> DnsAnalysis:
    """Parse every UDP port-53 payload and build DNS statistics.

    DNS-over-UDP only: a DNS-over-TCP message is length-prefixed and may be
    split across segments, which needs stream reassembly and is handled by the
    TCP phases instead of guessed at here.
    """
    analysis = DnsAnalysis()
    cap = limit if limit is not None else MAX_DNS_RECORDS
    queries: list[DnsRecord] = []

    for packet in ctx.iter_packets():
        if packet.transport != "UDP":
            continue
        if 53 not in (packet.src_port, packet.dst_port):
            continue
        payload_hex = packet.payload_hex or ""
        if not payload_hex:
            continue
        try:
            data = bytes.fromhex(payload_hex)
        except ValueError:
            continue
        record = _safe_parse(
            data,
            ts=packet.ts,
            src=packet.src,
            dst=packet.dst,
            packet_no=packet.number,
        )
        if record is None:
            continue
        if len(analysis.records) >= cap:
            analysis.warnings.append(f"DNS record cap ({cap}) reached; later messages ignored")
            break
        analysis.records.append(record)
        if record.query and not record.is_response:
            queries.append(record)

    analysis.stats = _build_stats(analysis.records, queries)
    analysis.tunnels = _tunnel_candidates(queries, ctx.config.dns)
    if analysis.tunnels:
        log.info(
            "dns: %d message(s), %d query(ies), %d tunnel candidate(s)",
            len(analysis.records),
            analysis.stats.queries,
            len(analysis.tunnels),
        )
    return analysis


def _safe_parse(data: bytes, **kwargs) -> DnsRecord | None:
    """Parse one message, turning any unexpected error into ``None``."""
    try:
        return parse_message(data, **kwargs)
    except (IndexError, ValueError) as exc:  # pragma: no cover - defensive
        log.debug("could not parse DNS payload: %s", exc)
        return None


def parse_message(
    data: bytes,
    *,
    ts: float,
    src: str | None,
    dst: str | None,
    packet_no: int,
    stream_id: int | None = None,
) -> DnsRecord | None:
    """Parse one DNS message into a :class:`DnsRecord` (``None`` when unusable)."""
    if len(data) < _HEADER_LEN:
        return None

    txid = int.from_bytes(data[0:2], "big")
    flags = int.from_bytes(data[2:4], "big")
    qdcount = int.from_bytes(data[4:6], "big")
    ancount = int.from_bytes(data[6:8], "big")
    nscount = int.from_bytes(data[8:10], "big")
    arcount = int.from_bytes(data[10:12], "big")
    if (
        qdcount > _MAX_QUESTIONS
        or ancount > _MAX_RESOURCE_RECORDS
        or nscount > _MAX_RESOURCE_RECORDS
        or arcount > _MAX_RESOURCE_RECORDS
    ):
        return None

    is_response = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0x0F
    rcode_num = flags & 0x000F
    record = DnsRecord(
        ts=ts,
        src=src,
        dst=dst,
        packet_no=packet_no,
        transaction_id=f"0x{txid:04x}",
        is_response=is_response,
        rcode=RCODE.get(rcode_num, str(rcode_num)) if is_response else None,
        opcode=opcode,
        stream_id=stream_id,
    )

    offset = _HEADER_LEN
    for _ in range(qdcount):
        name, offset = _read_name(data, offset)
        if name is None or offset + 4 > len(data):
            break
        qtype = int.from_bytes(data[offset : offset + 2], "big")
        offset += 4
        if record.query is None:
            record.query = name
            record.qtype = QTYPE.get(qtype, str(qtype))
            record.labels = name.split(".")

    if not is_response:
        return record

    total_rrs = min(ancount + nscount + arcount, _MAX_RRS)
    for _ in range(total_rrs):
        _, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype = int.from_bytes(data[offset : offset + 2], "big")
        rdlength = int.from_bytes(data[offset + 8 : offset + 10], "big")
        rdata_start = offset + 10
        rdata_end = rdata_start + rdlength
        if rdata_end > len(data):
            break
        offset = rdata_end
        _apply_rdata(record, rtype, data, rdata_start, rdata_end)

    return record


def _read_name(data: bytes, offset: int) -> tuple[str | None, int]:
    """Read a (possibly compressed) name, returning ``(name, next_offset)``.

    ``next_offset`` is the offset just past the name in the *original* position,
    so callers can continue parsing even when the name used a compression
    pointer.  On malformed input the name is ``None`` and the offset is the best
    position reached.
    """
    labels: list[str] = []
    total = 0
    hops = 0
    pos = offset
    next_offset = offset
    jumped = False

    while True:
        if pos >= len(data):
            return None, next_offset
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                next_offset = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                return None, next_offset
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                next_offset = pos + 2
                jumped = True
            hops += 1
            # Compression pointers must point strictly backwards; anything else
            # (a forward or self pointer) is a loop or an attack, not a name.
            if hops > _MAX_POINTER_HOPS or pointer >= pos:
                return None, next_offset
            pos = pointer
            continue
        if length > _MAX_LABEL_LEN:
            return None, next_offset
        pos += 1
        if pos + length > len(data):
            return None, next_offset
        labels.append(data[pos : pos + length].decode("ascii", errors="replace"))
        pos += length
        total += length + 1
        if total > _MAX_NAME_LEN:
            return None, next_offset

    if not labels:
        return None, next_offset
    return ".".join(labels), next_offset


def _apply_rdata(record: DnsRecord, rtype: int, data: bytes, start: int, end: int) -> None:
    """Decode one resource record's RDATA into the record's typed lists."""
    rdlength = end - start
    rdata = data[start:end]
    if rtype == _TYPE_A and rdlength == 4:
        value = ".".join(str(b) for b in rdata)
        record.answer_ips.append(value)
        record.answers.append(value)
    elif rtype == _TYPE_AAAA and rdlength == 16:
        try:
            value = str(ipaddress.IPv6Address(rdata))
        except ValueError:  # pragma: no cover - defensive
            return
        record.answer_ips.append(value)
        record.answers.append(value)
    elif rtype in (_TYPE_CNAME, _TYPE_NS, _TYPE_PTR):
        name, _ = _read_name(data, start)
        if not name:
            return
        record.answers.append(name)
        if rtype == _TYPE_CNAME:
            record.cnames.append(name)
        elif rtype == _TYPE_NS:
            record.ns.append(name)
        else:
            record.ptr.append(name)
    elif rtype == _TYPE_MX and rdlength >= 3:
        preference = int.from_bytes(rdata[0:2], "big")
        name, _ = _read_name(data, start + 2)
        if name:
            value = f"{preference} {name}"
            record.mx.append(value)
            record.answers.append(value)
    elif rtype == _TYPE_TXT:
        for text in _txt_strings(rdata):
            record.txt.append(text)
            record.answers.append(text)


def _txt_strings(rdata: bytes) -> list[str]:
    """Split RDATA into the length-prefixed strings of one TXT record."""
    out: list[str] = []
    pos = 0
    while pos < len(rdata):
        size = rdata[pos]
        pos += 1
        chunk = rdata[pos : pos + size] if pos + size <= len(rdata) else rdata[pos:]
        pos += size
        out.append(chunk.decode("utf-8", errors="replace"))
    return out


def _build_stats(records: list[DnsRecord], queries: list[DnsRecord]) -> DnsStats:
    """Aggregate counters for the whole case."""
    qtype_counter: Counter[str] = Counter()
    domain_counter: Counter[str] = Counter()
    for record in queries:
        if record.qtype:
            qtype_counter[record.qtype] += 1
        if record.parent_domain:
            domain_counter[record.parent_domain] += 1
    return DnsStats(
        queries=len(queries),
        responses=sum(1 for r in records if r.is_response),
        responses_no_answer=sum(1 for r in records if r.is_response and not r.answers),
        nxdomain=sum(1 for r in records if r.rcode == "NXDOMAIN"),
        unique_names=len({r.query for r in queries if r.query}),
        unique_domains=len(domain_counter),
        qtype_counts=dict(qtype_counter),
        top_domains=domain_counter.most_common(10),
        txt_records=sum(len(r.txt) for r in records),
    )


def _tunnel_candidates(
    queries: list[DnsRecord], thresholds: DnsThresholds
) -> list[DnsTunnelCandidate]:
    """Group queries by parent domain and score the suspicious groups."""
    groups: dict[str, list[DnsRecord]] = defaultdict(list)
    for record in queries:
        if record.parent_domain:
            groups[record.parent_domain].append(record)

    candidates: list[DnsTunnelCandidate] = []
    for parent, records in groups.items():
        count = len(records)
        if count < thresholds.min_queries:
            continue
        names = [r.query for r in records if r.query]
        unique = len(set(names))
        unique_ratio = unique / count if count else 0.0

        label_lengths: list[int] = []
        entropies: list[float] = []
        encoded = 0
        total_labels = 0
        for record in records:
            parent_labels = parent.count(".") + 1
            for label in record.labels[: len(record.labels) - parent_labels]:
                if not label:
                    continue
                total_labels += 1
                label_lengths.append(len(label))
                entropies.append(_entropy(label))
                if _looks_encoded(label):
                    encoded += 1

        max_label_len = max(label_lengths, default=0)
        mean_label_len = sum(label_lengths) / len(label_lengths) if label_lengths else 0.0
        max_entropy = max(entropies, default=0.0)
        encoded_ratio = encoded / total_labels if total_labels else 0.0
        times = [r.ts for r in records]
        span = max(times) - min(times)
        qps = count / span if span > 0 else float(count)

        reasons = _reasons(
            thresholds,
            count=count,
            unique=unique,
            unique_ratio=unique_ratio,
            max_label_len=max_label_len,
            max_entropy=max_entropy,
            encoded_ratio=encoded_ratio,
            qps=qps,
        )
        candidates.append(
            DnsTunnelCandidate(
                parent_domain=parent,
                query_count=count,
                unique_subdomains=unique,
                unique_ratio=unique_ratio,
                max_label_len=max_label_len,
                mean_label_len=mean_label_len,
                max_entropy=max_entropy,
                encoded_label_ratio=encoded_ratio,
                avg_queries_per_second=qps,
                seconds_spanned=span,
                example_queries=names[:5],
                reasons=reasons,
            )
        )

    candidates.sort(key=lambda c: c.score, reverse=True)
    return candidates


def _reasons(
    thresholds: DnsThresholds,
    *,
    count: int,
    unique: int,
    unique_ratio: float,
    max_label_len: int,
    max_entropy: float,
    encoded_ratio: float,
    qps: float,
) -> list[str]:
    """Human-readable, measured reasons a group looked interesting."""
    reasons: list[str] = []
    if unique_ratio >= thresholds.high_unique_ratio:
        reasons.append(f"{unique}/{count} queries used a previously unseen subdomain")
    if max_label_len >= thresholds.long_label_len:
        reasons.append(
            f"longest label {max_label_len} chars (threshold {thresholds.long_label_len})"
        )
    if max_entropy >= thresholds.high_entropy:
        reasons.append(f"label entropy up to {max_entropy:.2f} bits/char")
    if encoded_ratio >= thresholds.encoded_label_ratio:
        reasons.append(f"{encoded_ratio:.0%} of labels look base32/base64/hex encoded")
    if qps >= thresholds.min_query_rate:
        reasons.append(f"about {qps:.1f} queries/second")
    return reasons


def _entropy(text: str) -> float:
    """Shannon entropy of *text* in bits per character (0.0 for empty)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_encoded(label: str) -> bool:
    """Heuristic: an 8+ char label from the base32/base64/hex alphabet.

    Ordinary words (``challenge``, ``version``) are all letters and so fail the
    digit/symbol requirement; encoded payloads almost always carry one.
    """
    if len(label) < 8:
        return False
    if not all(ch in _ENCODED_CHARS for ch in label):
        return False
    has_digit = any(ch.isdigit() for ch in label)
    has_symbol = any(ch in "-_+/=" for ch in label)
    return has_digit or has_symbol
