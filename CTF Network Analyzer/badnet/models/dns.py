"""DNS query/response records and tunnelling heuristics."""

from __future__ import annotations

from dataclasses import dataclass, field

#: Response codes, indexed by rcode.
RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

#: Query types we care about; everything else is still recorded by name.
QTYPE = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    41: "OPT",
    43: "DS",
    48: "DNSKEY",
    52: "TLSA",
    65: "HTTPS",
    255: "ANY",
    257: "CAA",
}


@dataclass(slots=True)
class DnsRecord:
    """One DNS message (query or response) with its answers flattened."""

    ts: float
    src: str | None
    dst: str | None
    packet_no: int
    transaction_id: str | None = None
    is_response: bool = False
    rcode: str | None = None
    opcode: int | None = None
    query: str | None = None
    qtype: str | None = None
    answers: list[str] = field(default_factory=list)
    answer_ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    ptr: list[str] = field(default_factory=list)
    stream_id: int | None = None
    labels: list[str] = field(default_factory=list)
    """Individual labels of the queried name (for tunnelling heuristics)."""

    @property
    def parent_domain(self) -> str | None:
        """Registrable-looking parent of the queried name.

        Deliberately heuristic: the public suffix list is not shipped, so this
        keeps the last two labels (``a.b.example.com`` -> ``example.com``) which
        is correct for the overwhelming majority of CTF/lab traffic and is only
        ever used for grouping and rate statistics, never for a verdict.
        """
        if not self.query:
            return None
        labels = self.query.split(".")
        if len(labels) <= 2:
            return self.query
        return ".".join(labels[-2:])

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {
            "ts": self.ts,
            "src": self.src,
            "dst": self.dst,
            "packet_no": self.packet_no,
            "transaction_id": self.transaction_id,
            "is_response": self.is_response,
            "rcode": self.rcode,
            "opcode": self.opcode,
            "query": self.query,
            "qtype": self.qtype,
            "answers": self.answers,
            "answer_ips": self.answer_ips,
            "cnames": self.cnames,
            "txt": self.txt,
            "mx": self.mx,
            "ns": self.ns,
            "ptr": self.ptr,
            "stream_id": self.stream_id,
            "labels": self.labels,
            "parent_domain": self.parent_domain,
        }


@dataclass(slots=True)
class DnsStats:
    """Aggregate DNS counters for a case."""

    queries: int = 0
    responses: int = 0
    responses_no_answer: int = 0
    nxdomain: int = 0
    unique_names: int = 0
    unique_domains: int = 0
    qtype_counts: dict[str, int] = field(default_factory=dict)
    top_domains: list[tuple[str, int]] = field(default_factory=list)
    txt_records: int = 0

    def to_dict(self) -> dict[str, object]:
        """Serialise for JSON reports."""
        return {
            "queries": self.queries,
            "responses": self.responses,
            "responses_no_answer": self.responses_no_answer,
            "nxdomain": self.nxdomain,
            "unique_names": self.unique_names,
            "unique_domains": self.unique_domains,
            "qtype_counts": self.qtype_counts,
            "top_domains": [list(pair) for pair in self.top_domains],
            "txt_records": self.txt_records,
        }


@dataclass(slots=True)
class DnsTunnelCandidate:
    """Evidence for one possible DNS tunnelling/exfiltration pattern."""

    parent_domain: str
    query_count: int
    unique_subdomains: int
    unique_ratio: float
    """unique_subdomains / query_count - near 1.0 means every query was new."""
    max_label_len: int
    mean_label_len: float
    max_entropy: float
    """Highest per-label Shannon entropy observed (bits per byte)."""
    encoded_label_ratio: float
    """Fraction of labels looking base32/base64url/hex-ish."""
    avg_queries_per_second: float
    seconds_spanned: float
    example_queries: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        """0-100 heuristic score; ``>= 1`` only means "worth a look"."""
        points = 0.0
        if self.unique_ratio >= 0.9 and self.query_count >= 20:
            points += 30
        if self.max_label_len >= 40:
            points += 20
        if self.max_entropy >= 3.5:
            points += 20
        if self.encoded_label_ratio >= 0.5:
            points += 20
        if self.avg_queries_per_second >= 2.0 and self.query_count >= 30:
            points += 10
        return min(100.0, points)

    def to_dict(self) -> dict[str, object]:
        """Serialise for JSON reports and findings evidence."""
        return {
            "parent_domain": self.parent_domain,
            "query_count": self.query_count,
            "unique_subdomains": self.unique_subdomains,
            "unique_ratio": round(self.unique_ratio, 4),
            "max_label_len": self.max_label_len,
            "mean_label_len": round(self.mean_label_len, 2),
            "max_entropy": round(self.max_entropy, 3),
            "encoded_label_ratio": round(self.encoded_label_ratio, 4),
            "avg_queries_per_second": round(self.avg_queries_per_second, 3),
            "seconds_spanned": round(self.seconds_spanned, 3),
            "score": round(self.score, 1),
            "example_queries": self.example_queries,
            "reasons": self.reasons,
        }
