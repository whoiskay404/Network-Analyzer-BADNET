"""DNS detectors: signature matches on names/TXT plus tunnelling heuristics.

Nothing here decides intent.  A long, unique, high-entropy query stream to one
parent domain is reported as *consistent with* DNS tunnelling, with the measured
values, so the investigator can confirm or dismiss it.
"""

from __future__ import annotations

from badnet.config import Config
from badnet.detectors.signatures import scan_text
from badnet.models.dns import DnsRecord, DnsTunnelCandidate
from badnet.models.finding import Category, Confidence, Finding, Severity
from badnet.signatures import SignatureSet

#: Signature categories a DNS message can plausibly carry.
DNS_SIGNATURE_CATEGORIES = frozenset({"flag", "credential", "secret", "dns", "metadata"})

#: Heuristic score at or above which a tunnel candidate becomes a finding.  The
#: model's score already requires several independent signals, so 40 means at
#: least two of them agree.
TUNNEL_SCORE_THRESHOLD = 40.0


def detect(
    records: list[DnsRecord],
    *,
    config: Config,
    signatures: SignatureSet,
    tunnels: list[DnsTunnelCandidate] | None = None,
    max_findings: int = 5000,
) -> list[Finding]:
    """Return findings for DNS records and tunnelling candidates."""
    _ = config  # thresholds are applied by the analyzer; kept for a uniform API
    findings: list[Finding] = []
    for record in records:
        if not (record.query or record.answers):
            continue
        source = f"dns packet {record.packet_no} {record.query or ''}".rstrip()
        findings.extend(
            scan_text(
                _record_text(record),
                signatures=signatures,
                source=source,
                detector="dns",
                categories=DNS_SIGNATURE_CATEGORIES,
            )
        )
        if len(findings) >= max_findings:
            break

    for candidate in tunnels or ():
        if candidate.score >= TUNNEL_SCORE_THRESHOLD:
            findings.append(_tunnel_finding(candidate))

    return _dedupe(findings[:max_findings])


def _record_text(record: DnsRecord) -> str:
    """Flatten a record into text the signature scanner can search."""
    lines: list[str] = []
    if record.query:
        lines.append(f"query {record.query} {record.qtype or ''}".rstrip())
    lines.extend(f"answer {value}" for value in record.answers)
    return "\n".join(lines)


def _tunnel_finding(candidate: DnsTunnelCandidate) -> Finding:
    """Build the explained 'possible tunnelling' finding for one candidate."""
    example = candidate.example_queries[0] if candidate.example_queries else candidate.parent_domain
    evidence = "; ".join(candidate.reasons) or "heuristic thresholds exceeded"
    return Finding(
        id="",
        category=Category.DNS,
        title="Possible DNS tunnelling / exfiltration pattern",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        explanation=(
            f"{candidate.query_count} queries to {candidate.parent_domain} carried "
            f"{candidate.unique_subdomains} unique subdomains "
            f"({candidate.unique_ratio:.0%} unique, longest label "
            f"{candidate.max_label_len} chars, entropy up to {candidate.max_entropy:.2f} "
            f"bits/char, {candidate.encoded_label_ratio:.0%} encoded-looking, about "
            f"{candidate.avg_queries_per_second:.1f} queries/second). This is consistent "
            "with data being carried in DNS labels, but it is not proof of exfiltration."
        ),
        evidence=f"{evidence}; e.g. {example}",
        source=f"dns {candidate.parent_domain}",
        related=[f"dns:{candidate.parent_domain}"],
        detector="dns.tunnel",
        tags=["dns", "tunnel", "exfiltration", "heuristic"],
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that share a deterministic id, keeping the first."""
    seen: set[str] = set()
    out: list[Finding] = []
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        out.append(finding)
    return out
