"""Signature scanning: apply the YAML pattern set to captured text.

Signatures are data, so this module only owns the conversion from a regex match
to a :class:`~badnet.models.finding.Finding`.  Matching is bounded per signature
so a pathological capture with a million repetitions cannot produce a million
rows.
"""

from __future__ import annotations

from badnet.models.finding import Category, Confidence, Finding, Severity
from badnet.signatures import Signature, SignatureSet

#: Most matches kept per signature, per text blob.
DEFAULT_MAX_MATCHES = 10

#: Longest evidence string stored on a finding (before the ellipsis).
DEFAULT_MAX_EVIDENCE = 240

_SEVERITIES = {s: Severity(s) for s in ("info", "low", "medium", "high")}
_CONFIDENCES = {c: Confidence(c) for c in ("low", "medium", "high")}


def scan_text(
    text: str | None,
    *,
    signatures: SignatureSet,
    source: str,
    detector: str = "signature",
    categories: frozenset[str] | None = None,
    max_matches: int = DEFAULT_MAX_MATCHES,
    max_evidence: int = DEFAULT_MAX_EVIDENCE,
    max_findings: int = 5000,
) -> list[Finding]:
    """Match every signature against *text* and return bounded findings.

    Parameters
    ----------
    categories:
        When set, only signatures in these categories are applied.  Detectors
        pass the categories they own so an HTTP scan does not raise TLS notes.
    """
    findings: list[Finding] = []
    if not text:
        return findings

    for signature in signatures.patterns:
        if categories is not None and signature.category not in categories:
            continue
        for count, match in enumerate(signature.compiled.finditer(text), start=1):
            if count > max_matches:
                break
            findings.append(
                finding_from_match(
                    signature,
                    match.group(0),
                    source=source,
                    detector=detector,
                    max_evidence=max_evidence,
                )
            )
            if len(findings) >= max_findings:
                return findings
    return findings


def finding_from_match(
    signature: Signature,
    evidence: str,
    *,
    source: str,
    detector: str = "signature",
    max_evidence: int = DEFAULT_MAX_EVIDENCE,
) -> Finding:
    """Build a :class:`Finding` from a signature match."""
    snippet = evidence
    if len(snippet) > max_evidence:
        snippet = snippet[:max_evidence] + "..."
    return Finding(
        id="",
        category=_category(signature.category),
        title=signature.title,
        severity=_SEVERITIES.get(signature.severity, Severity.INFO),
        confidence=_CONFIDENCES.get(signature.confidence, Confidence.MEDIUM),
        explanation=signature.description or f"Matched signature {signature.id}.",
        evidence=snippet,
        source=source,
        detector=f"{detector}:{signature.id}",
        tags=list(signature.tags),
    )


def _category(value: str) -> Category:
    try:
        return Category(value)
    except ValueError:
        return Category.DATA
