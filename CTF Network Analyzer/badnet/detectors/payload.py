"""Payload detectors: signature + decoding scan over arbitrary stream bytes.

This is the backstop that makes ``badnet auto`` find a flag wherever it travels,
not only inside HTTP messages or DNS records.  Two passes run over each blob:

1. the signature set is applied directly to the payload text; and
2. common encodings (base64/hex/URL/ROT13, nested) are peeled off and the decoded
   text is scanned again for flag-shaped matches.

The decoded pass is narrowed to flag-shaped signatures: decoding raises the
false-positive rate, so broadening it to credentials would report noise.
"""

from __future__ import annotations

from badnet.analyzers.decode import iter_decoded
from badnet.analyzers.payload import PayloadBlob
from badnet.config import Config
from badnet.detectors.signatures import scan_text
from badnet.models.finding import Finding
from badnet.signatures import SignatureSet

#: Signature categories that make sense for an arbitrary byte stream.
PAYLOAD_SIGNATURE_CATEGORIES = frozenset({"flag", "credential", "secret"})
#: When scanning a *decoded* blob, only flag-shaped matches are reported.
DECODED_SIGNATURE_CATEGORIES = frozenset({"flag"})
#: The loose "any word{...}" heuristic is dropped from decoded results: applying
#: it to transformed text mostly matches the transform itself (e.g. ROT13 turns
#: ``flag{x}`` into ``synt{x}``, which the generic pattern then re-reports).
DECODED_EXCLUDED_SUFFIXES = (":flag_generic_brace",)


def detect(
    blobs: list[PayloadBlob],
    *,
    config: Config,
    signatures: SignatureSet,
    max_findings: int = 5000,
) -> list[Finding]:
    """Return findings for every payload blob (direct matches and decoded ones)."""
    findings: list[Finding] = []
    max_depth = getattr(config.limits, "max_decode_depth", 3)
    max_decode = getattr(config.limits, "max_decode_size", 1024 * 1024)

    for blob in blobs:
        findings.extend(
            scan_text(
                blob.text,
                signatures=signatures,
                source=blob.source,
                detector="payload",
                categories=PAYLOAD_SIGNATURE_CATEGORIES,
                max_findings=max_findings - len(findings),
            )
        )
        if len(findings) >= max_findings:
            break

        for method, decoded in iter_decoded(blob.text, max_depth=max_depth, max_size=max_decode):
            decoded_findings = scan_text(
                decoded,
                signatures=signatures,
                source=f"{blob.source} [{method}]",
                detector=f"payload.{method}",
                categories=DECODED_SIGNATURE_CATEGORIES,
                max_findings=max_findings - len(findings),
            )
            findings.extend(
                finding
                for finding in decoded_findings
                if not finding.detector.endswith(DECODED_EXCLUDED_SUFFIXES)
            )
            if len(findings) >= max_findings:
                break
        if len(findings) >= max_findings:
            break

    return _dedupe(findings[:max_findings])


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
