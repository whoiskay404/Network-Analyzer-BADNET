"""HTTP detectors: signature matches plus HTTP-specific, explained heuristics.

Nothing here decides intent.  A captured ``Authorization`` header, an admin URL
or a leaked-looking token are reported as *interesting*, with the reason spelled
out, so the investigator can make the call.
"""

from __future__ import annotations

from badnet.config import Config
from badnet.detectors.signatures import scan_text
from badnet.models.finding import Category, Confidence, Finding, Severity
from badnet.models.http import HttpExchange, HttpRequest, HttpResponse
from badnet.signatures import SignatureSet

#: Signature categories an HTTP message can plausibly carry.
HTTP_SIGNATURE_CATEGORIES = frozenset({"flag", "credential", "secret", "endpoint", "metadata"})


def detect(
    exchanges: list[HttpExchange],
    *,
    config: Config,
    signatures: SignatureSet,
    max_findings: int = 5000,
) -> list[Finding]:
    """Return findings for every parsed HTTP exchange."""
    findings: list[Finding] = []
    for exchange in exchanges:
        request = exchange.request
        request_source = f"stream {exchange.stream_id} request {request.method} {request.path}"
        findings.extend(
            scan_text(
                _request_text(request),
                signatures=signatures,
                source=request_source,
                detector="http",
                categories=HTTP_SIGNATURE_CATEGORIES,
            )
        )
        if request.authorization:
            findings.append(_authorization_finding(request, exchange.stream_id, request_source))
        findings.extend(_endpoint_findings(request, config, exchange.stream_id))

        response = exchange.response
        if response is not None:
            response_source = f"stream {exchange.stream_id} response {response.status_code or '?'}"
            findings.extend(
                scan_text(
                    _response_text(response),
                    signatures=signatures,
                    source=response_source,
                    detector="http",
                    categories=HTTP_SIGNATURE_CATEGORIES,
                )
            )
        if len(findings) >= max_findings:
            break
    return _dedupe(findings[:max_findings])


def _authorization_finding(request: HttpRequest, stream_id: int | None, source: str) -> Finding:
    scheme = request.display_authorization.split(" ", 1)[0] if request.authorization else ""
    return Finding(
        id="",
        category=Category.CREDENTIAL,
        title="Authorization header observed",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        explanation=(
            f"{request.method} {request.path} carried an Authorization header"
            + (f" using the {scheme} scheme" if scheme else "")
            + "; the credential is present in cleartext in the capture and is "
            "masked in default output (use --verbose to reveal it)."
        ),
        evidence=request.display_authorization or "Authorization present",
        source=source,
        related=[f"stream:{stream_id}"] if stream_id is not None else [],
        detector="http.authorization",
        tags=["credential", "http", "authorization"],
    )


def _endpoint_findings(
    request: HttpRequest, config: Config, stream_id: int | None
) -> list[Finding]:
    path = (request.path or "").lower()
    if not path:
        return []
    findings: list[Finding] = []
    source = f"stream {stream_id} request {request.method} {request.uri}"

    for endpoint in config.interesting_endpoints:
        needle = endpoint.lower()
        if needle and needle in path:
            findings.append(
                Finding(
                    id="",
                    category=Category.ENDPOINT,
                    title="Configured interesting endpoint requested",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    explanation=(
                        f"the path contains {endpoint!r}, which is on the configured "
                        "interesting-endpoints list; requesting it is not inherently "
                        "malicious, but it is commonly worth reading closely."
                    ),
                    evidence=request.uri,
                    source=source,
                    related=[f"stream:{stream_id}"] if stream_id is not None else [],
                    detector="http.endpoint",
                    tags=["endpoint", "configured"],
                )
            )

    lowered = path.split("?", 1)[0]
    for extension in config.interesting_extensions:
        ext = extension.lower()
        if ext and lowered.endswith(ext):
            findings.append(
                Finding(
                    id="",
                    category=Category.ENDPOINT,
                    title="Interesting file extension requested",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    explanation=(
                        f"the path ends with {extension!r}, a file type the config "
                        "marks as worth a look (archives, keys, backups)."
                    ),
                    evidence=request.uri,
                    source=source,
                    related=[f"stream:{stream_id}"] if stream_id is not None else [],
                    detector="http.endpoint",
                    tags=["endpoint", "extension"],
                )
            )
    return findings


def _request_text(request: HttpRequest) -> str:
    lines = [f"{request.method} {request.uri} HTTP/{request.version or '1.1'}"]
    lines.extend(f"{key}: {value}" for key, value in request.headers.items())
    if request.body_preview:
        lines.append("")
        lines.append(request.body_preview)
    return "\n".join(lines)


def _response_text(response: HttpResponse) -> str:
    lines = [
        f"HTTP/{response.version or '1.1'} {response.status_code or ''} {response.reason or ''}"
    ]
    lines.extend(f"{key}: {value}" for key, value in response.headers.items())
    if response.body_preview:
        lines.append("")
        lines.append(response.body_preview)
    return "\n".join(lines)


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
