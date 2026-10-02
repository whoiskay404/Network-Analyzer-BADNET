"""Phase 3 tests: the HTTP parser and the HTTP detectors.

The parser and detector tests are pure (no tshark) and prove the security
properties directly: bodies are bounded, malformed input never raises, and
secrets are masked in findings.  The two pipeline tests at the end drive the
real CLI over the deterministic synthetic capture, so they are gated on tshark
like the rest of the integration suite.
"""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from badnet.analyzers.http import _http_streams, parse_requests, parse_responses
from badnet.cli import app
from badnet.config import Config
from badnet.detectors.http import detect
from badnet.detectors.signatures import scan_text
from badnet.integrations.system_tools import detect_all
from badnet.models.http import HttpExchange, HttpRequest
from badnet.models.stream import StreamInfo
from badnet.signatures import Signature, SignatureSet

requires_tshark = pytest.mark.skipif(
    not detect_all().tshark.found, reason="tshark is not installed"
)

runner = CliRunner()


# ------------------------------------------------------------------- helpers


def _stream(stream_id: int = 0, *, app_protocol: str = "http", server_port: int = 80) -> StreamInfo:
    return StreamInfo(
        stream_id=stream_id,
        proto="TCP",
        client_ip="10.0.0.1",
        client_port=50000 + stream_id,
        server_ip="10.0.0.2",
        server_port=server_port,
        app_protocol=app_protocol,
        first_seen=1.5,
    )


def _request_bytes(method: str, target: str, headers: dict[str, str], body: bytes = b"") -> bytes:
    lines = [f"{method} {target} HTTP/1.1"]
    lines.extend(f"{key}: {value}" for key, value in headers.items())
    lines.append("")
    return ("\r\n".join(lines) + "\r\n").encode("latin-1") + body


def _response_bytes(status: int, reason: str, headers: dict[str, str], body: bytes = b"") -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}"]
    lines.extend(f"{key}: {value}" for key, value in headers.items())
    lines.append("")
    return ("\r\n".join(lines) + "\r\n").encode("latin-1") + body


def _sig(
    signature_id: str,
    regex: str,
    *,
    category: str = "flag",
    title: str | None = None,
    severity: str = "high",
    confidence: str = "high",
    description: str = "matched a test pattern",
) -> Signature:
    return Signature(
        id=signature_id,
        title=title or signature_id,
        regex=regex,
        severity=severity,
        confidence=confidence,
        category=category,
        description=description,
        tags=(),
        decoders=(),
        source_file="test",
        _compiled=re.compile(regex),
    )


def _sigset(*signatures: Signature) -> SignatureSet:
    return SignatureSet(patterns=tuple(signatures))


def _flag_request() -> HttpRequest:
    return HttpRequest(
        ts=0.0,
        packet_no=0,
        method="POST",
        uri="/submit",
        host="lab.internal",
        path="/submit",
        body_preview="flag{dup}",
    )


# -------------------------------------------------------------------- parser


def test_parse_requests_extracts_method_target_and_headers() -> None:
    data = _request_bytes(
        "GET",
        "/index.html?q=1",
        {"Host": "example.test", "User-Agent": "curl/8"},
    )
    request = parse_requests(data, stream=_stream(), src="10.0.0.1", dst="10.0.0.2", ts=1.5)[0]

    assert request.method == "GET"
    assert request.path == "/index.html"
    assert request.query_string == "q=1"
    assert request.host == "example.test"
    assert request.headers["User-Agent"] == "curl/8"
    assert request.stream_id == 0
    assert request.src == "10.0.0.1"
    assert request.dst == "10.0.0.2"
    assert request.ts == 1.5


def test_parse_requests_splits_pipelined_messages() -> None:
    data = _request_bytes("GET", "/a", {"Host": "h"}) + _request_bytes(
        "POST", "/b", {"Host": "h", "Content-Length": "3"}, b"xyz"
    )
    requests = parse_requests(data, stream=_stream())

    assert [r.path for r in requests] == ["/a", "/b"]
    assert requests[1].body_preview == "xyz"


def test_parse_requests_bounds_the_body_preview() -> None:
    body = b"B" * 100
    data = _request_bytes("POST", "/b", {"Content-Length": "100"}, body)
    request = parse_requests(data, stream=_stream(), max_body_preview=10)[0]

    assert request.body_size == 100
    assert request.body_preview == "B" * 10


def test_parse_requests_decodes_a_chunked_body_preview() -> None:
    body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    data = _request_bytes("POST", "/c", {"Transfer-Encoding": "chunked"}, body)
    request = parse_requests(data, stream=_stream())[0]

    assert request.body_preview == "Wikipedia"
    assert request.body_size == 9


def test_parse_requests_decodes_a_gzip_body_preview() -> None:
    body = gzip.compress(b"flag{compressed}")
    data = _request_bytes(
        "POST",
        "/g",
        {"Content-Length": str(len(body)), "Content-Encoding": "gzip"},
        body,
    )
    request = parse_requests(data, stream=_stream())[0]

    assert "flag{compressed}" in request.body_preview


def test_parse_responses_extracts_status_reason_and_server() -> None:
    data = _response_bytes(404, "Not Found", {"Server": "nginx", "Content-Length": "0"})
    response = parse_responses(data, stream=_stream())[0]

    assert response.status_code == 404
    assert response.reason == "Not Found"
    assert response.server == "nginx"
    assert response.stream_id == 0


def test_parse_responses_uses_content_length_to_find_the_next_message() -> None:
    data = _response_bytes(200, "OK", {"Content-Length": "2"}, b"hi") + _response_bytes(
        204, "No Content", {}
    )
    responses = parse_responses(data, stream=_stream())

    assert [r.status_code for r in responses] == [200, 204]


def test_parse_requests_never_allocates_for_a_lying_content_length() -> None:
    data = _request_bytes("POST", "/x", {"Content-Length": "999999999"}, b"short")
    requests = parse_requests(data, stream=_stream())

    assert len(requests) == 1
    assert requests[0].body_size == 999999999
    assert requests[0].body_preview == "short"


def test_parse_requests_does_not_raise_on_truncated_input() -> None:
    assert parse_requests(b"GET /", stream=_stream()) == []
    assert parse_requests(b"", stream=_stream()) == []


def test_http_streams_prefers_the_label_then_known_ports() -> None:
    streams = [
        _stream(0, app_protocol="http", server_port=9999),
        _stream(1, app_protocol="", server_port=80),
        _stream(2, app_protocol="tls", server_port=80),
        _stream(3, app_protocol="", server_port=1234),
    ]
    assert [s.stream_id for s in _http_streams(streams)] == [0, 1]


# ------------------------------------------------------------------ detectors


def test_scan_text_finds_a_signature_and_labels_the_detector() -> None:
    findings = scan_text(
        "here is flag{abc} in the body",
        signatures=_sigset(_sig("flag_brace", r"flag\{[^}]+\}")),
        source="stream 0",
    )

    assert len(findings) == 1
    assert findings[0].evidence == "flag{abc}"
    assert findings[0].detector == "signature:flag_brace"
    assert str(findings[0].category) == "flag"


def test_scan_text_filters_by_category() -> None:
    findings = scan_text(
        "flag{abc} TLS",
        signatures=_sigset(
            _sig("flag_brace", r"flag\{[^}]+\}", category="flag"),
            _sig("tls_version", r"TLS", category="tls"),
        ),
        source="s",
        categories=frozenset({"flag"}),
    )

    assert [f.detector for f in findings] == ["signature:flag_brace"]


def test_scan_text_caps_matches_per_signature() -> None:
    findings = scan_text(
        "aaaaa",
        signatures=_sigset(_sig("a", "a")),
        source="s",
        max_matches=3,
    )

    assert len(findings) == 3


def test_scan_text_truncates_long_evidence() -> None:
    findings = scan_text(
        "A" * 100,
        signatures=_sigset(_sig("long", "A+")),
        source="s",
        max_evidence=10,
    )

    assert findings[0].evidence == "A" * 10 + "..."


def test_detect_masks_the_authorization_header() -> None:
    request = HttpRequest(
        ts=0.0,
        packet_no=0,
        method="GET",
        uri="/",
        host="h",
        path="/",
        authorization="Basic dXNlcjpwYXNz",
    )
    findings = detect(
        [HttpExchange(request=request, stream_id=0)],
        config=Config(),
        signatures=SignatureSet(),
    )

    auth = [f for f in findings if f.detector == "http.authorization"]
    assert auth
    assert "dXNlcjpwYXNz" not in auth[0].evidence
    assert auth[0].evidence.startswith("Basic")


def test_detect_flags_configured_endpoints_and_extensions() -> None:
    request = HttpRequest(
        ts=0.0,
        packet_no=0,
        method="GET",
        uri="/admin/backup.sql",
        host="h",
        path="/admin/backup.sql",
    )
    findings = detect(
        [HttpExchange(request=request, stream_id=1)],
        config=Config(interesting_endpoints=["/admin"], interesting_extensions=[".sql"]),
        signatures=SignatureSet(),
    )

    titles = {f.title for f in findings}
    assert "Configured interesting endpoint requested" in titles
    assert "Interesting file extension requested" in titles


def test_detect_dedupes_identical_findings_across_exchanges() -> None:
    findings = detect(
        [
            HttpExchange(request=_flag_request(), stream_id=0),
            HttpExchange(request=_flag_request(), stream_id=1),
        ],
        config=Config(interesting_endpoints=[], interesting_extensions=[]),
        signatures=_sigset(_sig("flag_brace", r"flag\{[^}]+\}")),
    )

    assert sum(1 for f in findings if str(f.category) == "flag") == 1


def test_detect_finds_a_flag_in_a_parsed_request_body() -> None:
    data = _request_bytes(
        "POST", "/submit", {"Host": "h", "Content-Length": "15"}, b"token=flag{abc}"
    )
    request = parse_requests(data, stream=_stream())[0]
    findings = detect(
        [HttpExchange(request=request, stream_id=0)],
        config=Config(interesting_endpoints=[], interesting_extensions=[]),
        signatures=_sigset(_sig("flag_brace", r"flag\{[^}]+\}")),
    )

    assert any(f.evidence == "flag{abc}" for f in findings)


# ------------------------------------------------------------------- pipeline


@requires_tshark
def test_auto_parses_http_and_reports_the_flag(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["auto", str(committed_sample), "--output-dir", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)

    assert payload["summary"]["http_requests"] >= 1
    case_dir = Path(payload["case_dir"])
    assert (case_dir / "http" / "http.ndjson").is_file()
    assert (case_dir / "findings.ndjson").is_file()
    assert any("flag{" in finding["evidence"] for finding in payload["findings"])


@requires_tshark
def test_analyze_writes_the_http_dataset(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["analyze", str(committed_sample), "--output-dir", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    case_dir = Path(payload["case_dir"])

    assert payload["counts"]["http_requests"] >= 1
    rows = (case_dir / "http" / "http.ndjson").read_text(encoding="utf-8").strip().splitlines()
    assert rows and json.loads(rows[0])["request"]["method"]
