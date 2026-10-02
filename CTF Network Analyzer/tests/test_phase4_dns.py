"""Phase 4 tests: the DNS wire parser, tunnelling heuristics and detectors.

The parser and heuristic tests are pure (no tshark, no capture) and prove the
security properties directly: malformed and compression-looped input fails
closed, and counts are bounded.  The pipeline tests at the end drive the real
CLI over the deterministic synthetic capture, which contains a deliberate DNS
tunnelling burst.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner

from badnet.analyzers.dns import _looks_encoded, _tunnel_candidates, parse_message
from badnet.cli import app
from badnet.config import Config, DnsThresholds
from badnet.detectors.dns import detect
from badnet.integrations.system_tools import detect_all
from badnet.models.dns import DnsRecord, DnsTunnelCandidate
from badnet.models.finding import Category
from badnet.signatures import Signature, SignatureSet

requires_tshark = pytest.mark.skipif(
    not detect_all().tshark.found, reason="tshark is not installed"
)

runner = CliRunner()

TUNNEL_PARENT = "exfil-c2.lab"


# ------------------------------------------------------------------- helpers


def _message(**kwargs) -> bytes:
    from scapy.layers.dns import DNS

    return bytes(DNS(**kwargs))


def _parse(raw: bytes, packet_no: int = 1) -> DnsRecord | None:
    return parse_message(raw, ts=1.0, src="10.0.0.1", dst="10.0.0.2", packet_no=packet_no)


def _sig(signature_id: str, regex: str, *, category: str = "flag") -> Signature:
    return Signature(
        id=signature_id,
        title=signature_id,
        regex=regex,
        severity="high",
        confidence="high",
        category=category,
        description="matched a test pattern",
        _compiled=re.compile(regex),
    )


def _tunnel_records(count: int = 25, parent: str = TUNNEL_PARENT) -> list[DnsRecord]:
    records: list[DnsRecord] = []
    for i in range(count):
        qname = f"payload{i:02d}abcxyz.tun.{parent}"
        records.append(
            DnsRecord(
                ts=i * 0.01,
                src="10.0.0.1",
                dst="10.0.0.2",
                packet_no=i,
                query=qname,
                qtype="TXT",
                labels=qname.split("."),
            )
        )
    return records


# -------------------------------------------------------------------- parser


def test_parse_query_extracts_name_type_and_labels() -> None:
    from scapy.layers.dns import DNSQR

    raw = _message(id=0x1234, rd=1, qd=DNSQR(qname="www.example.com", qtype="A"))
    record = _parse(raw)

    assert record is not None
    assert record.query == "www.example.com"
    assert record.qtype == "A"
    assert record.is_response is False
    assert record.labels == ["www", "example", "com"]
    assert record.parent_domain == "example.com"


def test_parse_a_response_flattens_the_answer_ip() -> None:
    from scapy.layers.dns import DNSQR, DNSRR

    raw = _message(
        id=1,
        qr=1,
        qd=DNSQR(qname="a.example.com", qtype="A"),
        an=DNSRR(rrname="a.example.com", type="A", ttl=60, rdata="1.2.3.4"),
    )
    record = _parse(raw)

    assert record is not None
    assert record.is_response is True
    assert record.rcode == "NOERROR"
    assert record.answer_ips == ["1.2.3.4"]
    assert record.answers == ["1.2.3.4"]


def test_parse_txt_response_keeps_the_text() -> None:
    from scapy.layers.dns import DNSQR, DNSRR

    raw = _message(
        id=2,
        qr=1,
        qd=DNSQR(qname="v.example.com", qtype="TXT"),
        an=DNSRR(rrname="v.example.com", type="TXT", ttl=1, rdata=[b"flag{dns_txt}"]),
    )
    record = _parse(raw)

    assert record is not None
    assert "flag{dns_txt}" in record.txt


def test_parse_cname_and_mx_answers() -> None:
    from scapy.layers.dns import DNSQR, DNSRR

    raw = _message(
        id=3,
        qr=1,
        qd=DNSQR(qname="alias.example.com", qtype="CNAME"),
        an=DNSRR(rrname="alias.example.com", type="CNAME", rdata="real.example.com"),
    )
    record = _parse(raw)

    assert record is not None
    assert record.cnames == ["real.example.com"]


def test_parse_nxdomain_has_no_answers() -> None:
    from scapy.layers.dns import DNSQR

    raw = _message(id=4, qr=1, rcode=3, qd=DNSQR(qname="missing.example.com", qtype="A"))
    record = _parse(raw)

    assert record is not None
    assert record.rcode == "NXDOMAIN"
    assert record.answers == []


# ---------------------------------------------------------------- adversarial


def test_short_buffer_is_rejected() -> None:
    assert _parse(b"\x00\x01\x02\x03") is None


def test_absurd_header_count_is_rejected() -> None:
    # qdcount = 1000 is far above the cap and must fail closed.
    raw = struct.pack(">HHHHHH", 0x1234, 0x0000, 1000, 0, 0, 0)
    assert _parse(raw) is None


def test_compression_pointer_loop_does_not_hang() -> None:
    # Header with one question, then a name pointer at offset 12 pointing at
    # itself (0xC00C).  A compliant parser must refuse, not loop forever.
    header = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
    record = _parse(header + b"\xc0\x0c")

    assert record is not None
    assert record.query is None


def test_truncated_txt_rdata_is_tolerated() -> None:
    from scapy.layers.dns import DNSQR, DNSRR

    raw = _message(
        id=5,
        qr=1,
        qd=DNSQR(qname="x.example.com", qtype="TXT"),
        an=DNSRR(rrname="x.example.com", type="TXT", rdata=[b"ok"]),
    )
    # Chop the last few bytes so the declared rdlength overruns the buffer.
    record = _parse(raw[:-3])

    assert record is not None  # parsed as far as it could, no exception


# --------------------------------------------------------------- heuristics


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("aaaabqm6ev43c", True),
        ("payload00abcxyz", True),
        ("challenge", False),
        ("version", False),
        ("short", False),
    ],
)
def test_looks_encoded(label: str, expected: bool) -> None:
    assert _looks_encoded(label) is expected


def test_tunnel_candidates_flag_a_unique_high_entropy_burst() -> None:
    candidates = _tunnel_candidates(_tunnel_records(25), DnsThresholds())

    assert candidates
    candidate = candidates[0]
    assert candidate.parent_domain == TUNNEL_PARENT
    assert candidate.unique_ratio == 1.0
    assert candidate.encoded_label_ratio >= 0.5
    assert candidate.score >= 40


def test_tunnel_candidates_ignore_small_groups() -> None:
    assert _tunnel_candidates(_tunnel_records(3), DnsThresholds()) == []


# ------------------------------------------------------------------ detector


def test_detect_reports_a_tunnel_candidate_as_a_dns_finding() -> None:
    candidate = DnsTunnelCandidate(
        parent_domain=TUNNEL_PARENT,
        query_count=60,
        unique_subdomains=60,
        unique_ratio=1.0,
        max_label_len=13,
        mean_label_len=13.0,
        max_entropy=4.1,
        encoded_label_ratio=1.0,
        avg_queries_per_second=100.0,
        seconds_spanned=0.6,
        example_queries=[f"aaaabq.tun.{TUNNEL_PARENT}"],
        reasons=["60/60 queries used a previously unseen subdomain"],
    )
    findings = detect([], config=Config(), signatures=SignatureSet(), tunnels=[candidate])

    assert len(findings) == 1
    assert findings[0].category == Category.DNS
    assert findings[0].detector == "dns.tunnel"
    assert TUNNEL_PARENT in findings[0].source


def test_detect_scans_txt_records_for_flags() -> None:
    record = DnsRecord(
        ts=0.0,
        src="a",
        dst="b",
        packet_no=1,
        is_response=True,
        query="v.example.com",
        qtype="TXT",
        labels=["v", "example", "com"],
        txt=["flag{dns_txt}"],
        answers=["flag{dns_txt}"],
    )
    findings = detect(
        [record],
        config=Config(),
        signatures=SignatureSet(patterns=(_sig("flag_brace", r"flag\{[^}]+\}"),)),
    )

    assert any(f.evidence == "flag{dns_txt}" for f in findings)


# ------------------------------------------------------------------ pipeline


@requires_tshark
def test_auto_detects_dns_tunnelling_in_the_sample(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["auto", str(committed_sample), "--output-dir", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)

    assert payload["summary"]["dns_queries"] >= 60
    assert payload["counts"]["dns_queries"] >= 60
    case_dir = Path(payload["case_dir"])
    assert (case_dir / "dns" / "dns.ndjson").is_file()

    dns_findings = [f for f in payload["findings"] if f["category"] == "dns"]
    assert any(TUNNEL_PARENT in f["source"] for f in dns_findings)


@requires_tshark
def test_analyze_writes_the_dns_dataset_and_tunnel_metadata(
    committed_sample: Path, tmp_path: Path
) -> None:
    result = runner.invoke(
        app, ["analyze", str(committed_sample), "--output-dir", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    case_dir = Path(payload["case_dir"])

    assert payload["counts"]["dns_queries"] >= 60
    rows = (case_dir / "dns" / "dns.ndjson").read_text(encoding="utf-8").strip().splitlines()
    assert len(rows) >= 60

    metadata = json.loads((case_dir / "metadata.json").read_text(encoding="utf-8"))
    tunnels = metadata["options"]["dns_tunnels"]
    assert any(t["parent_domain"] == TUNNEL_PARENT for t in tunnels)
