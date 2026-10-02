"""Phase 5 tests: the generic payload sweep and encoding decoders.

The decoder and detector tests are pure.  The pipeline tests drive the real CLI:
one proves the shipped sample's base64-wrapped flag is recovered, and another
builds a capture whose flag travels over a raw TCP stream and a non-DNS UDP
datagram - neither of which the HTTP or DNS detectors would ever see.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from pathlib import Path

import pytest
from typer.testing import CliRunner

from badnet.analyzers.decode import iter_decoded
from badnet.analyzers.payload import PayloadBlob
from badnet.cli import app
from badnet.config import Config
from badnet.detectors.payload import detect
from badnet.integrations.system_tools import detect_all
from badnet.signatures import Signature, SignatureSet, load_signatures

requires_tshark = pytest.mark.skipif(
    not detect_all().tshark.found, reason="tshark is not installed"
)

runner = CliRunner()


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


# ------------------------------------------------------------------ decoders


def _decoded_values(text: str, **kwargs) -> list[str]:
    return [value for _method, value in iter_decoded(text, **kwargs)]


def test_base64_decoding_reveals_a_flag() -> None:
    blob = base64.b64encode(b"prefix flag{b64_here} suffix").decode()
    assert any("flag{b64_here}" in value for value in _decoded_values(blob))


def test_hex_decoding_reveals_a_flag() -> None:
    blob = b"header flag{hex_here} trailer".hex()
    assert any("flag{hex_here}" in value for value in _decoded_values(blob))


def test_url_decoding_reveals_a_flag() -> None:
    blob = urllib.parse.quote("token=1 flag{url_here}&x=2", safe="")
    assert any("flag{url_here}" in value for value in _decoded_values(blob))


def test_rot13_decoding_reveals_a_flag() -> None:
    rotated = "flag{rot_here}".translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        )
    )
    methods = {method for method, _value in iter_decoded(rotated)}
    assert "rot13" in methods
    assert any("flag{rot_here}" in value for value in _decoded_values(rotated))


def test_nested_base64_is_peeled_recursively() -> None:
    once = base64.b64encode(b"flag{nested_secret}").decode()
    twice = base64.b64encode(once.encode()).decode()
    methods = {method for method, _value in iter_decoded(twice, max_depth=3)}
    assert any("+" in method for method in methods)
    assert any("flag{nested_secret}" in value for value in _decoded_values(twice, max_depth=3))


def test_plain_identifiers_are_not_decoded() -> None:
    assert _decoded_values("unit_testing_is_a_long_identifier_with_underscores") == []


def test_max_depth_stops_recursion() -> None:
    once = base64.b64encode(b"flag{deep}").decode()
    twice = base64.b64encode(once.encode()).decode()
    assert not any("flag{deep}" in value for value in _decoded_values(twice, max_depth=1))


# ------------------------------------------------------------------ detector


def test_detector_finds_a_base64_wrapped_flag() -> None:
    blob = PayloadBlob(
        source="tcp-stream-9 server_to_client",
        text="payload=" + base64.b64encode(b"flag{decoded_secret}").decode(),
    )
    findings = detect(
        [blob],
        config=Config(),
        signatures=SignatureSet(patterns=(_sig("flag_brace", r"flag\{[^}]+\}"),)),
    )
    assert any(f.evidence == "flag{decoded_secret}" for f in findings)
    assert all(f.detector.startswith("payload") for f in findings)


def test_detector_reports_a_plain_flag_in_a_raw_blob() -> None:
    blob = PayloadBlob(source="tcp-stream-3 client_to_server", text="USER x\r\nflag{raw}")
    findings = detect(
        [blob],
        config=Config(),
        signatures=SignatureSet(patterns=(_sig("flag_brace", r"flag\{[^}]+\}"),)),
    )
    assert any(f.evidence == "flag{raw}" for f in findings)


def test_shipped_signatures_report_a_flag_only_once() -> None:
    """The generic brace heuristic must not repeat a flag the sharp pattern found."""
    signatures = load_signatures(Config().effective_signature_dir)
    blob = PayloadBlob(source="tcp-stream-0 client_to_server", text="answer=flag{only_once}")
    findings = detect([blob], config=Config(), signatures=signatures)
    matches = [f for f in findings if f.evidence == "flag{only_once}"]
    assert len(matches) == 1
    assert matches[0].detector == "payload:flag_brace"


# ------------------------------------------------------------------ pipeline


@requires_tshark
def test_auto_recovers_the_base64_flag_from_the_sample(
    committed_sample: Path, tmp_path: Path
) -> None:
    result = runner.invoke(
        app, ["auto", str(committed_sample), "--output-dir", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    evidence = {f["evidence"] for f in payload["findings"]}
    assert "flag{b64_in_http_post_wins}" in evidence
    assert payload["counts"]["payload_findings"] >= 1


def _write_raw_capture(path: Path) -> Path:
    """A capture whose flags travel over a raw TCP stream and a UDP datagram."""
    from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

    packets = []
    base = 1_700_000_000.0
    clock = [base]

    def add(layer) -> None:
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / layer
        packet.time = clock[0]
        clock[0] += 0.001
        packets.append(packet)

    cseq, sseq = 1000, 5000
    add(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000, dport=12345, flags="S", seq=cseq))
    cseq += 1
    add(
        IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=12345, dport=51000, flags="SA", seq=sseq, ack=cseq)
    )
    sseq += 1
    add(
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51000, dport=12345, flags="A", seq=cseq, ack=sseq)
    )
    add(
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51000, dport=12345, flags="PA", seq=cseq, ack=sseq)
        / Raw(load=b"cmd=run; flag{raw_tcp_stream}\n")
    )
    add(
        IP(src="10.0.0.3", dst="10.0.0.4")
        / UDP(sport=53000, dport=9999)
        / Raw(load=b"flag{raw_udp_datagram}")
    )

    wrpcap(str(path), packets, linktype=1)
    return path


@requires_tshark
def test_auto_finds_flags_outside_http_and_dns(tmp_path: Path) -> None:
    capture = _write_raw_capture(tmp_path / "raw.pcap")
    result = runner.invoke(app, ["auto", str(capture), "--output-dir", str(tmp_path), "--json"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    evidence = {f["evidence"] for f in payload["findings"]}
    assert "flag{raw_tcp_stream}" in evidence
    assert "flag{raw_udp_datagram}" in evidence


def _write_ipv6_capture(path: Path) -> Path:
    """A flag in an IPv6 TCP stream: reassembly must resolve ipv6.src/dst fields."""
    from scapy.all import TCP, Ether, IPv6, Raw, wrpcap

    packets = []
    clock = [1_700_000_000.0]

    def add(layer) -> None:
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / layer
        packet.time = clock[0]
        clock[0] += 0.001
        packets.append(packet)

    add(
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=51000, dport=12345, flags="S", seq=1000)
    )
    add(
        IPv6(src="2001:db8::2", dst="2001:db8::1")
        / TCP(sport=12345, dport=51000, flags="SA", seq=5000, ack=1001)
    )
    add(
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=51000, dport=12345, flags="A", seq=1001, ack=5001)
    )
    add(
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=51000, dport=12345, flags="PA", seq=1001, ack=5001)
        / Raw(load=b"flag{ipv6_tcp_payload}")
    )

    wrpcap(str(path), packets, linktype=1)
    return path


@requires_tshark
def test_auto_finds_a_flag_in_an_ipv6_tcp_stream(tmp_path: Path) -> None:
    capture = _write_ipv6_capture(tmp_path / "raw6.pcap")
    result = runner.invoke(app, ["auto", str(capture), "--output-dir", str(tmp_path), "--json"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    evidence = {f["evidence"] for f in payload["findings"]}
    assert "flag{ipv6_tcp_payload}" in evidence
