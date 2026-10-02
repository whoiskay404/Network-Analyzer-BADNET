"""Adversarial "must not crash" tests for the hardening pass.

Every case here feeds BADNET the kind of malformed or hostile input a CTF
capture can contain: a truncated TLS frame, a bare SYN, a non-UTF-8 config, a
config value of the wrong shape, and a child process that never exits.  The
contract is the same throughout: a clean error or a skipped packet, never an
unhandled traceback and never a hang.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import typer

from badnet.errors import ConfigError, ToolError

# --------------------------------------------------------------- scapy reader


def test_normalize_survives_a_one_byte_tls_looking_payload() -> None:
    """``payload[1]`` on a 1-byte payload raised IndexError before the guard."""
    pytest.importorskip("scapy")
    from scapy.all import IP, TCP, Raw

    from badnet.parsing import scapy_reader

    packet = scapy_reader.normalize(IP() / TCP() / Raw(b"\x16"), number=1)
    assert packet is not None


def test_normalize_survives_a_bare_syn_with_no_ack() -> None:
    """A bare SYN must normalise cleanly even if Scapy leaves the ack unset."""
    pytest.importorskip("scapy")
    from scapy.all import IP, TCP

    from badnet.parsing import scapy_reader

    packet = scapy_reader.normalize(IP() / TCP(flags="S"), number=1)
    assert packet is not None
    assert packet.tcp_ack is not None and isinstance(packet.tcp_ack, int)


# --------------------------------------------------------------------- config


def test_config_rejects_non_utf8_without_a_traceback(tmp_path: Path) -> None:
    """A cp1252 ``badnet.yaml`` raises ConfigError, not UnicodeDecodeError."""
    cfg = tmp_path / "badnet.yaml"
    cfg.write_bytes(b"output_dir: \xff\xfe\x00invalid")
    from badnet.config import Config

    with pytest.raises(ConfigError):
        Config.load(explicit_path=cfg)


def test_config_rejects_non_iterable_interesting_ports(tmp_path: Path) -> None:
    """``interesting_ports: 80`` used to raise TypeError from ``for p in value``."""
    cfg = tmp_path / "badnet.yaml"
    cfg.write_text("interesting_ports: 80\n", encoding="utf-8")
    from badnet.config import Config

    with pytest.raises(ConfigError):
        Config.load(explicit_path=cfg)


# ------------------------------------------------------------------ CLI guard


def test_cli_catch_all_turns_unexpected_errors_into_a_clean_exit() -> None:
    """An unexpected exception must exit via typer.Exit, never leak a traceback."""
    from badnet.cli import handle_errors

    @handle_errors
    def boom() -> None:
        raise RuntimeError("hostile capture")

    with pytest.raises(typer.Exit) as excinfo:
        boom()
    assert excinfo.value.exit_code != 0


# --------------------------------------------------------------- subprocess cap


def test_iter_lines_enforces_its_timeout() -> None:
    """A child that streams one line then sleeps must not hang the reader."""
    from badnet.utils.subprocess import iter_lines

    with pytest.raises(ToolError):
        list(
            iter_lines(
                [
                    sys.executable,
                    "-c",
                    "import time; print('ready', flush=True); time.sleep(30)",
                ],
                timeout=0.6,
            )
        )


def test_iter_lines_streams_a_fast_child() -> None:
    from badnet.utils.subprocess import iter_lines

    lines = list(iter_lines([sys.executable, "-c", "print('a'); print('b')"], timeout=30))
    assert lines == ["a", "b"]


# ------------------------------------------------------------- datagram search


def test_iter_datagram_payloads_yields_udp_and_icmp_only() -> None:
    from badnet.analyzers.search import iter_datagram_payloads
    from badnet.models.packet import NormalizedPacket

    class FakeCtx:
        def iter_packets(self):
            yield NormalizedPacket(
                number=1,
                ts=0.0,
                frame_len=10,
                cap_len=10,
                transport="TCP",
                payload_hex=b"ignored".hex(),
            )
            yield NormalizedPacket(
                number=2,
                ts=0.0,
                frame_len=10,
                cap_len=10,
                transport="UDP",
                payload_hex=b"dns-ish".hex(),
            )
            yield NormalizedPacket(
                number=3,
                ts=0.0,
                frame_len=10,
                cap_len=10,
                transport="ICMP",
                payload_hex=b"ping".hex(),
            )

    rows = list(iter_datagram_payloads(FakeCtx()))
    assert [(r[0], r[1]) for r in rows] == [(2, "udp"), (3, "icmp")]
    assert rows[0][3] == "udp-packet-2"
