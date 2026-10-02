"""End-to-end tests that run the real pipeline over the synthetic capture.

These are the tests that prove the Phase 1 deliverables work on real data rather
than mocks: the tshark fast path, capinfos facts, connection/stream tracking and
the case directory layout.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from badnet.analyzers.pipeline import PipelineContext
from badnet.cli import app

runner = CliRunner()


# ------------------------------------------------------------------ unit level


def test_capinfos_csv_parsing() -> None:
    from badnet.integrations.tshark import parse_capinfos_csv

    text = (
        "File name,File type,Number of packets,File size (bytes),"
        "Capture duration (seconds),Start time,SHA256\n"
        "x.pcap,pcap,211,26106,9.109098,2026-01-01 12:00:00.020000,abc123\n"
    )
    facts = parse_capinfos_csv(text)
    assert facts["packet_count"] == "211"
    assert facts["file_size"] == "26106"
    assert facts["capture_duration"] == "9.109098"
    assert facts["sha256"] == "abc123"


def test_capinfos_csv_rejects_empty_output() -> None:
    from badnet.errors import ToolError
    from badnet.integrations.tshark import parse_capinfos_csv

    with pytest.raises(ToolError):
        parse_capinfos_csv("   \n")


def test_tshark_fields_are_valid_for_this_build() -> None:
    """Every field name must exist in the installed tshark, or BADNET breaks.

    ``_ws.col.Protocol`` is a display column, not a field, so it is allowed even
    though ``tshark -G fields`` does not list it.
    """
    import subprocess

    from badnet.analyzers.tcp import CONNECTION_FIELDS, STREAM_FIELDS
    from badnet.integrations import tshark
    from badnet.integrations.tshark import FIELDS

    info = tshark.detect()
    if not info.tshark:
        pytest.skip("tshark is not installed")

    # Use the absolute path BADNET itself resolves, not a bare name: tshark is
    # often installed outside PATH (e.g. C:\Program Files\Wireshark).
    output = subprocess.run(
        [info.tshark, "-G", "fields"], capture_output=True, text=True, check=True
    ).stdout
    known = {line.split("\t")[2] for line in output.splitlines() if len(line.split("\t")) >= 3}

    allowed = {"_ws.col.Protocol"}
    for label, fields in (
        ("FIELDS", FIELDS),
        ("STREAM_FIELDS", STREAM_FIELDS),
        ("CONNECTION_FIELDS", CONNECTION_FIELDS),
    ):
        invalid = [f for f in fields if f not in known and f not in allowed]
        assert not invalid, f"{label} has fields tshark does not know: {invalid}"


def test_sample_generator_is_deterministic(tmp_path: Path) -> None:
    """Regenerating the sample must reproduce identical bytes."""
    from conftest import generate_sample

    first, second = generate_sample(tmp_path / "a"), generate_sample(tmp_path / "b")
    assert first.read_bytes() == second.read_bytes()
    assert len(first.read_bytes()) > 1000


def test_sample_pcap_is_a_valid_capture(sample_pcap: Path) -> None:
    from badnet.parsing.pcap_format import sniff

    fmt = sniff(sample_pcap)
    assert fmt.kind == "pcap"
    assert sample_pcap.stat().st_size > 1000


# ------------------------------------------------------------- through the CLI


@pytest.fixture(scope="module")
def analyzed(tmp_path_factory: pytest.TempPathFactory, sample_pcap: Path) -> Path:
    """Run ``badnet analyze`` once and return the case directory."""
    out = tmp_path_factory.mktemp("cases")
    result = runner.invoke(app, ["analyze", str(sample_pcap), "--output-dir", str(out), "--json"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    return Path(payload["case_dir"])


def test_analyze_writes_expected_datasets(analyzed: Path) -> None:
    assert (analyzed / "metadata.json").is_file()
    assert (analyzed / "connections.ndjson").is_file()
    assert (analyzed / "streams" / "streams.ndjson").is_file()


def test_analyze_records_input_hashes(analyzed: Path) -> None:
    metadata = json.loads((analyzed / "metadata.json").read_text(encoding="utf-8"))
    assert len(metadata["case"]["input_sha256"]) == 64


def test_connections_are_bidirectional_and_typed(analyzed: Path) -> None:
    rows = [
        json.loads(line)
        for line in (analyzed / "connections.ndjson").read_text(encoding="utf-8").splitlines()
    ]
    assert rows, "no connections were detected"
    for row in rows:
        assert row["proto"].lower() in {"tcp", "udp"}
        assert row["a_ip"] and row["b_ip"]
        assert row["a_port"] > 0 and row["b_port"] > 0
        assert row["packets"] > 0


def test_streams_have_app_protocols(analyzed: Path) -> None:
    rows = [
        json.loads(line)
        for line in (analyzed / "streams" / "streams.ndjson")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert rows, "no TCP streams were detected"
    protocols = {r["app_protocol"] for r in rows if r.get("app_protocol")}
    assert {"http", "dns", "ftp", "tls"} & protocols, protocols


def test_connection_services_are_protocol_names(analyzed: Path) -> None:
    """`service` must be a real service name, never a payload dissector layer."""
    rows = [
        json.loads(line)
        for line in (analyzed / "connections.ndjson").read_text(encoding="utf-8").splitlines()
    ]
    assert rows
    by_port = {int(r["server_port"]): r["service"] for r in rows if r["proto"] == "TCP"}
    assert by_port[80] == "http"
    assert by_port[443] == "https"
    assert by_port[21] == "ftp"
    for service in by_port.values():
        assert not service.startswith(("DATA", "MEDIA", "X509", "TCP:"))
    assert "http" in by_port.values()


def _stream_rows(analyzed: Path) -> list[dict]:
    """Parse streams.ndjson from a finished case."""
    return [
        json.loads(line)
        for line in (analyzed / "streams" / "streams.ndjson")
        .read_text(encoding="utf-8")
        .splitlines()
    ]


def _ctx_for(analyzed: Path, sample_pcap: Path, name: str) -> PipelineContext:
    """Build a fresh read-only pipeline context over the sample capture."""
    from badnet.config import Config
    from badnet.integrations import tshark
    from badnet.storage.casestore import CaseStore

    store = CaseStore.create(
        output_dir=analyzed.parent / name,
        case_name=name,
        input_path=str(sample_pcap),
    )
    return PipelineContext(
        pcap_path=sample_pcap,
        store=store,
        config=Config.load(),
        reader="tshark",
        tshark_info=tshark.detect(),
    )


def test_stream_reassembly_returns_bytes(analyzed: Path, sample_pcap: Path) -> None:
    from badnet.analyzers.tcp import reassemble_stream

    rows = _stream_rows(analyzed)
    http_stream = next(r for r in rows if r.get("app_protocol") == "http")
    ctx = _ctx_for(analyzed, sample_pcap, "reassembly")
    data = reassemble_stream(
        ctx,
        int(http_stream["stream_id"]),
        client=(
            http_stream["client_ip"],
            int(http_stream["client_port"]),
            http_stream["server_ip"],
            int(http_stream["server_port"]),
        ),
    )
    rebuilt = data.client_to_server
    assert rebuilt, "HTTP stream reassembled to nothing"
    assert b"GET" in rebuilt or b"POST" in rebuilt
    assert b"HTTP/1.1" in data.server_to_client


def test_greeting_first_stream_is_not_labelled_backwards(analyzed: Path, sample_pcap: Path) -> None:
    """FTP greets before the client speaks; directions must not be swapped."""
    from badnet.analyzers.tcp import reassemble_stream

    ftp = next(r for r in _stream_rows(analyzed) if r["server_port"] == 21)
    ctx = _ctx_for(analyzed, sample_pcap, "banner")

    # No client/server hint: BADNET must infer the orientation by itself.
    data = reassemble_stream(ctx, int(ftp["stream_id"]))
    assert data.client.src_port == ftp["client_port"]
    assert data.server.src_port == 21
    assert data.server_to_client.startswith(b"220"), "the FTP greeting is server-to-client"
    assert b"USER" in data.client_to_server


def test_reassembly_has_no_holes_for_a_complete_capture(analyzed: Path, sample_pcap: Path) -> None:
    """Every byte of the sample must be accounted for, with no zero-filled gaps."""
    from badnet.analyzers.tcp import reassemble_stream

    rows = _stream_rows(analyzed)
    assert rows, "no TCP streams were detected"
    ctx = _ctx_for(analyzed, sample_pcap, "holes")

    for row in rows:
        data = reassemble_stream(ctx, int(row["stream_id"]))
        assert data.client.bytes == len(data.client_to_server), row["stream_id"]
        assert data.server.bytes == len(data.server_to_client), row["stream_id"]
        assert data.client.gaps == 0 and data.server.gaps == 0, row["stream_id"]


def test_auto_followups_only_suggest_real_commands_and_files(
    committed_sample: Path, tmp_path: Path
) -> None:
    """`auto` must never tell the user to run something that does not exist."""
    out_dir = tmp_path / "output"
    result = runner.invoke(
        app,
        [
            "auto",
            str(committed_sample),
            "--case",
            "fu",
            "--output-dir",
            str(out_dir),
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.stdout

    out = result.stdout
    # The disclaimer line names unimplemented commands on purpose; every other
    # `badnet ...` token must be a command the CLI actually registers.
    advice = "\n".join(line for line in out.splitlines() if "not implemented" not in line)
    registered = {c.name for c in app.registered_commands if c.name}
    for token in re.findall(r"badnet\s+([a-z][a-z-]*)", advice):
        assert token in registered, f"auto suggests missing command: badnet {token}"

    # Every path `auto` tells the user to open must actually exist on disk.
    for raw in re.findall(r"(?:grep|less)\s+(?:-[a-zA-Z]+\s+)*(\S+)", out):
        candidate = raw.rstrip("*/")
        if candidate.startswith(("output", str(out_dir))):
            assert Path(candidate).exists(), f"auto suggests missing file: {candidate}"

    # Nothing may point at the unimplemented report.
    assert "report.html" not in out


def test_auto_writes_same_case_layout_as_analyze(committed_sample: Path, tmp_path: Path) -> None:
    """`auto` must produce the same files as `analyze`, including summary.txt."""
    analyze_dir = tmp_path / "a"
    auto_dir = tmp_path / "b"
    assert (
        runner.invoke(
            app,
            [
                "analyze",
                str(committed_sample),
                "--case",
                "x",
                "--output-dir",
                str(analyze_dir),
                "-q",
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app,
            ["auto", str(committed_sample), "--case", "x", "--output-dir", str(auto_dir), "-q"],
        ).exit_code
        == 0
    )

    def layout(root: Path) -> set[str]:
        case = next(root.iterdir())
        return {p.relative_to(case).as_posix() for p in case.rglob("*") if p.is_file()}

    assert layout(analyze_dir) == layout(auto_dir)
    assert "summary.txt" in layout(auto_dir)
    assert "streams/streams.ndjson" in layout(auto_dir)


def test_json_mode_writes_the_same_case_layout(committed_sample: Path, tmp_path: Path) -> None:
    """--json changes stdout only; the case directory must be identical."""
    layouts = {}
    for label, extra in (("human", ["-q"]), ("json", ["--json", "-q"])):
        out_dir = tmp_path / label
        result = runner.invoke(
            app,
            [
                "analyze",
                str(committed_sample),
                "--case",
                "x",
                "--output-dir",
                str(out_dir),
                *extra,
            ],
        )
        assert result.exit_code == 0, result.stdout
        case = next(out_dir.iterdir())
        layouts[label] = {p.relative_to(case).as_posix() for p in case.rglob("*") if p.is_file()}

    assert layouts["human"] == layouts["json"]
    assert "summary.txt" in layouts["json"]


def test_scapy_fallback_is_used_and_reported(committed_sample: Path, monkeypatch) -> None:
    """Without tshark the pipeline must fall back to Scapy *and say so*."""
    from badnet.integrations import tshark as tshark_mod

    real_detect = tshark_mod.detect

    def fake_detect(tshark_override=None, capinfos_override=None):
        return tshark_mod.TsharkInfo(
            tshark=None, tshark_version=None, capinfos=None, capinfos_version=None
        )

    monkeypatch.setattr(tshark_mod, "detect", fake_detect)
    result = runner.invoke(app, ["info", str(committed_sample), "--json", "-q"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["reader"] == "scapy"
    assert payload["degraded"], "scapy fallback must report what capability was lost"
    monkeypatch.setattr(tshark_mod, "detect", real_detect)


def test_interrupt_marks_case_incomplete(committed_sample: Path, tmp_path: Path) -> None:
    """Ctrl-C must exit 130 and never leave the case looking complete."""
    from badnet.analyzers import pcap as pcap_mod

    def boom(*args, **kwargs):
        raise KeyboardInterrupt

    original = pcap_mod.analyze
    pcap_mod.analyze = boom
    try:
        result = runner.invoke(
            app,
            ["analyze", str(committed_sample), "--output-dir", str(tmp_path), "--case", "i"],
        )
    finally:
        pcap_mod.analyze = original

    assert result.exit_code == 130, f"expected 130, got {result.exit_code}"
    case = next(p for p in tmp_path.iterdir() if p.is_dir())
    meta = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
    assert meta["case"]["status"] == "incomplete"
    assert meta["case"]["completed"] is None, "interrupted case must not look finished"
    assert all(r.get("status") != "complete" for r in meta.get("runs", []))


def test_successful_case_is_marked_complete(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["analyze", str(committed_sample), "--output-dir", str(tmp_path), "--case", "d", "-q"],
    )
    assert result.exit_code == 0, result.stdout
    case = next(p for p in tmp_path.iterdir() if p.is_dir())
    meta = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
    assert meta["case"]["status"] == "complete"
    assert meta["case"]["completed"], "a finished case needs a completion timestamp"


def test_info_command_reports_capture_facts(committed_sample: Path) -> None:
    result = runner.invoke(app, ["info", str(committed_sample), "--json"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["info"]["packet_count"] > 0
    assert payload["protocols"]
    assert payload["reader"] in {"tshark", "scapy"}


def test_limit_caps_info_tables(committed_sample: Path) -> None:
    """--limit must actually shorten the endpoint tables, not be silently ignored."""
    narrow = runner.invoke(app, ["info", str(committed_sample), "--limit", "2", "--no-color"])
    wide = runner.invoke(app, ["info", str(committed_sample), "--limit", "100", "--no-color"])
    assert narrow.exit_code == 0, narrow.stdout
    assert wide.exit_code == 0, wide.stdout
    # 0.0.0.0 is the fifth-ranked source, so it must be cut by --limit 2 and
    # present at --limit 100.
    assert "0.0.0.0" not in narrow.stdout
    assert "0.0.0.0" in wide.stdout


def test_info_default_limit_honours_config(committed_sample: Path, tmp_path: Path) -> None:
    """`output.default_limit` is documented as the default `--limit`; it must work."""
    from badnet.config import Config

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("output:\n  default_limit: 2\n", encoding="utf-8")
    limited = runner.invoke(
        app, ["info", str(committed_sample), "--config", str(cfg), "--no-color"]
    )
    override = runner.invoke(app, ["info", str(committed_sample), "--limit", "100", "--no-color"])
    assert limited.exit_code == 0, limited.stdout
    assert override.exit_code == 0, override.stdout
    # default_limit=2 must cut what the default (50) shows, and --limit must win over it.
    assert "0.0.0.0" not in limited.stdout
    assert "0.0.0.0" in override.stdout
    assert Config().output.default_limit >= 1


def test_include_banner_false_suppresses_banner(committed_sample: Path, tmp_path: Path) -> None:
    """`output.include_banner` is user-facing config; it must not be a no-op."""
    default = runner.invoke(app, ["info", str(committed_sample), "--no-color"])
    assert default.exit_code == 0, default.stdout
    assert "BADNET" in default.stdout

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("output:\n  include_banner: false\n", encoding="utf-8")
    quiet = runner.invoke(app, ["info", str(committed_sample), "--config", str(cfg), "--no-color"])
    assert quiet.exit_code == 0, quiet.stdout
    assert "BADNET" not in quiet.stdout
    # The rest of the output must still be there.
    assert "Capture" in quiet.stdout


def test_info_creates_no_case_directory(committed_sample: Path, tmp_path: Path) -> None:
    out = tmp_path / "should-stay-empty"
    result = runner.invoke(app, ["info", str(committed_sample), "--output-dir", str(out), "--json"])
    assert result.exit_code == 0
    assert not out.exists()


def test_max_packets_limits_the_run(committed_sample: Path) -> None:
    result = runner.invoke(app, ["info", str(committed_sample), "--max-packets", "5", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["info"]["packet_count"] == 5


def test_analyze_refuses_to_overwrite_without_force(committed_sample: Path, tmp_path: Path) -> None:
    out = tmp_path / "cases"
    first = runner.invoke(
        app,
        ["analyze", str(committed_sample), "--output-dir", str(out), "--case", "fixed"],
    )
    assert first.exit_code == 0
    second = runner.invoke(
        app,
        ["analyze", str(committed_sample), "--output-dir", str(out), "--case", "fixed"],
    )
    assert second.exit_code != 0


def test_force_reanalysis_keeps_both_runs(committed_sample: Path, tmp_path: Path) -> None:
    """--force must append: earlier evidence is never destroyed by a re-analysis."""
    out = tmp_path / "cases"
    args = ["analyze", str(committed_sample), "--output-dir", str(out), "--case", "twice"]
    assert runner.invoke(app, args).exit_code == 0
    dataset = out / "twice" / "connections.ndjson"
    first_rows = dataset.read_text(encoding="utf-8").splitlines()
    assert first_rows

    assert runner.invoke(app, [*args, "--force"]).exit_code == 0
    after = dataset.read_text(encoding="utf-8").splitlines()
    assert after[: len(first_rows)] == first_rows, "the first run's rows were altered"
    assert len(after) == 2 * len(first_rows)

    meta = json.loads((out / "twice" / "metadata.json").read_text(encoding="utf-8"))
    assert [r["run"] for r in meta["runs"]] == [1, 2]
    assert meta["runs"][0]["rows_before"]["connections"] == 0
    assert meta["runs"][1]["rows_before"]["connections"] == len(first_rows)
    assert all(r["status"] == "complete" for r in meta["runs"])


def test_missing_input_exits_cleanly(tmp_path: Path) -> None:
    result = runner.invoke(app, ["info", str(tmp_path / "nope.pcap")])
    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_debug_writes_a_log_file_into_the_case(committed_sample: Path, tmp_path: Path) -> None:
    """--debug promises a log file; it must land in the case's logs/ directory."""
    out = tmp_path / "cases"
    result = runner.invoke(
        app,
        ["analyze", str(committed_sample), "--output-dir", str(out), "--case", "dbg", "--debug"],
    )
    assert result.exit_code == 0, result.stdout
    log = out / "dbg" / "logs" / "badnet.log"
    assert log.is_file(), "--debug produced no log file"
    assert "tshark command" in log.read_text(encoding="utf-8", errors="replace")


def test_no_log_file_without_debug(committed_sample: Path, tmp_path: Path) -> None:
    """Without --debug, no log file is created and the directory stays empty."""
    out = tmp_path / "cases"
    assert (
        runner.invoke(
            app,
            ["analyze", str(committed_sample), "--output-dir", str(out), "--case", "nodebug"],
        ).exit_code
        == 0
    )
    assert list((out / "nodebug" / "logs").iterdir()) == []


def test_non_capture_input_exits_cleanly(tmp_path: Path) -> None:
    junk = tmp_path / "notes.pcap"
    junk.write_bytes(b"just text\n" * 50)
    result = runner.invoke(app, ["info", str(junk)])
    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_config_command_shows_effective_config() -> None:
    result = runner.invoke(app, ["config", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "output" in payload
    assert "signature_dir" in payload


def test_config_command_writes_a_template(tmp_path: Path) -> None:
    target = tmp_path / "template.yaml"
    result = runner.invoke(app, ["config", str(target), "--json"])
    assert result.exit_code == 0, result.stdout
    assert target.is_file()
    assert json.loads(result.stdout)["written"]
