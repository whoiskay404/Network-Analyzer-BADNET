"""Phase 2 integration tests: ``stream``, ``search`` and ``report`` through the CLI.

These run the real pipeline over the deterministic synthetic capture, so they
prove the commands work end to end and write the files they promise.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from badnet.cli import app

runner = CliRunner()


# ------------------------------------------------------------------- registry


def test_phase2_commands_are_registered() -> None:
    names = {c.name for c in app.registered_commands}
    assert {"stream", "search", "report"} <= names


def test_auto_now_suggests_the_new_commands() -> None:
    from badnet.commands.auto import _available_commands

    assert {"stream", "search"} <= _available_commands()


# --------------------------------------------------------------------- stream


def test_stream_lists_streams(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["stream", str(committed_sample), "--output-dir", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["total"] >= 1
    assert payload["streams"]
    assert payload["streams"][0]["stream_id"] >= 0


def test_stream_dump_writes_reassembled_payload(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "stream",
            str(committed_sample),
            "--output-dir",
            str(tmp_path),
            "--id",
            "0",
            "--carve",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    case_dir = Path(payload["case_dir"])
    assert payload["dumped"], "no direction was dumped"
    for entry in payload["dumped"]:
        saved = case_dir / "streams" / entry["path"]
        assert saved.is_file()
        assert len(entry["sha256"]) == 64
        assert entry["carved"] == []  # the synthetic capture has no embedded files


def test_stream_rejects_unknown_direction(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "stream",
            str(committed_sample),
            "--output-dir",
            str(tmp_path),
            "--direction",
            "sideways",
            "--json",
        ],
    )
    assert result.exit_code == 2


def test_stream_rejects_unknown_id(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["stream", str(committed_sample), "--output-dir", str(tmp_path), "--id", "9999", "--json"],
    )
    assert result.exit_code == 2


# --------------------------------------------------------------------- search


def test_search_finds_a_flag_and_records_hits(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "search",
            str(committed_sample),
            "--output-dir",
            str(tmp_path),
            "-e",
            r"flag\{[^}]+\}",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert any(hit["match"].startswith("flag{") for hit in payload["results"])
    rows = (Path(payload["case_dir"]) / "search.ndjson").read_text(encoding="utf-8")
    assert rows.strip()


def test_search_literal_and_case_insensitive(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "search",
            str(committed_sample),
            "--output-dir",
            str(tmp_path),
            "-F",
            "-i",
            "-e",
            "FLAG{",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert json.loads(result.stdout)["hits"] >= 1


def test_search_refuses_a_redos_pattern(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["search", str(committed_sample), "--output-dir", str(tmp_path), "-e", "(a+)+"]
    )
    assert result.exit_code == 2


def test_search_refuses_an_invalid_regex(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["search", str(committed_sample), "--output-dir", str(tmp_path), "-e", "("]
    )
    assert result.exit_code == 2


def test_search_reuses_an_existing_case(committed_sample: Path, tmp_path: Path) -> None:
    first = runner.invoke(
        app, ["analyze", str(committed_sample), "--output-dir", str(tmp_path), "--json"]
    )
    assert first.exit_code == 0, first.stdout
    case_dir = json.loads(first.stdout)["case_dir"]
    result = runner.invoke(app, ["search", case_dir, "-e", "flag", "--json"])
    assert result.exit_code == 0, result.stdout
    assert json.loads(result.stdout)["hits"] >= 1


# --------------------------------------------------------------------- report


def test_report_writes_a_self_contained_html(committed_sample: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["report", str(committed_sample), "--output-dir", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    case_dir = Path(payload["case_dir"])

    html = (case_dir / "report.html").read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>")
    assert "<script" not in html.lower()
    assert "<img" not in html.lower()
    assert "<link" not in html.lower()
    assert "http://" not in html.lower()

    report_json = case_dir / "report.json"
    assert report_json.is_file()
    parsed = json.loads(report_json.read_text(encoding="utf-8"))
    assert parsed["case"]
    assert "facts" in parsed


def test_report_rebuilds_from_an_existing_case(committed_sample: Path, tmp_path: Path) -> None:
    first = runner.invoke(
        app, ["analyze", str(committed_sample), "--output-dir", str(tmp_path), "--json"]
    )
    assert first.exit_code == 0, first.stdout
    case_dir = json.loads(first.stdout)["case_dir"]

    result = runner.invoke(app, ["report", case_dir, "--json"])
    assert result.exit_code == 0, result.stdout
    assert (Path(case_dir) / "report.html").is_file()
