"""Phase 2 unit tests: the carver, the search sweep and HTML escaping.

These run without tshark and without the pipeline, so they are fast and prove the
security properties (bounding and escaping) directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from badnet.analyzers.extract import carve, store
from badnet.analyzers.search import compile_search, looks_catastrophic, search_blob
from badnet.errors import ReDoSGuardError, UsageError
from badnet.models.artifact import ExtractionMethod
from badnet.reporting.html import ReportData, render

PNG = b"\x89PNG\r\n\x1a\n" + b"A" * 20
JPEG = b"\xff\xd8\xff\xe0" + b"J" * 20


# ---------------------------------------------------------------------- carver


def test_carve_finds_magic_and_stops_at_the_next_signature() -> None:
    data = b"prefix" + PNG + JPEG
    artifacts = carve(data, stream_id=3, direction="client_to_server")

    assert [a.detected_type for a in artifacts][:2] == ["PNG image data", "JPEG image data"]
    png = artifacts[0]
    assert png.offset == 6
    assert png.size == len(PNG)  # next-magic boundary, not end of buffer
    assert any("next-magic" in note for note in png.notes)
    assert png.method is ExtractionMethod.MAGIC_CARVE
    assert any("end-of-stream" in note for note in artifacts[-1].notes)


def test_carve_respects_max_objects() -> None:
    data = (PNG + b"x") * 5
    assert len(carve(data, max_objects=2)) == 2


def test_carve_truncates_oversize_objects() -> None:
    artifacts = carve(PNG + b"B" * 100, max_object_bytes=10)
    assert artifacts[0].truncated is True
    assert artifacts[0].size == 10


def test_carve_records_missing_bytes_as_a_warning() -> None:
    artifacts = carve(PNG + b"tail", missing_bytes=42)
    assert any("42 byte(s) never captured" in note for note in artifacts[0].notes)


def test_carve_on_empty_and_signature_free_input_returns_nothing() -> None:
    assert carve(b"") == []
    assert carve(b"no magic here at all") == []


def test_store_writes_file_hashes_and_never_overwrites(tmp_path: Path) -> None:
    data = b"zz" + PNG
    artifacts = carve(data, stream_id=3, direction="client_to_server")
    files = tmp_path / "files"

    first = store(artifacts, data, stream_id=3, direction="client_to_server", files_dir=files)
    assert len(first) == 1
    saved = files / first[0].stored_path
    assert saved.read_bytes() == PNG
    assert first[0].sha256 and len(first[0].sha256) == 64
    assert first[0].name.startswith("stream3_client_to_server_")

    second = store(
        carve(data, stream_id=3, direction="client_to_server"),
        data,
        stream_id=3,
        direction="client_to_server",
        files_dir=files,
    )
    assert second[0].stored_path != first[0].stored_path
    assert (files / second[0].stored_path).is_file()


# ---------------------------------------------------------------------- search


def test_looks_catastrophic_flags_nested_quantifiers() -> None:
    assert looks_catastrophic("(a+)+")
    assert looks_catastrophic("(.*)*")
    assert not looks_catastrophic(r"flag\{[^}]+\}")
    assert not looks_catastrophic("password")


def test_compile_search_literal_escapes_regex_metacharacters() -> None:
    pattern = compile_search("a.b*c", literal=True)
    assert pattern.search(b"x a.b*c y")
    assert not pattern.search(b"axbxc")


def test_compile_search_regex_uses_metacharacters() -> None:
    pattern = compile_search("a.b")
    assert pattern.search(b"axb")


def test_compile_search_is_case_insensitive_on_request() -> None:
    assert compile_search("flag", literal=True, ignore_case=True).search(b"FLAG")


def test_compile_search_rejects_empty_bad_and_dangerous_patterns() -> None:
    with pytest.raises(UsageError):
        compile_search("")
    with pytest.raises(UsageError):
        compile_search("(")
    with pytest.raises(ReDoSGuardError):
        compile_search("(a+)+")


def test_search_blob_reports_offsets_length_and_context() -> None:
    hit = search_blob(
        b"xxflag{abc}yy",
        compile_search(r"flag\{[^}]+\}"),
        stream_id=7,
        direction="client_to_server",
        source="tcp-stream-7",
    )[0]
    assert (hit.offset, hit.length, hit.match) == (2, 9, "flag{abc}")
    assert "xx" in hit.context
    assert hit.source == "tcp-stream-7"
    assert hit.to_dict()["offset"] == 2


def test_search_blob_truncates_a_very_long_match() -> None:
    hit = search_blob(b"AK" + b"A" * 600, compile_search("AK[A]+"), max_match_bytes=16)[0]
    assert hit.truncated is True
    assert len(hit.match) == 16


def test_search_blob_honours_max_hits() -> None:
    hits = search_blob(b"aaaa", compile_search("a"), max_hits=2)
    assert len(hits) == 2


def test_search_blob_decodes_hostile_bytes_without_crashing() -> None:
    hit = search_blob(b"\xff\xfeSECRET\x00\x80", compile_search("SECRET", literal=True))[0]
    assert hit.match == "SECRET"
    assert "\ufffd" in hit.context  # invalid UTF-8 replaced, never raised


# ------------------------------------------------------------------------ html


def test_html_escapes_every_capture_derived_value() -> None:
    data = ReportData(
        case_name="<script>alert(1)</script>",
        generated="now",
        warnings=["<img src=x onerror=alert(1)>"],
        findings=[
            {
                "title": "<b>flag</b>",
                "category": "flag",
                "severity": "high",
                "confidence": "high",
                "explanation": "<script>explain()</script>",
                "evidence": "<script>evil()</script>",
                "source": "stream <1>",
                "detector": "d",
            }
        ],
        streams=[
            {
                "stream_id": 1,
                "proto": "TCP",
                "client": "<x>",
                "server": "y",
                "app_protocol": "http",
                "packets": 1,
                "bytes": 2,
            }
        ],
    )
    out = render(data)

    assert "<script" not in out.lower()
    assert "<img" not in out.lower()
    assert "javascript:" not in out.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "&lt;b&gt;flag&lt;/b&gt;" in out
    assert "&lt;script&gt;evil()&lt;/script&gt;" in out


def test_html_is_fully_self_contained() -> None:
    out = render(ReportData(case_name="case", generated="now"))
    assert out.startswith("<!DOCTYPE html>")
    assert "<style>" in out  # styling is inlined ...
    assert "<link" not in out.lower()  # ... never external
    assert "<img" not in out.lower()
    assert "<script" not in out.lower()
    assert "http://" not in out.lower()
    assert "https://" not in out.lower()


def test_html_renders_empty_data_without_crashing() -> None:
    out = render(ReportData(case_name="empty", generated="now", status="incomplete"))
    assert "No protocol statistics recorded" in out
    assert "No files were recovered" in out
    assert "No indicator matched" in out
