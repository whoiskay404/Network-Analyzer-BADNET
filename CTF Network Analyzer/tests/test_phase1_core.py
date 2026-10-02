"""Tests for the Phase 1 building blocks: CLI wiring, config, storage, parsing."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from badnet import __version__
from badnet.cli import (
    Globals,
    app,
    cmd_analyze,
    cmd_auto,
    cmd_config,
    cmd_doctor,
    cmd_info,
    cmd_version,
    with_globals,
)

runner = CliRunner()


# ------------------------------------------------------------------ CLI shape


def test_help_lists_every_command() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ("doctor", "info", "analyze", "auto", "config", "version"):
        assert name in result.stdout


def test_help_has_no_duplicate_root_command() -> None:
    """The root callback must not be registered as a subcommand."""
    result = runner.invoke(app, ["--help"])
    assert result.stdout.count("main") == 0


@pytest.mark.parametrize("command", ["doctor", "info", "analyze", "auto", "config"])
def test_every_command_accepts_all_global_options(command: str) -> None:
    """Global flags are injected into every command signature by construction."""
    result = runner.invoke(app, [command, "--help"])
    assert result.exit_code == 0
    for flag in (
        "--output-dir",
        "--case",
        "--force",
        "--max-packets",
        "--verbose",
        "--no-color",
        "--quiet",
        "--debug",
        "--config",
        "--json",
        "--limit",
    ):
        assert flag in result.stdout, f"{command} is missing {flag}"


def test_command_annotations_are_real_types_not_strings() -> None:
    """`from __future__ import annotations` must not leak string annotations.

    Typer matches annotations by identity/equality against concrete types.  If a
    parameter reaches it as the string ``"Path"``, every command dies at import
    time with ``RuntimeError: Type not yet supported: Path`` - which is exactly
    what happened on Python 3.14 (PEP 649 lazy annotations).
    """

    @with_globals
    def probe(globals: Globals, capture: Path | None = None, flag: bool = False) -> None:
        return None

    annotations = inspect.signature(probe).parameters
    assert annotations["capture"].annotation == Path | None
    assert annotations["flag"].annotation is bool
    for name, param in annotations.items():
        assert not isinstance(param.annotation, str), f"{name} leaked a string annotation"


def test_every_registered_command_has_resolvable_annotations() -> None:
    """No command may carry an unresolved string annotation into Typer."""
    for command in (cmd_doctor, cmd_info, cmd_analyze, cmd_auto, cmd_config, cmd_version):
        for name, param in inspect.signature(command).parameters.items():
            assert not isinstance(param.annotation, str), f"{command.__name__}.{name}"


def test_bad_flag_values_exit_with_usage_code(committed_sample: Path) -> None:
    """A bad flag value is a usage error (exit 2), not a generic error (1).

    Documented contract: 0 ok, 1 error, 2 bad flags/config, 3 missing dep.
    """
    for args in (
        ["--max-packets", "0"],
        ["--max-packets", "-5"],
        ["--max-packets", "abc"],
        ["--limit", "0"],
        ["--limit", "abc"],
    ):
        result = runner.invoke(app, ["info", str(committed_sample), *args])
        assert result.exit_code == 2, f"{args} -> exit {result.exit_code}, expected 2"


def test_top_level_help_points_at_the_global_options() -> None:
    """`badnet --help` must mention that global options exist and where they go.

    They are registered per command, so without this pointer the top-level help
    looks as if the only flag is --help.
    """
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Global options" in result.stdout
    assert "--help" in result.stdout

    # And every global option is documented on at least one command's help.
    from badnet.cli import _global_options

    info_help = runner.invoke(app, ["info", "--help"]).stdout
    declared = set()
    for option in (o for o, _ in _global_options().values()):
        declared.update(p for p in getattr(option, "param_decls", ()) if p.startswith("--"))
    missing = sorted(d for d in declared if d not in info_help)
    assert not missing, f"undocumented in `info --help`: {missing}"


def test_ascii_terminal_does_not_crash_on_unicode() -> None:
    """Untrusted non-ASCII text must never abort output on an ASCII-only terminal.

    `LANG=C` is still common on minimal installs and cron; capture paths and URIs
    can contain characters such as e-acute or an emoji.
    """
    import io

    from badnet.reporting.terminal import safe_stream

    stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict")
    try:
        safe_stream(stream)
        stream.write("caf\u00e9-\u4f60\u597d-\U0001f600.pcap\n")  # must not raise
        stream.flush()
        assert stream.buffer.getvalue()  # something was actually written
    finally:
        stream.detach()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_json_output_is_valid_json() -> None:
    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["badnet"] == __version__


# ------------------------------------------------------------- doctor contract


def test_doctor_reports_every_component() -> None:
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code in (0, 1)
    payload = json.loads(result.stdout)
    names = {r["name"] for r in payload["requirements"]}
    assert {"python", "typer", "tshark", "capinfos", "scapy", "python-magic"} <= names
    for entry in payload["requirements"]:
        assert entry["kind"] in {"python", "package", "tool"}


def test_doctor_marks_missing_tools_without_crashing() -> None:
    result = runner.invoke(app, ["doctor", "--json"])
    payload = json.loads(result.stdout)
    missing = [r for r in payload["requirements"] if not r["found"]]
    for entry in missing:
        assert entry["degrades"], f"{entry['name']} is missing without saying what breaks"


def test_doctor_libmagic_reflects_real_library() -> None:
    """python-magic is only FOUND when libmagic itself loads."""
    from badnet.integrations.doctor import collect

    entry = next(r for r in collect() if r.name == "python-magic")
    from badnet.integrations import system_tools

    assert entry.found == system_tools.libmagic_available()


# ------------------------------------------------------------------- config


def test_defaults_load_without_files() -> None:
    from badnet.config import Config

    config = Config.load()
    assert config.output.max_findings_shown > 0
    assert config.output.redact_secrets is True
    assert config.limits.max_artifact_size > 0
    assert config.dns.min_queries > 0


def test_user_config_overrides_defaults(tmp_path: Path) -> None:
    from badnet.config import Config

    path = tmp_path / "badnet.yaml"
    path.write_text("output:\n  max_findings_shown: 7\n", encoding="utf-8")
    assert Config.load(explicit_path=path).output.max_findings_shown == 7


def test_unknown_keys_are_rejected(tmp_path: Path) -> None:
    from badnet.config import Config
    from badnet.errors import ConfigError

    path = tmp_path / "badnet.yaml"
    path.write_text("output:\n  nonsense_key: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        Config.load(explicit_path=path)


def test_config_template_round_trips(tmp_path: Path) -> None:
    from badnet.config import Config, write_template

    path = write_template(tmp_path / "template.yaml")
    assert Config.load(explicit_path=path) is not None


# ------------------------------------------------------------------ storage


def _store(output_dir: Path, name: str, **kwargs):
    """Create a case store the way the orchestrator does."""
    from badnet.storage.casestore import CaseStore

    return CaseStore.create(output_dir=output_dir, case_name=name, input_path="x.pcap", **kwargs)


def test_case_store_writes_ndjson_and_metadata(tmp_path: Path) -> None:
    store = _store(tmp_path, "unit")
    store.append("packets", [{"number": 1}, {"number": 2}])
    store.close(status="complete")

    directory = store.case.directory
    data = (directory / "packets.ndjson").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["number"] for line in data] == [1, 2]
    metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["case"]["status"] == "complete"
    assert metadata["datasets"]["packets"]["rows"] == 2


def test_case_store_refuses_to_overwrite(tmp_path: Path) -> None:
    from badnet.errors import CaseExistsError

    _store(tmp_path, "twice").close(status="complete")
    with pytest.raises(CaseExistsError):
        _store(tmp_path, "twice")


def test_force_appends_and_keeps_earlier_evidence(tmp_path: Path) -> None:
    """``--force`` re-analysis must append, never truncate, existing evidence."""
    first = _store(tmp_path, "again")
    first.append("packets", [{"number": 1}])
    first.close(status="complete")

    second = _store(tmp_path, "again", force=True)
    second.append("packets", [{"number": 2}])
    second.close(status="complete")

    rows = list(second.read("packets"))
    assert [r["number"] for r in rows] == [1, 2]


def test_dataset_writer_appends_and_preserves_creation_time(tmp_path: Path) -> None:
    """The ``dataset()`` path used by the pipeline must append like ``append()``.

    ``append()`` was append-only while ``dataset()`` truncated, so the real
    pipeline silently destroyed prior evidence on ``--force``.
    """
    first = _store(tmp_path, "writer")
    with first.dataset("connections") as writer:
        writer.write({"n": 1})
    created = first.case.created
    first.close(status="complete")

    second = _store(tmp_path, "writer", force=True)
    with second.dataset("connections") as writer:
        writer.write({"n": 2})
    second.close(status="complete")

    assert [r["n"] for r in second.read("connections")] == [1, 2]
    meta = json.loads((second.case.directory / "metadata.json").read_text(encoding="utf-8"))
    assert meta["case"]["created"] == created, "re-analysis reset the case creation time"
    assert len(meta["runs"]) == 2


def test_no_sqlite_anywhere_in_case_output(tmp_path: Path) -> None:
    store = _store(tmp_path, "nodb")
    store.close(status="complete")
    assert not list(store.case.directory.rglob("*.db"))
    assert not list(store.case.directory.rglob("*.sqlite*"))


def test_case_names_cannot_escape_the_output_directory(tmp_path: Path) -> None:
    from badnet.errors import SecurityError

    with pytest.raises(SecurityError):
        _store(tmp_path, "../escape")


def test_reopening_a_case_reads_existing_rows(tmp_path: Path) -> None:
    from badnet.storage.casestore import CaseStore

    store = _store(tmp_path, "reopen")
    store.append("connections", [{"a_ip": "1.1.1.1"}])
    store.close(status="complete")

    reopened = CaseStore.open(store.case.directory)
    assert list(reopened.read("connections")) == [{"a_ip": "1.1.1.1"}]


# ------------------------------------------------------------------ parsing


def test_pcap_magic_detection(tmp_path: Path) -> None:
    from badnet.parsing.pcap_format import sniff

    def write(name: str, head: bytes) -> Path:
        path = tmp_path / name
        path.write_bytes(head + b"\x00" * 60)
        return path

    assert sniff(write("le.pcap", b"\xd4\xc3\xb2\xa1")).kind == "pcap"
    assert sniff(write("be.pcap", b"\xa1\xb2\xc3\xd4")).kind == "pcap"
    assert sniff(write("ng.pcapng", b"\x0a\x0d\x0d\x0a\x1a\x2b\x3c\x4d")).kind == "pcapng"
    assert sniff(write("junk.pcap", b"not a capture at all")).kind == "unknown"


def test_sniff_reports_a_missing_file(tmp_path: Path) -> None:
    from badnet.errors import InputError
    from badnet.parsing.pcap_format import sniff

    with pytest.raises(InputError):
        sniff(tmp_path / "missing.pcap")


def test_empty_file_is_rejected(tmp_path: Path) -> None:
    from badnet.analyzers.pipeline import validate_input
    from badnet.errors import InputError

    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    with pytest.raises(InputError):
        validate_input(empty)


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    from badnet.analyzers.pipeline import validate_input
    from badnet.errors import InputError

    with pytest.raises(InputError):
        validate_input(tmp_path / "nope.pcap")


def test_non_capture_file_is_rejected(tmp_path: Path) -> None:
    from badnet.analyzers.pipeline import validate_input
    from badnet.errors import InputError

    junk = tmp_path / "notes.pcap"
    junk.write_bytes(b"this is a text file, not a capture\n" * 10)
    with pytest.raises(InputError):
        validate_input(junk)


# ------------------------------------------------------------------ signatures


def test_shipped_signatures_all_compile() -> None:
    from badnet.config import DEFAULT_SIGNATURE_DIR
    from badnet.signatures import load_signatures

    signatures = load_signatures(DEFAULT_SIGNATURE_DIR)
    assert len(signatures) > 0
    for signature in signatures.patterns:
        # Accessing .compiled raises if the regex failed to build at load time.
        assert signature.compiled.pattern


def test_signature_ids_are_unique() -> None:
    from badnet.config import DEFAULT_SIGNATURE_DIR
    from badnet.signatures import load_signatures

    ids = [p.id for p in load_signatures(DEFAULT_SIGNATURE_DIR).patterns]
    assert len(ids) == len(set(ids))


def test_port_service_table_is_loaded() -> None:
    """The port->service map must actually populate; it was silently empty."""
    from badnet.config import DEFAULT_SIGNATURE_DIR
    from badnet.signatures import load_signatures

    sigs = load_signatures(DEFAULT_SIGNATURE_DIR)
    assert sigs.port_services, "the port->service table parsed to nothing"
    assert sigs.service_for_port(80) == "http"
    assert sigs.service_for_port(443) == "https"
    assert sigs.service_for_port(22) == "ssh"
    assert sigs.service_for_port(9001) == ""


def test_bad_service_entry_is_rejected(tmp_path: Path) -> None:
    """A non-integer port key must fail loudly, not be dropped."""
    from badnet.config import ConfigError
    from badnet.signatures import load_signatures

    (tmp_path / "ports.yaml").write_text("services:\n  http: 80\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_signatures(tmp_path)


def test_service_name_ignores_pseudo_layers() -> None:
    """A service must never be reported as a payload dissector's internal name."""
    from badnet.models.connection import Connection

    def conn(protocols: str, service_name: str = "") -> Connection:
        return Connection(
            proto="TCP",
            a_ip="10.0.0.1",
            a_port=40000,
            b_ip="10.0.0.2",
            b_port=80,
            client_ip="10.0.0.1",
            client_port=40000,
            server_ip="10.0.0.2",
            server_port=80,
            protocols=protocols,
            service_name=service_name,
        )

    # Port table wins over the layer stack.
    assert conn("eth:ethertype:ip:tcp:http:data-text-lines", "http").service == "http"
    # Without the table, the most specific *real* layer wins.
    assert conn("eth:ethertype:ip:tcp:http:data-text-lines").service == "HTTP"
    assert conn("eth:ethertype:ip:tcp:tls:x509sat:x509sat").service == "TLS"
    # Nothing but transport/payload layers left: fall back to the transport.
    assert conn("eth:ethertype:ip:tcp:data").service == "TCP"
    assert conn("").service == "TCP"


def test_interesting_ports_come_from_yaml() -> None:
    from badnet.config import DEFAULT_SIGNATURE_DIR
    from badnet.signatures import load_signatures

    ports = load_signatures(DEFAULT_SIGNATURE_DIR).interesting_ports
    assert 80 in ports
    assert all(1 <= p <= 65535 for p in ports)


def test_a_broken_signature_file_fails_loudly(tmp_path: Path) -> None:
    from badnet.errors import ConfigError
    from badnet.signatures import load_signatures

    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 1\npatterns:\n  - id: broken\n    title: t\n"
        "    regex: '([unclosed'\n    severity: high\n"
        "    confidence: high\n    category: flag\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_signatures(tmp_path)


def test_unknown_signature_category_is_rejected(tmp_path: Path) -> None:
    from badnet.errors import ConfigError
    from badnet.signatures import load_signatures

    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 1\npatterns:\n  - id: x\n    title: t\n    regex: 'a'\n"
        "    severity: high\n    confidence: high\n    category: nonsense\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_signatures(tmp_path)


def test_signature_files_exist() -> None:
    from badnet.config import DEFAULT_SIGNATURE_DIR

    names = {p.name for p in DEFAULT_SIGNATURE_DIR.glob("*.yaml")}
    assert {"ctf_patterns.yaml", "secrets.yaml", "interesting_ports.yaml"} <= names


# ------------------------------------------------------------- subprocess API


def test_run_tool_never_uses_a_shell() -> None:
    from badnet.utils import subprocess as sp

    source = Path(sp.__file__).read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "shell = True" not in source


def test_run_tool_captures_timeout() -> None:
    import sys

    from badnet.utils.subprocess import run_tool

    result = run_tool([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
    assert result.timed_out is True


def test_run_tool_caps_output() -> None:
    import sys

    from badnet.utils.subprocess import run_tool

    result = run_tool(
        [sys.executable, "-c", "print('x' * 100000)"],
        timeout=30,
        max_output=1024,
    )
    assert len(result.stdout) <= 4096
