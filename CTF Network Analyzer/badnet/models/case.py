"""Case identity, output layout and reproducibility metadata."""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from badnet import __version__

#: Subdirectories created inside every case directory.
CASE_SUBDIRS = (
    "dns",
    "http",
    "tls",
    "streams",
    "files",
    "hashes",
    "nmap",
    "logs",
)

#: NDJSON dataset name -> (subdirectory, filename).
DATASETS: dict[str, tuple[str, str]] = {
    "packets": ("", "packets.ndjson"),
    "connections": ("", "connections.ndjson"),
    "dns": ("dns", "dns.ndjson"),
    "http": ("http", "http.ndjson"),
    "tls": ("tls", "tls.ndjson"),
    "streams": ("streams", "streams.ndjson"),
    "files": ("files", "files.ndjson"),
    "hashes": ("hashes", "hashes.ndjson"),
    "findings": ("", "findings.ndjson"),
    "extracted": ("files", "strings.ndjson"),
    "nmap": ("nmap", "nmap.ndjson"),
}

#: Files written at the root of a case directory.
METADATA_FILE = "metadata.json"
SUMMARY_FILE = "summary.txt"
REPORT_HTML = "report.html"
REPORT_JSON = "report.json"


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with second precision."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class CaseInfo:
    """Identity and state of a case directory."""

    name: str
    directory: Path
    input_path: str
    input_sha256: str = ""
    created: str = field(default_factory=utc_now_iso)
    completed: str | None = None
    status: str = "open"
    """``open`` while running, ``complete`` or ``incomplete`` at the end."""
    input_size: int = 0
    input_format: str = ""
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def log_file(self) -> Path:
        """Path of the case debug log."""
        return self.directory / "logs" / "badnet.log"

    def path(self, name: str) -> Path:
        """Absolute path inside the case directory.

        The name is sanitised first, so callers can pass protocol-supplied
        names without worrying about traversal.
        """
        from badnet.utils.filesystem import safe_join  # local import: avoids a cycle

        return safe_join(self.directory, name)

    def to_dict(self) -> dict[str, object]:
        """Serialise for metadata.json."""
        return {
            "name": self.name,
            "directory": str(self.directory),
            "input_path": self.input_path,
            "input_sha256": self.input_sha256,
            "input_size": self.input_size,
            "input_format": self.input_format,
            "created": self.created,
            "completed": self.completed,
            "status": self.status,
            "warnings": list(self.warnings),
            "notes": list(self.notes),
        }


@dataclass(slots=True)
class ToolVersions:
    """Versions of BADNET and every dependency that touched the evidence."""

    badnet: str = __version__
    python: str = sys.version.split()[0]
    platform: str = f"{platform.system()} {platform.release()} ({platform.machine()})"
    externals: dict[str, str | None] = field(default_factory=dict)
    packages: dict[str, str | None] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialise for metadata.json."""
        return {
            "badnet": self.badnet,
            "python": self.python,
            "platform": self.platform,
            "externals": self.externals,
            "packages": self.packages,
        }


@dataclass(slots=True)
class CaseMetadata:
    """``metadata.json`` contents: everything needed to reproduce the run."""

    case: CaseInfo
    tools: ToolVersions
    command_line: list[str]
    config_used: dict[str, object]
    options: dict[str, object]
    """Effective non-default options (max_packets, keylog, limits...)."""
    analysis_started: str = field(default_factory=utc_now_iso)
    analysis_finished: str | None = None
    datasets: dict[str, dict[str, object]] = field(default_factory=dict)
    runs: list[dict[str, object]] = field(default_factory=list)
    """One entry per analysis run against this case.

    Datasets are append-only, so a re-analysis adds rows rather than replacing
    them.  These records make it possible to tell which rows belong to which
    run, and record the run boundaries as evidence in their own right.
    """

    def to_dict(self) -> dict[str, object]:
        """Serialise the full metadata document."""
        return {
            "schema": "badnet/metadata/1.0",
            "analysis_started": self.analysis_started,
            "analysis_finished": self.analysis_finished,
            "case": self.case.to_dict(),
            "tools": self.tools.to_dict(),
            "command_line": list(self.command_line),
            "config": self.config_used,
            "options": self.options,
            "datasets": self.datasets,
            "runs": list(self.runs),
            "environment": {
                "cwd": os.getcwd(),
                "argv0": sys.argv[0] if sys.argv else "",
            },
        }
