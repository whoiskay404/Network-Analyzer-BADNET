"""Case persistence.

BADNET deliberately stores case data as newline-delimited JSON (NDJSON) rather
than in a database:

* writes are append-only and streamable, so a 40 GiB capture never needs the
  rows in memory at once;
* any tool can read a case (``grep``, ``jq``, a hex editor) which matters during
  an investigation;
* there is no database engine to corrupt or lock, and evidence stays
  human-auditable;
* each dataset is one file per type, so partial results survive an interrupt.

Uniqueness and indexing that a database would give us are handled explicitly:
datasets are keyed, rows are appended in analysis order, and lookups are done by
streaming the file.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any

from badnet.errors import AnalysisError, CaseExistsError, InputError
from badnet.models.case import CASE_SUBDIRS, DATASETS, METADATA_FILE, CaseInfo, CaseMetadata
from badnet.utils.filesystem import harden_dir, harden_file, safe_join

log = logging.getLogger("badnet.storage")

#: Rows buffered before an automatic flush.  Small enough to bound memory,
#: large enough that syscall overhead disappears.
FLUSH_EVERY = 500


class DatasetWriter:
    """Append-only NDJSON writer with bounded buffering.

    The file is opened with mode ``"a"`` so an interrupted or superseded run can
    never remove rows that are already on disk.  For a brand new dataset that is
    indistinguishable from truncating mode, because the file does not exist yet.
    """

    def __init__(self, path: Path, *, flush_every: int = FLUSH_EVERY) -> None:
        self.path = path
        self.count = 0
        self.bytes_written = 0
        self._buffer: list[str] = []
        self._flush_every = flush_every
        self._fh: IO[str] | None = None
        self.closed = False

    def __enter__(self) -> DatasetWriter:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8", newline="\n")
        harden_file(self.path)
        return self

    def write(self, row: Any) -> None:
        """Append one row (dataclass or plain object with ``to_dict``)."""
        if self._fh is None:
            raise AnalysisError(f"dataset {self.path.name} used before opening")
        payload = row.to_dict() if hasattr(row, "to_dict") else row
        try:
            line = json.dumps(payload, ensure_ascii=False, default=_json_default)
        except (TypeError, ValueError) as exc:
            raise AnalysisError(f"cannot serialise row for {self.path.name}: {exc}") from exc
        self._buffer.append(line)
        self.count += 1
        self.bytes_written += len(line) + 1
        if len(self._buffer) >= self._flush_every:
            self.flush()

    def write_many(self, rows: Iterable[Any]) -> None:
        """Append many rows."""
        for row in rows:
            self.write(row)

    def flush(self) -> None:
        """Push buffered rows to disk."""
        if not self._buffer or self._fh is None:
            return
        try:
            self._fh.write("\n".join(self._buffer) + "\n")
            self._fh.flush()
        except OSError as exc:
            # Almost always ENOSPC; report it with the real reason.
            raise AnalysisError(
                f"cannot write case data to {self.path}: {exc} (is the output volume full?)"
            ) from exc
        self._buffer.clear()

    def close(self) -> None:
        """Flush and close idempotently."""
        if self.closed:
            return
        self.closed = True
        try:
            self.flush()
        finally:
            if self._fh is not None:
                try:
                    self._fh.close()
                except OSError as exc:  # pragma: no cover - flush already raised
                    log.warning("error closing %s: %s", self.path, exc)
                self._fh = None

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class CaseStore:
    """Filesystem layout and NDJSON datasets for one case."""

    def __init__(self, case: CaseInfo, metadata: CaseMetadata) -> None:
        self.case = case
        self.metadata = metadata
        self._writers: dict[str, DatasetWriter] = {}

    # ------------------------------------------------------------------ setup

    @classmethod
    def create(
        cls,
        *,
        output_dir: Path,
        case_name: str,
        input_path: str,
        input_sha256: str = "",
        input_size: int = 0,
        input_format: str = "",
        force: bool = False,
    ) -> CaseStore:
        """Create a new case directory.

        Raises
        ------
        CaseExistsError
            When the directory already holds a case and *force* is False.  With
            *force* the case is re-analysed into the same directory: the original
            creation time and the run history are preserved, and every dataset is
            appended to rather than replaced, because previously extracted data is
            evidence.
        """
        root = Path(output_dir)
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise InputError(f"cannot create output directory {root}: {exc}") from exc
        harden_dir(root)

        case_dir = safe_join(root, case_name)
        meta_path = case_dir / METADATA_FILE
        if meta_path.exists() and not force:
            raise CaseExistsError(
                f"case {case_name!r} already exists at {case_dir}",
                hint="choose another --case name, or pass --force to analyse again into it",
            )
        try:
            case_dir.mkdir(parents=True, exist_ok=True)
            for sub in CASE_SUBDIRS:
                (case_dir / sub).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AnalysisError(f"cannot create case directory {case_dir}: {exc}") from exc
        harden_dir(case_dir)
        for sub in CASE_SUBDIRS:
            harden_dir(case_dir / sub)

        # Carry the provenance of the existing case forward: when the same name
        # is re-analysed, the case was not created today, and the earlier runs
        # contributed rows that are still on disk.
        prior: dict[str, Any] = {}
        if force and meta_path.exists():
            try:
                prior = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                log.warning(
                    "could not read previous metadata at %s (%s); starting fresh", meta_path, exc
                )

        case = CaseInfo(
            name=case_name,
            directory=case_dir,
            input_path=input_path,
            input_sha256=input_sha256,
            input_size=input_size,
            input_format=input_format,
        )
        if prior:
            case.created = str(prior.get("case", {}).get("created") or case.created)
        from badnet.models.case import ToolVersions  # local import avoids a cycle

        metadata = CaseMetadata(
            case=case,
            tools=ToolVersions(),
            command_line=list(os.sys.argv),
            config_used={},
            options={},
        )
        metadata.runs = list(prior.get("runs", []) or [])
        store = cls(case, metadata)
        store.start_run()
        store.write_metadata()
        log.info("case %s created at %s", case_name, case_dir)
        return store

    @classmethod
    def open(cls, directory: str | Path) -> CaseStore:
        """Open an existing case directory for read-only post-processing."""
        case_dir = Path(directory)
        meta_path = case_dir / METADATA_FILE
        if not meta_path.is_file():
            raise InputError(
                f"{case_dir} is not a BADNET case (no {METADATA_FILE})",
                hint="run 'badnet auto <file>' or 'badnet analyze <file>' first",
            )
        try:
            raw = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise InputError(f"cannot read {meta_path}: {exc}") from exc
        case = _case_from_dict(raw.get("case", {}), case_dir)
        from badnet.models.case import ToolVersions

        meta = CaseMetadata(
            case=case,
            tools=ToolVersions(
                **{k: v for k, v in raw.get("tools", {}).items() if k != "externals"}
            ),
            command_line=list(raw.get("command_line", [])),
            config_used=dict(raw.get("config", {})),
            options=dict(raw.get("options", {})),
        )
        meta.tools.externals = dict(raw.get("tools", {}).get("externals", {}))
        meta.tools.packages = dict(raw.get("tools", {}).get("packages", {}))
        meta.analysis_started = raw.get("analysis_started", meta.analysis_started)
        meta.analysis_finished = raw.get("analysis_finished")
        meta.runs = list(raw.get("runs", []) or [])
        return cls(case, meta)

    # --------------------------------------------------------------- datasets

    def dataset_path(self, name: str) -> Path:
        """Absolute path of a dataset file."""
        if name not in DATASETS:
            raise AnalysisError(f"unknown dataset {name!r}")
        sub, filename = DATASETS[name]
        base = self.case.directory / sub if sub else self.case.directory
        return safe_join(base, filename)

    @contextmanager
    def dataset(self, name: str, *, mode: str = "w") -> Iterator[DatasetWriter]:
        """Open a dataset writer for the duration of the context.

        Nested/concurrent writes to the same dataset are refused because the
        result would be an unreadable interleaving; callers should aggregate
        rows and write them once, or use distinct dataset names.
        """
        if name in self._writers:
            raise AnalysisError(f"dataset {name!r} is already open for writing")
        path = self.dataset_path(name)
        writer = DatasetWriter(path)
        self._writers[name] = writer
        try:
            with writer:
                yield writer
        finally:
            self._writers.pop(name, None)

    def append(self, name: str, rows: Iterable[Any]) -> int:
        """Append *rows* to a dataset (creating it when absent), return the count."""
        appender = _Appender(self.dataset_path(name))
        with appender:
            return appender.write_many(rows)

    def read(self, name: str) -> Iterator[dict[str, Any]]:
        """Stream a dataset row by row (never loads the file into memory)."""
        path = self.dataset_path(name)
        if not path.exists():
            return
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as exc:
                        # A truncated final line is expected after an interrupt.
                        log.warning("skipping malformed JSON at %s:%d: %s", path, lineno, exc)
        except OSError as exc:
            raise AnalysisError(f"cannot read case dataset {path}: {exc}") from exc

    def count(self, name: str) -> int:
        """Number of rows in a dataset (0 when absent)."""
        path = self.dataset_path(name)
        if not path.exists():
            return 0
        total = 0
        try:
            with path.open("rb") as fh:
                for line in fh:
                    if line.strip():
                        total += 1
        except OSError as exc:
            log.warning("cannot count %s: %s", path, exc)
        return total

    def dataset_stats(self) -> dict[str, dict[str, object]]:
        """Row counts and sizes for metadata.json."""
        stats: dict[str, dict[str, object]] = {}
        for name in DATASETS:
            path = self.dataset_path(name)
            if not path.exists():
                continue
            stats[name] = {"rows": self.count(name), "bytes": path.stat().st_size}
        return stats

    # --------------------------------------------------------------- metadata

    def write_metadata(self) -> None:
        """Persist ``metadata.json`` atomically."""
        self.metadata.datasets = self.dataset_stats()
        path = safe_join(self.case.directory, METADATA_FILE)
        tmp = path.with_suffix(".json.tmp")
        payload = json.dumps(
            self.metadata.to_dict(), indent=2, ensure_ascii=False, default=_json_default
        )
        try:
            tmp.write_text(payload + "\n", encoding="utf-8")
            os.replace(tmp, path)
        except OSError as exc:
            raise AnalysisError(f"cannot write {path}: {exc}") from exc
        harden_file(path)

    def warn(self, message: str) -> None:
        """Record a warning in the case metadata (shown in reports)."""
        if message not in self.case.warnings:
            self.case.warnings.append(message)
        log.warning(message)

    def close(self, *, status: str = "complete") -> None:
        """Flush open datasets and finalise the case."""
        for name in list(self._writers):
            self._writers[name].close()
        self._writers.clear()
        self.case.status = status
        from badnet.models.case import utc_now_iso

        self.metadata.analysis_finished = utc_now_iso()
        # `completed` means the analysis actually finished.  An interrupted or
        # failed run keeps the timestamp in `analysis_finished` but must not
        # look finished to anyone reading metadata.json.
        self.case.completed = self.metadata.analysis_finished if status == "complete" else None
        if self.metadata.runs:
            self.metadata.runs[-1]["finished"] = self.metadata.analysis_finished
            self.metadata.runs[-1]["status"] = status
        self.write_metadata()

    def start_run(self) -> int:
        """Record the start of an analysis run and return its 1-based index.

        Datasets are append-only, so this is what makes a re-analysis auditable:
        ``metadata.json`` shows how many runs contributed rows and when each one
        started and finished.
        """
        from badnet.models.case import utc_now_iso

        run = {
            "run": len(self.metadata.runs) + 1,
            "started": utc_now_iso(),
            "finished": None,
            "status": "running",
            "rows_before": {name: self.count(name) for name in DATASETS},
        }
        self.metadata.runs.append(run)
        return int(run["run"])


class _Appender(DatasetWriter):
    """Deprecated shim retained for callers written against the old API.

    :class:`DatasetWriter` is now append-only unconditionally, so this adds
    nothing beyond :class:`DatasetWriter` itself.
    """


def _case_from_dict(raw: dict[str, Any], directory: Path) -> CaseInfo:
    return CaseInfo(
        name=str(raw.get("name", directory.name)),
        directory=directory,
        input_path=str(raw.get("input_path", "")),
        input_sha256=str(raw.get("input_sha256", "")),
        created=str(raw.get("created", "")),
        completed=raw.get("completed"),
        status=str(raw.get("status", "complete")),
        input_size=int(raw.get("input_size", 0) or 0),
        input_format=str(raw.get("input_format", "")),
        warnings=list(raw.get("warnings", []) or []),
        notes=list(raw.get("notes", []) or []),
    )


def _json_default(value: Any) -> Any:
    """Fallback encoder for datetimes, sets and Paths."""
    import datetime as _dt

    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        # Bytes never belong in a report; represent them as hex, never decode.
        return value[:256].hex()
    raise TypeError(f"object of type {type(value).__name__} is not JSON serialisable")
