"""The orchestrator: one entry point that runs the whole passive pipeline.

``badnet auto`` and ``badnet analyze`` both call :func:`run_case`.  Phases run in
a fixed order and each one writes its dataset as it goes, so an interrupted run
still leaves usable data on disk (the case is then marked ``incomplete``).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from badnet.analyzers import pcap as pcap_analyzer
from badnet.analyzers import protocols as protocols_analyzer
from badnet.analyzers import tcp as tcp_analyzer
from badnet.analyzers.pipeline import PipelineContext, validate_input
from badnet.config import Config
from badnet.models.finding import Finding
from badnet.models.pcapinfo import PcapInfo
from badnet.storage.casestore import CaseStore
from badnet.utils.hashing import hash_file
from badnet.utils.logging import get_logger

log = get_logger("orchestrator")


@dataclass(slots=True)
class CaseResult:
    """Everything a report needs, assembled in memory as bounded samples."""

    case: CaseStore
    ctx: PipelineContext
    info: PcapInfo
    connections: list = field(default_factory=list)
    streams: list = field(default_factory=list)
    artifacts: list = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    dns_stats: object = field(default_factory=dict)
    http_stats: object = field(default_factory=dict)
    dns_top: list[dict] = field(default_factory=list)
    http_top: list[dict] = field(default_factory=list)
    tls_top: list[dict] = field(default_factory=list)
    duration: float = 0.0
    phases: list[dict] = field(default_factory=list)

    @property
    def case_dir(self) -> Path:
        """Directory holding the case output."""
        return self.case.case.directory


def run_case(
    pcap: Path | str,
    *,
    config: Config,
    case_name: str | None = None,
    output_dir: Path | None = None,
    force: bool = False,
    max_packets: int | None = None,
    keylog: str | Path | None = None,
    progress=None,
    on_case_created=None,
    phases: tuple[str, ...] = (
        "info",
        "protocols",
        "connections",
        "streams",
        "dns",
        "http",
        "tls",
        "files",
    ),
) -> CaseResult:
    """Analyse *pcap* and populate a case directory.

    Parameters
    ----------
    phases:
        Subset of the pipeline to run.  ``dns``/``http``/``tls``/``files`` are
        implemented in later phases of the build and are skipped with a log
        message when they are not registered yet.
    on_case_created:
        Called with the case :class:`~pathlib.Path` as soon as the directory
        exists, before any analysis runs.  The CLI uses this to attach a log
        file so ``--debug`` output is captured as evidence from the first packet.

    Returns
    -------
    CaseResult
        Bounded summary used by the reporters.
    """
    started = time.monotonic()
    path, fmt_kind, fmt_detail = validate_input(pcap)

    name = case_name or _default_case_name(path)
    out_dir = Path(output_dir) if output_dir else Path(config.output_dir)

    input_hashes = hash_file(path)
    store = CaseStore.create(
        output_dir=out_dir,
        case_name=name,
        input_path=str(path.resolve()),
        input_sha256=input_hashes.sha256,
        input_size=path.stat().st_size,
        input_format=fmt_detail or fmt_kind,
        force=force,
    )
    if on_case_created is not None:
        on_case_created(store.case.directory)
    store.metadata.tools.externals = {
        "tshark": None,
        "capinfos": None,
        "nmap": None,
    }
    store.metadata.options = {
        "max_packets": max_packets,
        "keylog": str(keylog) if keylog else None,
        "phases": list(phases),
    }
    store.metadata.config_used = config.to_dict()

    ctx = PipelineContext(
        pcap_path=path,
        store=store,
        config=config,
        max_packets=max_packets,
        keylog=keylog,
        progress=progress,
    )
    store.metadata.tools.externals["tshark"] = (
        ctx.tshark_info.tshark_version if ctx.tshark_info else None
    )
    store.metadata.tools.externals["capinfos"] = (
        ctx.tshark_info.capinfos_version if ctx.tshark_info else None
    )
    if ctx.degraded:
        store.metadata.options["degraded"] = list(ctx.degraded)
        for note in ctx.degraded:
            store.warn(note)

    result = CaseResult(
        case=store, ctx=ctx, info=PcapInfo(path=str(path), file_size=0, capture_format=fmt_kind)
    )

    # ------------------------------------------------------------ phase: info
    _record(result, "info")
    if "info" in phases:
        result.info = pcap_analyzer.analyze(ctx)
        for warning in result.info.warnings:
            ctx.warn(warning)
    else:
        result.info = _minimal_info(path, fmt_kind, fmt_detail)

    # -------------------------------------------------------- phase: protocols
    _record(result, "protocols")
    if "protocols" in phases:
        summary = protocols_analyzer.analyze(ctx)
        _write_summary(store, result, summary)

    # ----------------------------------------------------- phase: connections
    _record(result, "connections")
    connections: list = []
    streams: list = []
    if "connections" in phases or "streams" in phases:
        connections, streams = tcp_analyzer.analyze(ctx)
        result.connections = connections
        result.streams = streams
        with store.dataset("connections") as writer:
            writer.write_many(connections)
        with store.dataset("streams") as writer:
            writer.write_many(streams)

    result.duration = time.monotonic() - started
    store.metadata.options["pipeline_seconds"] = round(result.duration, 3)
    store.close(status="complete")
    log.info("case %s analysed in %.2fs", name, result.duration)
    return result


def _record(result: CaseResult, phase: str) -> None:
    result.phases.append({"phase": phase, "started": time.monotonic()})


def _write_summary(store: CaseStore, result: CaseResult, summary) -> None:
    store.metadata.options["protocol_counts"] = summary.present
    for name, count in summary.present.items():
        log.debug("protocol %s: %d packet(s)", name, count)


def _minimal_info(path: Path, kind: str, detail: str) -> PcapInfo:
    from badnet.models.pcapinfo import PcapInfo as _PcapInfo

    return _PcapInfo(
        path=str(path),
        file_size=path.stat().st_size,
        capture_format=kind,
        file_format_detail=detail,
        warnings=["only file-level facts were collected (--fast)"],
    )


def _default_case_name(path: Path) -> str:
    """``<stem>-<short hash>`` so repeated runs of different files never collide."""
    from badnet.utils.filesystem import sanitize_filename
    from badnet.utils.hashing import short_hash

    stem = sanitize_filename(path.stem, fallback="capture")[:60]
    return f"{stem}-{short_hash(str(path.resolve()), 8)}"
