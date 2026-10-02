"""The orchestrator: one entry point that runs the whole passive pipeline.

``badnet auto`` and ``badnet analyze`` both call :func:`run_case`.  Phases run in
a fixed order and each one writes its dataset as it goes, so an interrupted run
still leaves usable data on disk (the case is then marked ``incomplete``).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from badnet.analyzers import dns as dns_analyzer
from badnet.analyzers import http as http_analyzer
from badnet.analyzers import pcap as pcap_analyzer
from badnet.analyzers import protocols as protocols_analyzer
from badnet.analyzers import tcp as tcp_analyzer
from badnet.analyzers.pipeline import PipelineContext, validate_input
from badnet.config import Config
from badnet.detectors import dns as dns_detector
from badnet.detectors import http as http_detector
from badnet.models.finding import Finding
from badnet.models.pcapinfo import PcapInfo
from badnet.signatures import load_signatures
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
        Subset of the pipeline to run.  ``http`` and ``dns`` are implemented;
        ``tls``/``files`` are implemented in later phases of the build and are
        skipped with a log message when they are not registered yet.
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

    try:
        _run_phases(result, phases, store, fmt_kind=fmt_kind, fmt_detail=fmt_detail)
    except (KeyboardInterrupt, SystemExit):
        # Ctrl-C keeps whatever was already written, but the case must not be
        # left looking complete: partial evidence has to stay visibly partial.
        store.close(status="incomplete")
        log.warning("case %s interrupted; partial results kept and marked incomplete", name)
        raise
    except Exception:
        store.close(status="failed")
        raise

    result.duration = time.monotonic() - started
    store.metadata.options["pipeline_seconds"] = round(result.duration, 3)
    store.close(status="complete")
    log.info("case %s analysed in %.2fs", name, result.duration)
    return result


def _run_phases(
    result: CaseResult,
    phases,
    store: CaseStore,
    *,
    fmt_kind: str,
    fmt_detail: str,
) -> None:
    """Run the pipeline phases in fixed order, writing each dataset as it goes."""
    ctx = result.ctx

    # ------------------------------------------------------------ phase: info
    _record(result, "info")
    if "info" in phases:
        result.info = pcap_analyzer.analyze(ctx)
        for warning in result.info.warnings:
            ctx.warn(warning)
    else:
        result.info = _minimal_info(ctx.pcap_path, fmt_kind, fmt_detail)

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

    # ------------------------------------------------------------ phase: http
    _record(result, "http")
    if "http" in phases:
        _run_http(result, store, streams)

    # ------------------------------------------------------------- phase: dns
    # Runs after HTTP so DNS findings extend ``result.findings`` rather than
    # being overwritten by the HTTP phase's assignment.
    _record(result, "dns")
    if "dns" in phases:
        _run_dns(result, store)

    # --------------------------------------------- reserved (not built yet)
    # ``tls``/``files`` are named in the data model but have no analyzer yet.
    # Log it so a run that requested them is not silently short of evidence;
    # they are deliberately absent from ``result.phases``.
    for pending in ("tls", "files"):
        if pending in phases:
            log.info("phase %r is not implemented yet; skipped", pending)


def _run_http(result: CaseResult, store: CaseStore, streams) -> None:
    """Parse HTTP exchanges and run the HTTP detectors over them.

    Findings are written to the ``findings`` dataset and kept in memory for the
    reporters.  When a caller runs the ``http`` phase without the ``streams``
    phase there is nothing to reassemble, so the phase records a warning rather
    than silently producing zero results.
    """
    ctx = result.ctx
    if not streams:
        ctx.warn("http phase requested but no streams were tracked; skipping HTTP parsing")
        return

    analysis = http_analyzer.analyze(ctx, streams)
    result.http_stats = analysis.stats
    result.http_top = list(analysis.stats.top_paths)
    with store.dataset("http") as writer:
        writer.write_many(analysis.exchanges)
    for warning in analysis.warnings:
        ctx.warn(warning)

    signatures = load_signatures(ctx.config.effective_signature_dir)
    findings = http_detector.detect(
        analysis.exchanges,
        config=ctx.config,
        signatures=signatures,
    )
    result.findings = findings
    if findings:
        with store.dataset("findings") as writer:
            writer.write_many(findings)
    store.metadata.options["http"] = analysis.stats.to_dict()
    store.metadata.options["findings_count"] = len(findings)
    log.info(
        "http: %d exchange(s), %d finding(s) from %d http stream(s)",
        len(analysis.exchanges),
        len(findings),
        len(streams),
    )


def _run_dns(result: CaseResult, store: CaseStore) -> None:
    """Parse DNS from raw port-53 payloads and run the DNS detectors.

    Runs for either reader because it works on the normalised payload rather
    than on dissector fields.  Findings are appended to any HTTP findings that
    already ran, and written to the shared ``findings`` dataset.
    """
    analysis = dns_analyzer.analyze(result.ctx)
    result.dns_stats = analysis.stats
    result.dns_top = [{"name": name, "count": count} for name, count in analysis.stats.top_domains]
    with store.dataset("dns") as writer:
        writer.write_many(analysis.records)
    for warning in analysis.warnings:
        result.ctx.warn(warning)

    signatures = load_signatures(result.ctx.config.effective_signature_dir)
    findings = dns_detector.detect(
        analysis.records,
        config=result.ctx.config,
        signatures=signatures,
        tunnels=analysis.tunnels,
    )
    result.findings = list(result.findings) + findings
    if findings:
        with store.dataset("findings") as writer:
            writer.write_many(findings)

    store.metadata.options["dns"] = analysis.stats.to_dict()
    if analysis.tunnels:
        store.metadata.options["dns_tunnels"] = [
            candidate.to_dict() for candidate in analysis.tunnels
        ]
    store.metadata.options["findings_count"] = len(result.findings)
    log.info(
        "dns: %d message(s), %d query(ies), %d finding(s), %d tunnel candidate(s)",
        len(analysis.records),
        analysis.stats.queries,
        len(findings),
        len(analysis.tunnels),
    )


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
