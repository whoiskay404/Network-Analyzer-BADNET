"""``badnet report`` - render a self-contained offline HTML case report.

The target may be a capture file or an existing case directory.  Given a capture
the pipeline runs first; given a case the report is rebuilt from what is already
on disk, so a report can be regenerated no matter how old the case is.

Output is ``report.html`` (self-contained, no network requests) plus
``report.json`` (the same data, machine-readable) at the root of the case.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from badnet.analyzers.orchestrator import run_case
from badnet.commands.auto import rank
from badnet.models.case import REPORT_HTML, REPORT_JSON, utc_now_iso
from badnet.reporting import terminal as term
from badnet.reporting.html import ReportData, render
from badnet.storage.casestore import CaseStore
from badnet.utils.filesystem import human_size, safe_join
from badnet.utils.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover
    from badnet.cli import RunContext

log = get_logger("commands.report")


def run(ctx: RunContext, target: Path, *, top: int | None = None) -> Path:
    """Render ``report.html`` into the case and return its path."""
    top_n = top or ctx.g.limit or ctx.config.output.top_n

    if (target / "metadata.json").is_file():
        store = CaseStore.open(target)
        data = _from_case(ctx, store, top_n=top_n)
        from badnet.models.case import SUMMARY_FILE

        if not (store.case.directory / SUMMARY_FILE).is_file():
            store.warn("report rendered from a case that has no summary.txt")
    else:
        with term.progress(
            ctx.console(), "analysing", total=None, enabled=not ctx.g.wants_json
        ) as bar:
            result = run_case(
                target,
                config=ctx.config,
                case_name=ctx.g.case_name,
                output_dir=ctx.g.output_dir,
                force=ctx.g.force,
                max_packets=ctx.g.max_packets,
                progress=bar,
                on_case_created=ctx.log_callback(),
            )
            bar.update(description="done", msg="")
        from badnet.commands.analyze import write_summary

        write_summary(ctx, result)
        store = result.case
        data = _from_result(ctx, result, top_n=top_n)

    case_dir = store.case.directory
    html_path = safe_join(case_dir, REPORT_HTML)
    json_path = safe_join(case_dir, REPORT_JSON)
    html_path.write_text(render(data), encoding="utf-8")
    json_path.write_text(_json_text(data), encoding="utf-8")

    store.metadata.options["report"] = REPORT_HTML
    store.metadata.options["report_json"] = REPORT_JSON
    store.write_metadata()

    if ctx.g.wants_json:
        ctx.emit_json(
            {
                "case_dir": str(case_dir),
                "report": str(html_path),
                "report_json": str(json_path),
                "bytes": html_path.stat().st_size,
                "findings": len(data.findings),
                "streams": len(data.streams),
                "artifacts": len(data.artifacts),
            }
        )
        return html_path

    ctx.banner(store.case.name)
    term.section(ctx.console(), "Report")
    ctx.console().print(f"  [cyan]{html_path}[/cyan]")
    ctx.console().print(
        f"  [dim]also wrote[/dim] {json_path.name}  [dim]({human_size(html_path.stat().st_size)})[/dim]"
    )
    ctx.console().print(
        "  [dim]self-contained: no scripts, styles or images are loaded from the network[/dim]"
    )
    return html_path


# ------------------------------------------------------------------ builders


def _from_result(ctx: RunContext, result, *, top_n: int) -> ReportData:
    info = result.info
    facts = [
        ("packets", info.packet_count if info.packet_count is not None else "unknown"),
        ("duration", f"{info.duration:.3f} s" if info.duration else "unknown"),
        ("capture size", human_size(info.file_size)),
        ("format", info.file_format_detail or info.capture_format),
        ("connections", len(result.connections)),
        ("TCP streams", len(result.streams)),
        ("files recovered", len(result.artifacts)),
        ("findings", len(result.findings)),
        ("reader", result.ctx.reader),
        ("analysis time", f"{result.duration:.2f} s"),
    ]
    search_hits = list(result.case.read("search"))
    return ReportData(
        case_name=result.case.case.name,
        input_path=info.path,
        input_sha256=result.case.case.input_sha256,
        input_size=info.file_size,
        input_format=info.file_format_detail or info.capture_format,
        status=result.case.case.status,
        created=result.case.case.created,
        generated=utc_now_iso(),
        degraded=list(result.ctx.degraded),
        warnings=list(result.ctx.warnings),
        facts=facts,
        findings=[f.to_dict() for f in rank(result.findings)],
        protocols=[
            {"name": p.name, "packets": p.packets, "bytes": p.bytes} for p in info.protocols
        ],
        talkers=[
            {"name": e.value, "packets": e.packets, "bytes": e.bytes}
            for e in (info.top_sources or [])
        ],
        streams=[s.to_dict() for s in result.streams],
        artifacts=[a.to_dict() for a in result.artifacts],
        search_hits=search_hits,
        top_n=top_n,
    )


def _from_case(ctx: RunContext, store: CaseStore, *, top_n: int) -> ReportData:
    case = store.case
    options = store.metadata.options or {}
    protocol_counts = options.get("protocol_counts") or {}

    streams = list(store.read("streams"))
    findings = list(store.read("findings"))
    artifacts = list(store.read("files"))
    search_hits = list(store.read("search"))
    connections = list(store.read("connections"))

    facts = [
        ("capture size", human_size(case.input_size)),
        ("format", case.input_format or "unknown"),
        ("connections", len(connections)),
        ("TCP streams", len(streams)),
        ("files recovered", len(artifacts)),
        ("findings", len(findings)),
        ("analysis time", f"{options.get('pipeline_seconds', '-')} s"),
    ]
    if options.get("max_packets"):
        facts.append(("packet cap", options["max_packets"]))

    protocols = [
        {"name": name, "packets": count, "bytes": None}
        for name, count in sorted(protocol_counts.items(), key=lambda kv: -int(kv[1]))
    ]

    return ReportData(
        case_name=case.name,
        input_path=case.input_path,
        input_sha256=case.input_sha256,
        input_size=case.input_size,
        input_format=case.input_format,
        status=case.status,
        created=case.created,
        generated=utc_now_iso(),
        degraded=list(options.get("degraded") or []),
        warnings=list(case.warnings),
        facts=facts,
        findings=findings,
        protocols=protocols,
        streams=streams,
        artifacts=artifacts,
        search_hits=search_hits,
        top_n=top_n,
    )


def _json_text(data: ReportData) -> str:
    """Serialise the report payload for ``report.json``.

    Deliberately a plain structure rather than a dataclass dump: ``report.json``
    is a stable, documented shape that survives changes to internal models.
    """
    import json

    payload = {
        "case": data.case_name,
        "generated": data.generated,
        "status": data.status,
        "input": {
            "path": data.input_path,
            "sha256": data.input_sha256,
            "size": data.input_size,
            "format": data.input_format,
        },
        "facts": dict(data.facts),
        "warnings": data.warnings,
        "degraded": data.degraded,
        "findings": data.findings,
        "protocols": data.protocols,
        "streams": data.streams,
        "artifacts": data.artifacts,
        "search_hits": data.search_hits,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
