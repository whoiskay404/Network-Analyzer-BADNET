"""``badnet analyze`` - run the pipeline and write a case directory."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from badnet.analyzers.orchestrator import run_case
from badnet.models.case import SUMMARY_FILE
from badnet.reporting import terminal as term
from badnet.utils.filesystem import human_size

if TYPE_CHECKING:  # pragma: no cover
    from badnet.cli import RunContext


def run(ctx: RunContext, capture: Path, *, phases: tuple[str, ...] | None = None) -> object:
    """Analyse *capture*, writing a full case directory, and print a summary."""
    with term.progress(ctx.console(), "analysing", total=None, enabled=not ctx.g.wants_json) as bar:
        result = run_case(
            capture,
            config=ctx.config,
            case_name=ctx.g.case_name,
            output_dir=ctx.g.output_dir,
            force=ctx.g.force,
            max_packets=ctx.g.max_packets,
            progress=bar,
            on_case_created=ctx.log_callback(),
            phases=phases or ("info", "protocols", "connections", "streams", "http", "dns"),
        )
        bar.update(description="done", msg="")

    case_dir = result.case_dir
    info = result.info

    # The case directory is written identically in every output mode: --json only
    # changes stdout, never what lands on disk.  Scripts may run either mode and
    # rely on summary.txt being there.
    write_summary(ctx, result)

    if ctx.g.wants_json:
        ctx.emit_json(
            {
                "case_dir": str(case_dir),
                "case": result.case.case.name,
                "info": info.to_dict(),
                "counts": {
                    "connections": len(result.connections),
                    "streams": len(result.streams),
                    "http_requests": getattr(result.http_stats, "requests", 0),
                    "dns_queries": getattr(result.dns_stats, "queries", 0),
                    "artifacts": len(result.artifacts),
                    "findings": len(result.findings),
                },
                "degraded": list(result.ctx.degraded),
                "warnings": list(result.ctx.warnings),
                "seconds": round(result.duration, 3),
            }
        )
        return result

    console = ctx.console()
    ctx.banner(result.case.case.name)
    term.section(console, "What happened")
    console.print(
        term.kv_table(
            [
                ("capture", info.path),
                ("size", human_size(info.file_size)),
                ("format", info.file_format_detail or info.capture_format),
                ("packets", info.packet_count if info.packet_count is not None else "-"),
                ("connections", len(result.connections)),
                ("streams", len(result.streams)),
                ("HTTP requests", getattr(result.http_stats, "requests", 0)),
                ("DNS queries", getattr(result.dns_stats, "queries", 0)),
                ("artifacts", len(result.artifacts)),
                ("findings", len(result.findings)),
                ("reader", result.ctx.reader),
                ("elapsed", f"{result.duration:.2f}s"),
            ]
        )
    )
    for note in result.ctx.degraded:
        console.print(f"  [yellow]degraded:[/yellow] {note}")
    for warning in result.ctx.warnings:
        console.print(f"  [yellow]![/yellow] {warning}")

    term.section(console, "Case output")
    console.print(f"  [cyan]{case_dir}[/cyan]")
    console.print(f"  summary: {SUMMARY_FILE}   metadata: metadata.json   data: *.ndjson")
    return result


def write_summary(ctx: RunContext, result) -> Path:
    """Write ``summary.txt`` into the case directory and record it in metadata.

    Shared with ``badnet auto`` so both commands produce the same case layout.
    """
    summary_path = result.case_dir / SUMMARY_FILE
    summary_path.write_text(_summary_text(ctx, result), encoding="utf-8")
    result.case.metadata.options["summary"] = SUMMARY_FILE
    result.case.write_metadata()
    return summary_path


def _summary_text(ctx: RunContext, result) -> str:
    """Plain-text summary written to ``summary.txt``."""
    info = result.info
    lines = [
        "BADNET analysis summary",
        f"case      : {result.case.case.name}",
        f"capture   : {info.path}",
        f"format    : {info.file_format_detail or info.capture_format}",
        f"size      : {human_size(info.file_size)}",
        f"packets   : {info.packet_count if info.packet_count is not None else '?'}",
        f"reader    : {result.ctx.reader}",
        "",
        f"connections : {len(result.connections)}",
        f"streams     : {len(result.streams)}",
        f"http        : {getattr(result.http_stats, 'requests', 0)} request(s), "
        f"{getattr(result.http_stats, 'responses', 0)} response(s)",
        f"dns         : {getattr(result.dns_stats, 'queries', 0)} query(ies), "
        f"{getattr(result.dns_stats, 'responses', 0)} response(s)",
        f"artifacts   : {len(result.artifacts)}",
        f"findings    : {len(result.findings)}",
    ]
    if result.ctx.warnings:
        lines.append("")
        lines.append("warnings:")
        lines.extend(f"  - {w}" for w in result.ctx.warnings)
    if result.ctx.degraded:
        lines.append("")
        lines.append("degraded features:")
        lines.extend(f"  - {d}" for d in result.ctx.degraded)
    return "\n".join(lines) + "\n"
