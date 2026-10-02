"""``badnet auto`` - summary first, then ranked CTF findings and follow-ups.

The HTTP and DNS detector phases are wired; correlation and artifact extraction
are still to come.  This module is the presentation contract: a summary,
a ranked findings table where every row explains itself, and concrete next
commands.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from badnet.analyzers.orchestrator import run_case
from badnet.models.finding import Finding
from badnet.reporting import terminal as term
from badnet.utils.filesystem import human_size

if TYPE_CHECKING:  # pragma: no cover
    from badnet.cli import RunContext

#: Ranked CTF categories: earlier = more valuable to an investigator.
CTF_ORDER = (
    "flag",
    "credential",
    "secret",
    "encoding",
    "artifact",
    "endpoint",
    "dns",
    "http",
    "tls",
    "port",
    "anomaly",
    "metadata",
    "data",
)


def rank(findings: list[Finding]) -> list[Finding]:
    """Order findings by CTF value, then severity, then confidence."""
    order = {name: i for i, name in enumerate(CTF_ORDER)}
    return sorted(
        findings,
        key=lambda f: (
            order.get(str(f.category), 99),
            -f.severity.rank,
            -f.confidence.rank,
            str(f.title),
        ),
    )


def run(ctx: RunContext, capture: Path, *, ctf: bool = True) -> object:
    """Run the full pipeline and present the investigation."""
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
        )
        bar.update(description="done", msg="")

    findings = rank(result.findings) if ctf else result.findings
    summary = _narrative(ctx, result)

    # `auto` is a superset of `analyze`, so the case layout must match: write the
    # same summary.txt in every output mode, otherwise the follow-ups below would
    # point at a file that was never created.
    from badnet.commands.analyze import write_summary

    write_summary(ctx, result)

    if ctx.g.wants_json:
        ctx.emit_json(
            {
                "case_dir": str(result.case_dir),
                "summary": summary,
                "findings": [f.to_dict() for f in findings],
                "counts": {
                    "connections": len(result.connections),
                    "streams": len(result.streams),
                    "dns_queries": getattr(result.dns_stats, "queries", 0),
                    "artifacts": len(result.artifacts),
                    "findings": len(findings),
                },
                "warnings": list(result.ctx.warnings),
                "degraded": list(result.ctx.degraded),
            }
        )
        return result

    console = ctx.console()
    ctx.banner(result.case.case.name)
    _print_summary(console, ctx, result, summary)
    _print_findings(console, ctx, findings)
    _print_followups(console, ctx, result, findings)
    return result


def _narrative(ctx: RunContext, result) -> dict[str, object]:
    """The short 'what happened' summary."""
    info = result.info
    return {
        "hosts": len({c.a_ip for c in result.connections} | {c.b_ip for c in result.connections}),
        "packets": info.packet_count,
        "capture_format": info.file_format_detail or info.capture_format,
        "capture_size": human_size(info.file_size),
        "duration": info.duration,
        "connections": len(result.connections),
        "streams": len(result.streams),
        "http_requests": getattr(result.http_stats, "requests", 0),
        "dns_queries": getattr(result.dns_stats, "queries", 0),
        "files": len(result.artifacts),
        "hashes": len([a for a in result.artifacts if a.sha256]),
        "reader": result.ctx.reader,
    }


def _print_summary(console, ctx: RunContext, result, summary: dict) -> None:
    term.section(console, "What happened")
    duration = summary.get("duration")
    console.print(
        term.kv_table(
            [
                ("capture", f"{summary['capture_size']} {summary['capture_format']}"),
                ("packets", summary.get("packets")),
                ("duration", f"{duration:.2f} s" if duration else "-"),
                ("hosts seen", summary.get("hosts")),
                ("connections", summary.get("connections")),
                ("TCP streams", summary.get("streams")),
                ("HTTP requests", summary.get("http_requests")),
                ("DNS queries", summary.get("dns_queries")),
                ("files recovered", summary.get("files")),
                ("hashed artifacts", summary.get("hashes")),
                ("reader", summary.get("reader")),
            ]
        )
    )
    for note in result.ctx.degraded:
        console.print(f"  [yellow]degraded:[/yellow] {note}")
    for warning in result.ctx.warnings:
        console.print(f"  [yellow]![/yellow] {warning}")


def _print_findings(console, ctx: RunContext, findings: list[Finding]) -> None:
    term.section(console, "CTF FINDINGS" if findings else "Findings", subtitle=f"({len(findings)})")
    if not findings:
        console.print(
            "  [dim]No indicator matched the configured signatures in this capture.[/dim]"
        )
        return
    from rich.table import Table
    from rich.text import Text

    verbose = ctx.verbose_secrets()
    limit = ctx.g.limit or ctx.config.output.max_findings_shown
    table = Table(box=None, pad_edge=False, header_style="bold", show_lines=False)
    table.add_column("", no_wrap=True, width=3)
    table.add_column("category", style="cyan", no_wrap=True)
    table.add_column("title", overflow="fold", max_width=52)
    table.add_column("sev", no_wrap=True)
    table.add_column("evidence", overflow="fold", max_width=46)
    table.add_column("source", overflow="ellipsis", max_width=20)

    for f in findings[:limit]:
        marker = {"high": "[!]", "medium": "[~]", "low": "[-]", "info": "[i]"}.get(
            str(f.severity), " "
        )
        evidence = f.evidence if verbose else _redact_evidence(f.evidence)
        table.add_row(Text(marker), str(f.category), f.title, str(f.severity), evidence, f.source)
    console.print(table)
    if len(findings) > limit:
        console.print(
            f"  [dim]{len(findings) - limit} more finding(s); use --limit N to show them all[/dim]"
        )
    # Explain each finding in full below the table (the "why").
    term.section(console, "Why each finding fired", subtitle="(explanations + evidence)")
    from badnet.utils.redact import mask

    for f in findings[: min(limit, 25)]:
        console.print(
            f"  [{term.severity_style(str(f.severity))}]{f.title}[/]"
            f"  [dim]({f.category}/{f.severity}, confidence {f.confidence}, detector {f.detector or 'n/a'})[/dim]"
        )
        console.print(f"    [dim]why:[/dim] {f.explanation}")
        evidence = f.evidence if verbose else _redact_evidence(f.evidence)
        if evidence:
            console.print(f"    [dim]evidence:[/dim] {evidence}")
        if f.source:
            console.print(f"    [dim]source:[/dim] {f.source}")
        if f.related:
            console.print(f"    [dim]related:[/dim] {', '.join(f.related)}")
        console.print()
        _ = mask


def _redact_evidence(text: str) -> str:
    """Mask long opaque tokens in evidence for default (non-verbose) output."""
    if not text:
        return text
    from badnet.utils.redact import mask

    words = text.split()
    out = []
    for w in words:
        core = w.strip("'\"(),;:")
        if len(core) >= 24 and core.replace("-", "").replace("_", "").isalnum():
            out.append(w.replace(core, mask(core)))
        else:
            out.append(w)
    return " ".join(out)


def _available_commands() -> set[str]:
    """Names of commands the CLI actually registers, for honest suggestions."""
    from badnet.cli import app

    return {c.name for c in app.registered_commands if c.name}


def _print_followups(console, ctx: RunContext, result, findings: list[Finding]) -> None:
    term.section(console, "Suggested manual follow-ups")
    case_dir = result.case_dir
    available = _available_commands()
    streams_file = case_dir / "streams" / "streams.ndjson"
    lines: list[str] = []

    # Highest-value streams to inspect by hand, plus the raw dataset row so a
    # reader can pivot without re-running the pipeline.
    if streams_file.is_file():
        for stream in result.streams[:3]:
            detail = (
                f"# {stream.app_protocol or stream.proto} "
                f"{stream.client_label} -> {stream.server_label}, {human_size(stream.bytes)}"
            )
            lines.append(
                f"grep '\"stream_id\": {stream.stream_id}' {streams_file} "
                f"| python3 -m json.tool   {detail}"
            )

    connections_file = case_dir / "connections.ndjson"
    if connections_file.is_file():
        lines.append(
            f'grep -E \'"service": "(http|https|ftp|ssh|smb)"\' {connections_file}   '
            "# notable services"
        )
        lines.append(f'grep \'"proto": "UDP"\' {connections_file}   # non-TCP conversations')

    http_file = case_dir / "http" / "http.ndjson"
    if http_file.is_file():
        lines.append(f"less {http_file}   # parsed HTTP exchanges (headers + bodies)")

    dns_file = case_dir / "dns" / "dns.ndjson"
    if dns_file.is_file():
        lines.append(f"less {dns_file}   # parsed DNS messages (queries, answers, TXT)")

    if any(f.category == "flag" for f in findings):
        lines.append(f"grep -ri 'flag' {case_dir}   # confirm recovered flags")
    if any(f.category == "dns" for f in findings) and connections_file.is_file():
        lines.append(
            f'grep \'"proto": "UDP"\' {connections_file} | grep \'"service": "dns"\'   '
            "# DNS traffic"
        )
    if result.artifacts and (case_dir / "files").is_dir():
        lines.append(f"ls -la {case_dir / 'files'}   # recovered artifacts")

    # Only suggest commands that exist right now.
    if "search" in available:
        lines.append(
            f"badnet search {case_dir} --regex 'flag\\{{|password|token'   # sweep everything"
        )
    if "stream" in available:
        lines.append(f"badnet stream {result.case.case.input_path}   # interactive stream view")

    report = case_dir / "report.html"
    if report.is_file():
        lines.append(f"less {report}   # full offline report")
    summary_file = case_dir / "summary.txt"
    if summary_file.is_file():
        lines.append(f"less {summary_file}   # case summary")
    if (case_dir / "metadata.json").is_file():
        lines.append(f"less {case_dir / 'metadata.json'}   # capture facts and per-run stats")

    if not lines:
        console.print("  [dim]no follow-ups available for this capture[/dim]")
        return
    for line in lines:
        console.print(f"  [dim]$[/dim] {line}")
    missing = sorted({"stream", "search"} - available)
    if missing:
        quoted = " and ".join(f"badnet {name}" for name in missing)
        console.print(f"  [dim]note: {quoted} not implemented yet[/dim]")
