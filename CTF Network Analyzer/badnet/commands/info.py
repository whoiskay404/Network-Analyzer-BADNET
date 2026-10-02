"""``badnet info`` - capture facts without writing a case directory.

Counts and timing come from capinfos/tshark.  Only the endpoint tallies that
capinfos does not provide are computed by BADNET, and the command tells you which
tool produced each number.
"""

from __future__ import annotations

from datetime import UTC
from pathlib import Path
from typing import TYPE_CHECKING

from badnet.analyzers import pcap as pcap_analyzer
from badnet.analyzers import protocols as protocols_analyzer
from badnet.analyzers.pipeline import NullProgress, PipelineContext, validate_input
from badnet.utils.filesystem import human_size
from badnet.utils.textutil import safe_text_preview

if TYPE_CHECKING:  # pragma: no cover
    from badnet.cli import RunContext


def run(ctx: RunContext, capture: Path, *, fast: bool = False) -> None:
    """Print capture statistics for *capture*."""
    path, _fmt_kind, fmt_detail = validate_input(capture)

    # A read-only in-memory pipeline: no case directory is created.
    import tempfile

    from badnet.models.case import CaseInfo, CaseMetadata, ToolVersions
    from badnet.storage.casestore import CaseStore

    with tempfile.TemporaryDirectory(prefix="badnet-info-") as tmp:
        case = CaseInfo(
            name="info", directory=Path(tmp), input_path=str(path), input_format=fmt_detail
        )
        store = CaseStore(
            case,
            CaseMetadata(
                case=case, tools=ToolVersions(), command_line=[], config_used={}, options={}
            ),
        )
        pipeline = PipelineContext(
            pcap_path=path,
            store=store,
            config=ctx.config,
            max_packets=ctx.g.max_packets,
            progress=NullProgress(),
        )
        info = pcap_analyzer.analyze(pipeline, deep=not fast)
        summary = protocols_analyzer.analyze(pipeline)

    if ctx.g.wants_json:
        ctx.emit_json(
            {
                "info": info.to_dict(),
                "protocols": summary.present,
                "malformed_packets": summary.malformed,
                "reader": pipeline.reader,
                "degraded": list(pipeline.degraded),
            }
        )
        return

    console = ctx.console()
    from badnet.reporting import terminal as term

    ctx.banner(Path(path).name)
    term.section(console, "Capture")
    pairs = [
        ("file", str(path)),
        ("size", human_size(info.file_size)),
        ("format", info.file_format_detail or info.capture_format),
        ("link type", info.link_type or "-"),
        ("snaplen", info.snaplen if info.snaplen else "-"),
        ("packets", info.packet_count if info.packet_count is not None else "-"),
        ("first packet", _ts(info.first_ts)),
        ("last packet", _ts(info.last_ts)),
        ("duration", f"{info.duration:.3f} s" if info.duration is not None else "-"),
        ("avg rate", f"{info.avg_rate:.1f} pkt/s" if info.avg_rate else "-"),
        ("bit rate", f"{info.data_bit_rate / 1000:.1f} kbps" if info.data_bit_rate else "-"),
        ("malformed", f"{info.malformed_packets} packet(s)"),
        ("reader", pipeline.reader),
        ("computed by", ", ".join(info.readers)),
    ]
    if ctx.g.max_packets:
        pairs.append(("max packets", ctx.g.max_packets))
    console.print(term.kv_table(pairs))
    for warning in info.warnings:
        console.print(f"  [yellow]![/yellow] {warning}")
    for note in pipeline.degraded:
        console.print(f"  [yellow]degraded:[/yellow] {note}")

    term.section(console, "Protocols", subtitle="(only protocols present)")
    rows = [(name, count) for name, count in summary.present.items()]
    if rows:
        console.print(term.data_table(["protocol", "packets"], rows))
    else:
        console.print("  [dim]no protocol layers decoded[/dim]")

    term.section(console, "Top talkers")
    console.print(_endpoint_block("sources", info.top_sources))
    console.print(_endpoint_block("destinations", info.top_destinations))
    console.print(_endpoint_block("ports", info.top_ports))


def _endpoint_block(title: str, endpoints) -> object:
    from rich.table import Table

    table = Table(title=title, box=None, pad_edge=False, header_style="bold", title_justify="left")
    table.add_column("value", style="cyan", overflow="ellipsis")
    table.add_column("packets", justify="right")
    if not endpoints:
        table.add_row("-", "0")
    for ep in endpoints:
        table.add_row(ep.value, str(ep.count))
    return table


def _ts(value: float | None) -> str:
    if value is None:
        return "-"
    from datetime import datetime

    return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%d %H:%M:%S.%f UTC")


def describe_bytes(data: bytes, *, limit: int = 512) -> str:
    """Safe one-line preview of bytes (used by stream/extract views)."""
    return safe_text_preview(data, max_len=limit)
