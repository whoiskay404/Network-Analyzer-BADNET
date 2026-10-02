"""``badnet search`` - sweep reassembled streams for a pattern.

The target may be a capture file or an existing case directory.  Given a case,
BADNET reopens the capture recorded in ``metadata.json`` rather than re-analysing
it, so the search result and the earlier analysis always agree byte for byte.

Only TCP payload is searched, because reassembly is what makes an offset
meaningful.  A match is reported against the *reassembled* stream: if packets
were lost, the reconstruction has zero-filled holes and offsets after a hole are
approximate.  That limitation is stated in the output rather than hidden.

Regex safety: the standard library has no regex timeout, so ``--literal`` is the
recommended mode for hostile input.  A pattern with nested quantifiers is
refused outright, and every sweep is bounded by a wall-clock budget.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from badnet.analyzers import search as search_analyzer
from badnet.analyzers import tcp as tcp_analyzer
from badnet.analyzers.orchestrator import run_case
from badnet.analyzers.pipeline import PipelineContext
from badnet.errors import InputError
from badnet.reporting import terminal as term
from badnet.storage.casestore import CaseStore
from badnet.utils.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover
    from badnet.cli import RunContext

log = get_logger("commands.search")

#: Hard ceiling on stored hits so one generic pattern cannot fill the disk.
MAX_STORED_HITS = 10_000


def run(
    ctx: RunContext,
    target: Path,
    *,
    regex: str,
    literal: bool = False,
    ignore_case: bool = False,
    max_hits: int | None = None,
) -> object:
    """Search *target* (capture or case) for *regex* and record the hits."""
    pattern = search_analyzer.compile_search(regex, literal=literal, ignore_case=ignore_case)
    cap = max_hits if max_hits is not None else ctx.g.limit or MAX_STORED_HITS
    cap = min(cap, MAX_STORED_HITS)

    pipeline_ctx, store, streams, case_dir, capture_path = _prepare(ctx, target)
    budget_seconds = ctx.config.limits.regex_timeout_ms / 1000.0

    hits: list = []
    searched = 0
    regex_seconds = 0.0
    budget_exhausted = False
    for stream_id, direction, blob, source in search_analyzer.iter_stream_payloads(
        pipeline_ctx, streams
    ):
        if len(hits) >= cap:
            break
        started = time.monotonic()
        hits.extend(
            search_analyzer.search_blob(
                blob,
                pattern,
                stream_id=stream_id,
                direction=direction,
                source=source,
                max_hits=cap - len(hits),
            )
        )
        regex_seconds += time.monotonic() - started
        searched += 1
        if regex_seconds >= budget_seconds:
            # The budget measures regex execution only; reassembly is not charged.
            budget_exhausted = True
            break

    if hits:
        with store.dataset("search") as writer:
            writer.write_many(hits)

    if budget_exhausted:
        store.warn(
            "search stopped early: the regex budget "
            f"({ctx.config.limits.regex_timeout_ms} ms) elapsed; "
            "use --literal or a narrower pattern"
        )

    if hits or budget_exhausted:
        store.write_metadata()

    if ctx.g.wants_json:
        ctx.emit_json(
            {
                "case_dir": str(case_dir),
                "capture": str(capture_path),
                "regex": regex,
                "literal": literal,
                "ignore_case": ignore_case,
                "streams_searched": searched,
                "hits": len(hits),
                "capped": len(hits) >= cap,
                "budget_exhausted": budget_exhausted,
                "results": [h.to_dict() for h in hits],
            }
        )
        return hits

    console = ctx.console()
    ctx.banner(store.case.name)
    term.section(console, "Search", subtitle=f"{regex} in {capture_path.name}")
    if not hits:
        console.print(
            f"  [dim]no match in {searched} stream direction(s); "
            "try --literal, -i, or a simpler pattern[/dim]"
        )
        return hits

    display = ctx.g.limit or ctx.config.output.default_limit
    table = term.data_table(
        ["stream", "direction", "offset", "match", "context"],
        [
            [h.stream_id, h.direction, h.offset, _clip(h.match), _clip(h.context, 48)]
            for h in hits[:display]
        ],
    )
    console.print(table)
    if len(hits) > display:
        console.print(
            f"  [dim]{len(hits) - display} more hit(s); use --limit N to show them all[/dim]"
        )
    if budget_exhausted:
        console.print(
            "  [yellow]![/yellow] search stopped early: the regex budget elapsed; "
            "try --literal or a narrower pattern"
        )
    console.print("  [dim]hits recorded in: search.ndjson[/dim]")
    return hits


def _prepare(ctx: RunContext, target: Path):
    """Resolve *target* to a pipeline context, case store and stream list.

    A capture is analysed into a new case; an existing case is reopened and its
    recorded capture is analysed in place.  Both paths return the same tuple so
    the caller does not branch.
    """
    if (target / "metadata.json").is_file():
        store = CaseStore.open(target)
        capture_path = Path(store.case.input_path)
        if not capture_path.is_file():
            raise InputError(
                f"the capture recorded in this case is gone: {capture_path}",
                hint="re-run the analysis with the original capture, or pass the capture directly",
            )
        pipeline_ctx = PipelineContext(
            pcap_path=capture_path,
            store=store,
            config=ctx.config,
            max_packets=ctx.g.max_packets,
        )
        _connections, streams = tcp_analyzer.analyze(pipeline_ctx)
        return pipeline_ctx, store, streams, store.case.directory, capture_path

    with term.progress(ctx.console(), "analysing", total=None, enabled=not ctx.g.wants_json) as bar:
        result = run_case(
            target,
            config=ctx.config,
            case_name=ctx.g.case_name,
            output_dir=ctx.g.output_dir,
            force=ctx.g.force,
            max_packets=ctx.g.max_packets,
            progress=bar,
            on_case_created=ctx.log_callback(),
            phases=("info", "protocols", "connections", "streams"),
        )
        bar.update(description="done", msg="")
    from badnet.commands.analyze import write_summary

    write_summary(ctx, result)
    return result.ctx, result.case, result.streams, result.case_dir, Path(result.info.path)


def _clip(text: str, width: int = 40) -> str:
    """Collapse newlines and clip for a table cell."""
    flat = " ".join(text.split())
    return term.truncate(flat, width)
