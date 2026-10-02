"""``badnet stream`` - list TCP streams and dump one for inspection.

Dumping a stream is a focused alternative to scrolling a packet list: it writes
the reassembled bytes of each direction to the case, optionally carves embedded
files out of them by magic bytes, and prints a bounded preview.

Everything the capture supplies is untrusted.  Preview text is decoded with
``errors="replace"`` and printed through Rich, which escapes control characters;
nothing is ever executed or evaluated.  The raw dump is written under
``streams/`` and carved files under ``files/``, both inside the case directory,
so a hostile capture cannot influence the path.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from badnet.analyzers import extract
from badnet.analyzers.orchestrator import run_case
from badnet.analyzers.tcp import reassemble_stream
from badnet.errors import UsageError
from badnet.models.artifact import Artifact
from badnet.reporting import terminal as term
from badnet.utils.filesystem import human_size, safe_join
from badnet.utils.logging import get_logger
from badnet.utils.textutil import safe_text_preview

if TYPE_CHECKING:  # pragma: no cover
    from badnet.cli import RunContext

log = get_logger("commands.stream")

_DIRECTIONS = {
    "c2s": "client_to_server",
    "s2c": "server_to_client",
    "both": "both",
}


def run(
    ctx: RunContext,
    capture: Path,
    *,
    stream_id: int | None = None,
    direction: str = "both",
    carve: bool = False,
    hexdump: bool = False,
    limit: int | None = None,
) -> object:
    """List streams, or dump and preview one stream by id."""
    if direction not in _DIRECTIONS:
        raise UsageError(
            f"unknown --direction {direction!r}",
            hint="choose one of: c2s, s2c, both",
        )

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
            phases=("info", "protocols", "connections", "streams"),
        )
        bar.update(description="done", msg="")

    # Keep the case layout identical to `analyze`; a follow-up may read summary.txt.
    from badnet.commands.analyze import write_summary

    write_summary(ctx, result)

    if stream_id is None:
        return _list(ctx, result, limit=limit)
    return _dump(ctx, result, stream_id, direction=direction, carve=carve, hexdump=hexdump)


# ------------------------------------------------------------------ listing


def _list(ctx: RunContext, result, *, limit: int | None) -> object:
    streams = result.streams
    shown = limit if limit is not None else ctx.config.output.default_limit
    ordered = sorted(
        streams,
        key=lambda s: (not s.interesting_port, -s.bytes, s.stream_id),
    )
    rows = ordered[:shown]

    if ctx.g.wants_json:
        ctx.emit_json(
            {
                "case_dir": str(result.case_dir),
                "total": len(streams),
                "shown": len(rows),
                "streams": [s.to_dict() for s in rows],
            }
        )
        return result

    console = ctx.console()
    ctx.banner(result.case.case.name)
    term.section(console, "TCP streams", subtitle=f"({len(streams)} total)")
    if not streams:
        console.print("  [dim]no reassemblable TCP streams in this capture[/dim]")
        return result

    table = term.data_table(
        ["id", "proto", "endpoints", "application", "packets", "bytes"],
        [
            [
                s.stream_id,
                s.proto,
                f"{s.client_label} -> {s.server_label}",
                s.app_protocol or "-",
                s.packets,
                human_size(s.bytes),
            ]
            for s in rows
        ],
    )
    console.print(table)
    if len(streams) > len(rows):
        console.print(
            f"  [dim]{len(streams) - len(rows)} more stream(s); "
            "use --limit N to list them, then --id N to inspect one[/dim]"
        )
    console.print("  [dim]inspect one with: badnet stream <capture> --id N --carve[/dim]")
    return result


# --------------------------------------------------------------------- dump


def _dump(
    ctx: RunContext,
    result,
    stream_id: int,
    *,
    direction: str,
    carve: bool,
    hexdump: bool,
) -> object:
    stream = next((s for s in result.streams if s.stream_id == stream_id), None)
    if stream is None:
        available = ", ".join(str(s.stream_id) for s in result.streams[:10]) or "none"
        raise UsageError(
            f"stream {stream_id} is not present in this capture",
            hint=f"run 'badnet stream {result.info.path}' to list streams; first ids: {available}",
        )

    client = (stream.client_ip, stream.client_port, stream.server_ip, stream.server_port)
    server = (stream.server_ip, stream.server_port, stream.client_ip, stream.client_port)
    data = reassemble_stream(ctx=result.ctx, stream_id=stream_id, client=client, server=server)

    max_preview = ctx.config.limits.max_preview_bytes
    case_dir = result.case_dir
    payloads: dict[str, bytes] = {
        "client_to_server": data.client_to_server,
        "server_to_client": data.server_to_client,
    }

    requested = list(payloads) if direction == "both" else [_DIRECTIONS[direction]]

    dumped: list[dict] = []
    for name in requested:
        blob = payloads[name]
        if not blob:
            continue
        target = safe_join(case_dir / "streams", f"stream_{stream_id}_{name}.bin")
        try:
            target.write_bytes(blob)
        except OSError as exc:
            log.warning("cannot write stream dump %s: %s", target, exc)
            continue

        entry: dict = {
            "direction": name,
            "path": target.name,
            "bytes": len(blob),
            "sha256": _sha256(blob),
        }

        if carve:
            missing = data.client if name == "client_to_server" else data.server
            artifacts = extract.carve(
                blob,
                stream_id=stream_id,
                direction=name,
                max_object_bytes=ctx.config.limits.max_artifact_size,
                missing_bytes=missing.gaps,
            )
            stored = extract.store(
                artifacts,
                blob,
                stream_id=stream_id,
                direction=name,
                files_dir=case_dir / "files",
                max_object_bytes=ctx.config.limits.max_artifact_size,
            )
            _record_artifacts(result, stored)
            entry["carved"] = [a.to_dict() for a in stored]

        if hexdump:
            entry["hexdump"] = _hexdump(blob, max_preview)
        else:
            entry["preview"] = safe_text_preview(blob, max_len=max_preview)
        dumped.append(entry)

    if ctx.g.wants_json:
        ctx.emit_json(
            {
                "case_dir": str(case_dir),
                "stream": stream.to_dict(),
                "dumped": dumped,
            }
        )
        return result

    console = ctx.console()
    ctx.banner(result.case.case.name)
    term.section(console, f"Stream {stream_id}", subtitle=stream.app_protocol or stream.proto)
    console.print(
        term.kv_table(
            [
                ("endpoints", f"{stream.client_label} -> {stream.server_label}"),
                ("packets", stream.packets),
                ("bytes", human_size(stream.bytes)),
                ("flags", ", ".join(stream.tcp_flags) or "-"),
            ]
        )
    )
    if not dumped:
        console.print("  [yellow]no reassembled payload for the requested direction[/yellow]")
        return result

    for entry in dumped:
        term.section(console, entry["direction"], subtitle=human_size(entry["bytes"]))
        console.print(
            f"  [dim]saved:[/dim] streams/{entry['path']}  [dim]sha256:[/dim] {entry['sha256']}"
        )
        if entry.get("hexdump"):
            term.print_lines(console, entry["hexdump"].splitlines(), style="")
        elif entry.get("preview"):
            console.print(term.group(entry["preview"]))
        if entry.get("carved"):
            term.section(console, "carved files")
            for art in entry["carved"]:
                console.print(
                    f"  [cyan]{art['name']}[/cyan]  {art['detected_type']}  "
                    f"{human_size(art['size'])}  sha256 {art['sha256']}"
                )
    return result


# ------------------------------------------------------------------ helpers


def _record_artifacts(result, artifacts: list[Artifact]) -> None:
    """Append carved artifacts to the case ``files`` dataset and in-memory result."""
    if not artifacts:
        return
    with result.case.dataset("files") as writer:
        writer.write_many(artifacts)
    result.artifacts.extend(artifacts)
    result.case.write_metadata()


def _sha256(data: bytes) -> str:
    from badnet.utils.hashing import hash_bytes

    return hash_bytes(data).sha256


def _hexdump(data: bytes, max_bytes: int, *, width: int = 16) -> str:
    """Classic ``offset  hex  ascii`` dump, bounded to *max_bytes*."""
    lines: list[str] = []
    end = min(len(data), max_bytes)
    for offset in range(0, end, width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    if len(data) > end:
        lines.append(f"... {len(data) - end} more byte(s) not shown (preview cap)")
    return "\n".join(lines)
