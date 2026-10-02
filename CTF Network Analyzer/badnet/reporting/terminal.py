"""Terminal output helpers built on Rich (with graceful plain-text fallback)."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from contextlib import contextmanager
from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

from badnet import TOOL_NAME, TOOL_TAGLINE, __version__
from badnet.models.finding import Severity

log = logging.getLogger("badnet.terminal")

#: Colour used for each severity.  Hues are deliberately muted: a report should
#: be readable, not alarming.
SEVERITY_STYLE = {
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

SEVERITY_ORDER = ("high", "medium", "low", "info")

BANNER = f"[bold cyan]{TOOL_NAME}[/bold cyan] [dim]v{__version__}[/dim] {TOOL_TAGLINE}"


def make_console(
    *, no_color: bool = False, quiet: bool = False, force_terminal: bool | None = None
) -> Console:
    """Create a Rich console honouring --no-color and TTY detection."""
    return Console(
        no_color=no_color,
        quiet=quiet,
        force_terminal=force_terminal,
        soft_wrap=False,
        highlight=False,
        emoji=False,
    )


def print_banner(console: Console, *, subtitle: str = "") -> None:
    """Print the boxed BADNET banner."""
    title = Text(TOOL_NAME, style="bold cyan")
    title.append(f"  v{__version__}", style="dim")
    title.append(f"  {TOOL_TAGLINE}", style="bold")
    console.print(Panel(title, subtitle=subtitle or None, border_style="cyan", expand=False))


def section(console: Console, title: str, *, subtitle: str = "") -> None:
    """Print a section heading."""
    style = "bold cyan"
    text = Text(title, style=style)
    if subtitle:
        text.append(f"  {subtitle}", style="dim")
    console.print()
    console.rule(text)


def kv_table(pairs: Sequence[tuple[str, Any]], *, key_style: str = "cyan") -> Table:
    """Two-column key/value table."""
    table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 2, 0, 0))
    table.add_column(style=key_style, no_wrap=True)
    table.add_column(style="default", overflow="fold")
    for key, value in pairs:
        table.add_row(str(key), str(value))
    return table


def data_table(
    columns: Sequence[str],
    rows: Iterable[Sequence[Any]],
    *,
    max_width: int = 60,
) -> Table:
    """Build a table with sane defaults (no box, ellipsis, right-aligned numbers)."""
    table = Table(
        show_header=True,
        header_style="bold",
        box=None,
        pad_edge=False,
        padding=(0, 1, 0, 0),
        expand=False,
    )
    for col in columns:
        table.add_column(col, overflow="ellipsis", max_width=max_width, no_wrap=False)
    for row in rows:
        table.add_row(*[_render_cell(c) for c in row])
    return table


def _render_cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def finding_line(severity: str, title: str, *, style: str | None = None) -> Text:
    """One-line rendering of a finding for lists."""
    style = style or SEVERITY_STYLE.get(severity, "default")
    label = {"high": "[!]", "medium": "[~]", "low": "[-]", "info": "[i]"}.get(severity, "[ ]")
    return Text.assemble((f"{label} ", style), (title, style))


def severity_style(severity: str | Severity) -> str:
    """Rich style for a severity value."""
    return SEVERITY_STYLE.get(str(severity), "default")


def ordered_severities(counts: dict[str, int]) -> list[str]:
    """Severities present, ordered high to low."""
    return [s for s in SEVERITY_ORDER if counts.get(s, 0) > 0]


@contextmanager
def progress(console: Console, description: str, total: int | None = None, *, enabled: bool = True):
    """Rich progress bar with ETA that degrades cleanly when disabled."""
    if not enabled:
        yield _NoProgress()
        return
    progress_obj = Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28),
        MofNCompleteColumn(),
        TextColumn("[dim]{task.fields[msg]}", justify="left"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
        disable=console.is_jupyter,
    )
    task_id = progress_obj.add_task(description, total=total, msg="")
    try:
        yield _RichProgressAdapter(progress_obj, task_id)
    finally:
        progress_obj.stop()


class _NoProgress:
    def advance(self, step: int = 1, total: int | None = None) -> None:
        """Discard progress."""

    def update(self, description: str | None = None, msg: str | None = None) -> None:
        """Discard updates."""

    def advance_to(self, value: int, msg: str | None = None) -> None:
        """Discard updates."""


class _RichProgressAdapter:
    def __init__(self, progress_obj: Progress, task_id: Any) -> None:
        self._p = progress_obj
        self._id = task_id

    def advance(self, step: int = 1, total: int | None = None) -> None:
        """Advance the bar by *step*."""
        self._p.advance(self._id, step)

    def update(self, description: str | None = None, msg: str | None = None) -> None:
        """Update the description and/or free-text message column."""
        self._p.update(self._id, description=description, msg=msg)

    def advance_to(self, value: int, msg: str | None = None) -> None:
        """Jump the bar to an absolute value."""
        self._p.update(self._id, completed=value, msg=msg)


def truncate(text: str, width: int) -> str:
    """Width-aware truncation for table cells."""
    from badnet.utils.textutil import truncate as _truncate

    return _truncate(text, width)


def print_lines(console: Console, lines: Iterable[str], *, style: str = "dim") -> None:
    """Print pre-rendered lines."""
    for line in lines:
        console.print(line, style=style)


def group(*renderables: Any) -> Group:
    """Group renderables for a single print (used by the summary block)."""
    return Group(*renderables)
