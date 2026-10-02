"""Shared analyzer context: reader selection, progress reporting, case I/O."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from badnet.config import Config
from badnet.integrations import system_tools, tshark
from badnet.storage.casestore import CaseStore
from badnet.utils.logging import get_logger

log = get_logger("pipeline")


class ProgressReporter(Protocol):
    """Minimal progress sink so the pipeline does not depend on Rich."""

    def advance(
        self, step: int = 1, total: int | None = None
    ) -> None:  # pragma: no cover - protocol
        """Report progress."""

    def task(self, description: str) -> object:  # pragma: no cover - protocol
        """Return a context manager for a named phase."""

    def log(self, message: str) -> None:  # pragma: no cover - protocol
        """Report a status line."""


class NullProgress:
    """Progress sink used with ``--json`` and in tests."""

    def advance(self, step: int = 1, total: int | None = None) -> None:
        """Discard progress."""

    def task(self, description: str):
        """Return a no-op context manager."""
        return _NullTask()

    def log(self, message: str) -> None:
        """Log instead of printing."""
        log.info(message)


class _NullTask:
    def __enter__(self) -> _NullTask:
        """Enter the no-op block."""
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        """Exit the no-op block."""
        return None


@dataclass(slots=True)
class PipelineContext:
    """Everything an analyzer needs: input, case storage, config and tools."""

    pcap_path: Path
    store: CaseStore
    config: Config
    reader: str = "tshark"
    """``tshark`` or ``scapy`` - recorded in every report."""
    max_packets: int | None = None
    keylog: str | Path | None = None
    progress: object = field(default_factory=NullProgress)
    tools: system_tools.ToolRegistry = field(default_factory=system_tools.detect_all)
    tshark_info: tshark.TsharkInfo | None = None
    degraded: list[str] = field(default_factory=list)
    """Human-readable list of features lost because a dependency is missing."""
    warnings: list[str] = field(default_factory=list)
    findings_sink: Callable[[], None] | None = None

    def __post_init__(self) -> None:
        """Pick the reader based on what is actually installed."""
        if self.tshark_info is None:
            self.tshark_info = tshark.detect(self.config.tshark_path, None)
        if not self.tshark_info.available:
            if system_tools._module_available("scapy"):
                self.reader = "scapy"
                self.note_degradation(
                    "tshark not found: using the Scapy fallback reader "
                    "(no certificate parsing, reduced protocol dissection, slower)"
                )
            else:
                from badnet.errors import MissingDependencyError

                raise MissingDependencyError(
                    "no packet reader available",
                    hint="install tshark (sudo apt install tshark) or scapy (pip install scapy)",
                )
        else:
            self.reader = "tshark"

    def note_degradation(self, message: str) -> None:
        """Record (and log) a capability lost in this run."""
        if message not in self.degraded:
            self.degraded.append(message)
        log.warning(message)

    def warn(self, message: str) -> None:
        """Record a warning on the case and in the pipeline log."""
        if message not in self.warnings:
            self.warnings.append(message)
            self.store.warn(message)

    @property
    def limits(self):
        """Shortcut to ``config.limits``."""
        return self.config.limits

    def has_tshark(self) -> bool:
        """True when the tshark fast path is usable."""
        return self.reader == "tshark" and bool(self.tshark_info and self.tshark_info.available)

    def packet_rows(self, *, fields=None, display_filter=None):
        """Yield raw tshark field rows (requires tshark)."""
        if not self.has_tshark():
            raise RuntimeError("packet_rows() requires tshark")
        assert self.tshark_info is not None
        return tshark.iter_field_rows(
            self.tshark_info,
            self.pcap_path,
            fields=fields or tshark.FIELDS,
            display_filter=display_filter,
            max_packets=self.max_packets,
            keylog=self.keylog,
        )

    def iter_packets(self):
        """Yield :class:`NormalizedPacket` rows from whichever reader is active."""
        if self.has_tshark():
            assert self.tshark_info is not None
            yield from tshark.iter_packets(
                self.tshark_info,
                self.pcap_path,
                max_packets=self.max_packets,
                keylog=self.keylog,
            )
        else:
            from badnet.parsing import scapy_reader

            yield from scapy_reader.iter_packets(self.pcap_path, max_packets=self.max_packets)


def validate_input(path: str | Path) -> tuple[Path, str, str]:
    """Validate a capture path.

    Returns ``(resolved_path, format_kind, format_detail)``.

    Raises
    ------
    InputError
        When the path is missing, a directory, empty, unreadable, or not a
        capture file BADNET can read.
    """
    from badnet.errors import InputError
    from badnet.parsing import pcap_format

    p = Path(path).expanduser()
    if not p.exists():
        raise InputError(f"input file not found: {p}")
    if p.is_dir():
        raise InputError(f"expected a capture file but got a directory: {p}")
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise InputError(f"cannot stat {p}: {exc}") from exc
    if size == 0:
        raise InputError(f"capture file is empty: {p}")
    try:
        with p.open("rb") as fh:
            first = fh.read(1)
    except PermissionError as exc:
        raise InputError(f"permission denied reading {p}") from exc
    except OSError as exc:
        raise InputError(f"cannot read {p}: {exc}") from exc
    if not first:
        raise InputError(f"capture file is empty: {p}")

    fmt = pcap_format.sniff(p)
    if not fmt.supported:
        raise InputError(
            f"{p.name} does not look like a capture file ({fmt.detail})",
            hint="BADNET reads libpcap (pcap) and pcapng files",
        )
    return p, fmt.kind, fmt.detail
