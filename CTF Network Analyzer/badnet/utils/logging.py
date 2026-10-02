"""Logging setup: quiet by default, verbose only when asked for."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
LOG_DATEFMT = "%H:%M:%S"

_configured = False
#: Whether ``--debug`` was passed; mirrors the flag rather than the logger level.
_debug_enabled = False


def setup_logging(
    *,
    debug: bool = False,
    verbose: bool = False,
    log_file: Path | None = None,
    quiet: bool = False,
) -> Path | None:
    """Configure the ``badnet`` logger tree.

    * ``debug``    -> DEBUG to stderr *and* the case log file, plus tracebacks.
    * ``verbose``  -> INFO to stderr.
    * ``quiet``    -> WARNING and above only.
    * ``log_file`` -> always DEBUG-level when given (evidence trail).

    Returns the log file path when one was opened, else ``None``.
    """
    global _configured, _debug_enabled

    _debug_enabled = bool(debug)
    level = logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
    if quiet:
        level = logging.WARNING

    root = logging.getLogger("badnet")
    root.setLevel(logging.DEBUG)
    for handler in list(root.handlers):
        root.removeHandler(handler)
        try:
            handler.close()
        except Exception as exc:  # pragma: no cover - defensive
            print(f"badnet: could not close log handler: {exc}", file=sys.stderr)

    fmt = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT)

    if not quiet:
        stream = logging.StreamHandler(stream=sys.stderr)
        stream.setLevel(level)
        stream.setFormatter(fmt)
        root.addHandler(stream)

    opened: Path | None = None
    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            fileh = logging.FileHandler(log_file, encoding="utf-8")
            fileh.setLevel(logging.DEBUG)
            fileh.setFormatter(fmt)
            root.addHandler(fileh)
            opened = log_file
        except OSError as exc:
            # A read-only output directory must not abort the run; report and continue.
            print(f"badnet: cannot write log file {log_file}: {exc}", file=sys.stderr)

    # Third-party chatter is noise unless debugging.
    if not debug:
        for noisy in ("scapy", "urllib3", "asyncio", "chardet"):
            logging.getLogger(noisy).setLevel(logging.ERROR)

    _configured = True
    return opened


def get_logger(name: str) -> logging.Logger:
    """Return a child logger of the ``badnet`` tree."""
    return logging.getLogger(f"badnet.{name}" if not name.startswith("badnet") else name)


def is_debug() -> bool:
    """True when ``--debug`` was requested (decides whether to show tracebacks).

    The ``badnet`` logger is always left at DEBUG level so the case log file can
    record everything; the effective stderr level is carried by the handler.  So
    this cannot be answered by ``isEnabledFor`` - it must use the flag.
    """
    return _debug_enabled
