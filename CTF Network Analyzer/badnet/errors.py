"""Typed error hierarchy and process exit codes.

Every failure BADNET can produce is modelled here so the CLI layer can print a
single clean line and exit with a documented code.  Tracebacks are only shown
when ``--debug`` is active.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Process exit codes used by every BADNET command."""

    OK = 0
    ERROR = 1
    USAGE = 2
    MISSING_DEPENDENCY = 3
    INTERRUPTED = 130


class BadnetError(Exception):
    """Base class for all expected BADNET failures.

    Parameters
    ----------
    message:
        Human readable, single-line description shown to the user.
    hint:
        Optional second line with a concrete remediation step.
    exit_code:
        Process exit code to use.  Subclasses override the default.
    """

    exit_code: ExitCode = ExitCode.ERROR

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


class InputError(BadnetError):
    """The PCAP/PCAPNG path is missing, unreadable, empty or not a capture."""


class ConfigError(BadnetError):
    """Configuration file could not be parsed or contains invalid values."""

    exit_code = ExitCode.USAGE


class UsageError(BadnetError):
    """A command-line flag was given an unusable value (bad number, out of range)."""

    exit_code = ExitCode.USAGE


class CaseExistsError(BadnetError):
    """A case directory already exists and ``--force`` was not supplied."""


class MissingDependencyError(BadnetError):
    """A required external tool or Python package is unavailable."""

    exit_code = ExitCode.MISSING_DEPENDENCY


class ToolError(BadnetError):
    """An external tool was found but failed while running."""


class AnalysisError(BadnetError):
    """Analysis could not be completed (corrupt capture, disk full, ...)."""


class SecurityError(BadnetError):
    """A safety invariant was violated (e.g. an output path escaped the case dir)."""


class ReDoSGuardError(BadnetError):
    """A user-supplied regex exceeded the safety guard."""
