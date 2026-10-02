"""Command implementations.

Each module here is the wiring between the CLI layer and the analysis layers:
it resolves options, calls the orchestrator, and hands the result to a reporter.
Keeping them out of :mod:`badnet.cli` stops that file becoming a monolith while
preserving the layering (commands -> orchestrator -> analyzers -> readers).
"""

from __future__ import annotations
