"""Reporting layer: terminal (Rich), JSON, HTML.

Reporters are pure functions of the data model - they never re-read the capture
and never decide anything.  ``terminal`` is interactive-friendly, ``json`` is
machine-readable, ``html`` is a single self-contained offline file.
"""

from __future__ import annotations
