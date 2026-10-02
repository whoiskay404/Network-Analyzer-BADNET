"""Detectors: turn parsed evidence into hedged, explained findings.

Each detector states *why* it fired and hands back the matched evidence; none of
them ever emit a bare verdict.  The wording rules live in
:mod:`badnet.models.finding`.
"""

from __future__ import annotations

__all__ = ["http"]
