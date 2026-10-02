"""Case persistence (append-only NDJSON datasets plus metadata.json)."""

from __future__ import annotations

from badnet.storage.casestore import CaseStore, DatasetWriter

__all__ = ["CaseStore", "DatasetWriter"]
