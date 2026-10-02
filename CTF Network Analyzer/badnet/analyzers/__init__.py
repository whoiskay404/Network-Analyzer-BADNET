"""Analysis layer.

Analyzers turn reader rows into models, update aggregates and write NDJSON
datasets.  They never print and never decide anything is malicious - judgement
words live in :mod:`badnet.detectors`.
"""

from __future__ import annotations
