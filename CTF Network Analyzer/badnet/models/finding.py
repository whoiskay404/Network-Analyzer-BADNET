"""The Finding model - the core output of every detector.

Wording rules enforced here and in the detectors:

* heuristics never say "malicious", "confirmed" or "attack";
* titles are hedged (Interesting / Suspicious / Possible ... / Heuristic match);
* ``explanation`` states *why* the rule fired, with the measured values;
* ``evidence`` holds the matched snippet or values, never a bare verdict.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """How much attention a finding deserves.  Not a risk score."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        """Sort key (higher is more attention-worthy)."""
        return {"info": 0, "low": 1, "medium": 2, "high": 3}[self.value]


class Confidence(StrEnum):
    """How sure the detector is that it matched what it claims to match."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        """Sort key (higher is more certain)."""
        return {"low": 0, "medium": 1, "high": 2}[self.value]


class Category(StrEnum):
    """Finding categories used for grouping, filtering and CTF ranking."""

    FLAG = "flag"
    CREDENTIAL = "credential"
    SECRET = "secret"
    ENCODING = "encoding"
    ARTIFACT = "artifact"
    ENDPOINT = "endpoint"
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"
    PORT = "port"
    ANOMALY = "anomaly"
    METADATA = "metadata"
    DATA = "data"


@dataclass(slots=True)
class Finding:
    """One detected item of interest.

    Attributes are exactly those documented in the data model; adding a field
    requires updating :meth:`to_dict` and the JSON report schema version.
    """

    id: str
    category: Category
    title: str
    severity: Severity
    confidence: Confidence
    explanation: str
    evidence: str = ""
    source: str = ""
    """Where it was seen, e.g. ``packet 42``, ``stream 3``, ``files/flag.txt``, ``stream 3 line 12``."""
    timestamp: float | None = None
    related: list[str] = field(default_factory=list)
    """Related artifact/stream/connection ids or cross-references."""
    detector: str = ""
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = self.compute_id()

    def compute_id(self) -> str:
        """Deterministic fingerprint used for deduplication.

        Two findings with the same category, title and evidence collapse into
        one, which is how ``badnet auto`` avoids reporting the same Base64 blob
        once per header it appeared in.
        """
        basis = "|".join((str(self.category), self.title, self.evidence, str(self.timestamp or "")))
        return "f_" + hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest()[:12]

    @property
    def sort_key(self) -> tuple[int, int, str]:
        """CTF ranking key: severity, then confidence, then category name."""
        return (-self.severity.rank, -self.confidence.rank, str(self.category))

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {
            "id": self.id,
            "category": str(self.category),
            "title": self.title,
            "severity": str(self.severity),
            "confidence": str(self.confidence),
            "explanation": self.explanation,
            "evidence": self.evidence,
            "source": self.source,
            "timestamp": self.timestamp,
            "related": list(self.related),
            "detector": self.detector,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Finding:
        """Rebuild a finding from its serialised form (used by dedup/correlation)."""
        return cls(
            id=str(data.get("id", "")),
            category=Category(str(data.get("category", "data"))),
            title=str(data.get("title", "")),
            severity=Severity(str(data.get("severity", "info"))),
            confidence=Confidence(str(data.get("confidence", "medium"))),
            explanation=str(data.get("explanation", "")),
            evidence=str(data.get("evidence", "")),
            source=str(data.get("source", "")),
            timestamp=data.get("timestamp")
            if isinstance(data.get("timestamp"), (int, float))
            else None,
            related=list(data.get("related", []) or []),  # type: ignore[arg-type]
            detector=str(data.get("detector", "")),
            tags=list(data.get("tags", []) or []),  # type: ignore[arg-type]
        )


@dataclass(slots=True)
class DetectorStats:
    """How many findings each detector contributed (for report provenance)."""

    per_detector: dict[str, int] = field(default_factory=dict)
    per_category: dict[str, int] = field(default_factory=dict)
    deduped: int = 0
    correlated: int = 0

    def to_dict(self) -> dict[str, object]:
        """Serialise for JSON reports."""
        return {
            "per_detector": self.per_detector,
            "per_category": self.per_category,
            "deduped": self.deduped,
            "correlated": self.correlated,
        }
