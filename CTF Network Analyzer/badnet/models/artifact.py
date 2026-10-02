"""Extracted artifact model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ExtractionMethod(StrEnum):
    """How an artifact was recovered - recorded for evidence integrity."""

    TSHARK_EXPORT = "tshark-export-objects"
    STREAM_CARVE = "stream-carve"
    MAGIC_CARVE = "magic-byte-carve"
    PLAINTEXT = "reassembled-plaintext"

    @property
    def description(self) -> str:
        """Human-readable explanation used in reports."""
        return {
            ExtractionMethod.TSHARK_EXPORT: "extracted by tshark --export-objects",
            ExtractionMethod.STREAM_CARVE: "carved from a reassembled TCP stream by protocol structure",
            ExtractionMethod.MAGIC_CARVE: "carved from a reassembled TCP stream by magic bytes",
            ExtractionMethod.PLAINTEXT: "whole reassembled stream body saved as a text artifact",
        }[self]


@dataclass(slots=True)
class Artifact:
    """A file recovered from the capture, with its hashes and provenance."""

    name: str
    """Sanitised on-disk name inside ``files/``."""
    detected_type: str
    """libmagic / BADNET magic-table description, e.g. ``PNG image data``."""
    mime: str | None
    size: int
    method: ExtractionMethod
    stream_id: int | None = None
    packet_no: int | None = None
    protocol: str | None = None
    original_name: str | None = None
    """Filename as advertised by the protocol (``Content-Disposition``, FTP, ...)."""
    source: str | None = None
    """``http``, ``smb``, ``ftp-data``, ``tcp-stream-3`` ..."""
    offset: int | None = None
    """Byte offset inside the reassembled stream when carved."""
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    stored_path: str | None = None
    """Case-relative path of the saved copy."""
    is_text: bool = False
    truncated: bool = False
    notes: list[str] = field(default_factory=list)
    strings_extracted: int = 0
    interesting_strings: int = 0

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {
            "name": self.name,
            "detected_type": self.detected_type,
            "mime": self.mime,
            "size": self.size,
            "method": self.method.value,
            "method_description": self.method.description,
            "stream_id": self.stream_id,
            "packet_no": self.packet_no,
            "protocol": self.protocol,
            "original_name": self.original_name,
            "source": self.source,
            "offset": self.offset,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "stored_path": self.stored_path,
            "is_text": self.is_text,
            "truncated": self.truncated,
            "notes": list(self.notes),
            "strings_extracted": self.strings_extracted,
            "interesting_strings": self.interesting_strings,
        }


@dataclass(slots=True)
class ArtifactStats:
    """Aggregate counters for the extraction phase."""

    total: int = 0
    total_bytes: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_method: dict[str, int] = field(default_factory=dict)
    skipped_size: int = 0
    """Artifacts rejected because they exceeded ``max_artifact_size``."""
    skipped_duplicate: int = 0
    """Artifacts that were byte-identical to an already stored file."""

    def to_dict(self) -> dict[str, object]:
        """Serialise for JSON reports."""
        return {
            "total": self.total,
            "total_bytes": self.total_bytes,
            "by_type": self.by_type,
            "by_method": self.by_method,
            "skipped_size": self.skipped_size,
            "skipped_duplicate": self.skipped_duplicate,
        }
