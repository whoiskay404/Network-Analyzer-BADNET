"""TLS session and certificate models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

#: Human labels for TLS/SSL record versions seen on the wire.
VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x0002: "SSL 2.0",
}

#: Versions considered legacy; a neutral observation, not a verdict.
LEGACY_VERSIONS = frozenset({"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"})

HANDSHAKE_TYPES = {
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
    24: "KeyUpdate",
}


@dataclass(slots=True)
class CertificateInfo:
    """Parsed X.509 leaf certificate (or the first one presented).

    All textual values are stored verbatim as observed; BADNET makes no trust
    decision and does not contact any revocation endpoint.
    """

    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    serial: str | None = None
    san: list[str] = field(default_factory=list)
    key_algorithm: str | None = None
    key_size: int | None = None
    signature_algorithm: str | None = None
    version: int | None = None
    is_ca: bool = False
    self_signed: bool = False
    sha256: str | None = None
    """SHA-256 of the DER encoding - the same value OpenSSL's fingerprint uses."""
    parse_error: str | None = None

    @property
    def days_until_expiry(self) -> int | None:
        """Whole days until ``not_after`` (negative when already expired)."""
        parsed = self.not_after_datetime
        if parsed is None:
            return None
        delta = parsed - datetime.now(UTC)
        return int(delta.total_seconds() // 86400)

    @property
    def not_after_datetime(self) -> datetime | None:
        """Parsed ``not_after`` as an aware datetime, or ``None``."""
        return _parse_ts(self.not_after)

    @property
    def not_before_datetime(self) -> datetime | None:
        """Parsed ``not_before`` as an aware datetime, or ``None``."""
        return _parse_ts(self.not_before)

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial": self.serial,
            "san": self.san,
            "key_algorithm": self.key_algorithm,
            "key_size": self.key_size,
            "signature_algorithm": self.signature_algorithm,
            "version": self.version,
            "is_ca": self.is_ca,
            "self_signed": self.self_signed,
            "sha256": self.sha256,
            "parse_error": self.parse_error,
        }


@dataclass(slots=True)
class TlsHandshake:
    """One handshake message, or a summary of a whole session when ``is_session``."""

    ts: float
    packet_no: int
    src: str | None
    dst: str | None
    src_port: int | None
    dst_port: int | None
    handshake_type: str
    record_version: str | None = None
    handshake_version: str | None = None
    cipher_suite: str | None = None
    sni: str | None = None
    stream_id: int | None = None
    certificate: CertificateInfo | None = None
    ja3: str | None = None
    alpn: list[str] = field(default_factory=list)

    @property
    def server_label(self) -> str:
        """``ip:port`` of the server side of the handshake."""
        if self.src_port and self.handshake_type in ("ServerHello", "Certificate"):
            return f"{self.src}:{self.src_port}"
        return f"{self.dst}:{self.dst_port}"

    @property
    def legacy_version(self) -> bool:
        """True when a legacy SSL/TLS version was offered or negotiated."""
        return self.record_version in LEGACY_VERSIONS or self.handshake_version in LEGACY_VERSIONS

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {
            "ts": self.ts,
            "packet_no": self.packet_no,
            "src": self.src,
            "dst": self.dst,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "handshake_type": self.handshake_type,
            "record_version": self.record_version,
            "handshake_version": self.handshake_version,
            "cipher_suite": self.cipher_suite,
            "sni": self.sni,
            "stream_id": self.stream_id,
            "ja3": self.ja3,
            "alpn": self.alpn,
            "certificate": self.certificate.to_dict() if self.certificate else None,
        }


@dataclass(slots=True)
class TlsSession:
    """A TLS conversation aggregated per TCP stream."""

    stream_id: int | None
    client_ip: str | None
    client_port: int | None
    server_ip: str | None
    server_port: int | None
    first_seen: float = 0.0
    last_seen: float = 0.0
    record_versions: set[str] = field(default_factory=set)
    handshake_versions: set[str] = field(default_factory=set)
    cipher_suites: set[str] = field(default_factory=set)
    sni_names: set[str] = field(default_factory=set)
    certificates: list[CertificateInfo] = field(default_factory=list)
    ja3: set[str] = field(default_factory=set)
    alpn: set[str] = field(default_factory=set)
    handshake_messages: int = 0
    decrypted: bool = False
    """True when a key log file let tshark decrypt application data."""

    @property
    def duration(self) -> float:
        """Seconds spanned by the TLS conversation."""
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def sni(self) -> str | None:
        """First observed SNI, if any."""
        return next(iter(sorted(self.sni_names)), None)

    @property
    def version(self) -> str | None:
        """Lowest (most conservative) protocol version observed."""
        ordered = [
            v
            for v in VERSION_NAMES.values()
            if v in self.record_versions or v in self.handshake_versions
        ]
        return (
            min(ordered, key=lambda v: list(VERSION_NAMES.values()).index(v)) if ordered else None
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {
            "stream_id": self.stream_id,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "server_ip": self.server_ip,
            "server_port": self.server_port,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": self.duration,
            "record_versions": sorted(self.record_versions),
            "handshake_versions": sorted(self.handshake_versions),
            "cipher_suites": sorted(self.cipher_suites),
            "sni_names": sorted(self.sni_names),
            "ja3": sorted(self.ja3),
            "alpn": sorted(self.alpn),
            "handshake_messages": self.handshake_messages,
            "decrypted": self.decrypted,
            "sni": self.sni,
            "version": self.version,
            "certificates": [c.to_dict() for c in self.certificates],
        }


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        # ``cryptography`` returns e.g. "Jun  1 12:00:00 2026 GMT" on old builds.
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
            try:
                parsed = datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed
