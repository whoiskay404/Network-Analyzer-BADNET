"""YAML signature loading and validation.

Signatures are data, not code: each ``*.yaml`` file in the signature directory
contributes patterns (and, for ``interesting_ports.yaml``, port metadata).  The
loader compiles every regex up front so a typo in a user signature file fails
immediately with a clear message instead of silently never matching.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from badnet.errors import ConfigError

log = logging.getLogger(__name__)

#: Fields every pattern entry must define.
_REQUIRED = ("id", "title", "regex", "severity", "confidence", "category")

#: Allowed enumeration values, kept in sync with the YAML documentation.
SEVERITIES = ("info", "low", "medium", "high")
CONFIDENCES = ("low", "medium", "high")
CATEGORIES = (
    "flag",
    "credential",
    "secret",
    "encoding",
    "artifact",
    "endpoint",
    "dns",
    "http",
    "tls",
    "port",
    "anomaly",
    "metadata",
    "data",
)


@dataclass(frozen=True, slots=True)
class Signature:
    """One compiled pattern from a signature file."""

    id: str
    title: str
    regex: str
    severity: str
    confidence: str
    category: str
    description: str
    tags: tuple[str, ...] = ()
    decoders: tuple[str, ...] = ()
    source_file: str = ""
    _compiled: re.Pattern[str] | None = field(default=None, compare=False, repr=False)

    @property
    def compiled(self) -> re.Pattern[str]:
        """The compiled regex (raises if the pattern never compiled)."""
        if self._compiled is None:  # pragma: no cover - guarded by load_signatures
            raise ConfigError(f"signature {self.id!r} was never compiled")
        return self._compiled

    def search(self, text: str) -> re.Match[str] | None:
        """Return the first match of this signature in *text*, if any."""
        return self.compiled.search(text)


@dataclass(frozen=True, slots=True)
class SignatureSet:
    """All patterns loaded from a signature directory."""

    patterns: tuple[Signature, ...] = ()
    interesting_ports: frozenset[int] = frozenset()
    port_services: dict[int, str] = field(default_factory=dict)
    """Port → service name, e.g. ``{80: "http"}``.  Display metadata only."""

    def by_category(self, category: str) -> tuple[Signature, ...]:
        """Patterns in one category."""
        return tuple(p for p in self.patterns if p.category == category)

    def service_for_port(self, port: int) -> str:
        """Service name for *port*, or ``""`` when the port is not in the table."""
        return self.port_services.get(int(port), "")

    def __len__(self) -> int:
        return len(self.patterns)


def load_signatures(
    directory: str | Path,
    *,
    extra_files: tuple[Path, ...] = (),
) -> SignatureSet:
    """Load and compile every signature file in *directory*.

    A malformed file raises :class:`ConfigError` naming the file and the pattern,
    because a silently ignored signature is worse than a loud failure.
    """
    base = Path(directory)
    if not base.is_dir():
        log.debug("signature directory %s does not exist; using no signatures", base)
        return SignatureSet()

    paths = sorted(base.glob("*.yaml")) + sorted(base.glob("*.yml"))
    paths.extend(Path(p) for p in extra_files)

    patterns: list[Signature] = []
    interesting: set[int] = set()
    port_services: dict[int, str] = {}
    seen_ids: dict[str, str] = {}

    for path in paths:
        data = _read_yaml(path)
        for entry in data.get("patterns", []) or []:
            signature = _build_pattern(entry, path)
            if signature.id in seen_ids:
                raise ConfigError(
                    f"duplicate signature id {signature.id!r} in {path} "
                    f"(already defined in {seen_ids[signature.id]})"
                )
            seen_ids[signature.id] = str(path)
            patterns.append(signature)

        for port in data.get("interesting", []) or []:
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise ConfigError(f"invalid port {port!r} in {path}")
            interesting.add(port)

        mapping = data.get("services", {}) or {}
        if isinstance(mapping, dict):
            for port, service in mapping.items():
                if not isinstance(port, int) or not 1 <= port <= 65535:
                    raise ConfigError(f"invalid service port {port!r} in {path}")
                if not isinstance(service, str) or not service.strip():
                    raise ConfigError(f"service for port {port} in {path} must be a non-empty name")
                port_services[port] = service.strip().lower()

    log.info(
        "loaded %d signature pattern(s) from %d file(s); %d interesting port(s)",
        len(patterns),
        len(paths),
        len(interesting),
    )
    return SignatureSet(
        patterns=tuple(patterns),
        interesting_ports=frozenset(interesting),
        port_services=port_services,
    )


def _read_yaml(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read signature file {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in signature file {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"signature file {path} must contain a mapping at the top level")
    return data


def _build_pattern(entry: object, path: Path) -> Signature:
    """Validate and compile one pattern entry."""
    if not isinstance(entry, dict):
        raise ConfigError(f"pattern entries in {path} must be mappings, got {type(entry).__name__}")

    missing = [key for key in _REQUIRED if not entry.get(key)]
    if missing:
        raise ConfigError(f"pattern in {path} is missing required field(s): {', '.join(missing)}")

    for key, allowed in (
        ("severity", SEVERITIES),
        ("confidence", CONFIDENCES),
        ("category", CATEGORIES),
    ):
        value = str(entry[key])
        if value not in allowed:
            raise ConfigError(
                f"pattern {entry['id']!r} in {path} has invalid {key} {value!r}; "
                f"allowed: {', '.join(allowed)}"
            )

    try:
        compiled = re.compile(str(entry["regex"]))
    except re.error as exc:
        raise ConfigError(f"pattern {entry['id']!r} in {path} has an invalid regex: {exc}") from exc

    return Signature(
        id=str(entry["id"]),
        title=str(entry["title"]),
        regex=str(entry["regex"]),
        severity=str(entry["severity"]),
        confidence=str(entry["confidence"]),
        category=str(entry["category"]),
        description=str(entry.get("description", "")).strip(),
        tags=tuple(str(t) for t in (entry.get("tags") or ())),
        decoders=tuple(str(d) for d in (entry.get("decoders") or ())),
        source_file=str(path),
        _compiled=compiled,
    )
