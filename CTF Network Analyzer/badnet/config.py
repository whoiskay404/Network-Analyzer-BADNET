"""Configuration: defaults <- user config <- project config <- CLI flags.

Precedence (later wins):

1. built-in defaults (this module)
2. ``~/.config/badnet/config.yaml`` (or ``$XDG_CONFIG_HOME/badnet/config.yaml``)
3. ``./badnet.yaml`` in the current working directory
4. the file given with ``--config FILE``
5. command-line flags

Validation is strict: a bad value produces a :class:`ConfigError` naming the key
and the offending value rather than silently falling back, because a silently
ignored limit is worse than a refused run in a forensics tool.
"""

from __future__ import annotations

import copy
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from badnet.errors import ConfigError

log = logging.getLogger("badnet.config")

CONFIG_BASENAME = "config.yaml"
PROJECT_CONFIG_NAMES = ("badnet.yaml", "badnet.yml")

#: Location of the shipped default signatures (overridable via ``signatures.dir``).
DEFAULT_SIGNATURE_DIR = Path(__file__).resolve().parent.parent / "signatures"


@dataclass(slots=True)
class DnsThresholds:
    """Tunnelling heuristic thresholds (all configurable)."""

    min_queries: int = 20
    """Minimum queries to the same parent domain before it is considered at all."""
    high_unique_ratio: float = 0.85
    """Fraction of queries that must carry a previously unseen subdomain."""
    long_label_len: int = 40
    """A label at least this long is 'long' for DNS-over-length heuristics."""
    high_entropy: float = 3.5
    """Shannon entropy (bits/char) above which a label looks encoded."""
    encoded_label_ratio: float = 0.5
    """Fraction of encoded-looking labels needed to flag a parent domain."""
    min_query_rate: float = 2.0
    """Queries/second to the same parent that counts as a burst."""

    def validate(self) -> None:
        """Raise :class:`ConfigError` when a threshold is out of range."""
        _check_range("dns.min_queries", self.min_queries, 1, 1_000_000)
        _check_range("dns.high_unique_ratio", self.high_unique_ratio, 0.0, 1.0)
        _check_range("dns.long_label_len", self.long_label_len, 1, 512)
        _check_range("dns.high_entropy", self.high_entropy, 0.0, 8.0)
        _check_range("dns.encoded_label_ratio", self.encoded_label_ratio, 0.0, 1.0)
        _check_range("dns.min_query_rate", self.min_query_rate, 0.0, 100000.0)


@dataclass(slots=True)
class Limits:
    """Resource limits that protect the analyst's machine."""

    max_artifact_size: int = 64 * 1024 * 1024
    """Largest artifact BADNET will write to disk (64 MiB)."""
    max_body_preview: int = 4096
    """Bytes of an HTTP body kept for display/search."""
    max_strings_bytes: int = 8 * 1024 * 1024
    """How much of each text artifact is scanned for strings."""
    max_strings_count: int = 5000
    """Upper bound on strings extracted per artifact."""
    max_decode_depth: int = 3
    """Recursion limit for nested encodings."""
    max_decode_size: int = 1024 * 1024
    """Largest decoded blob (1 MiB)."""
    max_decompress_ratio: int = 200
    """Decompression-bomb guard: total/total-compressed ratio cap."""
    max_decompress_size: int = 64 * 1024 * 1024
    """Absolute cap on decompressed output (64 MiB)."""
    max_preview_bytes: int = 2048
    """Default cap for ``badnet stream --id N`` text previews."""
    regex_timeout_ms: int = 2000
    """Wall-clock budget for regex execution in ``badnet search``.

    The standard library :mod:`re` has no timeout, so this bounds the total time
    spent *matching* between streams; reassembly time is not charged against it,
    and a single pathological call is still not interruptible.  ``badnet search
    --literal`` avoids the regex engine entirely and is the safe mode.
    """

    def validate(self) -> None:
        """Raise :class:`ConfigError` when a limit is out of range."""
        for key in (
            "max_artifact_size",
            "max_body_preview",
            "max_strings_bytes",
            "max_strings_count",
            "max_decode_depth",
            "max_decode_size",
            "max_decompress_ratio",
            "max_decompress_size",
            "max_preview_bytes",
            "regex_timeout_ms",
        ):
            value = getattr(self, key)
            _check_range(f"limits.{key}", value, 1, 1 << 40)
        _check_range("limits.max_decode_depth", self.max_decode_depth, 1, 16)


@dataclass(slots=True)
class OutputPrefs:
    """Presentation defaults for reports."""

    top_n: int = 20
    """Rows shown before the 'N more' hint."""
    default_limit: int = 50
    """Default ``--limit`` for list commands."""
    include_banner: bool = True
    max_findings_shown: int = 50
    redact_secrets: bool = True
    """Masks secrets unless ``--verbose``."""

    def validate(self) -> None:
        """Raise :class:`ConfigError` when a preference is out of range."""
        _check_range("output.top_n", self.top_n, 1, 100_000)
        _check_range("output.default_limit", self.default_limit, 1, 100_000)
        _check_range("output.max_findings_shown", self.max_findings_shown, 1, 100_000)


@dataclass(slots=True)
class Config:
    """Effective configuration for one BADNET invocation."""

    output_dir: Path = field(default_factory=lambda: Path("output"))
    interesting_ports: list[int] = field(default_factory=lambda: list(DEFAULT_INTERESTING_PORTS))
    interesting_endpoints: list[str] = field(
        default_factory=lambda: list(DEFAULT_INTERESTING_ENDPOINTS)
    )
    """URI substrings considered interesting (``/admin``, ``/.git`` ...)."""
    interesting_extensions: list[str] = field(
        default_factory=lambda: [".zip", ".bak", ".sql", ".tar.gz", ".7z", ".rar", ".key", ".pem"]
    )
    dns: DnsThresholds = field(default_factory=DnsThresholds)
    limits: Limits = field(default_factory=Limits)
    output: OutputPrefs = field(default_factory=OutputPrefs)
    signature_dir: Path | None = None
    """Where ctf_patterns.yaml / secrets.yaml live (defaults to the shipped set)."""
    tshark_path: str | None = None
    nmap_path: str | None = None
    files_path: str | None = None
    strings_path: str | None = None
    use_libmagic: bool = True
    run_nmap_scripts: bool = True
    """Whether the ``full`` nmap profile may use default safe scripts (-sC)."""
    nmap_authorized: bool = False
    """Set true to skip the interactive authorisation prompt (lab convenience)."""
    nmap_default_profile: str = "quick"
    sources: list[str] = field(default_factory=list)
    """Config files that contributed, in load order (recorded in metadata.json)."""

    # ------------------------------------------------------------------ paths

    @property
    def effective_signature_dir(self) -> Path:
        """Directory containing the YAML signature files."""
        return self.signature_dir or DEFAULT_SIGNATURE_DIR

    @property
    def redact_secrets(self) -> bool:
        """Whether secrets must be masked in output (False when ``--verbose``)."""
        return self.output.redact_secrets

    # ------------------------------------------------------------------ load

    @classmethod
    def load(
        cls,
        *,
        explicit_path: str | Path | None = None,
        project_dir: str | Path | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> Config:
        """Build the effective configuration.

        Raises
        ------
        ConfigError
            For unreadable files, invalid YAML, unknown keys or out-of-range values.
        """
        cfg = cls()
        cfg.sources = []

        for path in cls._default_sources(project_dir):
            if path.is_file():
                _apply_file(cfg, path)

        if explicit_path is not None:
            path = Path(explicit_path).expanduser()
            if not path.is_file():
                raise ConfigError(f"config file not found: {path}")
            _apply_file(cfg, path)

        if overrides:
            _apply_overrides(cfg, overrides)

        cfg.validate()
        log.debug("configuration sources: %s", cfg.sources or ["defaults only"])
        return cfg

    @staticmethod
    def _default_sources(project_dir: str | Path | None) -> Iterable[Path]:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
        yield base / "badnet" / CONFIG_BASENAME
        root = Path(project_dir) if project_dir else Path.cwd()
        for name in PROJECT_CONFIG_NAMES:
            yield root / name

    def to_dict(self) -> dict[str, Any]:
        """Serialise for metadata.json (config actually used)."""
        return {
            "sources": list(self.sources),
            "output_dir": str(self.output_dir),
            "interesting_ports": list(self.interesting_ports),
            "interesting_endpoints": list(self.interesting_endpoints),
            "interesting_extensions": list(self.interesting_extensions),
            "dns": _dataclass_dict(self.dns),
            "limits": _dataclass_dict(self.limits),
            "output": _dataclass_dict(self.output),
            "signature_dir": str(self.effective_signature_dir),
            "tshark_path": self.tshark_path,
            "nmap_path": self.nmap_path,
            "files_path": self.files_path,
            "strings_path": self.strings_path,
            "use_libmagic": self.use_libmagic,
            "run_nmap_scripts": self.run_nmap_scripts,
            "nmap_default_profile": self.nmap_default_profile,
            "nmap_authorized": self.nmap_authorized,
        }

    def validate(self) -> None:
        """Validate every section, raising :class:`ConfigError` on bad values."""
        self.dns.validate()
        self.limits.validate()
        self.output.validate()
        for port in self.interesting_ports:
            _check_range("interesting_ports", port, 1, 65535)
        if self.nmap_default_profile not in ("quick", "full"):
            raise ConfigError(
                f"nmap_default_profile must be 'quick' or 'full', got {self.nmap_default_profile!r}"
            )


#: Default "worth a look" ports.  Unusual is not the same as malicious - BADNET
#: never claims otherwise.
DEFAULT_INTERESTING_PORTS: list[int] = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    143,
    443,
    445,
    3306,
    3389,
    5000,
    8000,
    8080,
    8443,
]

DEFAULT_INTERESTING_ENDPOINTS: list[str] = [
    "/admin",
    "/administrator",
    "/login",
    "/backup",
    "/backups",
    "/.git",
    "/.env",
    "/.svn",
    "/.hg",
    "/robots.txt",
    "/sitemap.xml",
    "/.DS_Store",
    "/wp-login.php",
    "/phpmyadmin",
    "/server-status",
    "/actuator",
    "/debug",
    "/console",
    "/shell",
    "/private",
    "/secret",
    "/config",
    "/config.php",
    "/phpinfo.php",
    "/.aws/credentials",
    "/id_rsa",
    "/wp-config.php",
    "/database.sql",
    "/dump.sql",
]

#: Nested key -> dataclass attribute mapping, used by the loader.
_SECTIONS: dict[str, tuple[str, type]] = {
    "dns": ("dns", DnsThresholds),
    "limits": ("limits", Limits),
    "output": ("output", OutputPrefs),
}

_SCALARS: dict[str, tuple[type, ...]] = {
    "output_dir": (str, Path),
    "interesting_ports": (list,),
    "interesting_endpoints": (list,),
    "interesting_extensions": (list,),
    "signature_dir": (str, Path),
    "tshark_path": (str,),
    "nmap_path": (str,),
    "files_path": (str,),
    "strings_path": (str,),
    "use_libmagic": (bool,),
    "run_nmap_scripts": (bool,),
    "nmap_authorized": (bool,),
    "nmap_default_profile": (str,),
}

_KNOWN_KEYS = set(_SECTIONS) | set(_SCALARS)


def _apply_file(cfg: Config, path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        # UnicodeDecodeError subclasses ValueError, not OSError, so it must be
        # listed explicitly or a non-UTF-8 ./badnet.yaml escapes as a traceback.
        raise ConfigError(
            f"config {path} is not valid UTF-8: {exc}",
            hint="save the file as UTF-8 (a Windows editor may have written cp1252)",
        ) from exc
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {_yaml_error(exc)}") from exc
    if data is None:
        return
    if not isinstance(data, dict):
        raise ConfigError(f"config {path} must contain a YAML mapping at the top level")
    unknown = set(data) - _KNOWN_KEYS
    if unknown:
        raise ConfigError(
            f"unknown config key(s) in {path}: {', '.join(sorted(unknown))}",
            hint=f"supported keys: {', '.join(sorted(_KNOWN_KEYS))}",
        )
    _apply_mapping(cfg, data, origin=str(path))
    cfg.sources.append(str(path))


def _apply_overrides(cfg: Config, overrides: dict[str, Any]) -> None:
    if not overrides:
        return
    unknown = set(overrides) - _KNOWN_KEYS
    if unknown:
        raise ConfigError(f"unknown config override(s): {', '.join(sorted(unknown))}")
    _apply_mapping(
        cfg, {k: v for k, v in overrides.items() if v is not None}, origin="--config flags"
    )


def _apply_mapping(cfg: Config, data: dict[str, Any], *, origin: str) -> None:
    for key, value in data.items():
        if key in _SECTIONS:
            attr, _cls = _SECTIONS[key]
            if not isinstance(value, dict):
                raise ConfigError(f"{origin}: section '{key}' must be a mapping")
            section = getattr(cfg, attr)
            allowed = set(section.__slots__)
            unknown = set(value) - allowed
            if unknown:
                raise ConfigError(
                    f"{origin}: unknown key(s) in '{key}': {', '.join(sorted(unknown))}",
                    hint=f"supported: {', '.join(sorted(allowed))}",
                )
            for sub, subval in value.items():
                current = getattr(section, sub)
                if isinstance(current, bool) or isinstance(subval, bool):
                    if not isinstance(subval, bool):
                        raise ConfigError(f"{origin}: {key}.{sub} must be true or false")
                elif isinstance(current, int) and not isinstance(subval, bool):
                    if not isinstance(subval, int):
                        raise ConfigError(f"{origin}: {key}.{sub} must be an integer")
                elif isinstance(current, float):
                    if isinstance(subval, (int, float)) and not isinstance(subval, bool):
                        subval = float(subval)
                    else:
                        raise ConfigError(f"{origin}: {key}.{sub} must be a number")
                elif not isinstance(subval, type(current)):
                    raise ConfigError(
                        f"{origin}: {key}.{sub} must be {type(current).__name__}, "
                        f"got {type(subval).__name__}"
                    )
                setattr(section, sub, subval)
        else:
            expected = _SCALARS[key]
            if not isinstance(value, expected):
                names = "/".join(t.__name__ for t in expected)
                raise ConfigError(f"{origin}: '{key}' must be {names}, got {type(value).__name__}")
            if key in ("output_dir", "signature_dir"):
                value = Path(str(value)).expanduser()
            if key == "interesting_ports":
                try:
                    value = [int(p) for p in value]
                except (TypeError, ValueError) as exc:
                    raise ConfigError(
                        f"{origin}: 'interesting_ports' must be a list of integers"
                    ) from exc
            if key in ("interesting_endpoints", "interesting_extensions"):
                value = [str(v) for v in value]
            setattr(cfg, key, value)


def _check_range(name: str, value: Any, low: float, high: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name} must be a number, got {value!r}")
    if not (low <= value <= high):
        raise ConfigError(f"{name} must be between {low} and {high}, got {value!r}")


def _dataclass_dict(obj: Any) -> dict[str, Any]:
    return {slot: getattr(obj, slot) for slot in obj.__slots__}


def _yaml_error(exc: yaml.YAMLError) -> str:
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or str(exc)
    if mark is not None:
        return f"{problem} (line {mark.line + 1}, column {mark.column + 1})"
    return problem


def default_config_template() -> str:
    """Render an annotated YAML template for ``badnet.yaml``."""
    cfg = Config()
    lines = [
        "# BADNET configuration.  Values shown are the built-in defaults.",
        "# Precedence: defaults < ~/.config/badnet/config.yaml < ./badnet.yaml < --config FILE < CLI flags",
        "",
        "# Where case directories are created.",
        f"output_dir: {cfg.output_dir}",
        "",
        "# Ports highlighted in connection/stream tables.",
        "# NOTE: an unusual port is not evidence of malicious activity; BADNET never claims it is.",
        "interesting_ports:",
        *(f"  - {p}" for p in cfg.interesting_ports),
        "",
        "# URI substrings worth a second look (case-insensitive).",
        "interesting_endpoints:",
        *(f"  - {e}" for e in cfg.interesting_endpoints),
        "",
        "# File extensions worth a second look when carving streams.",
        "interesting_extensions:",
        *(f"  - {e}" for e in cfg.interesting_extensions),
        "",
        "# DNS tunnelling heuristics.",
        "dns:",
        f"  min_queries: {cfg.dns.min_queries}",
        f"  high_unique_ratio: {cfg.dns.high_unique_ratio}",
        f"  long_label_len: {cfg.dns.long_label_len}",
        f"  high_entropy: {cfg.dns.high_entropy}",
        f"  encoded_label_ratio: {cfg.dns.encoded_label_ratio}",
        f"  min_query_rate: {cfg.dns.min_query_rate}",
        "",
        "# Resource limits (protect your machine; raise deliberately, not casually).",
        "limits:",
        f"  max_artifact_size: {cfg.limits.max_artifact_size}",
        f"  max_body_preview: {cfg.limits.max_body_preview}",
        f"  max_strings_bytes: {cfg.limits.max_strings_bytes}",
        f"  max_strings_count: {cfg.limits.max_strings_count}",
        f"  max_decode_depth: {cfg.limits.max_decode_depth}",
        f"  max_decode_size: {cfg.limits.max_decode_size}",
        f"  max_decompress_ratio: {cfg.limits.max_decompress_ratio}",
        f"  max_decompress_size: {cfg.limits.max_decompress_size}",
        f"  max_preview_bytes: {cfg.limits.max_preview_bytes}",
        f"  regex_timeout_ms: {cfg.limits.regex_timeout_ms}",
        "",
        "# Presentation.",
        "output:",
        f"  top_n: {cfg.output.top_n}",
        f"  default_limit: {cfg.output.default_limit}",
        f"  include_banner: {cfg.output.include_banner}",
        f"  max_findings_shown: {cfg.output.max_findings_shown}",
        "  redact_secrets: true   # masked unless --verbose",
        "",
        "# Signature files (ctf_patterns.yaml, secrets.yaml, interesting_ports.yaml).",
        "# signature_dir: /etc/badnet/signatures",
        "",
        "# External tool overrides (leave unset to auto-detect).",
        "# tshark_path: /usr/bin/tshark",
        "# nmap_path: /usr/sbin/nmap",
        "# files_path: /usr/bin/file",
        "# strings_path: /usr/bin/strings",
        "",
        "# Use libmagic via python-magic when available (falls back to file(1), then a built-in table).",
        f"use_libmagic: {str(cfg.use_libmagic).lower()}",
        "",
        "# Nmap: allow -sC in the 'full' profile; skip the per-session authorisation prompt.",
        f"run_nmap_scripts: {str(cfg.run_nmap_scripts).lower()}",
        f"nmap_authorized: {str(cfg.nmap_authorized).lower()}",
        f"nmap_default_profile: {cfg.nmap_default_profile}",
        "",
    ]
    return "\n".join(lines)


_ENDPOINT_COMMENTS: list[str] = []


def write_template(path: str | Path) -> Path:
    """Write an annotated configuration template to *path*.

    Refuses to clobber an existing file unless the caller removed it first, so a
    real config cannot be destroyed by accident.
    """
    target = Path(path)
    if target.exists():
        raise ConfigError(
            f"refusing to overwrite existing file {target}",
            hint="remove it first or choose another path",
        )
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(default_config_template(), encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot write {target}: {exc}") from exc
    return target


def deepcopy_config(cfg: Config) -> Config:
    """Return an independent copy (used by tests and by CLI flag application)."""
    return copy.deepcopy(cfg)
