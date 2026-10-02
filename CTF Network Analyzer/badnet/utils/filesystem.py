"""Filesystem hardening helpers.

Every path BADNET writes to is derived from *untrusted* input (HTTP request
URIs, DNS names, ``Content-Disposition`` filenames, user-supplied target
globs...).  This module is the single place where such names are made safe, and
the single place that enforces the "output must stay inside the case directory"
invariant.
"""

from __future__ import annotations

import logging
import os
import re
import unicodedata
from pathlib import Path, PurePosixPath, PureWindowsPath

from badnet.errors import SecurityError

log = logging.getLogger("badnet.filesystem")

#: Filesystem-reserved device names (Windows).  Rejected on every platform so a
#: case directory stays portable between Kali and a Windows workstation.
RESERVED_NAMES = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
)

#: Maximum length of a single generated filename component (ext4: 255 bytes).
MAX_NAME_LEN = 120

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_UNSAFE_CHARS = re.compile(r'[<>:"|?*\\/]')
_WHITESPACE = re.compile(r"\s+")

#: Directory / file permissions.  Case material may contain stolen credentials,
#: so it is owner-only on POSIX.
DIR_MODE = 0o700
FILE_MODE = 0o600


def sanitize_filename(
    name: str | None,
    *,
    fallback: str = "unnamed",
    max_len: int = MAX_NAME_LEN,
) -> str:
    """Turn an arbitrary untrusted string into a safe single path component.

    Strips directory separators (both POSIX and Windows style, plus drive
    letters and UNC prefixes), control characters, NUL bytes, leading dots and
    reserved device names, normalises Unicode (NFKC, so fullwidth ``．．／／``
    cannot smuggle a separator past the character filter), collapses whitespace
    and length-caps the result.

    Parameters
    ----------
    name:
        The untrusted name.  May be ``None`` or empty.
    fallback:
        Used when nothing printable survives sanitisation.
    max_len:
        Hard cap on the returned length in characters.

    Returns
    -------
    str
        A non-empty component that contains no path separator and cannot be
        absolute, relative-traversing, or a reserved name.
    """
    if not name:
        return fallback

    # NFKC folds compatibility characters (e.g. fullwidth solidus) into ASCII,
    # so the ASCII filter below is sufficient to block Unicode separator tricks.
    text = unicodedata.normalize("NFKC", str(name))

    # Remove directory components explicitly rather than relying on separators.
    text = PurePosixPath(text.replace("\\", "/")).name
    text = PureWindowsPath(text).name

    text = _CONTROL_CHARS.sub("", text)
    text = _UNSAFE_CHARS.sub("_", text)
    text = text.replace("\u2024", "_").replace("\u2025", "_").replace("\u2026", "...")
    text = _WHITESPACE.sub(" ", text).strip()
    text = text.strip(". ")  # leading dots hide files; trailing dots break Windows

    if not text:
        return fallback
    if text.split(".")[0].lower() in RESERVED_NAMES:
        text = "_" + text

    if len(text) > max_len:
        stem, dot, ext = text.rpartition(".")
        if dot and 0 < len(ext) <= 12:
            keep = max(8, max_len - len(ext) - 1)
            text = stem[:keep] + "." + ext
        else:
            text = text[:max_len]
    text = text.strip(". ") or fallback
    return text


def sanitize_hash_component(value: str, *, max_len: int = MAX_NAME_LEN) -> str:
    """Sanitise a component that is expected to look like a hex digest."""
    return sanitize_filename(value, fallback="deadbeef", max_len=max_len)


def is_within(base: Path, target: Path) -> bool:
    """Return True when *target* resolves to a location inside *base*.

    Both paths are fully resolved first, so symlink games and ``..`` segments
    cannot make a path look contained when it is not.
    """
    try:
        base_r = base.resolve()
        target_r = target.resolve()
    except OSError as exc:  # pragma: no cover - unreadable path
        log.warning("resolve() failed for %s: %s", target, exc)
        return False
    try:
        target_r.relative_to(base_r)
    except ValueError:
        return False
    return True


def safe_join(base: Path, *parts: str, must_exist: bool = False) -> Path:
    """Join *parts* onto *base* and guarantee the result stays inside *base*.

    Raises
    ------
    SecurityError
        If the joined path escapes *base* after resolution.
    """
    base_p = Path(base)
    candidate = base_p.joinpath(*parts)
    if not is_within(base_p, candidate):
        raise SecurityError(
            f"refusing to write outside the case directory (attempted: {candidate})"
        )
    if must_exist and not candidate.exists():
        raise SecurityError(f"path does not exist: {candidate}")
    return candidate


def ensure_dir(base: Path, *parts: str) -> Path:
    """Create (and permission-restrict) a directory inside *base*."""
    target = safe_join(base, *parts)
    target.mkdir(parents=True, exist_ok=True)
    harden_dir(target)
    return target


def unique_name(parent: Path, name: str) -> Path:
    """Return a non-colliding path for *name* inside *parent*.

    If *name* exists, ``name_1``, ``name_2`` ... are tried.  Content-based
    deduplication is the caller's job (see :mod:`badnet.analyzers.artifacts`,
    which prefixes names with a content hash).
    """
    candidate = parent / name
    if not candidate.exists():
        return candidate
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    for i in range(1, 1000):
        alt = f"{stem}_{i}" + (f".{ext}" if ext else "")
        probe = parent / alt
        if not probe.exists():
            return probe
    raise SecurityError(f"could not find a free filename for {name!r}")


def harden_dir(path: Path) -> None:
    """Best-effort 0700 on directories (no-op semantics on Windows)."""
    _chmod(path, DIR_MODE, directories=True)


def harden_file(path: Path) -> None:
    """Best-effort 0600 on files (no-op semantics on Windows)."""
    _chmod(path, FILE_MODE, directories=False)


def _chmod(path: Path, mode: int, *, directories: bool) -> None:
    if os.name == "nt":
        # Windows has no POSIX mode bits; ACL inheritance from the user profile
        # applies instead.  Nothing to do, and pretending otherwise would be a lie.
        log.debug("skipping chmod on Windows for %s", path)
        return
    try:
        if directories:
            os.chmod(path, mode)
        else:
            os.chmod(path, mode)
    except OSError as exc:  # pragma: no cover - FAT/exotic mounts
        log.warning("could not restrict permissions on %s: %s", path, exc)


def human_size(num: float) -> str:
    """Format a byte count for terminal output."""
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    value = float(num)
    for unit in units:
        if abs(value) < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TiB"  # pragma: no cover - loop always returns
