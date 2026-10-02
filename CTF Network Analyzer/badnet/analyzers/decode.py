"""Bounded decoders for the encodings CTF authors wrap flags in.

A flag is frequently encoded before it goes on the wire - most often base64, but
also hex, URL-encoding, or a Caesar/ROT13 rotation.  These helpers peel those
layers off so the signature scanners can see through them.  Everything here is
deliberately conservative and bounded, because blindly decoding hostile bytes
produces noise and burns CPU:

* candidates are matched by explicit character-class regexes with boundaries and
  a minimum length, so ordinary words are not fed to the decoder;
* a decoded blob is kept only when it is mostly printable text;
* recursion stops at ``limits.max_decode_depth`` and every decoded blob is capped
  at ``limits.max_decode_size`` bytes;
* the number of candidates taken from one input is capped.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator
from urllib.parse import unquote

#: Standard base64: the ``+``/``/`` alphabet keeps it from matching plain words.
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{12,}={0,2})(?![A-Za-z0-9+/=])")
#: URL-safe base64.  Noisier (it overlaps [_a-z0-9-] identifiers), so it needs a
#: longer minimum and at least one ``-``/``_`` before it is attempted.
_B64URL_RE = re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{20,}={0,2})(?![A-Za-z0-9_=-])")
#: Hex runs of even length (checked separately).
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{16,})(?![0-9A-Fa-f])")
_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")

_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)

DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_SIZE = 1024 * 1024
DEFAULT_MAX_CANDIDATES = 64
#: A token longer than this is almost certainly not a simple encoded secret.
_MAX_TOKEN = 16384

_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def iter_decoded(
    text: str | None,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_size: int = DEFAULT_MAX_SIZE,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> Iterator[tuple[str, str]]:
    """Yield ``(method, decoded_text)`` for each plausible decoding of *text*.

    ``method`` names the chain that produced the result (``base64``,
    ``base64+hex``, ...).  The generator follows nested encodings breadth-first
    up to *max_depth* levels and stops after *max_candidates* results.
    """
    if not text:
        return

    root = text[:max_size]
    frontier: list[tuple[str, str, int]] = [(root, "", 0)]
    seen: set[str] = {root}
    yielded = 0

    while frontier and yielded < max_candidates:
        current, chain, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for method, decoded in _one_level(current, max_size=max_size):
            if decoded in seen:
                continue
            seen.add(decoded)
            combined = f"{chain}+{method}" if chain else method
            yield combined, decoded
            yielded += 1
            if yielded >= max_candidates:
                break
            frontier.append((decoded, combined, depth + 1))


def _one_level(text: str, *, max_size: int) -> list[tuple[str, str]]:
    """Return every one-step decoding of *text* that survives validation."""
    out: list[tuple[str, str]] = []

    for token in _base64_candidates(_B64_RE, text):
        decoded = _b64(token)
        if decoded and _is_text(decoded):
            out.append(("base64", _as_text(decoded)[:max_size]))

    for token in _base64_candidates(_B64URL_RE, text):
        if "-" not in token and "_" not in token:
            continue
        decoded = _urlsafe_b64(token)
        if decoded and _is_text(decoded):
            out.append(("base64url", _as_text(decoded)[:max_size]))

    for token in _hex_candidates(text):
        decoded = _hex(token)
        if decoded and _is_text(decoded):
            out.append(("hex", _as_text(decoded)[:max_size]))

    if _PERCENT_RE.search(text):
        decoded = unquote(text)
        if decoded and decoded != text:
            out.append(("url", decoded[:max_size]))

    if "{" in text or "}" in text:
        rotated = text.translate(_ROT13)
        if rotated != text:
            out.append(("rot13", rotated[:max_size]))

    return out


def _base64_candidates(regex: re.Pattern[str], text: str) -> Iterator[str]:
    seen: set[str] = set()
    for match in regex.finditer(text):
        token = match.group(1)
        if token in seen or len(token) > _MAX_TOKEN:
            continue
        seen.add(token)
        if _plausible_base64(token):
            yield token


def _hex_candidates(text: str) -> Iterator[str]:
    seen: set[str] = set()
    for match in _HEX_RE.finditer(text):
        token = match.group(1)
        if token in seen or len(token) > _MAX_TOKEN:
            continue
        seen.add(token)
        if len(token) % 2 == 0:
            yield token


def _plausible_base64(token: str) -> bool:
    """Reject runs that are obviously not base64 (e.g. a single long word)."""
    body = token.rstrip("=")
    if len(body) < 12:
        return False
    classes = (
        any(c.islower() for c in body)
        + any(c.isupper() for c in body)
        + any(c.isdigit() for c in body)
    )
    return classes >= 2


def _is_text(data: bytes) -> bool:
    """True when *data* is mostly printable ASCII (a decoded secret, not binary)."""
    if not data:
        return False
    printable = sum(1 for byte in data if byte in _PRINTABLE)
    return printable / len(data) >= 0.85


def _as_text(data: bytes) -> str:
    """Decode validated bytes to text for the (str-based) signature scanner."""
    return data.decode("utf-8", errors="replace")


def _b64(token: str) -> bytes:
    padded = token + "=" * (-len(token) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return b""


def _urlsafe_b64(token: str) -> bytes:
    padded = token + "=" * (-len(token) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return b""


def _hex(token: str) -> bytes:
    if len(token) % 2:
        return b""
    try:
        return bytes.fromhex(token)
    except ValueError:
        return b""
