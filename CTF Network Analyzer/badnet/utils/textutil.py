"""Text/binary utilities for safe previews, entropy and string extraction.

All display helpers here obey two rules:

* captured bytes are never round-tripped through ``encode`` after ``decode``;
  previews escape non-printable bytes as ``\\xNN`` so the exact bytes can be
  recovered by hand;
* ``errors="replace"`` is used only for *display* paths, never for data that is
  written back to disk.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator

#: Minimum run length used when extracting ASCII/UTF-16 strings.
DEFAULT_MIN_STRING_LEN = 4

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

_WS_RUN = re.compile(r"[\t\r\n ]+")

_ESCAPES = {
    0x5C: "\\\\",
    0x0A: "\\n",
    0x0D: "\\r",
    0x09: "\\t",
}


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of *data* in bits per byte (0.0 for empty input)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    total = 0.0
    for count in counts:
        if count:
            p = count / length
            total -= p * math.log2(p)
    return total


def printable_ratio(data: bytes) -> float:
    """Fraction of *data* made of printable ASCII/UTF-8 whitespace (0.0-1.0)."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if b in _PRINTABLE)
    return printable / len(data)


def looks_binary(data: bytes, *, threshold: float = 0.85) -> bool:
    """Heuristic: True when *data* looks like binary rather than text.

    Uses a high printable ratio plus a NUL-byte check, which is the same signal
    ``file(1)`` uses for "data".
    """
    if not data:
        return False
    if b"\x00" in data[:4096]:
        return True
    return printable_ratio(data[:4096]) < threshold


def escape_bytes(data: bytes, *, max_len: int = 512, ellipsis: str = "...") -> str:
    """Render *data* as a printable string with non-printables escaped.

    Non-UTF-8 bytes become ``\\xNN`` and a UTF-8 decode error is *not* replaced
    silently in a way that hides bytes: undecodable sequences are escaped too.
    """
    view = data[:max_len]
    out: list[str] = []
    for byte in view:
        if byte in _ESCAPES:
            out.append(_ESCAPES[byte])
        elif byte in _PRINTABLE:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    text = "".join(out)
    if len(data) > max_len:
        text += ellipsis
    return text


def safe_text_preview(data: bytes, *, max_len: int = 512) -> str:
    """Produce a human-readable preview of possibly-binary *data*.

    Tries a strict UTF-8 decode first (preserving multi-byte characters); bytes
    that fail to decode are escaped individually so no information is lost.
    """
    view = data[:max_len]
    try:
        text = view.decode("utf-8")
    except UnicodeDecodeError:
        return escape_bytes(view, max_len=max_len)
    text = _WS_RUN.sub(" ", text)
    text = "".join(
        ch if ch.isprintable() or ch == " " else escape_bytes(ch.encode()) for ch in text
    )
    if len(data) > max_len:
        text += "..."
    return text.strip()


def iter_strings(data: bytes, *, min_len: int = DEFAULT_MIN_STRING_LEN, limit: int | None = None):
    """Yield printable ASCII strings of at least *min_len* characters.

    Mirrors ``strings(1)`` defaults (ASCII, min length 4) but bounded: at most
    *limit* strings are produced so a 100 MiB artifact cannot generate millions
    of candidates.
    """
    count = 0
    buf: list[str] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            buf.append(chr(byte))
            continue
        if len(buf) >= min_len:
            yield "".join(buf)
            count += 1
            if limit is not None and count >= limit:
                return
        buf.clear()
    if len(buf) >= min_len:
        yield "".join(buf)


def iter_utf16_strings(
    data: bytes, *, min_len: int = DEFAULT_MIN_STRING_LEN, limit: int | None = None
):
    """Yield UTF-16LE printable strings (what ``strings -el`` finds)."""
    count = 0
    start = None
    chars: list[str] = []
    for i in range(0, len(data) - 1, 2):
        low, high = data[i], data[i + 1]
        if high == 0 and 0x20 <= low <= 0x7E:
            if start is None:
                start = i
            chars.append(chr(low))
        else:
            if len(chars) >= min_len:
                yield "".join(chars)
                count += 1
                if limit is not None and count >= limit:
                    return
            chars = []
            start = None
    if len(chars) >= min_len:
        yield "".join(chars)


def bounded_lines(data: bytes, *, max_bytes: int, min_len: int = 1) -> Iterator[str]:
    """Yield printable lines from at most the first *max_bytes* of *data*."""
    view = data[:max_bytes]
    for raw in view.split(b"\n"):
        cleaned = bytes(b for b in raw if b in _PRINTABLE)
        if len(cleaned) >= min_len:
            yield cleaned.decode("ascii", errors="replace")


def truncate(text: str, limit: int, *, ellipsis: str = "...") -> str:
    """Truncate *text* to *limit* characters, appending an ellipsis when cut."""
    if len(text) <= limit:
        return text
    if limit <= len(ellipsis):
        return text[:limit]
    return text[: limit - len(ellipsis)] + ellipsis


def collapse_ws(text: str) -> str:
    """Collapse whitespace runs into single spaces and strip."""
    return _WS_RUN.sub(" ", text).strip()
