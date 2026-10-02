"""Cryptographic hashing helpers (chunked, bounded memory)."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from badnet.errors import InputError

log = logging.getLogger("badnet.hashing")

#: 1 MiB read size: large enough to keep syscall overhead low, small enough that
#: hashing a 40 GiB capture never allocates more than this at once.
CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class Hashes:
    """The three digests BADNET records for every artifact and input file."""

    md5: str
    sha1: str
    sha256: str

    def to_dict(self) -> dict[str, str]:
        """Serialise for JSON reports and metadata.json."""
        return {"md5": self.md5, "sha1": self.sha1, "sha256": self.sha256}

    @property
    def short(self) -> str:
        """First 12 hex characters of SHA256, for compact terminal output."""
        return self.sha256[:12]

    def as_table_row(self) -> dict[str, str]:
        """Column-name -> digest mapping used by ``badnet hashes``."""
        return {"MD5": self.md5, "SHA1": self.sha1, "SHA256": self.sha256}


def hash_bytes(data: bytes) -> Hashes:
    """Compute MD5/SHA1/SHA256 of an in-memory buffer."""
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    for chunk in _chunks(data):
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
    return Hashes(md5=md5.hexdigest(), sha1=sha1.hexdigest(), sha256=sha256.hexdigest())


def hash_stream(chunks: Iterable[bytes]) -> Hashes:
    """Compute all three digests over an arbitrary iterable of byte chunks."""
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    for chunk in chunks:
        if not chunk:
            continue
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
    return Hashes(md5=md5.hexdigest(), sha1=sha1.hexdigest(), sha256=sha256.hexdigest())


def hash_file(path: str | Path, *, max_bytes: int | None = None) -> Hashes:
    """Hash a file on disk in chunks.

    Parameters
    ----------
    path:
        File to hash.  Not resolved or followed through symlinks by this
        function; the caller is responsible for containment checks.
    max_bytes:
        Optional cap.  When set and the file is larger, an
        :class:`~badnet.errors.InputError` is raised rather than hashing a
        truncated file (a truncated hash would be misleading evidence).
    """
    p = Path(path)
    try:
        with p.open("rb") as fh:
            return hash_stream(_read_capped(fh, p, max_bytes))
    except FileNotFoundError as exc:
        raise InputError(f"file not found: {p}") from exc
    except PermissionError as exc:
        raise InputError(f"permission denied reading {p}") from exc
    except IsADirectoryError as exc:
        raise InputError(f"not a regular file: {p}") from exc
    except OSError as exc:
        raise InputError(f"cannot read {p}: {exc}") from exc


def _read_capped(fh, path: Path, max_bytes: int | None):
    total = 0
    while True:
        chunk = fh.read(CHUNK_SIZE)
        if not chunk:
            return
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise InputError(
                f"{path} is larger than the configured limit "
                f"({total} bytes > {max_bytes}); refusing to produce a partial hash"
            )
        yield chunk


def _chunks(data: bytes):
    for i in range(0, len(data), CHUNK_SIZE):
        yield data[i : i + CHUNK_SIZE]


def short_hash(text: str, length: int = 8) -> str:
    """Stable short hash of a string, used for default case names."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:length]
