"""Magic-byte carver: recover candidate files from reassembled stream payload.

This is deliberately *carving*, not parsing.  A carver does not understand the
protocol that carried the bytes; it finds file signatures and guesses where each
file ends.  Two consequences are baked into the output rather than hidden:

* every artifact's ``notes`` record whether it stopped at the next signature or
  ran to the end of what was captured (``end-of-stream``);
* a reassembled stream can contain **holes** where packets were never captured.
  Carving across a hole produces a file with a run of zero bytes in the middle
  that no parser will accept.  When the caller knows the stream had gaps it can
  pass ``missing_bytes`` so that warning is carried on every carved artifact.

No bytes are ever executed, parsed with ``eval``, or interpreted as code.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from badnet.integrations.system_tools import BUILTIN_MAGIC, MagicEntry
from badnet.models.artifact import Artifact, ExtractionMethod
from badnet.utils.hashing import hash_bytes
from badnet.utils.logging import get_logger

log = get_logger("analyzer.extract")

#: Extensions used when saving a carved object, keyed by MIME type.  Only used to
#: make the saved file readable; the MIME is the authoritative type.
_MIME_EXT: dict[str, str] = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/gif": "gif",
    "image/bmp": "bmp",
    "image/x-icon": "ico",
    "application/pdf": "pdf",
    "application/postscript": "ps",
    "application/gzip": "gz",
    "application/x-bzip2": "bz2",
    "application/x-xz": "xz",
    "application/x-7z-compressed": "7z",
    "application/vnd.rar": "rar",
    "application/zip": "zip",
    "application/x-ole-storage": "ole",
    "application/x-executable": "elf",
    "application/x-dosexec": "exe",
    "application/vnd.sqlite3": "sqlite",
    "application/java-vm": "class",
    "application/ogg": "ogg",
    "audio/mpeg": "mp3",
    "application/rtf": "rtf",
    "application/vnd.tcpdump.pcap": "pcap",
    "application/x-pcapng": "pcapng",
}


@dataclass(slots=True)
class _Match:
    offset: int
    entry: MagicEntry


def _signature_matches(data: bytes, magic: tuple[MagicEntry, ...]) -> list[_Match]:
    """Find every magic-signature occurrence in *data*, earliest offset first.

    When two signatures overlap at the same offset the longer one wins, so a
    ``PK\\x03\\x04`` zip does not also register as the shorter ``PK`` alias.
    """
    matches: list[_Match] = []
    for entry in magic:
        sig = entry.signature
        if not sig:
            continue
        start = data.find(sig)
        while start != -1:
            matches.append(_Match(start, entry))
            start = data.find(sig, start + 1)
    matches.sort(key=lambda m: (m.offset, -len(m.entry.signature)))
    deduped: list[_Match] = []
    for match in matches:
        if deduped and match.offset == deduped[-1].offset:
            continue  # same start, shorter signature: keep the first (longest)
        deduped.append(match)
    return deduped


def carve(
    data: bytes,
    *,
    stream_id: int = 0,
    direction: str = "",
    magic: tuple[MagicEntry, ...] = BUILTIN_MAGIC,
    max_object_bytes: int = 64 * 1024 * 1024,
    max_objects: int = 256,
    missing_bytes: int = 0,
) -> list[Artifact]:
    """Carve objects out of one reassembled direction of a stream.

    Parameters
    ----------
    data:
        Reassembled payload.  Holes in the reconstruction are already zero-filled.
    max_object_bytes:
        An object longer than this is stored truncated, with ``truncated=True``.
    max_objects:
        Stop after this many objects to bound work on adversarial input.
    missing_bytes:
        Recorded in ``notes`` so a reader knows the reconstruction had holes.

    Returns
    -------
    list[Artifact]
        Objects in file order.  ``stored_path`` is unset here; persisting is the
        caller's job (:func:`store`).
    """
    if not data:
        return []

    matches = _signature_matches(data, magic)
    artifacts: list[Artifact] = []

    for index, match in enumerate(matches):
        if len(artifacts) >= max_objects:
            log.info(
                "stream %d %s: stopping carve at %d object(s) (max_objects)",
                stream_id,
                direction,
                max_objects,
            )
            break

        next_offset = matches[index + 1].offset if index + 1 < len(matches) else len(data)
        end_reason = "next-magic" if index + 1 < len(matches) else "end-of-stream"

        size = next_offset - match.offset
        if size <= 0:
            continue

        truncated = size > max_object_bytes
        if truncated:
            size = max_object_bytes

        notes = [
            f"carved by magic signature {match.entry.signature!r} "
            f"({match.entry.label}) at offset {match.offset}",
            f"boundary decided by {end_reason}; carving is a guess, not a parse",
        ]
        if missing_bytes:
            notes.append(
                f"the reassembled stream had {missing_bytes} byte(s) never captured; "
                "an object spanning a hole contains zero padding and is likely corrupt"
            )
        if truncated:
            notes.append(f"object exceeded {max_object_bytes} byte cap and was truncated")

        artifacts.append(
            Artifact(
                name="",  # filled in by store()
                detected_type=match.entry.label,
                mime=match.entry.mime,
                size=size,
                method=ExtractionMethod.MAGIC_CARVE,
                stream_id=stream_id,
                protocol="tcp",
                source=f"tcp-stream-{stream_id}" if stream_id else "tcp-stream",
                offset=match.offset,
                truncated=truncated,
                notes=notes,
            )
        )

    return artifacts


def store(
    artifacts: list[Artifact],
    data: bytes,
    *,
    stream_id: int,
    direction: str,
    files_dir: Path,
    max_object_bytes: int = 64 * 1024 * 1024,
) -> list[Artifact]:
    """Write carved artifacts into *files_dir*, filling in names, hashes and paths.

    *data* is the same reassembled direction :func:`carve` was run over, so the
    bytes on disk are always the bytes the offsets refer to.  Names are derived
    from the stream, direction and offset rather than from anything the capture
    claims, so a hostile capture cannot choose a filename (and therefore cannot
    traverse out of ``files/``).
    """
    from badnet.utils.filesystem import harden_file, safe_join

    files_dir.mkdir(parents=True, exist_ok=True)
    written: list[Artifact] = []

    for artifact in artifacts:
        offset = artifact.offset or 0
        blob = data[offset : offset + artifact.size]
        if not blob:
            continue
        ext = _MIME_EXT.get(artifact.mime or "", "bin")
        safe_direction = direction or "unknown"
        name = f"stream{stream_id}_{safe_direction}_{offset:08x}.{ext}"
        target = safe_join(files_dir, name)

        # Never overwrite an existing carve: an earlier run's bytes are evidence.
        if target.exists():
            stem, suffix = target.stem, target.suffix
            n = 1
            while target.exists():
                target = safe_join(files_dir, f"{stem}_{n}{suffix}")
                n += 1

        try:
            target.write_bytes(blob)
            harden_file(target)
        except OSError as exc:
            log.warning("cannot write carved artifact %s: %s", target, exc)
            continue

        hashes = hash_bytes(blob[:max_object_bytes])
        artifact.name = target.name
        artifact.stored_path = target.name
        artifact.md5 = hashes.md5
        artifact.sha256 = hashes.sha256
        written.append(artifact)

    return written
