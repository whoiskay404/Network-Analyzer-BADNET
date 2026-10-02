"""External tool and library detection, plus the optional ``file``/``strings`` helpers.

Design rules:

* nothing here ever assumes a tool exists - every helper reports degradation;
* ``file``/``strings`` are optional; a pure-Python fallback keeps BADNET useful
  on a bare Kali container and on Windows dev boxes;
* libmagic is optional: python-magic -> ``file(1)`` -> BADNET's own magic table.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
import struct
import zipfile
from dataclasses import dataclass
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from typing import IO, Any

from badnet.errors import ToolError
from badnet.utils.subprocess import ToolStatus, detect_tool, iter_lines, run_tool, which
from badnet.utils.textutil import iter_strings, iter_utf16_strings

log = logging.getLogger("badnet.system")


@dataclass(frozen=True, slots=True)
class MagicEntry:
    """One entry of BADNET's built-in magic table (used when libmagic is absent)."""

    offset: int
    signature: bytes
    label: str
    mime: str
    #: Length of a header field that must also be plausible (0 = skip the check).
    length_field: int = 0


#: Minimal but practical magic table.  Covers everything the extractor reports on.
BUILTIN_MAGIC: tuple[MagicEntry, ...] = (
    MagicEntry(0, b"\x89PNG\r\n\x1a\n", "PNG image data", "image/png"),
    MagicEntry(0, b"\xff\xd8\xff", "JPEG image data", "image/jpeg"),
    MagicEntry(0, b"GIF87a", "GIF image data", "image/gif"),
    MagicEntry(0, b"GIF89a", "GIF image data", "image/gif"),
    MagicEntry(0, b"BM", "PC bitmap image data", "image/bmp", 0),
    MagicEntry(0, b"%PDF-", "PDF document", "application/pdf"),
    MagicEntry(0, b"%!PS", "PostScript document", "application/postscript"),
    MagicEntry(0, b"\x1f\x8b", "gzip compressed data", "application/gzip"),
    MagicEntry(0, b"BZh", "bzip2 compressed data", "application/x-bzip2"),
    MagicEntry(0, b"\xfd7zXZ\x00", "XZ compressed data", "application/x-xz"),
    MagicEntry(0, b"7z\xbc\xaf\x27\x1c", "7-zip archive data", "application/x-7z-compressed"),
    MagicEntry(0, b"Rar!\x1a\x07", "RAR archive data", "application/vnd.rar"),
    MagicEntry(0, b"PK\x03\x04", "Zip archive data", "application/zip"),
    MagicEntry(0, b"PK\x05\x06", "Zip archive data (empty)", "application/zip"),
    MagicEntry(
        0,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "Composite Document File V2 (OLE2)",
        "application/x-ole-storage",
    ),
    MagicEntry(0, b"\x7fELF", "ELF binary", "application/x-executable"),
    MagicEntry(0, b"MZ", "DOS/Windows executable (PE)", "application/x-dosexec"),
    MagicEntry(0, b"SQLite format 3\x00", "SQLite 3.x database", "application/vnd.sqlite3"),
    MagicEntry(0, b"\xca\xfe\xba\xbe", "Java class file", "application/java-vm"),
    MagicEntry(0, b"\xed\xab\xee\xdb", "Berkeley DB file", "application/x-berkeley-db"),
    MagicEntry(0, b"RIFF", "RIFF container (WAV/AVI/WebP)", "application/octet-stream", 0),
    MagicEntry(0, b"OggS", "Ogg data", "application/ogg"),
    MagicEntry(0, b"ID3", "MPEG audio with ID3 tag", "audio/mpeg"),
    MagicEntry(0, b"\xff\xfb", "MPEG audio stream", "audio/mpeg"),
    MagicEntry(0, b"\x00\x00\x01\x00", "Windows icon resource", "image/x-icon"),
    MagicEntry(0, b"{\\rtf", "Rich Text Format data", "application/rtf"),
    MagicEntry(
        0, b"\xd4\xc3\xb2\xa1", "PCAP capture file (little-endian)", "application/vnd.tcpdump.pcap"
    ),
    MagicEntry(
        0, b"\xa1\xb2\xc3\xd4", "PCAP capture file (big-endian)", "application/vnd.tcpdump.pcap"
    ),
    MagicEntry(
        0,
        b"\x4d\x3c\xb2\xa1",
        "PCAP capture file nanosecond resolution",
        "application/vnd.tcpdump.pcap",
    ),
    MagicEntry(
        0,
        b"\xa1\xb2\x3c\x4d",
        "PCAP capture file nanosecond resolution (big-endian)",
        "application/vnd.tcpdump.pcap",
    ),
    MagicEntry(0, b"\x0a\x0d\x0d\x0a", "PCAPNG capture file", "application/x-pcapng"),
    MagicEntry(0, b"\x50\x4b\x03\x04", "Zip archive data", "application/zip"),
    MagicEntry(0, b"-----BEGIN CERTIFICATE-----", "PEM certificate", "application/x-pem-file"),
    MagicEntry(
        0, b"-----BEGIN RSA PRIVATE KEY-----", "PEM RSA private key", "application/x-pem-file"
    ),
    MagicEntry(0, b"-----BEGIN PRIVATE KEY-----", "PEM private key", "application/x-pem-file"),
    MagicEntry(
        0,
        b"-----BEGIN OPENSSH PRIVATE KEY-----",
        "PEM OpenSSH private key",
        "application/x-pem-file",
    ),
    MagicEntry(0, b"\x30\x82", "DER sequence (ASN.1)", "application/pkix-cert", 0),
    MagicEntry(4, b"ftyp", "ISO base media (MP4/MOV)", "video/mp4"),
    MagicEntry(0, b"<?xml ", "XML document text", "text/xml"),
    MagicEntry(0, b"#!", "script text executable", "text/x-script"),
    MagicEntry(0, b"%!PS", "PostScript document", "application/postscript"),
)

#: Application types tshark's ``--export-objects`` can write, in probe order.
EXPORT_PROTOCOLS = ("http", "smb", "dicom", "smtp", "pop", "imap", "tftp", "ftp-data", "imf")


@dataclass(slots=True)
class ToolRegistry:
    """Detected availability of every external tool and optional Python library."""

    tshark: ToolStatus
    capinfos: ToolStatus
    nmap: ToolStatus
    file_cmd: ToolStatus
    strings_cmd: ToolStatus
    tcpdump: ToolStatus
    xxd: ToolStatus
    scapy: bool
    libmagic: bool
    cryptography: bool
    python_version: str

    def to_dict(self) -> dict[str, Any]:
        """Serialise for ``doctor --json`` and metadata.json."""
        return {
            "externals": {
                "tshark": self.tshark.to_dict(),
                "capinfos": self.capinfos.to_dict(),
                "nmap": self.nmap.to_dict(),
                "file": self.file_cmd.to_dict(),
                "strings": self.strings_cmd.to_dict(),
                "tcpdump": self.tcpdump.to_dict(),
                "xxd": self.xxd.to_dict(),
            },
            "packages": {
                "scapy": self.scapy,
                "libmagic": self.libmagic,
                "cryptography": self.cryptography,
                "python": self.python_version,
            },
        }

    def version_strings(self) -> dict[str, str | None]:
        """``tool -> version`` mapping recorded in case metadata."""
        return {
            "tshark": self.tshark.version,
            "capinfos": self.capinfos.version,
            "nmap": self.nmap.version,
            "file": self.file_cmd.version,
            "strings": self.strings_cmd.version,
        }


@lru_cache(maxsize=1)
def detect_all() -> ToolRegistry:
    """Detect every dependency once per process.

    Safe to call with nothing installed: every status simply reports NOT FOUND.
    """
    import sys

    return ToolRegistry(
        tshark=detect_tool("tshark", ["--version"]),
        capinfos=detect_tool("capinfos", ["--version"]),
        nmap=detect_tool("nmap", ["--version"]),
        file_cmd=detect_tool("file", ["--version"]),
        strings_cmd=detect_tool("strings", ["--version"]),
        tcpdump=detect_tool("tcpdump", ["--version"]),
        xxd=detect_tool("xxd", ["-v"]),
        scapy=_module_available("scapy"),
        libmagic=libmagic_available(),
        cryptography=_module_available("cryptography"),
        python_version=sys.version.split()[0],
    )


def package_version(name: str) -> str | None:
    """Installed version of a Python package, or None when absent."""
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None
    except Exception as exc:  # pragma: no cover - broken metadata on disk
        log.debug("cannot read version of %s: %s", name, exc)
        return None


def _module_available(name: str) -> bool:
    try:
        importlib.import_module(name)
    except ImportError:
        return False
    except Exception as exc:  # pragma: no cover - a broken install must not crash us
        log.warning("importing %s failed: %s", name, exc)
        return False
    return True


@lru_cache(maxsize=1)
def libmagic_available() -> bool:
    """True when python-magic *and* libmagic can both be loaded."""
    try:
        import magic
    except ImportError:
        return False
    except Exception as exc:  # libmagic1 shared library missing is an ImportError subclass
        log.debug("python-magic unusable: %s", exc)
        return False
    try:
        import magic

        magic.from_buffer(b"\x89PNG\r\n\x1a\n", mime=False)
    except Exception as exc:  # pragma: no cover - libmagic present but broken
        log.debug("libmagic probe failed: %s", exc)
        return False
    return True


def file_description(data: bytes, *, use_libmagic: bool = True) -> tuple[str, str | None]:
    """Describe a byte buffer, returning ``(description, mime)``.

    Resolution order:

    1. ``libmagic`` via python-magic (if enabled and loadable);
    2. BADNET's built-in magic table, refined for zip containers;
    3. a plain-text heuristic.

    The result is a *description*, never a verdict.
    """
    if not data:
        return "empty", None
    if use_libmagic and libmagic_available():
        try:
            import magic

            desc = magic.from_buffer(data[:4096])
            mime = magic.from_buffer(data[:4096], mime=True)
            return str(desc), str(mime)
        except Exception as exc:  # libmagic can fail on arbitrary bytes
            log.debug("libmagic failed, falling back: %s", exc)

    built = builtin_guess(data)
    if built is not None:
        desc, mime = built
        return desc, mime
    if _looks_text(data):
        return "ASCII text", "text/plain"
    return "data", None


def builtin_guess(data: bytes) -> tuple[str, str] | None:
    """Match *data* against :data:`BUILTIN_MAGIC`, refining container types."""
    for entry in BUILTIN_MAGIC:
        if len(data) < entry.offset + len(entry.signature):
            continue
        if data[entry.offset : entry.offset + len(entry.signature)] != entry.signature:
            continue
        if entry.mime == "application/zip":
            refined = _describe_zip(data)
            if refined:
                return refined
        if entry.mime == "image/x-icon":
            return "Windows icon resource", "image/x-icon"
        return entry.label, entry.mime
    return None


def _describe_zip(data: bytes) -> tuple[str, str] | None:
    """Identify OOXML/OpenDocument/JAR families by their zip entry names."""
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            names = set(zf.namelist())
    except (zipfile.BadZipFile, OSError, ValueError, MemoryError, NotImplementedError):
        return None
    if not names:
        return "Zip archive data", "application/zip"
    if "word/document.xml" in names:
        return (
            "Microsoft Word 2007+ (OOXML) document",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    if "xl/workbook.xml" in names:
        return (
            "Microsoft Excel 2007+ (OOXML) spreadsheet",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    if "ppt/presentation.xml" in names:
        return (
            "Microsoft PowerPoint 2007+ (OOXML) presentation",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        )
    if "mimetype" in names:
        # OpenDocument stores its type uncompressed as the first entry.
        try:
            kind = zf.read("mimetype")[:128].decode("ascii", errors="replace")
        except (KeyError, zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as exc:
            log.debug("cannot read ODF mimetype entry: %s", exc)
            kind = ""
        if kind.startswith("application/vnd.oasis.opendocument."):
            return f"OpenDocument ({kind.rsplit('.', 1)[-1]})", kind
        return "Zip archive data", "application/zip"
    if any(n.endswith(".class") for n in names):
        return "Java archive (JAR)", "application/java-archive"
    if any(n.startswith("AndroidManifest.xml") for n in names):
        return "Android package (APK)", "application/vnd.android.package-archive"
    if (
        any(n.startswith("_rels/") or n.endswith(".rels") for n in names)
        and "[Content_Types].xml" in names
    ):
        return "OpenDocument / OOXML package", "application/zip"
    if "[Content_Types].xml" in names:
        return "Office Open XML package", "application/zip"
    return "Zip archive data", "application/zip"


def _looks_text(data: bytes, sample: int = 4096) -> bool:
    view = data[:sample]
    if not view:
        return False
    if b"\x00" in view:
        return False
    printable = sum(1 for b in view if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return printable / len(view) >= 0.85


def file_description_path(path: Path, *, use_libmagic: bool = True) -> tuple[str, str | None]:
    """Describe a file on disk, using the ``file(1)`` binary when available."""
    binary = which("file")
    if binary:
        try:
            res = run_tool(
                [binary, "-b", "--mime-type", str(path)], timeout=20, max_output=64 * 1024
            )
            mime = res.text().strip()
            res2 = run_tool([binary, "-b", str(path)], timeout=20, max_output=64 * 1024)
            desc = res2.text().strip()
            if desc or mime:
                return (desc or "data"), (mime or None)
        except ToolError as exc:
            log.debug("file(1) failed for %s: %s", path, exc)
    try:
        with path.open("rb") as fh:
            head = fh.read(8192)
    except OSError as exc:
        log.warning("cannot read %s for type detection: %s", path, exc)
        return "unreadable", None
    return file_description(head, use_libmagic=use_libmagic)


def extract_strings(
    path: Path,
    *,
    min_len: int = 4,
    max_bytes: int = 8 * 1024 * 1024,
    limit: int = 5000,
    use_binary: bool = True,
):
    """Yield printable strings from a file.

    Uses ``strings(1)`` when available (it is C-fast and well tested), otherwise
    the equivalent pure-Python implementation.  Output is bounded by *limit* and
    the input is capped at *max_bytes*.
    """
    if use_binary:
        binary = which("strings")
        if binary:
            args = [binary, "-a", "-n", str(min_len), "-t", "d"]
            try:
                for seen, line in enumerate(
                    iter_lines([*args, str(path)], timeout=120, max_output=max_bytes * 4)
                ):
                    offset, _, text = line.partition(" ")
                    yield int(offset) if offset.isdigit() else 0, text
                    if seen + 1 >= limit:
                        return
                return
            except (ToolError, ValueError) as exc:
                log.debug("strings(1) failed on %s (%s); using built-in scanner", path, exc)

    try:
        data = path.read_bytes()[:max_bytes]
    except OSError as exc:
        raise ToolError(f"cannot read {path} for string extraction: {exc}") from exc
    for offset, text in _python_strings(data, min_len=min_len, limit=limit):
        yield offset, text


def _python_strings(data: bytes, *, min_len: int, limit: int):
    buf: list[str] = []
    start = 0
    count = 0
    for index, byte in enumerate(data):
        if 0x20 <= byte <= 0x7E:
            if not buf:
                start = index
            buf.append(chr(byte))
            continue
        if len(buf) >= min_len:
            yield start, "".join(buf)
            count += 1
            if count >= limit:
                return
        buf.clear()
    if len(buf) >= min_len:
        yield start, "".join(buf)


def iter_all_strings(data: bytes, *, min_len: int = 4, limit: int = 5000):
    """Yield ``(offset, text)`` for ASCII and UTF-16LE strings, bounded."""
    count = 0
    offset = 0
    for text in iter_strings(data, min_len=min_len, limit=limit):
        yield offset, text
        count += 1
        offset += len(text)
        if count >= limit:
            return
    for text in iter_utf16_strings(data, min_len=min_len, limit=limit - count):
        yield offset, text


def open_zip_safely(data: bytes, *, max_ratio: int, max_size: int) -> zipfile.ZipFile | None:
    """Open a zip from memory with decompression-bomb guards.

    Returns ``None`` when the archive is malformed or would expand beyond
    *max_size* / *max_ratio*.  Never extracts anything itself.
    """
    try:
        zf = zipfile.ZipFile(BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError):
        return None
    compressed = sum(max(1, i.compress_size) for i in zf.infolist())
    uncompressed = sum(i.file_size for i in zf.infolist())
    if uncompressed > max_size:
        log.warning("zip archive declares %d bytes, limit is %d", uncompressed, max_size)
        return None
    if compressed and uncompressed / compressed > max_ratio:
        log.warning(
            "zip archive expansion ratio %.1f:1 exceeds limit %d:1",
            uncompressed / compressed,
            max_ratio,
        )
        return None
    return zf


def png_dimensions(data: bytes) -> tuple[int, int] | None:
    """Read width/height from a PNG IHDR chunk (no image library needed)."""
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    if data[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", data[16:24])
    return int(width), int(height)


def read_head(path: Path | str, size: int = 4096) -> bytes:
    """Read at most *size* bytes from the start of a file."""
    with Path(path).open("rb") as fh:
        return fh.read(size)


def stream_handle(path: Path, mode: str = "rb") -> IO[Any]:  # pragma: no cover - thin wrapper
    """Open a file, raising a :class:`ToolError` with a clear message on failure."""
    try:
        return Path(path).open(mode)
    except FileNotFoundError as exc:
        raise ToolError(f"file not found: {path}") from exc
    except PermissionError as exc:
        raise ToolError(f"permission denied: {path}") from exc
    except OSError as exc:
        raise ToolError(f"cannot open {path}: {exc}") from exc
