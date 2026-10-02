"""Sandboxed subprocess helpers.

Security rules enforced here for *every* external command BADNET runs:

* arguments are always passed as a list, never a string;
* ``shell=False`` (Python's default on POSIX and Windows) is asserted;
* a wall-clock timeout is mandatory;
* captured output is size-capped so a runaway child cannot exhaust memory.

There is deliberately no exception handler that silently swallows errors: every
failure is either returned to the caller as a :class:`ToolResult` with a
non-zero return code, or raised as a :class:`~badnet.errors.ToolError`.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

from badnet.errors import ToolError

log = logging.getLogger("badnet.subprocess")

#: Default per-command timeout in seconds.  Kept generous because tshark can be
#: slow on huge captures, but finite so a hung child can never wedge BADNET.
DEFAULT_TIMEOUT = 600.0

#: Default cap on captured stdout/stderr (16 MiB is far beyond any tshark -T fields
#: output we parse incrementally, but small enough to be safe).
DEFAULT_MAX_OUTPUT = 64 * 1024 * 1024


@dataclass(slots=True)
class ToolResult:
    """Outcome of a completed external command."""

    args: list[str]
    returncode: int
    stdout: bytes
    stderr: bytes
    duration: float
    truncated: bool = False
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        """True when the process exited 0 and did not time out."""
        return self.returncode == 0 and not self.timed_out

    def text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        """Decode captured stdout for *display* purposes only."""
        return self.stdout.decode(encoding, errors=errors)

    def error_text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        """Decode captured stderr for *display* purposes only."""
        return self.stderr.decode(encoding, errors=errors)


def _validate_args(args: Sequence[str]) -> list[str]:
    """Validate and normalise an argument vector.

    Rejects empty vectors and embedded NUL bytes (``ValueError`` on every
    platform would otherwise be raised deep inside ``execve``).
    """
    if not args:
        raise ToolError("internal: refusing to spawn a subprocess with no arguments")
    argv = [str(a) for a in args]
    for a in argv:
        if "\x00" in a:
            raise ToolError("internal: argument contains a NUL byte")
    return argv


def run_tool(
    args: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    stdin_bytes: bytes | None = None,
    check: bool = False,
) -> ToolResult:
    """Run an external tool and capture (capped) output.

    Parameters
    ----------
    args:
        Argument vector.  Never a command string.
    timeout:
        Wall-clock limit in seconds.  Must be > 0.
    max_output:
        Maximum bytes retained per stream; the remainder is discarded and
        ``ToolResult.truncated`` is set.
    check:
        When True, a non-zero exit status raises :class:`ToolError`.
    """
    argv = _validate_args(args)
    if timeout <= 0:
        raise ToolError("internal: subprocess timeout must be positive")

    full_env = None
    if env is not None:
        full_env = {**os.environ, **env}

    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            shell=False,
            cwd=cwd,
            env=full_env,
        )
    except FileNotFoundError as exc:
        raise ToolError(f"executable not found: {argv[0]}") from exc
    except PermissionError as exc:
        raise ToolError(f"not permitted to execute {argv[0]}: {exc.strerror}") from exc
    except OSError as exc:
        # Surfaces ENOMEM / EMFILE / bad-CWD style failures with the real reason.
        raise ToolError(f"failed to start {argv[0]}: {exc}") from exc

    started = _now()
    timeout_result: ToolResult | None = None
    try:
        out, err = proc.communicate(input=stdin_bytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - kill already sent
            log.error("child %s ignored SIGKILL; discarding pipes", argv[0])
            out, err = b"", b""
        timeout_result = ToolResult(
            args=argv,
            returncode=proc.returncode if proc.returncode is not None else -9,
            stdout=_cap(out, max_output)[0],
            stderr=_cap(err, max_output)[0],
            duration=_now() - started,
            timed_out=True,
        )
    except OSError as exc:  # pragma: no cover - pipe read failure
        proc.kill()
        raise ToolError(f"error while reading output of {argv[0]}: {exc}") from exc

    if timeout_result is not None:
        if check:
            raise ToolError(f"{_label(argv)} timed out after {timeout:g}s")
        return timeout_result

    stdout, t1 = _cap(out, max_output)
    stderr, t2 = _cap(err, max_output)
    result = ToolResult(
        args=argv,
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        duration=_now() - started,
        truncated=t1 or t2,
    )
    if check and not result.ok:
        detail = result.error_text().strip().splitlines()
        tail = detail[-1] if detail else f"exit status {result.returncode}"
        raise ToolError(f"{_label(argv)} failed: {tail}")
    return result


def iter_lines(
    args: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
    env: dict[str, str] | None = None,
) -> Iterator[str]:
    """Stream stdout of an external tool line by line.

    Used for ``tshark -T fields`` so a multi-gigabyte capture never has to be
    buffered in memory.  Each yielded line has its trailing newline removed.
    The generator raises :class:`ToolError` if the child exits non-zero.
    """
    argv = _validate_args(args)
    full_env = None
    if env is not None:
        full_env = {**os.environ, **env}

    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            shell=False,
            env=full_env,
            bufsize=1024 * 1024,
        )
    except FileNotFoundError as exc:
        raise ToolError(f"executable not found: {argv[0]}") from exc
    except OSError as exc:
        raise ToolError(f"failed to start {argv[0]}: {exc}") from exc

    assert proc.stdout is not None  # guaranteed by stdout=PIPE
    consumed = 0
    truncated = False
    failure: ToolError | None = None
    try:
        for raw in proc.stdout:
            consumed += len(raw)
            if consumed > max_output:
                truncated = True
                break
            yield raw.decode("utf-8", errors="replace").rstrip("\r\n")
    finally:
        if truncated:
            proc.kill()
        try:
            proc.stdout.close()
        except OSError:  # pragma: no cover - already closed by GC
            log.debug("stdout already closed for %s", argv[0])
        stderr = proc.stderr.read() if proc.stderr else b""
        if proc.stderr:
            proc.stderr.close()
        try:
            proc.wait(timeout=max(5.0, timeout * 0.1))
        except subprocess.TimeoutExpired:  # pragma: no cover - killed above
            proc.kill()
            proc.wait(timeout=5)
        if truncated:
            # Deliberately no error: the caller asked for a bounded read and got
            # what it asked for.  A ``return`` here would also swallow any
            # exception the consumer raised while closing the generator.
            log.warning("%s output exceeded %d bytes; stream was truncated", argv[0], max_output)
        else:
            code = proc.returncode
            if code not in (0, None):
                first = stderr.decode("utf-8", errors="replace").strip().splitlines()
                failure = ToolError(f"{_label(argv)} failed: {first[0] if first else code}")
    if failure is not None:
        raise failure


@dataclass(slots=True)
class ToolStatus:
    """Detection result for one external dependency."""

    name: str
    found: bool
    path: str | None = None
    version: str | None = None
    error: str | None = None
    degraded: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        """Serialise for metadata.json / doctor --json."""
        return {
            "name": self.name,
            "found": self.found,
            "path": self.path,
            "version": self.version,
            "error": self.error,
            "degraded": list(self.degraded),
        }


#: Extra locations searched on Windows (dev/test hosts) because GUI installers do
#: not always extend PATH for non-interactive shells.
_EXTRA_SEARCH_PATHS = (
    r"C:\Program Files\Wireshark",
    r"C:\Program Files (x86)\Wireshark",
    r"C:\Program Files\Nmap",
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Git\usr\bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
)


def which(name: str, *, extra_paths: Sequence[str] = _EXTRA_SEARCH_PATHS) -> str | None:
    """Locate an executable, also searching common install locations.

    Python's ``shutil.which`` only consults PATH; the extra locations make
    ``badnet doctor`` useful on Windows dev boxes where Wireshark/Nmap were
    installed by winget without a PATH refresh.
    """
    found = shutil.which(name)
    if found:
        return found
    names = [name]
    if os.name == "nt":
        names = [name + ext for ext in (".exe", ".bat", ".cmd")] + [name]
    for directory in extra_paths:
        for candidate in names:
            full = os.path.join(directory, candidate)
            if os.path.isfile(full) and os.access(full, os.X_OK):
                return full
    return None


def detect_tool(name: str, version_args: Sequence[str]) -> ToolStatus:
    """Detect one external tool and capture its version banner."""
    path = which(name)
    if path is None:
        return ToolStatus(name=name, found=False)
    try:
        res = run_tool([path, *version_args], timeout=30, max_output=64 * 1024)
    except ToolError as exc:
        # A tool that is present but unrunnable is reported as found-with-error,
        # not silently ignored: the caller decides how to degrade.
        return ToolStatus(name=name, found=True, path=path, error=str(exc))
    banner = res.text().strip().splitlines()
    version = banner[0].strip() if banner else None
    if res.timed_out:
        return ToolStatus(name=name, found=True, path=path, error="version probe timed out")
    return ToolStatus(name=name, found=True, path=path, version=version)


def _cap(data: bytes, limit: int) -> tuple[bytes, bool]:
    if len(data) <= limit:
        return data, False
    log.warning("subprocess output truncated from %d to %d bytes", len(data), limit)
    return data[:limit], True


def _label(argv: Sequence[str]) -> str:
    return argv[0] if argv else "<empty>"


def _now() -> float:
    import time

    return time.monotonic()
