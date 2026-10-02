"""``badnet doctor`` - dependency report.

States FOUND / NOT FOUND with a version for every dependency, and - crucially -
what BADNET loses when each one is missing.  Never crashes on a missing optional
dependency.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from badnet import __version__
from badnet.errors import ExitCode
from badnet.integrations import system_tools
from badnet.utils.subprocess import detect_tool

if TYPE_CHECKING:  # pragma: no cover
    from badnet.cli import RunContext


@dataclass(frozen=True, slots=True)
class Requirement:
    """One line of the doctor report."""

    name: str
    kind: str
    """``python``, ``package`` or ``tool``."""
    found: bool
    version: str | None
    path: str | None
    required: bool
    degrades: str
    fix: str = ""


#: What BADNET loses without each dependency.  Kept explicit so the report can be
#: honest instead of a wall of FOUND/NOT FOUND.
DEGRADES: dict[str, tuple[str, str]] = {
    "python": ("", "Kali ships Python 3; BADNET needs 3.12+"),
    "scapy": (
        "no packet reading at all (tshark also missing) and no Scapy-based stream carving",
        "pip install scapy  (or: sudo apt install python3-scapy)",
    ),
    "rich": ("plain-text output with no tables or colours", "pip install rich"),
    "typer": ("the CLI cannot start", "pip install typer"),
    "cryptography": (
        "no X.509 certificate parsing; TLS reports show no subject/issuer/validity",
        "pip install cryptography",
    ),
    "python-magic": (
        "file type detection falls back to the file(1) binary and then BADNET's built-in table",
        "pip install python-magic  +  sudo apt install libmagic1",
    ),
    "tshark": (
        "the fast path is unavailable: BADNET falls back to Scapy (no certificate parsing, "
        "reduced HTTP/TLS dissection, no --export-objects, slower on large captures)",
        "sudo apt install tshark   (no capture privileges are needed for PCAP files)",
    ),
    "capinfos": (
        "packet counts, timestamps and protocol hierarchy are computed by BADNET instead "
        "(slower, and the numbers may differ slightly from tshark's own)",
        "sudo apt install wireshark-common  (ships with tshark)",
    ),
    "nmap": (
        "'badnet scan' is unavailable; every other command still works",
        "sudo apt install nmap",
    ),
    "file": (
        "artifact type detection relies on libmagic or BADNET's built-in magic table only",
        "sudo apt install file",
    ),
    "strings": (
        "string extraction uses BADNET's built-in scanner (same output, slower on large files)",
        "sudo apt install binutils",
    ),
    "tcpdump": (
        "no raw packet triage helper; not required for any command",
        "sudo apt install tcpdump",
    ),
    "xxd": ("hex previews are rendered by BADNET itself", "sudo apt install xxd"),
}


def collect() -> list[Requirement]:
    """Detect every dependency and describe any degradation."""
    import platform
    import sys

    out: list[Requirement] = []

    py_ok = sys.version_info >= (3, 12)
    out.append(
        Requirement(
            name="python",
            kind="python",
            found=py_ok,
            version=platform.python_version(),
            path=sys.executable,
            required=True,
            degrades=DEGRADES["python"][0] if not py_ok else "",
            fix=DEGRADES["python"][1] if not py_ok else "",
        )
    )

    packages = (
        ("typer", "typer", True),
        ("rich", "rich", False),
        ("scapy", "scapy", True),
        ("cryptography", "cryptography", False),
    )
    for name, key, required in packages:
        version = system_tools.package_version(name)
        out.append(
            Requirement(
                name=name,
                kind="package",
                found=version is not None,
                version=version,
                path=None,
                required=required,
                degrades=DEGRADES[key][0] if version is None else "",
                fix=DEGRADES[key][1] if version is None else "",
            )
        )

    # python-magic is only usable when the native libmagic library actually loads;
    # importing the Python wrapper succeeds even without libmagic on some systems.
    magic_version = system_tools.package_version("python-magic")
    magic_ok = system_tools.libmagic_available()
    if magic_ok:
        magic_version = magic_version or "system libmagic"
    out.append(
        Requirement(
            name="python-magic",
            kind="package",
            found=magic_ok,
            version=magic_version if magic_ok else None,
            path=None,
            required=False,
            degrades="" if magic_ok else DEGRADES["python-magic"][0],
            fix="" if magic_ok else DEGRADES["python-magic"][1],
        )
    )

    tools = (
        ("tshark", ["--version"], False),
        ("capinfos", ["--version"], False),
        ("nmap", ["--version"], False),
        ("file", ["--version"], False),
        ("strings", ["--version"], False),
        ("tcpdump", ["--version"], False),
        ("xxd", ["-v"], False),
    )
    for name, args, required in tools:
        status = detect_tool(name, args)
        out.append(
            Requirement(
                name=name,
                kind="tool",
                found=status.found and not status.error,
                version=status.version if status.found else None,
                path=status.path,
                required=required,
                degrades="" if (status.found and not status.error) else DEGRADES[name][0],
                fix=DEGRADES[name][1] if not (status.found and not status.error) else "",
            )
        )
    return out


def short_version(name: str, raw: str | None) -> str:
    """Reduce a ``--version`` banner to ``"<tool> <version>"``.

    ``tshark --version`` prints ``TShark (Wireshark) 4.6.8 (v4.6.8-0-ge677bf052328).``
    and ``nmap --version`` prints a URL on the same line; neither helps in a table.
    """
    if not raw or raw == "-":
        return "-"
    match = re.search(r"\d+\.\d+(?:\.\d+)*", raw)
    if match:
        return f"{name} {match.group(0)}"
    return raw.splitlines()[0].strip()


def run(ctx: RunContext) -> None:
    """Print the doctor report (or JSON with ``--json``)."""
    requirements = collect()
    registry = system_tools.detect_all()
    missing_required = [r for r in requirements if r.required and not r.found]

    if ctx.g.wants_json:
        ctx.emit_json(
            {
                "badnet": __version__,
                "requirements": [
                    {
                        "name": r.name,
                        "kind": r.kind,
                        "found": r.found,
                        "version": r.version,
                        "path": r.path,
                        "required": r.required,
                        "degrades": r.degrades,
                        "fix": r.fix,
                    }
                    for r in requirements
                ],
                "reader": "tshark"
                if registry.tshark.found
                else ("scapy" if registry.scapy else None),
                "capable": not missing_required,
            }
        )
        return

    console = ctx.console()
    ctx.banner("environment check")
    from rich.table import Table

    table = Table(box=None, pad_edge=False, padding=(0, 1, 0, 0), header_style="bold")
    table.add_column("component", style="cyan", no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("version", overflow="fold", max_width=38)
    table.add_column("notes", overflow="fold")

    for req in requirements:
        if req.found:
            status = "[green]FOUND    [/green]"
        elif req.required:
            status = "[bold red]NOT FOUND[/bold red]"
        else:
            status = "[yellow]NOT FOUND[/yellow]"
        version = req.version or "-"
        if req.kind == "tool" and req.found:
            version = short_version(req.name, version)
        note = req.degrades
        table.add_row(req.name, status, version, note if note else "")
    console.print()
    console.print(table)

    reader = (
        "tshark (fast path)"
        if registry.tshark.found
        else ("scapy (fallback, reduced features)" if registry.scapy else "none")
    )
    console.print()
    console.print(f"  reader: [cyan]{reader}[/cyan]")
    if missing_required:
        console.print(
            f"  [bold red]missing required dependency:[/bold red] "
            f"{', '.join(r.name for r in missing_required)}"
        )
        for req in missing_required:
            if req.fix:
                console.print(f"    fix: {req.fix}")
        import typer

        raise typer.Exit(code=int(ExitCode.MISSING_DEPENDENCY))
    console.print(
        "  [green]BADNET is ready.[/green] "
        "Missing optional components only reduce detail; see the notes above."
    )
