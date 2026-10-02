"""Cli layer: Typer commands, global options and error handling.

No Python traceback ever reaches the user in normal operation: every expected
failure is a :class:`~badnet.errors.BadnetError` with a one-line message and an
exit code from :class:`~badnet.errors.ExitCode`.  ``--debug`` restores full
tracebacks and the debug log.
"""

from __future__ import annotations

import functools
import inspect
import json
import sys
import typing
from pathlib import Path
from typing import Any, NoReturn

import typer

from badnet import TOOL_NAME, TOOL_TAGLINE, __version__
from badnet.config import Config
from badnet.errors import BadnetError, ExitCode, UsageError
from badnet.utils.logging import is_debug, setup_logging

# --------------------------------------------------------------------------- app

app = typer.Typer(
    name="badnet",
    help=(
        f"{TOOL_NAME} v{__version__} - {TOOL_TAGLINE}\n\n"
        "Passive network forensics for authorised CTFs and lab captures. "
        "Only analyse systems you own or have explicit permission to test."
    ),
    epilog=(
        "Global options: these are accepted by every command and go AFTER the "
        "subcommand, e.g. `badnet info --json capture.pcap`. Run "
        "`badnet <command> --help` for the full list."
    ),
    add_completion=False,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 100},
)

# --------------------------------------------------------------- global options


def _global_options() -> dict[str, tuple[Any, Any]]:
    """The option set shared by every command.

    Defined once and injected into each command signature by :func:`with_globals`
    so the flags can never drift apart between commands.  Each entry is
    ``(option_info, annotation)``: the annotation is explicit because Typer
    resolves parameter types through :func:`typing.get_type_hints`.
    """
    return {
        "output_dir": (
            typer.Option(
                None, "--output-dir", metavar="DIR", help="Where case directories are created."
            ),
            str | None,
        ),
        "case_name": (
            typer.Option(
                None, "--case", metavar="NAME", help="Case name (default: <file stem>-<hash>)."
            ),
            str | None,
        ),
        "force": (
            typer.Option(
                False,
                "--force",
                help="Re-analyse into an existing case directory (evidence is kept).",
            ),
            bool,
        ),
        "max_packets": (
            typer.Option(None, "--max-packets", metavar="N", help="Stop after N packets."),
            int | None,
        ),
        "verbose": (
            typer.Option(False, "--verbose", "-v", help="Show unredacted secrets and INFO logs."),
            bool,
        ),
        "no_color": (typer.Option(False, "--no-color", help="Disable colour output."), bool),
        "quiet": (typer.Option(False, "--quiet", "-q", help="Only warnings and errors."), bool),
        "debug": (
            typer.Option(False, "--debug", help="Full tracebacks and a debug log file."),
            bool,
        ),
        "config": (
            typer.Option(None, "--config", metavar="FILE", help="YAML config file to load."),
            str | None,
        ),
        "json_output": (
            typer.Option(
                False, "--json", help="Emit machine-readable JSON on stdout (no banner/progress)."
            ),
            bool,
        ),
        "limit": (
            typer.Option(None, "--limit", metavar="N", help="Maximum rows to display."),
            int | None,
        ),
    }


def with_globals(fn):
    """Inject the global options into *fn* and pass them as one object.

    Typer reads both ``inspect.signature`` and :func:`typing.get_type_hints` of
    the decorated function, so we rebuild the two together with keyword-only
    ``Option`` parameters and wrap the body to collect them into a
    :class:`Globals` instance.  Every command therefore has an identical flag
    set by construction.
    """
    original = inspect.signature(fn)

    # ``from __future__ import annotations`` leaves every annotation as a string,
    # e.g. ``capture`` is literally annotated ``"Path"``.  Typer normally
    # resolves those through ``inspect.signature(..., eval_str=True)``, but on
    # Python 3.14 (PEP 649 lazy annotations) the string can reach Typer
    # unresolved, and it rejects it with "Type not yet supported: Path" before
    # any command runs.  Resolve them to real objects here so no downstream
    # version-specific string evaluation is needed.
    try:
        resolved_hints = typing.get_type_hints(fn)
    except NameError:  # pragma: no cover - defensive, keeps registration working
        resolved_hints = {}

    new_params: list[inspect.Parameter] = []
    annotations: dict[str, Any] = {}
    for name, param in original.parameters.items():
        if name == "globals":
            continue
        annotation = resolved_hints.get(name, param.annotation)
        new_params.append(param.replace(annotation=annotation))
        annotations[name] = annotation

    options = _global_options()
    for name, (option, annotation) in options.items():
        new_params.append(
            inspect.Parameter(
                name, inspect.Parameter.KEYWORD_ONLY, default=option, annotation=annotation
            )
        )
        annotations[name] = annotation
    fn.__signature__ = original.replace(parameters=new_params)

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        globals_obj = Globals(**{name: kwargs.pop(name) for name in options})
        return fn(*args, globals=globals_obj, **kwargs)

    wrapper.__annotations__ = annotations  # type: ignore[attr-defined]
    wrapper.__globals_names__ = tuple(options)  # type: ignore[attr-defined]
    return wrapper


class Globals:
    """Resolved global options for one invocation."""

    __slots__ = (
        "case_name",
        "config",
        "debug",
        "force",
        "json_output",
        "limit",
        "max_packets",
        "no_color",
        "output_dir",
        "quiet",
        "verbose",
    )

    def __init__(self, **kwargs: Any) -> None:
        for name in self.__slots__:
            setattr(self, name, kwargs.get(name))
        # Normalise
        self.force = bool(self.force)
        self.verbose = bool(self.verbose)
        self.no_color = bool(self.no_color)
        self.quiet = bool(self.quiet)
        self.debug = bool(self.debug)
        self.json_output = bool(self.json_output)
        if self.max_packets is not None:
            try:
                self.max_packets = int(self.max_packets)
            except (TypeError, ValueError):
                raise UsageError("--max-packets must be a whole number") from None
            if self.max_packets < 1:
                raise UsageError(
                    "--max-packets must be at least 1",
                    hint="use --max-packets 1000 to sample the first 1000 packets",
                )
        if self.limit is not None:
            try:
                self.limit = int(self.limit)
            except (TypeError, ValueError):
                raise UsageError("--limit must be a whole number") from None
            if self.limit < 1:
                raise UsageError("--limit must be at least 1")
        self.output_dir = Path(self.output_dir).expanduser() if self.output_dir else None
        self.config = Path(self.config).expanduser() if self.config else None

    @property
    def wants_json(self) -> bool:
        """True when stdout must be machine readable."""
        return self.json_output

    @property
    def show_banner(self) -> bool:
        """True when the branding banner may be printed."""
        return not self.json_output and not self.quiet


# --------------------------------------------------------------------- context


class RunContext:
    """Per-invocation state: config, console, case store, progress."""

    def __init__(self, globals_obj: Globals) -> None:
        self.g = globals_obj
        self.config = Config.load(explicit_path=globals_obj.config)
        if globals_obj.verbose:
            self.config.output.redact_secrets = False
        self._console = None  # created lazily by reporting.terminal
        self._progress_enabled = not (globals_obj.json_output or globals_obj.quiet)

    def console(self):
        """Return the shared Rich console."""
        if self._console is None:
            from badnet.reporting.terminal import make_console

            self._console = make_console(no_color=self.g.no_color, quiet=self.g.quiet)
        return self._console

    def setup_logging(self, log_file: Path | None = None) -> None:
        """Configure logging honouring --verbose/--debug/--quiet."""
        setup_logging(
            debug=self.g.debug,
            verbose=self.g.verbose,
            quiet=self.g.quiet,
            log_file=log_file,
        )

    def attach_case_log(self, case_dir: Path) -> None:
        """Start writing the debug log into *case_dir* once it exists.

        ``--debug`` promises "full tracebacks and a debug log file", but the
        case directory is only known after input validation and hashing.  This
        re-points the log handler at the case's ``logs/`` directory at the
        earliest moment the path is known, so the log covers the whole analysis.
        """
        if not self.g.debug:
            return
        log_path = case_dir / "logs" / "badnet.log"
        self.setup_logging(log_file=log_path)
        if self._console is not None:
            self._console.print(f"  [dim]log:[/dim] {log_path}")

    def log_callback(self):
        """Return a ``run_case(on_case_created=...)`` callback, or None.

        Returns ``None`` unless ``--debug`` is active, so that a normal run
        never pays for a log file it was not asked for.
        """
        if not self.g.debug:
            return None
        return self.attach_case_log

    def verbose_secrets(self) -> bool:
        """True when secrets may be shown in full."""
        return self.g.verbose or not self.config.output.redact_secrets

    def emit_json(self, payload: Any) -> None:
        """Write a JSON document to stdout (used with --json)."""
        text = json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default)
        typer.echo(text)

    def banner(self, subtitle: str = "") -> None:
        """Print the banner unless suppressed."""
        if self.g.show_banner and self.config.output.include_banner:
            from badnet.reporting.terminal import print_banner

            print_banner(self.console(), subtitle=subtitle)


def _json_default(value: Any) -> Any:
    import datetime as _dt

    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    raise TypeError(f"object of type {type(value).__name__} is not JSON serialisable")


def fail(message: str, *, hint: str = "", code: ExitCode = ExitCode.ERROR) -> NoReturn:
    """Print a clean error and exit with the documented code."""
    from badnet.reporting.terminal import make_error_console

    console = make_error_console()
    console.print(f"[bold red]error:[/bold red] {message}", highlight=False)
    if hint:
        console.print(f"[dim]hint: {hint}[/dim]", highlight=False)
    if is_debug():
        import traceback

        traceback.print_exc()
    raise typer.Exit(code=int(code))


def handle_errors(fn):
    """Decorator translating BADNET errors into clean CLI failures."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except BadnetError as exc:
            from badnet.reporting.terminal import make_error_console

            console = make_error_console()
            console.print(f"[bold red]error:[/bold red] {exc.message}", highlight=False)
            if exc.hint:
                console.print(f"[dim]hint: {exc.hint}[/dim]", highlight=False)
            if is_debug():
                import traceback

                traceback.print_exc()
            raise typer.Exit(code=int(exc.exit_code)) from None
        except KeyboardInterrupt:
            from badnet.reporting.terminal import make_error_console

            make_error_console().print(
                "[yellow]interrupted[/yellow] - partial results were kept; "
                "the case is marked incomplete"
            )
            raise typer.Exit(code=int(ExitCode.INTERRUPTED)) from None
        except PermissionError as exc:
            fail(f"permission denied: {exc.filename or exc}", code=ExitCode.ERROR)
        except OSError as exc:
            fail(str(exc), code=ExitCode.ERROR)
        except BrokenPipeError:  # pragma: no cover - piped to head/less
            raise typer.Exit(code=int(ExitCode.OK)) from None

    return wrapper


# --------------------------------------------------------------------- commands


@app.callback()
def root_callback() -> None:
    """Root callback: no global options here, they are injected per command."""


@app.command("doctor")
@handle_errors
@with_globals
def cmd_doctor(globals: Globals) -> None:
    """Check which dependencies are present and what degrades without them."""
    from badnet.integrations import doctor

    ctx = RunContext(globals)
    ctx.setup_logging()
    doctor.run(ctx)


@app.command("info")
@handle_errors
@with_globals
def cmd_info(
    globals: Globals, capture: Path = typer.Argument(..., help="Capture file to inspect.")
) -> None:
    """Show file facts, timing, protocol hierarchy and top talkers."""
    from badnet.commands import info as info_cmd

    ctx = RunContext(globals)
    ctx.setup_logging()
    info_cmd.run(ctx, capture)


@app.command("analyze")
@handle_errors
@with_globals
def cmd_analyze(
    globals: Globals, capture: Path = typer.Argument(..., help="Capture file to analyse.")
) -> None:
    """Run the passive pipeline and write a case directory."""
    from badnet.commands import analyze as analyze_cmd

    ctx = RunContext(globals)
    ctx.setup_logging()
    analyze_cmd.run(ctx, capture)


@app.command("auto")
@handle_errors
@with_globals
def cmd_auto(
    globals: Globals,
    capture: Path = typer.Argument(..., help="Capture file to analyse."),
    ctf: bool = typer.Option(
        True, "--ctf/--no-ctf", help="Prioritise CTF indicators (flags, credentials, artifacts)."
    ),
) -> None:
    """Full investigation summary, ranked findings and follow-up suggestions.

    With --ctf (the default) findings are ranked flags -> credentials -> secrets ->
    artifacts -> endpoints -> anomalies -> unusual ports.
    """
    from badnet.commands import auto as auto_cmd

    ctx = RunContext(globals)
    ctx.setup_logging()
    auto_cmd.run(ctx, capture, ctf=ctf)


@app.command("config")
@handle_errors
@with_globals
def cmd_config(
    globals: Globals,
    template: Path = typer.Argument(
        None,
        metavar="[TEMPLATE_PATH]",
        help="Write a documented YAML template here instead of printing the config.",
        exists=False,
        dir_okay=False,
    ),
) -> None:
    """Show the effective configuration, or write a template to TEMPLATE_PATH."""
    from badnet.commands import config as config_cmd

    ctx = RunContext(globals)
    ctx.setup_logging()
    config_cmd.run(ctx, template_path=template)


@app.command("version")
@handle_errors
@with_globals
def cmd_version(globals: Globals) -> None:
    """Print the BADNET version."""
    ctx = RunContext(globals)
    ctx.setup_logging()
    if ctx.g.wants_json:
        ctx.emit_json({"badnet": __version__})
    else:
        typer.echo(f"{TOOL_NAME} {__version__}")


@app.command("stream")
@handle_errors
@with_globals
def cmd_stream(
    globals: Globals,
    capture: Path = typer.Argument(..., help="Capture file to inspect."),
    stream_id: int = typer.Option(
        None, "--id", metavar="N", help="Stream id to dump (omit to list all streams)."
    ),
    direction: str = typer.Option(
        "both", "--direction", help="Which direction to dump: c2s, s2c or both."
    ),
    carve: bool = typer.Option(
        False, "--carve", help="Also carve embedded files by magic bytes into files/."
    ),
    hex_view: bool = typer.Option(
        False, "--hex", help="Show a hex dump instead of a text preview."
    ),
) -> None:
    """List TCP streams, or dump and preview one stream by --id.

    A dump writes the reassembled bytes to the case ``streams/`` directory and,
    with --carve, recovers embedded files by magic bytes into ``files/``.
    """
    from badnet.commands import stream as stream_cmd

    ctx = RunContext(globals)
    ctx.setup_logging()
    stream_cmd.run(
        ctx,
        capture,
        stream_id=stream_id,
        direction=direction,
        carve=carve,
        hexdump=hex_view,
    )


@app.command("search")
@handle_errors
@with_globals
def cmd_search(
    globals: Globals,
    target: Path = typer.Argument(..., help="Capture file or an existing case directory."),
    regex: str = typer.Option(..., "--regex", "-e", help="Pattern to search for."),
    literal: bool = typer.Option(
        False, "--literal", "-F", help="Treat --regex as literal text (safest for hostile input)."
    ),
    ignore_case: bool = typer.Option(False, "--ignore-case", "-i", help="Case-insensitive match."),
    max_hits: int = typer.Option(None, "--max-hits", metavar="N", help="Stop after N matches."),
) -> None:
    """Sweep reassembled TCP streams for a regex or literal and record the hits."""
    from badnet.commands import search as search_cmd

    ctx = RunContext(globals)
    ctx.setup_logging()
    search_cmd.run(
        ctx, target, regex=regex, literal=literal, ignore_case=ignore_case, max_hits=max_hits
    )


@app.command("report")
@handle_errors
@with_globals
def cmd_report(
    globals: Globals,
    target: Path = typer.Argument(..., help="Capture file or an existing case directory."),
    top: int = typer.Option(None, "--top", metavar="N", help="Maximum rows shown per section."),
) -> None:
    """Write a self-contained offline HTML report (report.html) into the case."""
    from badnet.commands import report as report_cmd

    ctx = RunContext(globals)
    ctx.setup_logging()
    report_cmd.run(ctx, target, top=top)


def run() -> None:
    """Console-script entry point with top-level error handling."""
    try:
        app()
    except BadnetError as exc:  # pragma: no cover - defensive
        print(f"error: {exc.message}", file=sys.stderr)
        if exc.hint:
            print(f"hint: {exc.hint}", file=sys.stderr)
        raise SystemExit(int(exc.exit_code)) from None
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("interrupted", file=sys.stderr)
        raise SystemExit(int(ExitCode.INTERRUPTED)) from None


if __name__ == "__main__":  # pragma: no cover
    run()
