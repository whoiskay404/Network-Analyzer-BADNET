"""``badnet config`` - show the effective configuration or write a template."""

from __future__ import annotations

from typing import TYPE_CHECKING

from badnet.config import default_config_template, write_template

if TYPE_CHECKING:  # pragma: no cover
    from badnet.cli import RunContext


def run(ctx: RunContext, *, template_path: str | None = None) -> None:
    """Print the effective config, or write a template when *template_path* is set."""
    if template_path:
        path = write_template(template_path)
        if ctx.g.wants_json:
            ctx.emit_json({"written": str(path)})
        else:
            ctx.console().print(f"wrote configuration template: [cyan]{path}[/cyan]")
        return

    cfg = ctx.config.to_dict()
    if ctx.g.wants_json:
        ctx.emit_json(cfg)
        return

    import yaml

    console = ctx.console()
    from badnet.reporting import terminal as term

    ctx.banner("effective configuration")
    term.section(console, "Config")
    console.print(yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False).rstrip())

    term.section(console, "Annotated template")
    console.print(
        "[dim]badnet.yaml can hold any of these keys; project config overrides the user config.[/dim]"
    )
    console.print(default_config_template())
