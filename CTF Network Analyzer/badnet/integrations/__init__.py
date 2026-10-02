"""Integration layer: external tools and optional libraries."""

from __future__ import annotations

from badnet.integrations.system_tools import ToolRegistry, detect_all

__all__ = ["ToolRegistry", "detect_all"]
