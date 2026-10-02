"""BADNET - CLI-first network forensics and CTF investigation tool.

BADNET orchestrates mature packet-analysis tooling (tshark, capinfos, nmap,
file(1)) and Python libraries (Scapy, cryptography), normalises the output into
one data model, correlates the results and reports them quickly.

All captured content is treated as untrusted data.  Nothing extracted from a
capture is ever executed, imported or evaluated.
"""

from __future__ import annotations

__all__ = ["SCHEMA_VERSION", "TOOL_NAME", "TOOL_TAGLINE", "__version__"]

__version__ = "1.0.0"

TOOL_NAME = "BADNET"
TOOL_TAGLINE = "Network CTF Analyzer"

#: Version of the machine-readable report schema emitted by ``badnet report --format json``.
SCHEMA_VERSION = "1.0"
