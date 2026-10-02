"""Self-contained offline HTML report.

Design constraints, all of which exist because capture content is hostile input:

* **No external resources.**  The CSS is inlined and there is no JavaScript, no
  CDN, no web font and no ``<img>``.  The file opens from a case directory on an
  air-gapped machine and never makes a network request.
* **Everything is escaped.**  Every value that came from the capture - stream
  bytes, HTTP headers, filenames, DNS labels, decoded strings - goes through
  :func:`html.escape` with ``quote=True``.  A capture containing the literal text
  ``<script>alert(1)</script>`` must render as visible text, never as markup.
  :func:`render` is the only place markup is produced, so the escaping cannot be
  forgotten at a call site.
* **No active content.**  We never emit ``<script>``, ``on*`` handlers,
  ``javascript:`` URLs or ``<style>`` built from untrusted text.

The report is a pure function of already-collected data: it never re-reads the
capture and never decides anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html import escape

from badnet.utils.filesystem import human_size

#: Severity -> CSS class.  Kept here so the palette and the data model cannot
#: drift apart.
_SEVERITY_CLASS = {
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "info": "sev-info",
}

_CSS = """\
:root{--bg:#12141a;--panel:#1a1d26;--ink:#e6e8ee;--dim:#9aa3b2;--line:#2b3040;--accent:#6aa9ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{padding:24px 32px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0 0 4px;font-size:22px}
h2{margin:0 0 12px;font-size:16px;color:var(--accent)}
sub{color:var(--dim)}
main{padding:24px 32px;max-width:1200px;margin:0 auto}
section{margin:0 0 32px}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}
th{background:var(--panel);color:var(--dim);font-weight:600}
td.num{text-align:right}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;border:1px solid var(--line)}
.status-complete{color:#7ee0a0}
.status-incomplete,.status-failed{color:#ff9a7a}
.note{padding:8px 12px;border-left:3px solid var(--accent);background:var(--panel);margin:8px 0;color:var(--dim)}
.warn{border-left-color:#ffce6a}
.finding{padding:10px 12px;border:1px solid var(--line);border-radius:6px;margin:8px 0;background:var(--panel)}
.finding .title{font-weight:700}
.sev-high{color:#ff7a7a}.sev-medium{color:#ffce6a}.sev-low{color:#9adcff}.sev-info{color:var(--dim)}
.meta{color:var(--dim);font-size:12px}
pre{white-space:pre-wrap;word-break:break-word;background:#0e1016;border:1px solid var(--line);padding:8px;border-radius:4px;margin:6px 0 0;overflow:auto}
footer{padding:16px 32px;color:var(--dim);border-top:1px solid var(--line);font-size:12px}
.empty{color:var(--dim);font-style:italic}
code{color:var(--accent)}
"""


@dataclass(slots=True)
class ReportData:
    """Everything the HTML renderer needs, already normalised to plain data.

    All values are treated as untrusted text.  There is no type distinction that
    would let a string bypass escaping.
    """

    case_name: str
    input_path: str = ""
    input_sha256: str = ""
    input_size: int = 0
    input_format: str = ""
    status: str = "complete"
    created: str = ""
    generated: str = ""
    degraded: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    facts: list[tuple[str, str]] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    protocols: list[dict] = field(default_factory=list)
    talkers: list[dict] = field(default_factory=list)
    streams: list[dict] = field(default_factory=list)
    artifacts: list[dict] = field(default_factory=list)
    search_hits: list[dict] = field(default_factory=list)

    top_n: int = 20
    """Maximum rows per table before a 'showing N of M' note is added."""


def _esc(value: object) -> str:
    """Escape any value for use in element text or a quoted attribute."""
    return escape("" if value is None else str(value), quote=True)


def _to_int(value: object) -> int:
    """Best-effort int for a value that may have been hand-edited in a case file."""
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _table(columns: list[str], rows: list[list[object]], *, numeric: set[int] | None = None) -> str:
    """Render a table, escaping every column name and cell."""
    numeric = numeric or set()
    head = "".join(f"<th>{_esc(c)}</th>" for c in columns)
    body = []
    for row in rows:
        cells = []
        for index, cell in enumerate(row):
            cls = ' class="num"' if index in numeric else ""
            cells.append(f"<td{cls}>{_esc(cell)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def _capped(rows: list, top_n: int) -> tuple[list, str]:
    """Return the first *top_n* rows and an honest note about what was hidden."""
    if top_n > 0 and len(rows) > top_n:
        return rows[:top_n], f"showing {top_n} of {len(rows)} rows"
    return rows, ""


def _findings_html(findings: list[dict], top_n: int) -> str:
    if not findings:
        return '<p class="empty">No indicator matched the configured signatures.</p>'
    shown, note = _capped(findings, top_n)
    parts = []
    if note:
        parts.append(f'<p class="meta">{_esc(note)}</p>')
    for finding in shown:
        severity = str(finding.get("severity", "info"))
        cls = _SEVERITY_CLASS.get(severity, "sev-info")
        title = _esc(finding.get("title", ""))
        parts.append('<div class="finding">')
        parts.append(f'<div class="title {cls}">[{_esc(severity)}] {title}</div>')
        category = _esc(finding.get("category", ""))
        confidence = _esc(finding.get("confidence", ""))
        detector = _esc(finding.get("detector", "") or "n/a")
        parts.append(
            f'<div class="meta">category {category} - confidence {confidence} - detector {detector}</div>'
        )
        explanation = finding.get("explanation")
        if explanation:
            parts.append(f"<p>{_esc(explanation)}</p>")
        evidence = finding.get("evidence")
        if evidence:
            parts.append(f"<pre>{_esc(evidence)}</pre>")
        source = finding.get("source")
        if source:
            parts.append(f'<div class="meta">source: {_esc(source)}</div>')
        parts.append("</div>")
    return "".join(parts)


def _notes_html(warnings: list[str], degraded: list[str]) -> str:
    parts = []
    for warning in warnings:
        parts.append(f'<div class="note warn">warning: {_esc(warning)}</div>')
    for note in degraded:
        parts.append(f'<div class="note">degraded: {_esc(note)}</div>')
    return "".join(parts)


def render(data: ReportData) -> str:
    """Render *data* to a complete HTML document.

    Every dynamic value passes through :func:`_esc`.  The only literal markup in
    the output is authored in this module.
    """
    status = str(data.status or "unknown")
    status_class = f"status-{status}" if status in {"complete", "incomplete", "failed"} else ""

    facts_rows = [[k, v] for k, v in data.facts]
    facts = _table(["fact", "value"], facts_rows)

    protocol_rows = [
        [p.get("name", ""), p.get("packets", ""), human_size(_to_int(p.get("bytes", 0)))]
        for p in _capped(data.protocols, data.top_n)[0]
    ]
    protocols = (
        _table(["protocol", "packets", "bytes"], protocol_rows, numeric={1, 2})
        if protocol_rows
        else '<p class="empty">No protocol statistics recorded.</p>'
    )

    talker_rows = [
        [t.get("name", ""), t.get("packets", ""), human_size(_to_int(t.get("bytes", 0)))]
        for t in _capped(data.talkers, data.top_n)[0]
    ]
    talkers = (
        _table(["endpoint", "packets", "bytes"], talker_rows, numeric={1, 2})
        if talker_rows
        else '<p class="empty">No endpoint statistics recorded.</p>'
    )

    stream_rows = [
        [
            s.get("stream_id", ""),
            s.get("proto", ""),
            f"{s.get('client', '')} -> {s.get('server', '')}",
            s.get("app_protocol", ""),
            s.get("packets", ""),
            human_size(_to_int(s.get("bytes", 0))),
        ]
        for s in _capped(data.streams, data.top_n)[0]
    ]
    streams = (
        _table(
            ["stream", "proto", "endpoints", "application", "packets", "bytes"],
            stream_rows,
            numeric={0, 4, 5},
        )
        if stream_rows
        else '<p class="empty">No TCP streams were reassembled.</p>'
    )

    artifact_rows = [
        [
            a.get("name", ""),
            a.get("detected_type", ""),
            human_size(_to_int(a.get("size", 0))),
            a.get("method", ""),
            a.get("sha256", "") or "",
        ]
        for a in _capped(data.artifacts, data.top_n)[0]
    ]
    artifacts = (
        _table(["file", "type", "size", "method", "sha256"], artifact_rows, numeric={2})
        if artifact_rows
        else '<p class="empty">No files were recovered.</p>'
    )

    hit_rows = [
        [
            h.get("stream_id", ""),
            h.get("direction", ""),
            h.get("offset", ""),
            h.get("match", ""),
            h.get("context", ""),
        ]
        for h in _capped(data.search_hits, data.top_n)[0]
    ]
    hits = (
        _table(["stream", "direction", "offset", "match", "context"], hit_rows, numeric={0, 2})
        if hit_rows
        else ""
    )

    digest = data.input_sha256 or "unavailable"
    footer = (
        "Generated by BADNET. Capture content is untrusted and is rendered as "
        "escaped text. This file is self-contained: it loads no scripts, styles or "
        "images from the network."
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BADNET report - {_esc(data.case_name)}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
<h1>BADNET report: {_esc(data.case_name)}</h1>
<sub>status <span class="badge {_esc(status_class)}">{_esc(status)}</span> &middot; generated {_esc(data.generated)}</sub>
</header>
<main>
<section>
<h2>Capture</h2>
{facts}
<pre>input : {_esc(data.input_path)}
sha256: {_esc(digest)}</pre>
{_notes_html(data.warnings, data.degraded)}
</section>
<section>
<h2>Findings</h2>
{_findings_html(data.findings, data.top_n)}
</section>
<section>
<h2>Protocols</h2>
{protocols}
</section>
<section>
<h2>Top talkers</h2>
{talkers}
</section>
<section>
<h2>TCP streams</h2>
{streams}
</section>
<section>
<h2>Recovered files</h2>
{artifacts}
</section>
{f"<section><h2>Search hits</h2>{hits}</section>" if hits else ""}
</main>
<footer>{_esc(footer)}</footer>
</body>
</html>
"""
