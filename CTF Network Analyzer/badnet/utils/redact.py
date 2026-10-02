"""Redaction of secret material.

Findings and headers can contain credentials, API keys and cookies.  Default
terminal and HTML output shows a masked form (``pas****rd``) so that shoulder
surfers, screen shares and pasted issues do not leak the secret.  The full value
is always kept in the case store and is only rendered with ``--verbose``.
"""

from __future__ import annotations

import re

#: Values that are public by design and never need masking.
SAFE_SCHEMES = ("basic", "digest", "negotiate")

_SCHEME_RE = re.compile(r"^(\w+)\s+(.*)$", re.DOTALL)


def mask(value: str | None, *, keep_start: int = 3, keep_end: int = 2, min_len: int = 6) -> str:
    """Mask the middle of a string, keeping a few characters at each end.

    Short values (below *min_len*) are fully masked so nothing meaningful leaks.
    """
    if value is None:
        return ""
    text = str(value)
    if len(text) < min_len:
        return "*" * len(text)
    if keep_start <= 0 and keep_end <= 0:
        return "*" * len(text)
    start = text[:keep_start]
    end = text[-keep_end:] if keep_end else ""
    hidden = len(text) - keep_start - keep_end
    return f"{start}{'*' * max(3, min(hidden, 12))}{end}"


def mask_authorization(value: str | None) -> str:
    """Mask an HTTP ``Authorization`` header value.

    Keeps the auth scheme visible (it is informative) and masks the credential.
    Bearer/JWT tokens and Basic blobs are both fully replaced apart from a short
    prefix/suffix so the report still shows *which* kind of credential was used.
    """
    if not value:
        return ""
    match = _SCHEME_RE.match(value.strip())
    if not match:
        return mask(value)
    scheme, payload = match.group(1), match.group(2)
    if scheme.lower() == "basic":
        # Base64 blob: show only a sliver of it.
        return f"{scheme} {mask(payload, keep_start=2, keep_end=2, min_len=4)}"
    return f"{scheme} {mask(payload, keep_start=6, keep_end=4, min_len=4)}"


def mask_cookie(value: str | None) -> str:
    """Mask the value part of a ``Cookie:``/``Set-Cookie:`` pair list."""
    if not value:
        return ""
    parts: list[str] = []
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if "=" in chunk:
            name, _, val = chunk.partition("=")
            parts.append(f"{name}={mask(val, keep_start=1, keep_end=1, min_len=4)}")
        else:
            parts.append(mask(chunk, keep_start=1, keep_end=1, min_len=4))
    return "; ".join(parts)


def redact_mapping(
    values: dict[str, str],
    *,
    sensitive_keys: tuple[str, ...] = (
        "authorization",
        "cookie",
        "set-cookie",
        "password",
        "token",
    ),
    verbose: bool = False,
) -> dict[str, str]:
    """Redact the sensitive entries of a header/query mapping."""
    out: dict[str, str] = {}
    for key, val in values.items():
        if verbose:
            out[key] = val
            continue
        lowered = key.lower()
        if lowered in sensitive_keys:
            out[key] = mask_authorization(val) if lowered == "authorization" else mask_cookie(val)
        elif any(s in lowered for s in ("password", "passwd", "secret", "api_key", "apikey")):
            out[key] = mask(val)
        else:
            out[key] = val
    return out
