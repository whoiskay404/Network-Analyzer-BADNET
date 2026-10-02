"""HTTP request/response records."""

from __future__ import annotations

from dataclasses import dataclass, field

from badnet.utils.redact import mask_authorization, mask_cookie


@dataclass(slots=True)
class HttpRequest:
    """A parsed HTTP request (or CONNECT/upgrade preamble)."""

    ts: float
    packet_no: int
    method: str
    uri: str
    host: str | None
    path: str
    query_string: str | None = None
    version: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    user_agent: str | None = None
    referer: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    authorization: str | None = None
    cookie: str | None = None
    body_preview: str | None = None
    """Bounded, escaped preview of the request body (never the full body)."""
    body_size: int | None = None
    stream_id: int | None = None
    src: str | None = None
    dst: str | None = None

    @property
    def full_url(self) -> str:
        """Absolute URL when a Host header exists, otherwise the request target."""
        if self.host and self.uri.startswith("/"):
            scheme = "https" if self.host_is_tls else "http"
            return f"{scheme}://{self.host}{self.uri}"
        return self.uri

    @property
    def host_is_tls(self) -> bool:
        """True when the request came from a decrypted TLS stream."""
        port = None
        if self.host and ":" in self.host:
            port = self.host.rsplit(":", 1)[-1]
        return port == "443"

    @property
    def display_authorization(self) -> str:
        """Redacted Authorization header for default output."""
        return mask_authorization(self.authorization)

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON (raw secrets are stored here on purpose)."""
        return {
            "ts": self.ts,
            "packet_no": self.packet_no,
            "method": self.method,
            "uri": self.uri,
            "host": self.host,
            "path": self.path,
            "query_string": self.query_string,
            "version": self.version,
            "headers": self.headers,
            "user_agent": self.user_agent,
            "referer": self.referer,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "authorization": self.authorization,
            "cookie": self.cookie,
            "body_preview": self.body_preview,
            "body_size": self.body_size,
            "stream_id": self.stream_id,
            "src": self.src,
            "dst": self.dst,
        }

    def to_display_dict(self, *, verbose: bool = False) -> dict[str, object]:
        """Serialise with secrets redacted unless *verbose*."""
        data = self.to_dict()
        if not verbose:
            data["authorization"] = self.display_authorization or None
            data["cookie"] = mask_cookie(self.cookie) or None
        return data


@dataclass(slots=True)
class HttpResponse:
    """A parsed HTTP response."""

    ts: float
    packet_no: int
    version: str | None
    status_code: int | None
    reason: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str | None = None
    content_length: int | None = None
    server: str | None = None
    set_cookie: str | None = None
    body_preview: str | None = None
    body_size: int | None = None
    stream_id: int | None = None
    src: str | None = None
    dst: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {
            "ts": self.ts,
            "packet_no": self.packet_no,
            "version": self.version,
            "status_code": self.status_code,
            "reason": self.reason,
            "headers": self.headers,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "server": self.server,
            "set_cookie": self.set_cookie,
            "body_preview": self.body_preview,
            "body_size": self.body_size,
            "stream_id": self.stream_id,
            "src": self.src,
            "dst": self.dst,
        }

    def to_display_dict(self, *, verbose: bool = False) -> dict[str, object]:
        """Serialise with Set-Cookie redacted unless *verbose*."""
        data = self.to_dict()
        if not verbose:
            data["set_cookie"] = mask_cookie(self.set_cookie) or None
        return data


@dataclass(slots=True)
class HttpExchange:
    """A request paired with its response over the same TCP stream."""

    request: HttpRequest
    response: HttpResponse | None = None
    stream_id: int | None = None

    @property
    def status(self) -> int | None:
        """Response status code, if a response was seen."""
        return self.response.status_code if self.response else None

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {
            "request": self.request.to_dict(),
            "response": self.response.to_dict() if self.response else None,
            "stream_id": self.stream_id,
        }

    def to_display_dict(self, *, verbose: bool = False) -> dict[str, object]:
        """Serialise with secrets redacted unless *verbose*."""
        return {
            "request": self.request.to_display_dict(verbose=verbose),
            "response": self.response.to_display_dict(verbose=verbose) if self.response else None,
            "stream_id": self.stream_id,
        }


@dataclass(slots=True)
class HttpStats:
    """Aggregate HTTP counters."""

    requests: int = 0
    responses: int = 0
    unique_hosts: int = 0
    unique_paths: int = 0
    top_hosts: list[tuple[str, int]] = field(default_factory=list)
    top_paths: list[tuple[str, int]] = field(default_factory=list)
    status_counts: dict[str, int] = field(default_factory=dict)
    methods: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialise for JSON reports."""
        return {
            "requests": self.requests,
            "responses": self.responses,
            "unique_hosts": self.unique_hosts,
            "unique_paths": self.unique_paths,
            "top_hosts": [list(p) for p in self.top_hosts],
            "top_paths": [list(p) for p in self.top_paths],
            "status_counts": self.status_counts,
            "methods": self.methods,
        }
