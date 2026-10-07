"""The HTTPS endpoint the iPhone's shortcuts talk to.

Small on purpose: one request per connection, a bounded number of
concurrent connections (two per address), a total deadline per request,
per-address rate limits (stricter for failed
logins), hard body limits and a constant-time token check. The TLS
handshake runs on the connection's own thread with a timeout, so a slow
client cannot block the accept loop. Nothing here logs request contents,
and nothing is forwarded anywhere: requests only reach the desktop
clipboard and BlueFerry's card and notifications.

Endpoints (all but ``/ca.crt`` need ``Authorization: Bearer <token>``):

- ``POST /clipboard``: ``{"text": "…"}``, ``text/plain`` or (opt-in) an image
- ``GET /clipboard``: the PC clipboard as ``text/plain`` (opt-in)
- ``POST /link``: ``{"url": "https://…"}`` or ``text/plain``
- ``POST /battery``: ``{"level": 87, "charging": true}`` (``charging`` optional:
  without it the last known state stays)
- ``GET /ca.crt``: the public CA certificate, to install on the iPhone
"""
from __future__ import annotations

import hmac
import json
import logging
import math
import ssl
import threading
import time
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlsplit

from blueferry_plugin_kit.clipboard import ClipboardError
from blueferry_plugin_kit.lanserver import (
    DeadlineRequestHandler,
    HardenedHTTPServer,
    RequestError,
    serve_in_thread,
)
from blueferry_plugin_kit.lanserver import RateLimiter as _KitRateLimiter

log = logging.getLogger(__name__)

MAX_TEXT_BYTES = 64 * 1024
MAX_IMAGE_BYTES = 10 * 1024 * 1024
# JSON escapes may grow text up to six times (\uXXXX).
MAX_JSON_CLIPBOARD = MAX_TEXT_BYTES * 6 + 1024
MAX_SMALL_BODY = 8 * 1024
MAX_URL = 2048
CONNECTION_TIMEOUT_S = 15
MAX_CONNECTIONS = 8
MAX_CONNECTIONS_PER_ADDRESS = 2
# The whole request (TLS handshake, request line, headers) within this; a
# body gets as long again plus one second per 32 KiB (10 MB: about 5 min).
REQUEST_DEADLINE_S = 20
MIN_BODY_RATE = 32 * 1024
LINGER_S = 1.0
LINGER_BYTES = 1024 * 1024
REQUESTS_PER_MINUTE = 30
FAILURES_ALLOWED = 5
FAILURE_WINDOW_S = 600
_IMAGE_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)
_TRUE = {"true", "yes", "ja", "1", "on"}
_FALSE = {"false", "no", "nein", "0", "off", ""}


class Endpoints(Protocol):
    """What the server needs from the plugin; called on connection threads."""

    def token(self) -> str: ...
    def allow_clipboard_read(self) -> bool: ...
    def accept_images(self) -> bool: ...
    def ca_pem(self) -> bytes: ...
    def on_clipboard_text(self, text: str) -> None: ...
    def on_clipboard_image(self, data: bytes, mime: str) -> None: ...
    def read_clipboard(self, limit: int) -> str | None: ...
    def on_link(self, url: str) -> None: ...
    def on_battery(self, level: int, charging: bool | None) -> None: ...


class RateLimiter(_KitRateLimiter):
    """Sliding windows per client address, with this plugin's limits."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        super().__init__(
            clock, requests_per_minute=REQUESTS_PER_MINUTE, failures_allowed=FAILURES_ALLOWED,
            failure_window=FAILURE_WINDOW_S,
        )


def check_url(value: object) -> str:
    if not isinstance(value, str):
        raise RequestError(400, "url-missing")
    url = value.strip()
    if not url or len(url) > MAX_URL or any(ch.isspace() or not ch.isprintable() for ch in url):
        raise RequestError(400, "url-invalid")
    try:
        parts = urlsplit(url)
    except ValueError:
        raise RequestError(400, "url-invalid") from None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise RequestError(400, "url-not-http")
    return url


def parse_level(value: object) -> int:
    if isinstance(value, bool):
        raise RequestError(400, "level-invalid")
    if isinstance(value, str):
        text = value.strip().rstrip("%").strip().replace(",", ".")
        try:
            value = float(text)
        except ValueError:
            raise RequestError(400, "level-invalid") from None
    if not isinstance(value, (int, float)) or not math.isfinite(value):
        raise RequestError(400, "level-invalid")
    level = round(value)
    if not 0 <= level <= 100:
        raise RequestError(400, "level-out-of-range")
    return int(level)


def parse_flag(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().casefold()
        if lowered in _TRUE:
            return True
        if lowered in _FALSE:
            return False
    raise RequestError(400, "charging-invalid")


def sniff_image(data: bytes) -> str | None:
    for magic, mime in _IMAGE_MAGIC:
        if data.startswith(magic):
            return mime
    if len(data) > 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


class _Server(HardenedHTTPServer):
    log = log  # under this plugin's logger, not the kit's

    def __init__(self, address, endpoints: Endpoints, context: ssl.SSLContext,
                 limiter: RateLimiter) -> None:
        self.endpoints = endpoints
        self.limiter = limiter
        super().__init__(
            address, _Handler, context=context, max_connections=MAX_CONNECTIONS,
            max_per_address=MAX_CONNECTIONS_PER_ADDRESS,
        )

    def handshake_timeout(self) -> float:
        # Read at runtime, so the deadline can be changed (tests do).
        return REQUEST_DEADLINE_S

    def finish_request(self, request, client_address) -> None:
        # The kit's server drops a failed handshake silently. A phone that
        # does not trust the CA yet looks exactly like that, so say it at
        # debug level: only the reason, never the peer or any bytes.
        request.settimeout(self.handshake_timeout())
        context = self.ssl_context
        if context is not None:
            try:
                request = context.wrap_socket(request, server_side=True)
            except (OSError, ssl.SSLError) as error:
                log.debug("TLS handshake failed: %s", handshake_reason(error))
                return
        self.RequestHandlerClass(request, client_address, self)


def handshake_reason(error: BaseException) -> str:
    """A content-free reason: the TLS alert name, a timeout or the error class."""
    if isinstance(error, ssl.SSLError):
        reason = error.reason if isinstance(error.reason, str) else ""
        if reason and reason.replace("_", "").isalnum():
            return reason.lower()
        return type(error).__name__
    if isinstance(error, TimeoutError):
        return "timeout"
    return type(error).__name__


class _Handler(DeadlineRequestHandler):
    log = log
    server: _Server
    server_version = "BlueFerryShortcuts"
    timeout = CONNECTION_TIMEOUT_S
    linger_s = LINGER_S
    linger_bytes = LINGER_BYTES

    def request_deadline(self) -> float:
        # Read at runtime, so the deadline can be changed (tests do).
        return REQUEST_DEADLINE_S

    # ---- plumbing --------------------------------------------------------

    def _send(self, status: int, body: bytes, content_type: str,
              extra: dict[str, str] | None = None) -> None:
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, value: dict[str, object],
              extra: dict[str, str] | None = None) -> None:
        self._send(status, json.dumps(value).encode(), "application/json", extra)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        scheme, _, provided = header.strip().partition(" ")
        expected = self.server.endpoints.token().encode("utf-8")
        given = provided.strip().encode("utf-8", "replace")
        # Compare even without a header, so timing does not tell either case apart.
        match = hmac.compare_digest(given, expected)
        return scheme.casefold() == "bearer" and match

    def _body(self, limit: int) -> bytes:
        return self.read_body(limit, min_rate=MIN_BODY_RATE)

    def _content_type(self) -> str:
        return self.headers.get("Content-Type", "").split(";", 1)[0].strip().casefold()

    def _json_body(self, limit: int) -> object:
        data = self._body(limit)
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise RequestError(400, "bad-json") from None

    # ---- dispatch ----------------------------------------------------------

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def _dispatch(self, method: str) -> None:
        path = urlsplit(self.path).path.rstrip("/") or "/"
        client = str(self.client_address[0])
        if not self.server.limiter.admit(client):
            self._json(429, {"error": "rate-limited"}, {"Retry-After": "60"})
            return
        if path == "/ca.crt" and method in ("GET", "HEAD"):
            self._send(200, self.server.endpoints.ca_pem(), "application/x-x509-ca-cert",
                       {"Content-Disposition": 'attachment; filename="blueferry-shortcuts.crt"'})
            return
        routes = {
            "/clipboard": {"GET": self._get_clipboard, "POST": self._post_clipboard},
            "/link": {"POST": self._post_link},
            "/battery": {"POST": self._post_battery},
        }
        if path not in routes:
            self._json(404, {"error": "not-found"})
            return
        if not self._authorized():
            self.server.limiter.failed(client)
            self._json(401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})
            return
        handler = routes[path].get(method)
        if handler is None:
            self._json(405, {"error": "method-not-allowed"},
                       {"Allow": ", ".join(routes[path])})
            return
        try:
            handler()
        except RequestError as error:
            self._json(error.status, {"error": error.token})
        except ClipboardError:
            self._json(503, {"error": "clipboard-unavailable"})

    # ---- endpoints ---------------------------------------------------------

    def _post_clipboard(self) -> None:
        endpoints = self.server.endpoints
        kind = self._content_type()
        if kind == "application/json":
            value = self._json_body(MAX_JSON_CLIPBOARD)
            text = value.get("text") if isinstance(value, dict) else None
            if not isinstance(text, str):
                raise RequestError(400, "text-missing")
            self._clipboard_text(text)
        elif kind.startswith("text/"):
            data = self._body(MAX_TEXT_BYTES)
            try:
                self._clipboard_text(data.decode("utf-8"))
            except UnicodeDecodeError:
                raise RequestError(400, "not-utf8") from None
        else:
            if not endpoints.accept_images():
                raise RequestError(415, "images-disabled")
            data = self._body(MAX_IMAGE_BYTES)
            mime = sniff_image(data)
            if mime is None:
                raise RequestError(415, "unsupported-type")
            endpoints.on_clipboard_image(data, mime)
        self._json(200, {"ok": True})

    def _clipboard_text(self, text: str) -> None:
        if not text:
            raise RequestError(400, "text-empty")
        if len(text.encode("utf-8", "surrogatepass")) > MAX_TEXT_BYTES:
            raise RequestError(413, "too-large")
        if "\x00" in text:
            raise RequestError(400, "text-invalid")
        self.server.endpoints.on_clipboard_text(text)

    def _get_clipboard(self) -> None:
        endpoints = self.server.endpoints
        if not endpoints.allow_clipboard_read():
            raise RequestError(403, "clipboard-read-disabled")
        text = endpoints.read_clipboard(MAX_TEXT_BYTES)
        if text is None:
            raise RequestError(413, "too-large")
        self._send(200, text.encode("utf-8"), "text/plain; charset=utf-8")

    def _post_link(self) -> None:
        if self._content_type() == "application/json":
            value = self._json_body(MAX_SMALL_BODY)
            url = value.get("url") if isinstance(value, dict) else None
        else:
            try:
                url = self._body(MAX_SMALL_BODY).decode("utf-8")
            except UnicodeDecodeError:
                raise RequestError(400, "not-utf8") from None
        self.server.endpoints.on_link(check_url(url))
        self._json(200, {"ok": True})

    def _post_battery(self) -> None:
        value = self._json_body(MAX_SMALL_BODY)
        if not isinstance(value, dict) or "level" not in value:
            raise RequestError(400, "level-missing")
        level = parse_level(value["level"])
        raw = value.get("charging")
        charging = None if raw is None or raw == "" else parse_flag(raw)
        self.server.endpoints.on_battery(level, charging)
        self._json(200, {"ok": True})


class HttpsBridge:
    """Starts and stops the server on its own thread."""

    def __init__(self, endpoints: Endpoints, limiter: RateLimiter | None = None) -> None:
        self._endpoints = endpoints
        self._limiter = limiter or RateLimiter()
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def address(self) -> tuple[str, int] | None:
        server = self._server
        return server.server_address[:2] if server is not None else None

    def start(self, host: str, port: int, context: ssl.SSLContext) -> None:
        """Bind and serve; raise OSError when the address is unusable."""
        with self._lock:
            self._stop_locked()
            server = _Server((host, port), self._endpoints, context, self._limiter)
            thread = serve_in_thread(server, "blueferry-shortcuts-https")
            self._server, self._thread = server, thread

    def reload_context(self, context: ssl.SSLContext) -> None:
        with self._lock:
            if self._server is not None:
                self._server.ssl_context = context

    def stop(self) -> None:
        with self._lock:
            self._stop_locked()

    def _stop_locked(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.shutdown()
            server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
