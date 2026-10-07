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
import socket
import ssl
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Protocol
from urllib.parse import urlsplit

from blueferry_plugin_kit.clipboard import ClipboardError

from blueferry_shortcuts.limits import ConnectionsPerAddress, DeadlineReader, deadline_rfile

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


class RequestError(Exception):
    def __init__(self, status: int, token: str) -> None:
        super().__init__(token)
        self.status = status
        self.token = token


class RateLimiter:
    """Sliding windows per client address."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _trim(self, window: deque[float], span: float, now: float) -> None:
        while window and now - window[0] > span:
            window.popleft()

    def admit(self, client: str) -> bool:
        now = self._clock()
        with self._lock:
            failures = self._failures[client]
            self._trim(failures, FAILURE_WINDOW_S, now)
            if len(failures) >= FAILURES_ALLOWED:
                return False
            requests = self._requests[client]
            self._trim(requests, 60, now)
            if len(requests) >= REQUESTS_PER_MINUTE:
                return False
            requests.append(now)
            if len(self._requests) > 1024:
                self._forget_idle(now)
            return True

    def failed(self, client: str) -> None:
        with self._lock:
            self._failures[client].append(self._clock())

    def _forget_idle(self, now: float) -> None:
        for table, span in ((self._requests, 60), (self._failures, FAILURE_WINDOW_S)):
            for key in [k for k, window in table.items() if not window or now - window[-1] > span]:
                del table[key]


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


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, address, endpoints: Endpoints, context: ssl.SSLContext,
                 limiter: RateLimiter) -> None:
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        self.endpoints = endpoints
        self.ssl_context = context
        self.limiter = limiter
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._per_address = ConnectionsPerAddress(MAX_CONNECTIONS_PER_ADDRESS)
        super().__init__(address, _Handler)

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        if not self._per_address.acquire(str(client_address[0])):
            self._slots.release()
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._release(client_address)
            raise

    def _release(self, client_address) -> None:
        self._per_address.release(str(client_address[0]))
        self._slots.release()

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release(client_address)

    def handle_error(self, request, client_address) -> None:
        # TLS handshakes from browsers that do not trust the CA, timeouts…
        log.debug("connection error", exc_info=True)


class _Handler(BaseHTTPRequestHandler):
    server: _Server
    server_version = "BlueFerryShortcuts"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = CONNECTION_TIMEOUT_S
    _deadline: DeadlineReader

    def setup(self) -> None:
        # CPython bounds the whole handshake by the socket timeout, not
        # each read, so a trickled ClientHello ends here too.
        self.request.settimeout(REQUEST_DEADLINE_S)
        self.request = self.server.ssl_context.wrap_socket(self.request, server_side=True)
        super().setup()
        # Every read gets the time left of the request, so a client
        # trickling a byte now and then cannot keep the connection.
        self.rfile.close()
        self._deadline, self.rfile = deadline_rfile(self.connection, CONNECTION_TIMEOUT_S)
        self._deadline.start(REQUEST_DEADLINE_S)

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            self._linger()

    def _linger(self) -> None:
        """Swallow what the client still sends before closing.

        An early answer (401, 413, …) leaves the body unread; closing then
        would reset the connection and the shortcut would show a network
        error instead of the answer. Bounded in total time (not per read,
        or a trickling client would keep it going) and size.
        """
        deadline = time.monotonic() + LINGER_S
        try:
            budget = LINGER_BYTES
            while budget > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.connection.settimeout(remaining)
                chunk = self.connection.recv(min(65536, budget))
                if not chunk:
                    break
                budget -= len(chunk)
        except (OSError, ValueError):
            pass

    def log_message(self, format: str, *args: object) -> None:
        """Never log paths, headers or bodies."""

    def log_request(self, code: object = "-", size: object = "-") -> None:
        log.debug("%s %s", self.command, code)

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
        if self.headers.get("Transfer-Encoding"):
            raise RequestError(411, "length-required")
        raw = self.headers.get("Content-Length")
        if raw is None:
            raise RequestError(411, "length-required")
        try:
            length = int(raw)
        except ValueError:
            raise RequestError(400, "bad-length") from None
        if length < 0:
            raise RequestError(400, "bad-length")
        if length > limit:
            raise RequestError(413, "too-large")
        self._deadline.stream(max(0.0, self._deadline.remaining()) + REQUEST_DEADLINE_S,
                              MIN_BODY_RATE)
        data = self.rfile.read(length)
        if len(data) != length:
            raise RequestError(400, "short-body")
        return data

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
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.5},
                name="blueferry-shortcuts-https", daemon=True,
            )
            thread.start()
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
