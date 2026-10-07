"""The PC side of "Set up iPhone": a page with the QR code on 127.0.0.1.

Plain HTTP is fine here: the server binds to the loopback address only.
Other local users can reach the port, so the page sits under a random
path (``/<secret>/``) that only the card action hands out, and the
``Host`` header must name the loopback address (no DNS rebinding). The
server stops by itself after :data:`IDLE_SECONDS` without a request.
Nothing is logged.
"""
from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from blueferry_shortcuts import pages

IDLE_SECONDS = 30 * 60
HOST = "127.0.0.1"


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, render: Callable[[str, bool], tuple[bytes, str]], secret: str) -> None:
        self.render = render
        self.secret = secret
        self.last_used = time.monotonic()
        super().__init__((HOST, 0), _Handler)


class _Handler(BaseHTTPRequestHandler):
    server: _Server
    server_version = "BlueFerryShortcuts"
    timeout = 10

    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.close_connection = True
        parts = urlsplit(self.path)
        port = self.server.server_address[1]
        host_ok = self.headers.get("Host", "") in (f"{HOST}:{port}", f"localhost:{port}")
        given = parts.path.strip("/").encode("utf-8", "replace")
        if not hmac.compare_digest(given, self.server.secret.encode()) or not host_ok:
            self._answer(404, b"not found", "text/plain; charset=utf-8", {})
            return
        self.server.last_used = time.monotonic()
        if parts.query == "new=1":
            # Renew, then drop the query so the page's refresh does not renew again.
            self.server.render(self.headers.get("Accept-Language", "")[:200], True)
            self._answer(303, b"", "text/plain", {"Location": f"/{self.server.secret}/"})
            return
        body, policy = self.server.render(self.headers.get("Accept-Language", "")[:200], False)
        self._answer(200, body, "text/html; charset=utf-8",
                     {"Content-Security-Policy": policy, **pages.SECURITY_HEADERS})

    def _answer(self, status: int, body: bytes, kind: str, extra: dict[str, str]) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in extra.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


class LocalPage:
    """Starts the page on demand; :meth:`url` is what the card action opens.

    ``render(accept_language, renew)`` returns the page and its CSP; it runs
    on the server's threads.
    """

    def __init__(self, render: Callable[[str, bool], tuple[bytes, str]]) -> None:
        self._render = render
        self._server: _Server | None = None
        self._lock = threading.Lock()

    def url(self) -> str:
        with self._lock:
            if self._server is None:
                self._server = _Server(self._render, secrets.token_urlsafe(24))
                threading.Thread(target=self._server.serve_forever,
                                 name="blueferry-shortcuts-setup-page", daemon=True).start()
            self._server.last_used = time.monotonic()
            return f"http://{HOST}:{self._server.server_address[1]}/{self._server.secret}/"

    def running(self) -> bool:
        with self._lock:
            return self._server is not None

    def stop_if_idle(self) -> None:
        with self._lock:
            server = self._server
            if server is None or time.monotonic() - server.last_used < IDLE_SECONDS:
                return
            self._server = None
        server.shutdown()
        server.server_close()

    def stop(self) -> None:
        with self._lock:
            server, self._server = self._server, None
        if server is not None:
            server.shutdown()
            server.server_close()
