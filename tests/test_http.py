"""The real HTTPS endpoint on localhost with a test CA, fake clipboard and fake host."""
from __future__ import annotations

import http.client
import json
import logging
import socket
import ssl
import time

import pytest
from blueferry.plugin_api.testing import inline_service
from fakehost import FakeHost

from blueferry_shortcuts import load_manifest
from blueferry_shortcuts.server import MAX_TEXT_BYTES, RateLimiter
from blueferry_shortcuts.service import ShortcutsService, mask_token
from blueferry_shortcuts.settings import Settings, SettingsStore
from blueferry_shortcuts.tls import CertificateStore

SECRET_TEXT = "geheim-4711-clipboard-content"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


class FakeClipboard:
    def __init__(self, current: str = "") -> None:
        self.copies: list[tuple[bytes, str]] = []
        self.current = current

    def copy(self, data: bytes, mime: str) -> bool:
        self.copies.append((data, mime))
        return True

    def copy_text(self, text: str) -> bool:
        return self.copy(text.encode(), "text/plain;charset=utf-8")

    def read_text(self, limit: int):
        data = self.current.encode()
        return None if len(data) > limit else self.current


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Harness:
    def __init__(self, tmp_path, **settings) -> None:
        self.store = SettingsStore(tmp_path / "config", tmp_path / "state")
        self.port = _free_port()
        self.store.save(Settings(port=self.port, **settings))
        self.clipboard = FakeClipboard("PC-Text äöü")
        self.service = inline_service(
            ShortcutsService, load_manifest(), None,
            settings=self.store, clipboard=self.clipboard,
            resolve=lambda setting, allow_all: "127.0.0.1",
            local_addresses=lambda: ["127.0.0.1"], lang="de",
        )
        self.host = FakeHost(self.service)
        self.service.start()
        assert self.service.status()["state"] == "ok", self.service.status()
        self.context = ssl.create_default_context(
            cafile=str(CertificateStore(self.store.directory).ca_cert_path),
        )

    @property
    def token(self) -> str:
        return self.store.token()

    def request(self, method, path, body=None, *, token=True, content_type=None,
                headers=None):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.port, context=self.context, timeout=10,
        )
        sent = dict(headers or {})
        if token:
            sent["Authorization"] = f"Bearer {self.token if token is True else token}"
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
            content_type = content_type or "application/json"
        if content_type:
            sent["Content-Type"] = content_type
        try:
            connection.request(method, path, body=body, headers=sent)
            response = connection.getresponse()
            return response.status, response.getheader("Content-Type"), response.read()
        finally:
            connection.close()

    def close(self) -> None:
        self.service.stop()


@pytest.fixture
def harness(tmp_path):
    made = []

    def make(**settings):
        made.append(Harness(tmp_path, **settings))
        return made[-1]

    yield make
    for item in made:
        item.close()


def test_post_clipboard_sets_clipboard_and_notifies(harness, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    h = harness()
    status, _type, body = h.request("POST", "/clipboard", {"text": SECRET_TEXT})
    assert status == 200 and json.loads(body) == {"ok": True}
    assert h.clipboard.copies == [(SECRET_TEXT.encode(), "text/plain;charset=utf-8")]
    title, text, _icon, label, action = h.host.notifications[-1]
    assert title == "Zwischenablage vom iPhone"
    assert SECRET_TEXT not in text and str(len(SECRET_TEXT)) in text
    assert (label, action) == ("", "")
    # Plain text bodies work too.
    status, _type, _body = h.request("POST", "/clipboard", b"Hallo",
                                     content_type="text/plain; charset=utf-8")
    assert status == 200 and h.clipboard.copies[-1][0] == b"Hallo"
    assert SECRET_TEXT not in caplog.text and h.token not in caplog.text


def test_token_is_required_and_failures_are_limited(harness) -> None:
    h = harness()
    assert h.request("POST", "/clipboard", {"text": "x"}, token=False)[0] == 401
    assert h.request("POST", "/clipboard", {"text": "x"}, token="wrong-token")[0] == 401
    status, _t, _b = h.request("POST", "/clipboard", {"text": "x"},
                               headers={"Authorization": f"Basic {h.token}"}, token=False)
    assert status == 401
    for _ in range(2):
        h.request("GET", "/clipboard", token="nope-nope-nope")
    # Five failures from this address: even the right token waits now.
    assert h.request("POST", "/clipboard", {"text": "x"})[0] == 429
    assert h.clipboard.copies == []


def test_request_rate_limit(harness) -> None:
    h = harness()
    statuses = [h.request("POST", "/battery", {"level": 50})[0] for _ in range(31)]
    assert statuses[:30] == [200] * 30 and statuses[30] == 429


def test_text_size_limit(harness) -> None:
    h = harness()
    assert h.request("POST", "/clipboard", {"text": "a" * MAX_TEXT_BYTES})[0] == 200
    assert h.request("POST", "/clipboard", {"text": "a" * (MAX_TEXT_BYTES + 1)})[0] == 413
    assert h.request("POST", "/clipboard", b"a" * (MAX_TEXT_BYTES + 1),
                     content_type="text/plain")[0] == 413
    assert h.request("POST", "/clipboard", {"text": ""})[0] == 400
    assert h.request("POST", "/clipboard", {"nope": 1})[0] == 400
    assert h.request("POST", "/clipboard", b"{broken", content_type="application/json")[0] == 400


def test_images_need_opt_in_and_a_known_format(harness) -> None:
    h = harness()
    assert h.request("POST", "/clipboard", PNG, content_type="image/png")[0] == 415
    h.close()
    h = harness(accept_images=True)
    assert h.request("POST", "/clipboard", PNG, content_type="image/png")[0] == 200
    assert h.clipboard.copies[-1] == (PNG, "image/png")
    assert "PNG" in h.host.notifications[-1][1]
    assert h.request("POST", "/clipboard", b"MZ\x90\x00 not an image",
                     content_type="application/octet-stream")[0] == 415


def test_oversized_image_is_refused_before_reading(harness) -> None:
    h = harness(accept_images=True)
    connection = http.client.HTTPSConnection("127.0.0.1", h.port, context=h.context, timeout=10)
    connection.putrequest("POST", "/clipboard")
    connection.putheader("Authorization", f"Bearer {h.token}")
    connection.putheader("Content-Type", "image/png")
    connection.putheader("Content-Length", str(10 * 1024 * 1024 + 1))
    connection.endheaders()
    assert connection.getresponse().status == 413
    connection.close()


def test_chunked_bodies_are_refused(harness) -> None:
    h = harness()
    status, _t, _b = h.request(
        "POST", "/clipboard", iter([b'{"text": "x"}']),
        content_type="application/json", headers={"Transfer-Encoding": "chunked"},
    )
    assert status == 411


def test_get_clipboard_only_when_enabled(harness) -> None:
    h = harness()
    assert h.request("GET", "/clipboard")[0] == 403
    h.close()
    h = harness(allow_clipboard_read=True)
    status, content_type, body = h.request("GET", "/clipboard")
    assert status == 200 and content_type.startswith("text/plain")
    assert body.decode() == "PC-Text äöü"
    h.clipboard.current = "x" * (MAX_TEXT_BYTES + 1)
    assert h.request("GET", "/clipboard")[0] == 413
    assert h.request("GET", "/clipboard", token=False)[0] == 401


def test_link_notification_opens_through_invoke_action(harness) -> None:
    h = harness()
    url = "https://example.org/a?b=c"
    assert h.request("POST", "/link", {"url": url})[0] == 200
    title, body, _icon, label, action = h.host.notifications[-1]
    assert (title, body, label) == ("Link vom iPhone", url, "Öffnen") and action
    assert h.host.click_notification() == {"ok": True, "message": None, "open_uri": url}
    assert h.host.invoke("notify", "open-999")["ok"] is False
    assert h.request("POST", "/link", b"http://192.168.1.1/",
                     content_type="text/plain")[0] == 200
    for bad in ("javascript:alert(1)", "file:///etc/passwd", "https://", "http://a b", 42):
        assert h.request("POST", "/link", {"url": bad})[0] == 400, bad


def test_battery_becomes_a_card_item(harness) -> None:
    h = harness()
    before = h.host.card_changed
    assert h.request("POST", "/battery", {"level": 87, "charging": True})[0] == 200
    assert h.host.card_changed > before
    item = h.host.item("battery")
    assert item["title"] == "iPhone-Akku 87 % ⚡ lädt"
    assert item["subtitle"] == "Stand " + time.strftime("%H:%M")
    assert item["icon"] == "battery-good-charging"
    assert h.request("POST", "/battery", {"level": "42,4", "charging": "Nein"})[0] == 200
    assert h.host.item("battery")["title"] == "iPhone-Akku 42 %"
    assert h.request("POST", "/battery", {"level": 50, "charging": True})[0] == 200
    assert h.request("POST", "/battery", {"level": 51})[0] == 200
    assert h.host.item("battery")["title"] == "iPhone-Akku 51 % ⚡ lädt"
    assert h.request("POST", "/battery", {"level": 42.4, "charging": False})[0] == 200
    for bad in ({"level": 101}, {"level": -1}, {"level": True}, {"charging": True},
                {"level": 50, "charging": "maybe"}, {"level": "NaN"}):
        assert h.request("POST", "/battery", bad)[0] == 400, bad
    # The last report survives a restart.
    assert SettingsStore(h.store.directory, h.store.state_directory).load_state()["battery"][
        "level"] == 42


def test_routes_and_methods(harness) -> None:
    h = harness()
    assert h.request("GET", "/nothing")[0] == 404
    assert h.request("GET", "/battery")[0] == 405
    status, content_type, body = h.request("GET", "/ca.crt", token=False)
    assert status == 200 and content_type == "application/x-x509-ca-cert"
    assert body.startswith(b"-----BEGIN CERTIFICATE-----")


def test_setup_card_masks_and_reveals_the_token(harness) -> None:
    h = harness()
    bridge = h.host.item("bridge")
    assert bridge["subtitle"] == f"Bereit auf https://127.0.0.1:{h.port}"
    assert [a["id"] for a in bridge["actions"]] == ["show_setup", "new_token"]
    assert bridge["actions"][0]["label"] == "Einrichtungsdaten anzeigen"
    assert not any(i["id"].startswith("setup_") for i in h.host.items())

    assert h.host.invoke("bridge", "show_setup")["ok"]
    ids = [i["id"] for i in h.host.items()]
    assert ids == ["bridge", "setup_url", "setup_token", "setup_fingerprint", "setup_ca"]
    token_item = h.host.item("setup_token")
    assert token_item["subtitle"] == mask_token(h.token) and h.token not in json.dumps(
        h.host.items())
    fingerprint = h.host.item("setup_fingerprint")["subtitle"]
    assert fingerprint == CertificateStore(h.store.directory).ca_fingerprint()

    assert h.host.invoke("setup_token", "reveal")["ok"]
    assert h.host.item("setup_token")["subtitle"] == h.token
    assert h.host.invoke("setup_token", "hide")["ok"]
    assert h.host.item("setup_token")["subtitle"] == mask_token(h.token)
    assert h.host.invoke("bridge", "hide_setup")["ok"]
    assert [i["id"] for i in h.host.items()] == ["bridge"]
    assert h.host.invoke("bridge", "explode")["ok"] is False
    assert h.host.invoke("bridge", "show_setup", "not json")["ok"] is False


def test_new_token_replaces_the_old_one(harness) -> None:
    h = harness()
    old = h.token
    reply = h.host.invoke("bridge", "new_token")
    assert reply["ok"] and reply["message"]
    assert h.token != old
    assert h.request("POST", "/battery", {"level": 5}, token=old)[0] == 401
    assert h.request("POST", "/battery", {"level": 5})[0] == 200


def test_port_in_use_is_reported(tmp_path) -> None:
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        store = SettingsStore(tmp_path / "c", tmp_path / "s")
        store.save(Settings(port=busy.getsockname()[1]))
        service = inline_service(
            ShortcutsService, load_manifest(), None, settings=store,
            clipboard=FakeClipboard(), resolve=lambda s, a: "127.0.0.1",
            local_addresses=lambda: ["127.0.0.1"], lang="en",
        )
        host = FakeHost(service)
        service.start()
        assert service.status() == {"state": "error", "detail": "the port is already in use"}
        assert host.item("bridge")["subtitle"] == "Not running: the port is already in use"
        assert host.item("bridge")["icon"] == "dialog-warning"


def test_limiter_forgets_idle_clients() -> None:
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0])
    for index in range(1100):
        assert limiter.admit(f"10.0.{index // 256}.{index % 256}")
        now[0] += 0.1
    assert len(limiter._requests) < 1100


def _raw_tls(harness):
    sock = socket.create_connection(("127.0.0.1", harness.port), timeout=5)
    return harness.context.wrap_socket(sock, server_hostname="127.0.0.1")


def _closed(sock) -> bool:
    sock.settimeout(0.05)
    try:
        return sock.recv(1) == b""
    except (TimeoutError, ssl.SSLWantReadError):
        return False
    except OSError:
        return True
    finally:
        sock.settimeout(5)


def test_a_trickling_client_is_cut_off_at_the_deadline(harness, monkeypatch) -> None:
    from blueferry_shortcuts import server as server_module

    monkeypatch.setattr(server_module, "REQUEST_DEADLINE_S", 0.6)
    sock = _raw_tls(harness())
    started, closed = time.monotonic(), False
    for byte in b"POST /battery HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: 1\r\n":
        try:
            sock.sendall(bytes([byte]))
        except OSError:
            closed = True
            break
        time.sleep(0.05)
        if _closed(sock):
            closed = True
            break
    sock.close()
    # Every byte came long before the 15 s read timeout, yet the request ended.
    assert closed and time.monotonic() - started < 3


def test_at_most_two_connections_per_address(harness) -> None:
    harness = harness()
    first, second = _raw_tls(harness), _raw_tls(harness)
    with pytest.raises(OSError):
        third = _raw_tls(harness)
        third.sendall(b"GET /ca.crt HTTP/1.1\r\nHost: x\r\n\r\n")
        if third.recv(1) == b"":
            raise ConnectionResetError
    first.close()
    second.close()
    time.sleep(0.2)
    status, _type, _body = harness.request("GET", "/ca.crt", token=False)
    assert status == 200
