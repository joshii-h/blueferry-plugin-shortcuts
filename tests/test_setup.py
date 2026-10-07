"""The guided setup end to end, the card states and plain HTTP per network."""
from __future__ import annotations

import http.client
import json
import logging
import re
import socket
import ssl
import urllib.error
import urllib.request

import pytest
from blueferry.plugin_api.testing import inline_service
from blueferry_plugin_kit.testing import FakeClipboard
from fakehost import FakeHost
from fakenet import CAFE_OPEN, HOME, TWIN, FakeNetworks
from test_http import Harness, _free_port

from blueferry_shortcuts import load_manifest
from blueferry_shortcuts.netguard import Network, decide, is_open_wifi
from blueferry_shortcuts.server import _Server, private_client
from blueferry_shortcuts.service import ShortcutsService
from blueferry_shortcuts.settings import Settings, SettingsStore


@pytest.fixture
def harness(tmp_path):
    made = []

    def make(**settings):
        made.append(Harness(tmp_path, **settings))
        return made[-1]

    yield make
    for item in made:
        item.close()


def _https(h, method, path, *, headers=None, body=None, port=None, context=None):
    connection = http.client.HTTPSConnection(
        "127.0.0.1", port or h.port, context=context or h.context, timeout=10,
    )
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def _plain(port, method, path, *, headers=None, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def _pc_page(url: str, host: str | None = None) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"Host": host} if host else {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, ""


def _link(page: str) -> str:
    return re.search(r"<code>(https?://[^<]+/setup/[^<]+)</code>", page).group(1)


# ---- plain pages -------------------------------------------------------------------

def test_root_is_a_friendly_page_without_secrets(harness) -> None:
    h = harness()
    status, headers, body = _https(h, "GET", "/", headers={"Accept-Language": "de-CH,de"})
    assert status == 200 and headers["Content-Type"].startswith("text/html")
    assert "iPhone einrichten" in body.decode() and h.token.encode() not in body
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    status, headers, body = _https(h, "GET", "/ca.mobileconfig")
    assert status == 200 and headers["Content-Type"] == "application/x-apple-aspen-config"
    assert b"com.apple.security.root" in body


# ---- the guided setup ------------------------------------------------------------------

def test_setup_flow_from_card_to_test(harness, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    h = harness()
    reply = h.host.invoke("bridge", "setup_iphone")
    assert reply["ok"] is True
    page_url = reply["open_uri"]
    assert re.fullmatch(r"http://127\.0\.0\.1:\d+/[\w-]{20,}/", page_url)
    status, page = _pc_page(page_url)
    assert status == 200 and "<svg" in page and "○ Auf dem iPhone geöffnet" in page
    link = _link(page)
    assert link.startswith(f"https://127.0.0.1:{h.port}/setup/")
    assert h.token not in page
    path = link.split(str(h.port), 1)[1]

    # The iPhone opens the link: the nonce becomes a session cookie.
    status, headers, _ = _https(h, "GET", path)
    assert status == 303 and headers["Location"] == "/setup"
    cookie = headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Lax" in cookie
    session = cookie.split(";", 1)[0]
    status, _headers, body = _https(h, "GET", path)
    assert status == 404 and b"ten minutes" in body   # spent
    status, headers, body = _https(h, "GET", "/setup", headers={"Cookie": session})
    assert status == 200 and h.token.encode() in body
    assert "script-src 'sha256-" in headers["Content-Security-Policy"]
    assert b"/ca.mobileconfig" in body
    status, _headers, body = _https(h, "GET", "/setup")
    assert status == 403 and h.token.encode() not in body

    # "Test now": same-origin fetch with the session.
    assert _https(h, "POST", "/setup/test", headers={"Cookie": session})[0] == 403
    status, _h, _b = _https(h, "POST", "/setup/test", headers={
        "Cookie": session, "X-BlueFerry-Setup": "1", "Origin": "https://evil.example"})
    assert status == 403
    status, _h, body = _https(h, "POST", "/setup/test", headers={
        "Cookie": session, "X-BlueFerry-Setup": "1",
        "Origin": f"https://127.0.0.1:{h.port}"})
    assert status == 200 and json.loads(body) == {"ok": True}
    assert h.host.notifications[-1][:2] == ("iPhone verbunden ✅", "Die Einrichtung hat geklappt.")
    status, page = _pc_page(page_url)
    assert "✅ Auf dem iPhone geöffnet" in page and "✅ Test angekommen" in page
    assert "Neuer Code" in page and "<svg" not in page
    state = h.host.item("state")
    assert state["title"] == "iPhone zuletzt verbunden gerade eben"

    # Secrets never reach the logs.
    nonce = path.rsplit("/", 1)[1]
    for secret in (h.token, nonce, session.split("=", 1)[1], page_url.split("/")[3]):
        assert secret not in caplog.text


def test_pc_page_needs_its_secret_and_a_loopback_host(harness) -> None:
    h = harness()
    url = h.host.invoke("bridge", "setup_iphone")["open_uri"]
    base, secret = url.rstrip("/").rsplit("/", 1)
    assert _pc_page(f"{base}/{secret[:-1]}x/")[0] == 404
    assert _pc_page(f"{base}/")[0] == 404
    assert _pc_page(url, host="evil.example")[0] == 404


def test_new_code_replaces_the_old_link(harness) -> None:
    h = harness()
    url = h.host.invoke("bridge", "setup_iphone")["open_uri"]
    old = _link(_pc_page(url)[1])
    _pc_page(url + "?new=1")
    new = _link(_pc_page(url)[1])
    assert new != old
    old_path = old.split(str(h.port), 1)[1]
    assert _https(h, "GET", old_path)[0] == 404


def test_wrong_nonces_count_as_failed_logins(harness) -> None:
    h = harness()
    h.host.invoke("bridge", "setup_iphone")
    statuses = [_https(h, "GET", f"/setup/guess-{index}")[0] for index in range(6)]
    assert statuses[:5] == [404] * 5 and statuses[5] == 429


def test_probe_answers_only_with_its_own_certificate_and_marks_trust(harness) -> None:
    h = harness()
    assert h.host.invoke("bridge", "setup_iphone")["ok"]
    probe = h.service._bridge.probe_address
    assert probe is not None and probe[1] == h.port + 1
    main_cert = ssl.get_server_certificate(("127.0.0.1", h.port))
    probe_cert = ssl.get_server_certificate(("127.0.0.1", probe[1]))
    assert main_cert != probe_cert
    status, _headers, _body = _https(h, "GET", "/probe", port=probe[1])
    assert status == 204
    assert _pc_page(h.host.invoke("bridge", "setup_iphone")["open_uri"])[0] == 200
    assert h.service._progress["trusted"] is False  # a new setup starts over
    _https(h, "GET", "/probe", port=probe[1])
    assert h.service._progress["trusted"] is True
    view = h.service.setup_view(secure=True)
    assert view.probe_url == f"https://127.0.0.1:{probe[1]}/probe"


# ---- card states -------------------------------------------------------------------------

def test_card_state_new_then_certificate_missing_then_connected(harness) -> None:
    h = harness()
    state = h.host.item("state")
    assert state["title"] == "iPhone noch nicht eingerichtet"
    untrusting = ssl.create_default_context()
    with socket.create_connection(("127.0.0.1", h.port), timeout=5) as sock:
        with pytest.raises(ssl.SSLError):
            untrusting.wrap_socket(sock, server_hostname="127.0.0.1")
    for _ in range(100):
        if h.host.item("state")["title"].startswith("Zertifikat"):
            break
        import time

        time.sleep(0.05)
    assert h.host.item("state")["title"] == "Zertifikat fehlt vermutlich auf dem iPhone"
    assert h.request("POST", "/battery", {"level": 50})[0] == 200
    state = h.host.item("state")
    assert state["title"] == "iPhone zuletzt verbunden gerade eben"
    assert state["subtitle"] == "Verschlüsselt (HTTPS)"
    # Kept across a restart.
    saved = SettingsStore(h.store.directory, h.store.state_directory).load_state()
    assert "at" in saved["seen"] and saved["battery"]["level"] == 50


def test_ago_texts(harness) -> None:
    h = harness()
    now = h.service._now()
    assert h.service._ago(now - 5) == "gerade eben"
    assert h.service._ago(now - 600) == "vor 10 Min."
    assert h.service._ago(now - 7200) == "vor 2 Std."
    assert h.service._ago(now - 3 * 86400).startswith("am ")


# ---- plain HTTP -------------------------------------------------------------------------

def _plain_harness(harness, networks=None):
    port = _free_port()
    h = harness(networks=networks or FakeNetworks([HOME]), allow_http=True, http_port=port,
                http_networks=((HOME.uuid, HOME.name),), allow_clipboard_read=True)
    h.service.start_maintenance()     # follows the NetworkManager signals
    return h, port


def test_private_clients_only_over_plain_http() -> None:
    for address in ("192.168.1.5", "10.1.2.3", "172.20.0.1", "169.254.3.4", "fd00::1",
                    "fe80::1%eth0", "::ffff:192.168.1.2", "127.0.0.1", "::1"):
        assert private_client(address), address
    for address in ("8.8.8.8", "100.64.0.1", "2001:4860::8888", "::ffff:8.8.8.8",
                    "172.32.0.1", "nonsense"):
        assert not private_client(address), address


def test_public_source_address_is_refused_by_the_http_server(harness) -> None:
    h, _port = _plain_harness(harness)
    server = h.service._bridge._plain.server
    assert isinstance(server, _Server) and server.secure is False
    assert server.verify_request(None, ("203.0.113.9", 50000)) is False
    assert server.verify_request(None, ("2001:db8::1", 50000)) is False
    assert server.verify_request(None, ("192.168.178.20", 50000)) is True
    # The HTTPS server keeps its own rules (any peer that reaches the LAN address).
    assert h.service._bridge._main.server.verify_request(None, ("203.0.113.9", 1)) is True


def test_plain_http_works_with_token_and_never_reads_the_clipboard(harness) -> None:
    h, port = _plain_harness(harness)
    auth = {"Authorization": f"Bearer {h.token}", "Content-Type": "application/json"}
    status, _h, _b = _plain(port, "POST", "/battery", headers=auth, body=b'{"level": 40}')
    assert status == 200
    assert _plain(port, "POST", "/battery", body=b'{"level": 40}',
                  headers={"Content-Type": "application/json"})[0] == 401
    status, _h, body = _plain(port, "GET", "/clipboard", headers=auth)
    assert status == 403 and json.loads(body) == {"error": "clipboard-read-needs-https"}
    state = h.host.item("state")
    assert state["subtitle"] == "Unverschlüsselt (HTTP)"
    assert h.request("GET", "/clipboard")[0] == 200   # HTTPS may, when allowed
    plain = h.host.item("plain")
    assert plain["title"] == "Unverschlüsselt aktiv in „Zuhause“"
    assert f"http://127.0.0.1:{port}" in plain["subtitle"]


def test_setup_link_uses_http_in_an_approved_network(harness) -> None:
    h, port = _plain_harness(harness)
    page = _pc_page(h.host.invoke("bridge", "setup_iphone")["open_uri"])[1]
    link = _link(page)
    assert link.startswith(f"http://127.0.0.1:{port}/setup/") and "Zuhause" in page
    status, headers, _ = _plain(port, "GET", link.split(str(port), 1)[1])
    assert status == 303 and "Secure" not in headers["Set-Cookie"]
    session = headers["Set-Cookie"].split(";", 1)[0]
    status, _h, body = _plain(port, "GET", "/setup",
                              headers={"Cookie": session, "Accept-Language": "de"})
    text = body.decode()
    assert status == 200 and "optional, empfohlen" in text
    assert f'value="http://127.0.0.1:{port}"' in text
    assert f'data-secure-address="https://127.0.0.1:{h.port}"' in text


def test_network_changes_open_and_close_the_http_listener(harness) -> None:
    networks = FakeNetworks([HOME])
    h, port = _plain_harness(harness, networks)
    assert _plain(port, "GET", "/")[0] == 200
    networks.change([TWIN])                       # same SSID, other profile
    with pytest.raises(OSError):
        _plain(port, "GET", "/")
    plain = h.host.item("plain")
    assert plain["title"] == "Unverschlüsselt pausiert – fremdes Netz"
    assert [a["id"] for a in plain["actions"]] == ["allow_network"]
    networks.change([CAFE_OPEN])
    assert h.host.item("plain")["title"] == "Unverschlüsselt pausiert – offenes WLAN"
    assert h.host.invoke("plain", "allow_network")["ok"] is False
    assert h.service._bridge.plain_address is None
    networks.change([HOME, Network("x" * 12, "Gast", False, open_wifi=True)])
    assert h.service._bridge.plain_address is None, "open Wi-Fi beside home: never"
    networks.change([HOME])
    assert _plain(port, "GET", "/")[0] == 200
    networks.available = False
    networks.change([HOME])
    assert h.host.item("plain")["title"] == "Unverschlüsselt nicht verfügbar"
    with pytest.raises(OSError):
        _plain(port, "GET", "/")
    networks.available = True
    networks.change([TWIN])
    reply = h.host.invoke("plain", "allow_network")
    assert reply["ok"] is True and "Zuhause" in reply["message"]
    assert _plain(port, "GET", "/")[0] == 200
    assert {uuid for uuid, _ in h.store.load().http_networks} == {HOME.uuid, TWIN.uuid}


# ---- settings ------------------------------------------------------------------------------

def _service(tmp_path, networks):
    store = SettingsStore(tmp_path / "c", tmp_path / "s")
    store.save(Settings(port=_free_port()))
    service = inline_service(
        ShortcutsService, load_manifest(), None, settings=store, clipboard=FakeClipboard(),
        resolve=lambda s, a: "127.0.0.1", local_addresses=lambda: ["127.0.0.1"], lang="en",
        networks=networks, run_async=lambda work: work(),
    )
    host = FakeHost(service)
    service.start()
    return service, host, store


def test_turning_http_on_approves_the_current_network(tmp_path) -> None:
    networks = FakeNetworks([HOME])
    service, host, store = _service(tmp_path, networks)
    port = _free_port()
    try:
        values = {**host.get_config()["values"], "allow_http": True, "http_port": port}
        values.pop("token")
        assert host.set_config(values) == {"ok": True}
        assert store.load().http_networks == ((HOME.uuid, HOME.name),)
        assert host.get_config()["values"]["http_networks"] == "Zuhause"
        assert service._bridge.plain_address == ("127.0.0.1", port)
        # Deleting the name removes the approval and closes the listener.
        values = {**values, "http_networks": ""}
        assert host.set_config(values) == {"ok": True}
        assert store.load().http_networks == ()
        assert service._bridge.plain_address is None
    finally:
        service.stop()


def test_http_cannot_be_turned_on_without_nm_or_in_open_wifi(tmp_path) -> None:
    for networks, word in ((FakeNetworks(available=False), "NetworkManager"),
                           (FakeNetworks([CAFE_OPEN]), "open Wi-Fi")):
        service, host, _store = _service(tmp_path, networks)
        try:
            values = {**host.get_config()["values"], "allow_http": True}
            values.pop("token")
            reply = host.set_config(values)
            assert reply["ok"] is False and word in reply["errors"]["allow_http"]
        finally:
            service.stop()


def test_shortcut_link_must_be_an_icloud_link(tmp_path) -> None:
    service, host, store = _service(tmp_path, FakeNetworks())
    try:
        values = {**host.get_config()["values"], "shortcut_url": "https://evil.example/x"}
        values.pop("token")
        assert "shortcut_url" in host.set_config(values)["errors"]
        link = "https://www.icloud.com/shortcuts/0123456789abcdef0123456789abcdef"
        assert host.set_config({**values, "shortcut_url": link}) == {"ok": True}
        assert store.load().shortcut_url == link
        assert service.setup_view(secure=True).shortcut_url == link
    finally:
        service.stop()


# ---- network rules ---------------------------------------------------------------------------

def test_decide_and_open_wifi_detection() -> None:
    approved = ((HOME.uuid, HOME.name),)
    assert decide(False, approved, [HOME]).reason == "off"
    assert decide(True, approved, None).reason == "no-nm"
    assert decide(True, approved, [HOME]) == decide(True, approved, [HOME])
    assert decide(True, approved, [HOME]).active
    assert decide(True, approved, [TWIN]).reason == "foreign"
    assert decide(True, approved, [CAFE_OPEN]).reason == "open-wifi"
    assert decide(True, approved, []).reason == "no-network"
    assert decide(True, ((CAFE_OPEN.uuid, "x"),), [CAFE_OPEN]).active is False
    wifi = {"connection": {"type": "802-11-wireless"}}
    assert is_open_wifi(wifi)
    assert is_open_wifi({**wifi, "802-11-wireless-security": {"key-mgmt": "owe"}})
    assert is_open_wifi({**wifi, "802-11-wireless-security": {"key-mgmt": "none"}})
    assert not is_open_wifi({**wifi, "802-11-wireless-security": {"key-mgmt": "wpa-psk"}})
    assert not is_open_wifi({**wifi, "802-11-wireless-security": {"key-mgmt": "sae"}})
    assert not is_open_wifi({"connection": {"type": "802-3-ethernet"}})
