"""Manifest, settings, request parsing, settings form and CLI."""
from __future__ import annotations

import json
import os
import socket
import stat

from blueferry.plugin_api import PLUGIN_INTERFACE
from blueferry.plugin_api.testing import inline_service
from fakehost import FakeHost
from fakenet import FakeNetworks

from blueferry_shortcuts import PLUGIN_ID, load_manifest, manifest_text
from blueferry_shortcuts import __main__ as cli
from blueferry_shortcuts.server import check_url, parse_flag, parse_level, sniff_image
from blueferry_shortcuts.service import ShortcutsService, battery_icon, mask_token
from blueferry_shortcuts.settings import (
    TOKEN_ALPHABET,
    Settings,
    SettingsStore,
    new_token,
    valid_token,
)
from blueferry_shortcuts.surfaces import language

# ---- manifest -------------------------------------------------------------------

def test_manifest_declares_the_surfaces_and_the_guided_settings() -> None:
    text = manifest_text()
    assert "ApiVersion=1.3" in text and "Capabilities=card;notify;" in text
    manifest = load_manifest()
    assert manifest.id == PLUGIN_ID
    assert manifest.capabilities == ("card", "notify")
    assert manifest.api_minor == 3 and manifest.config_test and not manifest.config_login
    fields = {field.key: field for field in manifest.config}
    assert list(fields) == ["bind_address", "allow_all_interfaces", "port", "token",
                            "allow_clipboard_read", "accept_images", "shortcut_url",
                            "allow_http", "http_port", "http_networks"]
    assert fields["port"].default == 47801
    assert fields["token"].secret
    assert fields["allow_clipboard_read"].empty() is False
    assert fields["allow_all_interfaces"].empty() is False
    groups = {key: field.group for key, field in fields.items()}
    assert groups == {"bind_address": "options", "allow_all_interfaces": "advanced",
                      "port": "options", "token": "advanced",
                      "allow_clipboard_read": "options", "accept_images": "options",
                      "shortcut_url": "options", "allow_http": "advanced",
                      "http_port": "advanced", "http_networks": "advanced"}
    assert fields["allow_http"].default in (False, "false")
    assert fields["http_port"].default == 47800
    assert fields["token"].help_url.startswith("https://github.com/")
    assert fields["port"].error_text and fields["bind_address"].placeholder


def test_activation_files_and_autostart(tmp_path) -> None:
    written = cli.install_activation(tmp_path / "data")
    manifest_path, service_path = written
    load_manifest(manifest_path.read_text())
    assert "serve" in service_path.read_text()
    autostart = cli.install_autostart(tmp_path / "config")
    assert "Exec=" in autostart.read_text() and autostart.read_text().count("serve") == 1


def test_surface_members_live_on_plugin1() -> None:
    """Spec "D-Bus placement": no Card1/Notify1, everything on Plugin1."""
    table = ShortcutsService._dbus_class_table[
        f"{ShortcutsService.__module__}.{ShortcutsService.__name__}"
    ]
    assert set(table) - {"org.freedesktop.DBus.Introspectable"} == {PLUGIN_INTERFACE}
    members = table[PLUGIN_INTERFACE]
    for name in ("GetInfo", "Status", "GetConfig", "SetConfig",
                 "GetCardItems", "InvokeAction", "CardChanged", "Notify"):
        assert name in members, name
    assert members["Notify"]._dbus_signature == "sssss"
    assert members["InvokeAction"]._dbus_in_signature == "sss"


# ---- settings ---------------------------------------------------------------------

def test_tokens_are_typeable_and_private(tmp_path) -> None:
    token = new_token()
    assert len(token) == 29 and token.count("-") == 5
    assert set(token.replace("-", "")) <= set(TOKEN_ALPHABET)
    assert valid_token(token) and not valid_token("short") and not valid_token("a b" * 10)
    store = SettingsStore(tmp_path / "c", tmp_path / "s")
    first = store.token()
    assert store.token() == first
    assert stat.S_IMODE(os.stat(store.token_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(store.directory).st_mode) == 0o700
    store.save(Settings(port=50000, allow_clipboard_read=True))
    assert store.load() == Settings(port=50000, allow_clipboard_read=True)
    store.config_path.write_text(json.dumps({"port": 80, "allow_clipboard_read": "yes"}))
    store.config_path.chmod(0o600)
    assert store.load() == Settings()


def test_mask_token() -> None:
    assert mask_token("abcd-efgh-jkmn") == "••••-••••-jkmn"
    assert mask_token("abcdefghjkmnpqrs") == "••••••••••••pqrs"


# ---- request parsing ----------------------------------------------------------------

def test_parsers() -> None:
    assert parse_level(87) == 87 and parse_level(86.6) == 87 and parse_level("55 %") == 55
    assert parse_flag("Ja") is True and parse_flag(0) is False and parse_flag(None) is False
    assert check_url(" https://x.org ") == "https://x.org"
    assert sniff_image(b"\xff\xd8\xff\xe0rest") == "image/jpeg"
    assert sniff_image(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "image/webp"
    assert sniff_image(b"<svg>") is None
    assert battery_icon(3, False) == "battery-empty"
    assert battery_icon(95, True) == "battery-full-charging"


def test_language_detection() -> None:
    assert language({"LANG": "de_CH.UTF-8"}) == "de"
    assert language({"LANGUAGE": "en_US:de", "LANG": "de_DE.UTF-8"}) == "en"
    assert language({}) == "en"


# ---- settings form (Plugin1.GetConfig/SetConfig) ------------------------------------

class _Bridge:
    plain_address = None
    probe_address = None

    def __init__(self, _endpoints) -> None:
        self.started = []
        self.fail_port = None

    def start_plain(self, host, port) -> None:
        self.plain_address = (host, port)

    def stop_plain(self) -> None:
        self.plain_address = None

    def start_probe(self, host, port, context) -> None:
        self.probe_address = (host, port)

    def stop_probe(self) -> None:
        self.probe_address = None

    def start(self, host, port, context) -> None:
        if port == self.fail_port:
            raise OSError(98, "in use")
        self.started.append((host, port))

    def reload_context(self, context) -> None:
        pass

    def stop(self) -> None:
        pass


def _call(method, *args):
    outcome = {}
    method(*args, reply=lambda v: outcome.setdefault("reply", v),
           error=lambda e: outcome.setdefault("error", e), sender=":1.t")
    assert "error" not in outcome, outcome
    return json.loads(outcome["reply"])


def test_settings_form(tmp_path) -> None:
    store = SettingsStore(tmp_path / "c", tmp_path / "s")
    service = inline_service(
        ShortcutsService, load_manifest(), None, settings=store, bridge_factory=_Bridge,
        resolve=lambda s, a: s or "192.168.1.20", local_addresses=lambda: ["192.168.1.20"],
        lang="en", networks=FakeNetworks(), run_async=lambda work: work(),
    )
    host = FakeHost(service)
    service.start()
    values = _call(service.GetConfig)["values"]
    assert values == {"bind_address": "", "allow_all_interfaces": False, "port": 47801,
                      "token": "********", "allow_clipboard_read": False,
                      "accept_images": False, "allow_http": False, "http_port": 47800,
                      "http_networks": "", "shortcut_url": ""}
    reply = _call(service.SetConfig, json.dumps({"bind_address": "0.0.0.0"}))
    assert reply["ok"] is False and "bind_address" in reply["errors"]
    reply = _call(service.SetConfig, json.dumps({"token": "short"}))
    assert reply["ok"] is False and "token" in reply["errors"]
    service._bridge.fail_port = 50001
    reply = _call(service.SetConfig, json.dumps({"port": 50001}))
    assert reply == {"ok": False, "errors": {"port": "the port is already in use"}}
    assert service._bridge.started[-1] == ("192.168.1.20", 47801)  # rolled back
    chosen = "my-own-token-0123456789"
    reply = _call(service.SetConfig, json.dumps({
        "port": 50002, "allow_clipboard_read": True, "token": chosen,
    }))
    assert reply == {"ok": True}
    assert service._bridge.started[-1] == ("192.168.1.20", 50002)
    assert store.token() == chosen and service.token() == chosen
    assert store.load().allow_clipboard_read is True
    assert host.card_changed >= 2
    assert service.status()["detail"] == "listening on https://192.168.1.20:50002"


def test_test_connection_checks_without_storing(tmp_path, caplog) -> None:
    import logging

    caplog.set_level(logging.DEBUG)
    store = SettingsStore(tmp_path / "c", tmp_path / "s")
    store.save(Settings())
    service = inline_service(
        ShortcutsService, load_manifest(), None, settings=store, bridge_factory=_Bridge,
        resolve=lambda s, a: "127.0.0.1", local_addresses=lambda: ["127.0.0.1"], lang="en",
        networks=FakeNetworks(), run_async=lambda work: work(),
    )
    host = FakeHost(service)
    service.start()
    before = (store.config_path.read_bytes(), store.token())
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        result = host.test_config({"port": port})
        assert result["ok"] is False and result["errors"] == {"port": "the port is already in use"}
    result = host.test_config({"port": port})
    free = f"https://127.0.0.1:{port} is free; save to start listening there."
    assert result == {"ok": True, "message": free}
    result = host.test_config({"bind_address": "0.0.0.0"})
    assert result["ok"] is False and "bind_address" in result["errors"]
    secret = "typed-token-0123456789-secret"
    assert host.test_config({"token": secret, "port": port})["ok"] is True
    assert host.test_config({"token": "short"})["errors"].keys() == {"token"}
    # The configured endpoint is "running" on the fake bridge but answers nothing.
    result = host.test_config({})
    assert result == {"ok": False, "message":
                      "The endpoint at https://127.0.0.1:47801 did not answer (no connection)."}
    assert (store.config_path.read_bytes(), store.token()) == before
    assert service._bridge.started == [("127.0.0.1", 47801)]   # nothing restarted
    host.assert_never_sent(secret, store.token())
    assert secret not in caplog.text and "127.0.0.1" not in caplog.text


def test_cli_networks(tmp_path, capsys) -> None:
    from fakenet import CAFE_OPEN, HOME, TWIN

    store = SettingsStore(tmp_path / "c", tmp_path / "s")
    store.save(Settings(allow_http=True))
    assert cli.networks("list", None, store) == 0
    assert "No network" in capsys.readouterr().out
    assert cli.networks("allow-current", None, store, FakeNetworks([HOME])) == 0
    assert cli.networks("allow-current", None, store, FakeNetworks([CAFE_OPEN])) == 1
    assert cli.networks("allow-current", None, store, FakeNetworks(available=False)) == 1
    assert cli.networks("allow-current", None, store, FakeNetworks([TWIN])) == 0
    assert len(store.load().http_networks) == 2
    assert cli.networks("remove", TWIN.uuid, store) == 0
    assert store.load().http_networks == ((HOME.uuid, "Zuhause"),)
    assert cli.networks("remove", "Nirgendwo", store) == 1
    capsys.readouterr()
    assert cli.networks("list", None, store) == 0
    out = capsys.readouterr().out
    assert HOME.uuid in out and "Plain HTTP is on" in out
