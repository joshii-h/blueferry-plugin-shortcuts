"""Manifest, settings, request parsing, settings form and CLI."""
from __future__ import annotations

import json
import os
import stat

from blueferry.plugin_api import PLUGIN_INTERFACE
from blueferry.plugin_api.testing import inline_service
from fakehost import FakeHost

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

def test_manifest_declares_the_12_surfaces_and_settings() -> None:
    text = manifest_text()
    assert "ApiVersion=1.2" in text and "Capabilities=card;notify;" in text
    manifest = load_manifest()
    assert manifest.id == PLUGIN_ID
    assert manifest.capabilities == ("card", "notify")
    assert manifest.api_minor == 2
    fields = {field.key: field for field in manifest.config}
    assert list(fields) == ["bind_address", "allow_all_interfaces", "port", "token",
                            "allow_clipboard_read", "accept_images"]
    assert fields["port"].default == 47801
    assert fields["token"].secret
    assert fields["allow_clipboard_read"].empty() is False
    assert fields["allow_all_interfaces"].empty() is False


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
    def __init__(self, _endpoints) -> None:
        self.started = []
        self.fail_port = None

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
        lang="en",
    )
    host = FakeHost(service)
    service.start()
    values = _call(service.GetConfig)["values"]
    assert values == {"bind_address": "", "allow_all_interfaces": False, "port": 47801,
                      "token": "********", "allow_clipboard_read": False,
                      "accept_images": False}
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
