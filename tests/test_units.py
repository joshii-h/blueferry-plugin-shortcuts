"""Manifest, settings, addresses, certificates, clipboard helper and CLI."""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import stat
import subprocess

import pytest
from blueferry.plugin_api import PLUGIN_INTERFACE
from blueferry.plugin_api.testing import inline_service
from cryptography import x509
from fakehost import FakeHost

from blueferry_shortcuts import PLUGIN_ID, load_manifest, manifest_text, netaddr
from blueferry_shortcuts import __main__ as cli
from blueferry_shortcuts.clipboard import Clipboard, ClipboardError, helper_environment
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
from blueferry_shortcuts.tls import SERVER_DAYS, CertificateStore

ROUTES = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
enp5s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
enp5s0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
"""


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


# ---- addresses --------------------------------------------------------------------

def test_default_route_picks_lowest_metric() -> None:
    assert netaddr.default_route_interface(ROUTES) == "enp5s0"
    assert netaddr.default_route_interface(ROUTES.splitlines()[0]) is None


VPN_ROUTES = ROUTES + "wg0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n"


def test_a_vpn_default_route_is_passed_over_for_the_lan(tmp_path) -> None:
    assert netaddr.default_route_interface(VPN_ROUTES) == "enp5s0"
    assert netaddr.default_route_tunnel(VPN_ROUTES) == ("wg0", True)
    assert netaddr.default_route_tunnel(ROUTES) is None
    only = ROUTES.splitlines()[0] + "\n" + VPN_ROUTES.splitlines()[-1]
    assert netaddr.default_route_interface(only) == "wg0"
    assert netaddr.default_route_tunnel(only) == ("wg0", False)
    # A custom name (NetworkManager WireGuard profile) is known by its type.
    for name, kind in (("Immeditech", "65534"), ("enp5s0", "1"), ("vpn1", "512")):
        (tmp_path / name).mkdir()
        (tmp_path / name / "type").write_text(kind + "\n")
    assert netaddr.is_tunnel("Immeditech", tmp_path) and netaddr.is_tunnel("vpn1", tmp_path)
    assert not netaddr.is_tunnel("enp5s0", tmp_path)
    assert netaddr.is_tunnel("tun0", tmp_path) and netaddr.is_tunnel("ppp0", tmp_path)


@pytest.mark.parametrize("setting,allow_all,ok", [
    ("", False, True), ("192.168.1.20", False, True), ("enp5s0", False, True),
    ("0.0.0.0", False, False), ("::", False, False), ("0.0.0.0", True, True),
    ("224.0.0.1", False, False), ("bad name!", False, False),
])
def test_listen_setting_validation(setting, allow_all, ok) -> None:
    assert (netaddr.check_setting(setting, allow_all) is None) is ok


def test_resolve() -> None:
    addresses = {"enp5s0": "192.168.1.20"}
    resolve = lambda s, a=False: netaddr.resolve(  # noqa: E731
        s, a, default_interface=lambda: "enp5s0", address_of=addresses.get,
    )
    assert resolve("") == "192.168.1.20"
    assert resolve("enp5s0") == "192.168.1.20"
    assert resolve("10.0.0.5") == "10.0.0.5"
    with pytest.raises(netaddr.AddressError):
        resolve("wlan9")
    with pytest.raises(netaddr.AddressError):
        resolve("0.0.0.0")
    assert resolve("0.0.0.0", True) == "0.0.0.0"
    with pytest.raises(netaddr.AddressError, match="no default route"):
        netaddr.resolve("", False, default_interface=lambda: None)


# ---- certificates -------------------------------------------------------------------

def test_certificates_chain_and_follow_the_address(tmp_path) -> None:
    store = CertificateStore(tmp_path / "certs")
    first = store.ensure(["192.168.1.20"])
    ca = x509.load_pem_x509_certificate(first.ca_pem)
    leaf = x509.load_pem_x509_certificate(first.cert_path.read_bytes())
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert leaf.issuer == ca.subject
    leaf.verify_directly_issued_by(ca)
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ipaddress.ip_address("192.168.1.20") in sans.get_values_for_type(x509.IPAddress)
    lifetime = leaf.not_valid_after_utc - leaf.not_valid_before_utc
    assert lifetime <= dt.timedelta(days=SERVER_DAYS, minutes=5) < dt.timedelta(days=825)
    for path in (store.ca_key_path, store.key_path):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert len(first.fingerprint) == 95 and first.fingerprint == store.ca_fingerprint()
    # Same address: nothing changes. New address: new leaf, same CA (no new trust on iOS).
    serial = leaf.serial_number
    assert x509.load_pem_x509_certificate(
        store.ensure(["192.168.1.20"]).cert_path.read_bytes()).serial_number == serial
    second = store.ensure(["192.168.1.33"])
    assert second.fingerprint == first.fingerprint
    assert x509.load_pem_x509_certificate(second.cert_path.read_bytes()).serial_number != serial


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


# ---- clipboard helper ---------------------------------------------------------------

class _Runner:
    def __init__(self, help_text="  --sensitive  Hint", returncode=0, stdout=b"") -> None:
        self.calls = []
        self.help_text = help_text
        self.returncode = returncode
        self.stdout = stdout

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[-1] == "--help":
            return subprocess.CompletedProcess(argv, 0, self.help_text, "")
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, b"")


def _clipboard(runner, environ=None) -> Clipboard:
    environ = environ or {"WAYLAND_DISPLAY": "wayland-0", "PATH": "/usr/bin",
                          "SECRET_ENV": "x", "LC_ALL": "C"}
    return Clipboard(environ=environ, which=lambda name: f"/usr/bin/{name}", run=runner)


def test_copy_uses_stdin_sensitive_hint_and_clean_environment() -> None:
    runner = _Runner()
    assert _clipboard(runner).copy_text("geheim") is True
    argv, kwargs = runner.calls[-1]
    assert argv == ["/usr/bin/wl-copy", "--type", "text/plain;charset=utf-8", "--sensitive"]
    assert kwargs["input"] == b"geheim" and "geheim" not in " ".join(argv)
    assert kwargs["stdout"] == subprocess.DEVNULL
    assert "SECRET_ENV" not in kwargs["env"] and kwargs["env"]["LC_ALL"] == "C"


def test_copy_without_sensitive_support_and_failures() -> None:
    runner = _Runner(help_text="usage")
    assert _clipboard(runner).copy(b"\x89PNG", "image/png") is False
    assert "--sensitive" not in runner.calls[-1][0]
    with pytest.raises(ClipboardError):
        _clipboard(_Runner(returncode=1)).copy_text("x")
    missing = Clipboard(environ={"WAYLAND_DISPLAY": "w"}, which=lambda name: None)
    with pytest.raises(ClipboardError, match="not installed"):
        missing.copy_text("x")


def test_read_text_limits() -> None:
    assert _clipboard(_Runner(stdout="äöü".encode())).read_text(100) == "äöü"
    assert _clipboard(_Runner(stdout=b"x" * 11)).read_text(10) is None
    assert _clipboard(_Runner(returncode=1)).read_text(10) == ""


def test_wayland_socket_discovery(tmp_path) -> None:
    import socket

    runtime = tmp_path / "run"
    runtime.mkdir()
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(runtime / "wayland-1"))
        env = helper_environment({"XDG_RUNTIME_DIR": str(runtime)})
        assert env is not None and env["WAYLAND_DISPLAY"] == "wayland-1"
    assert helper_environment({"XDG_RUNTIME_DIR": str(tmp_path / "none")}) is None


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
