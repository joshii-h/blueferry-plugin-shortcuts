"""Settings, access token and the small persistent state.

Everything lives in owner-only files below
``~/.config/blueferry/plugins/io.weirdware.blueferry.shortcuts/``:
``config.json`` (listen address, port, switches), ``token`` (0600) and the
certificates (see :func:`certificate_store`). The last battery report
is kept in ``$XDG_STATE_HOME`` so the card survives a restart. The token
is not kept in the keyring on purpose: the card must be able to show it
for typing it into a shortcut, and the HTTPS thread checks it per request.
"""
from __future__ import annotations

import json
import re
import secrets
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from blueferry_plugin_kit.lanserver.tls import CertificateStore
from blueferry_plugin_kit.secrets import (
    SecretsError,
    config_dir,
    read_private,
    state_dir,
    write_private,
)

from blueferry_shortcuts import PLUGIN_ID

DEFAULT_PORT = 47801
# Plain HTTP (opt-in, approved networks only) listens one port below.
DEFAULT_HTTP_PORT = 47800
MAX_NETWORKS = 16
# No 0/o, 1/l/i: the token is typed into the Shortcuts app by hand.
TOKEN_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
TOKEN_GROUPS = 6
_TOKEN = re.compile(r"^[\x21-\x7e]{16,128}$")
# Common name of the local CA ("<name> (<host>)"); existing CAs stay valid.
CA_NAME = "BlueFerry Shortcuts CA"

# The kit's private-file helpers raise SecretsError; every ``except
# SettingsError`` in the plugin catches them through this alias.
SettingsError = SecretsError


def certificate_store(directory: Path) -> CertificateStore:
    """The local CA and server certificate next to the settings."""
    return CertificateStore(directory, ca_name=CA_NAME)


@dataclass(frozen=True, slots=True)
class Settings:
    bind_address: str = ""          # IP, interface name or "" (default route)
    allow_all_interfaces: bool = False
    port: int = DEFAULT_PORT
    allow_clipboard_read: bool = False
    accept_images: bool = False
    # Opt-in: plain HTTP in approved home networks (NetworkManager profiles).
    allow_http: bool = False
    http_port: int = DEFAULT_HTTP_PORT
    # (uuid, name) of the NetworkManager profiles approved for plain HTTP.
    http_networks: tuple[tuple[str, str], ...] = ()
    # iCloud link of the shared "BlueFerry" shortcut (empty: built-in default).
    shortcut_url: str = ""

    def changed(self, **values: object) -> Settings:
        return replace(self, **values)


def new_token() -> str:
    """Six groups of four characters, about 118 bits."""
    groups = (
        "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(4)) for _ in range(TOKEN_GROUPS)
    )
    return "-".join(groups)


def valid_token(token: str) -> bool:
    return bool(_TOKEN.fullmatch(token))


_UUID = re.compile(r"^[0-9A-Za-z-]{8,64}$")
_SHORTCUT_URL = re.compile(r"^https://(www\.)?icloud\.com/shortcuts/[0-9A-Za-z]{16,64}/?$")


def valid_shortcut_url(url: object) -> bool:
    """An iCloud link to a shared shortcut, or empty."""
    return isinstance(url, str) and (url == "" or bool(_SHORTCUT_URL.fullmatch(url)))


def _networks(raw: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(raw, list):
        return ()
    found: dict[str, str] = {}
    for entry in raw[:MAX_NETWORKS]:
        if not isinstance(entry, dict):
            continue
        uuid, name = entry.get("uuid"), entry.get("name")
        if isinstance(uuid, str) and _UUID.fullmatch(uuid) and isinstance(name, str):
            found.setdefault(uuid, "".join(ch for ch in name if ch.isprintable())[:64])
    return tuple(found.items())


class SettingsStore:
    def __init__(self, directory: Path | None = None, state: Path | None = None) -> None:
        self.directory = directory or config_dir(PLUGIN_ID)
        self.state_directory = state or state_dir(PLUGIN_ID)

    @property
    def config_path(self) -> Path:
        return self.directory / "config.json"

    @property
    def token_path(self) -> Path:
        return self.directory / "token"

    @property
    def state_path(self) -> Path:
        return self.state_directory / "state.json"

    def load(self) -> Settings:
        try:
            raw = json.loads(read_private(self.config_path))
        except FileNotFoundError:
            return Settings()
        except ValueError:
            raise SettingsError("config.json is not valid JSON") from None
        if not isinstance(raw, dict):
            raise SettingsError("config.json is not an object")
        defaults = Settings()
        port = raw.get("port", defaults.port)
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            port = defaults.port
        bind = raw.get("bind_address", "")
        http_port = raw.get("http_port", defaults.http_port)
        if (isinstance(http_port, bool) or not isinstance(http_port, int)
                or not 1024 <= http_port <= 65535):
            http_port = defaults.http_port
        shortcut_url = raw.get("shortcut_url", "")
        return Settings(
            bind_address=bind if isinstance(bind, str) else "",
            allow_all_interfaces=raw.get("allow_all_interfaces") is True,
            port=port,
            allow_clipboard_read=raw.get("allow_clipboard_read") is True,
            accept_images=raw.get("accept_images") is True,
            allow_http=raw.get("allow_http") is True,
            http_port=http_port,
            http_networks=_networks(raw.get("http_networks")),
            shortcut_url=shortcut_url if valid_shortcut_url(shortcut_url) else "",
        )

    def save(self, settings: Settings) -> None:
        values = asdict(settings)
        values["http_networks"] = [
            {"uuid": uuid, "name": name} for uuid, name in settings.http_networks
        ]
        write_private(self.config_path, json.dumps(values, indent=2) + "\n")

    def token(self) -> str:
        """The stored token; a new one is created on first use."""
        try:
            token = read_private(self.token_path).decode("utf-8", "replace").strip()
        except FileNotFoundError:
            token = ""
        if valid_token(token):
            return token
        return self.set_token(new_token())

    def set_token(self, token: str) -> str:
        if not valid_token(token):
            raise SettingsError("the token must be 16 to 128 printable characters")
        write_private(self.token_path, token + "\n")
        return token

    def load_state(self) -> dict[str, object]:
        try:
            raw = json.loads(read_private(self.state_path))
        except (OSError, ValueError, SettingsError):
            return {}
        return raw if isinstance(raw, dict) else {}

    def save_state(self, state: dict[str, object]) -> None:
        write_private(self.state_path, json.dumps(state) + "\n")

    def forget(self) -> None:
        for path in (self.config_path, self.token_path, self.state_path):
            path.unlink(missing_ok=True)
