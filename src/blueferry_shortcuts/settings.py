"""Settings, access token and the small persistent state.

Everything lives in owner-only files below
``~/.config/blueferry/plugins/io.weirdware.blueferry.shortcuts/``:
``config.json`` (listen address, port, switches), ``token`` (0600) and the
certificates (see :mod:`blueferry_shortcuts.tls`). The last battery report
is kept in ``$XDG_STATE_HOME`` so the card survives a restart. The token
is not kept in the keyring on purpose: the card must be able to show it
for typing it into a shortcut, and the HTTPS thread checks it per request.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import stat
import tempfile
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from blueferry_shortcuts import PLUGIN_ID

MAX_FILE_BYTES = 16 * 1024
DEFAULT_PORT = 47801
# No 0/o, 1/l/i: the token is typed into the Shortcuts app by hand.
TOKEN_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
TOKEN_GROUPS = 6
_TOKEN = re.compile(r"^[\x21-\x7e]{16,128}$")


class SettingsError(Exception):
    pass


def config_dir() -> Path:
    config_home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return Path(config_home) / "blueferry" / "plugins" / PLUGIN_ID


def state_dir() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )
    return Path(state_home) / "blueferry" / "plugins" / PLUGIN_ID


@dataclass(frozen=True, slots=True)
class Settings:
    bind_address: str = ""          # IP, interface name or "" (default route)
    allow_all_interfaces: bool = False
    port: int = DEFAULT_PORT
    allow_clipboard_read: bool = False
    accept_images: bool = False

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


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise SettingsError("config directory has the wrong owner or type")
    path.chmod(0o700)
    return path


def write_private(path: Path, data: str | bytes) -> None:
    private_dir(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data.encode("utf-8") if isinstance(data, str) else data)
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        Path(temporary).unlink(missing_ok=True)


def read_private(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise SettingsError(f"{path.name} has the wrong owner or type")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise SettingsError(f"{path.name} is readable by other users")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise SettingsError(f"{path.name} is too large")
    return data


class SettingsStore:
    def __init__(self, directory: Path | None = None, state: Path | None = None) -> None:
        self.directory = directory or config_dir()
        self.state_directory = state or state_dir()

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
        return Settings(
            bind_address=bind if isinstance(bind, str) else "",
            allow_all_interfaces=raw.get("allow_all_interfaces") is True,
            port=port,
            allow_clipboard_read=raw.get("allow_clipboard_read") is True,
            accept_images=raw.get("accept_images") is True,
        )

    def save(self, settings: Settings) -> None:
        write_private(self.config_path, json.dumps(asdict(settings), indent=2) + "\n")

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
