"""The desktop clipboard through wl-clipboard, like BlueFerry's OTP copy.

A background process on Wayland can only own or read the clipboard through
a data-control protocol, which ``wl-copy`` and ``wl-paste`` use (KWin,
wlroots and others support it). Data always goes through stdin/stdout,
never argv, and the helpers get only an allowlisted environment. A
bus-activated plugin may start without ``WAYLAND_DISPLAY``; a single
``wayland-N`` socket in the runtime directory identifies the session then.

``wl-copy --sensitive`` (wl-clipboard 2.3+) offers
``x-kde-passwordManagerHint: secret`` so Klipper and other clipboard
managers keep the text out of their history; it is used when available.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess  # nosec B404 - fixed argv, data on stdin
import threading
from collections.abc import Callable, Mapping
from pathlib import Path

_WAYLAND_SOCKET = re.compile(r"^wayland-[0-9]+$")
_ENV_KEYS = frozenset({
    "PATH", "HOME", "TMPDIR", "XDG_RUNTIME_DIR", "WAYLAND_DISPLAY", "LANG",
})
TIMEOUT_S = 5.0


class ClipboardError(Exception):
    """The clipboard is not reachable; the message names no content."""


def _wayland_sockets(runtime_dir: str | None) -> list[str]:
    if not runtime_dir:
        return []
    try:
        names = sorted(os.listdir(runtime_dir))
    except OSError:
        return []
    found = []
    for name in names:
        if not _WAYLAND_SOCKET.fullmatch(name):
            continue
        try:
            if stat.S_ISSOCK(os.lstat(Path(runtime_dir) / name).st_mode):
                found.append(name)
        except OSError:
            continue
    return found


def helper_environment(environ: Mapping[str, str]) -> dict[str, str] | None:
    """The helper environment, or None when no Wayland session is known."""
    env = {k: v for k, v in environ.items() if k in _ENV_KEYS or k.startswith("LC_")}
    if not env.get("WAYLAND_DISPLAY", "").strip():
        sockets = _wayland_sockets(env.get("XDG_RUNTIME_DIR"))
        if len(sockets) != 1:
            return None
        env["WAYLAND_DISPLAY"] = sockets[0]
    return env


Runner = Callable[..., subprocess.CompletedProcess]


class Clipboard:
    def __init__(
        self,
        *,
        environ: Mapping[str, str] | None = None,
        which: Callable[[str], str | None] = shutil.which,
        run: Runner = subprocess.run,
    ) -> None:
        self._environ = environ
        self._which = which
        self._run = run
        self._sensitive: bool | None = None
        self._lock = threading.Lock()

    def _tool(self, name: str) -> tuple[str, dict[str, str]]:
        executable = self._which(name)
        if not executable:
            raise ClipboardError("wl-clipboard is not installed")
        env = helper_environment(self._environ if self._environ is not None else os.environ)
        if env is None:
            raise ClipboardError("no Wayland session found")
        return os.path.abspath(executable), env

    def _supports_sensitive(self, executable: str, env: dict[str, str]) -> bool:
        if self._sensitive is None:
            try:
                result = self._run(
                    [executable, "--help"], capture_output=True, text=True,
                    timeout=TIMEOUT_S, env=env, check=False,
                )
                self._sensitive = "--sensitive" in f"{result.stdout}\n{result.stderr}"
            except (OSError, subprocess.SubprocessError):
                self._sensitive = False
        return self._sensitive

    def copy(self, data: bytes, mime: str) -> bool:
        """Own the clipboard with ``data``; return whether the history hint was set."""
        executable, env = self._tool("wl-copy")
        with self._lock:
            sensitive = self._supports_sensitive(executable, env)
            argv = [executable, "--type", mime]
            if sensitive:
                argv.append("--sensitive")
            try:
                # wl-copy forks a child that serves the selection; its output
                # must not be a pipe, or run() would wait for that child.
                result = self._run(
                    argv, input=data, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=TIMEOUT_S, env=env, check=False,
                )
            except (OSError, subprocess.SubprocessError):
                raise ClipboardError("wl-copy failed") from None
        if result.returncode != 0:
            raise ClipboardError("wl-copy failed")
        return sensitive

    def copy_text(self, text: str) -> bool:
        return self.copy(text.encode("utf-8"), "text/plain;charset=utf-8")

    def read_text(self, limit: int) -> str | None:
        """The clipboard as text, "" when empty; None when larger than ``limit`` bytes."""
        executable, env = self._tool("wl-paste")
        try:
            result = self._run(
                [executable, "--no-newline", "--type", "text"], capture_output=True,
                timeout=TIMEOUT_S, env=env, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise ClipboardError("wl-paste failed") from None
        if result.returncode != 0:
            # "Nothing is copied" or no text offered.
            return ""
        data = result.stdout or b""
        if len(data) > limit:
            return None
        return data.decode("utf-8", "replace")
