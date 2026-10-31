"""Play on PC: a link from the iPhone plays in mpv, straight from the internet.

One player at a time: a new link **replaces** what is playing (through mpv's
IPC socket, so the window and its fullscreen state stay), like casting to a
TV. mpv resolves YouTube and similar sites with yt-dlp by itself.

Safety rules, all enforced here:

- The link is never passed through a shell. mpv is started with an argument
  list, ``--`` before the link, so even a value starting with ``-`` could
  never become an option (the server only lets ``http``/``https`` through
  anyway). Replacing goes through mpv's JSON IPC, where the link is a JSON
  string, not a command line.
- Extra mpv options come from a fixed allowlist (:func:`check_options`).
- The IPC socket (a new random name per player) lives in a private
  directory below ``$XDG_RUNTIME_DIR`` (0700, owned by the user, no
  symlink); mpv is started with umask 077 and the socket is set to 0600.
  Without ``XDG_RUNTIME_DIR`` there is no socket: a new link then restarts
  the player and pause is unavailable.
- At most :data:`PLAYS_PER_MINUTE` new links per minute.
- Nothing here logs the link.
"""
from __future__ import annotations

import collections
import glob
import json
import logging
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

log = logging.getLogger(__name__)

PLAYS_PER_MINUTE = 6
IPC_TIMEOUT_S = 2.0
MAX_IPC_REPLY = 1024 * 1024
MAX_OPTIONS = 8
MAX_OPTIONS_LENGTH = 300
SOCKET_DIR = "blueferry-shortcuts"

# yt-dlp format strings per quality setting ("Video quality" in the form).
QUALITIES: dict[str, str] = {
    "best": "bestvideo+bestaudio/best",
    "1080p": "bestvideo[height<=?1080]+bestaudio/best[height<=?1080]/best",
    "720p": "bestvideo[height<=?720]+bestaudio/best[height<=?720]/best",
    "480p": "bestvideo[height<=?480]+bestaudio/best[height<=?480]/best",
    "audio": "bestaudio/best",
}
DEFAULT_QUALITY = "best"

# The only extra options a user may add. Each entry matches one whole
# argument; nothing that names files, scripts, sockets or commands.
_ALLOWED_OPTIONS = tuple(re.compile(pattern) for pattern in (
    r"--mute=(yes|no)",
    r"--volume=(100|[1-9]?[0-9])",
    r"--loop-file=(inf|no|[1-9][0-9]?)",
    r"--loop-playlist=(inf|no)",
    r"--(no-)?ontop",
    r"--ontop=(yes|no)",
    r"--(no-)?border",
    r"--border=(yes|no)",
    r"--hwdec=(auto|auto-safe|no|vaapi|vulkan)",
    r"--(fs-)?screen=[0-9]",
    r"--keep-open=(yes|no|always)",
    r"--(no-)?save-position-on-quit",
    r"--(no-)?resume-playback",
    r"--sub-auto=(no|exact|fuzzy|all)",
    r"--[as]lang=[a-z]{2,3}(,[a-z]{2,3}){0,3}",
    r"--speed=(0\.(2[5-9]|[3-9][0-9]?)|[1-3](\.[0-9][0-9]?)?|4)",
    r"--profile=[A-Za-z0-9_-]{1,32}",
))

# Where mpv-mpris (media keys, desktop media controls) usually installs.
_MPRIS_GLOBS = (
    "{config}/mpv/scripts/mpris*.so",
    "/etc/mpv/scripts/mpris*.so",
    "/usr/share/mpv/scripts/mpris*.so",
    "/usr/lib/mpv-mpris/mpris*.so",
    "/usr/lib*/mpv/mpris*.so",
    "/usr/local/lib*/mpv/mpris*.so",
)


class PlayerError(Exception):
    """``token`` is the error word the HTTP endpoint answers with."""

    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


def check_options(text: str) -> tuple[str, ...]:
    """The allowed extra mpv options in ``text``; ValueError names the first bad one."""
    if len(text) > MAX_OPTIONS_LENGTH:
        raise ValueError(f"at most {MAX_OPTIONS_LENGTH} characters")
    options = tuple(text.split())
    if len(options) > MAX_OPTIONS:
        raise ValueError(f"at most {MAX_OPTIONS} options")
    for option in options:
        if not any(pattern.fullmatch(option) for pattern in _ALLOWED_OPTIONS):
            shown = "".join(ch for ch in option[:40] if ch.isprintable())
            raise ValueError(f"not an allowed option: {shown}")
    return options


@dataclass(frozen=True, slots=True)
class PlayOptions:
    fullscreen: bool = True
    quality: str = DEFAULT_QUALITY
    extra: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Tools:
    mpv: str | None
    ytdlp: str | None
    mpris: bool


class Process(Protocol):
    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...


Spawn = Callable[[Sequence[str], Callable[[], None]], Process]
Ipc = Callable[[str, list], object]


def spawn_detached(argv: Sequence[str], on_exit: Callable[[], None]) -> Process:
    """Start ``argv`` (a list, never a shell) in its own session, private umask."""
    process = subprocess.Popen(
        list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True, umask=0o077,
    )

    def reap() -> None:
        process.wait()
        on_exit()

    threading.Thread(target=reap, name="blueferry-shortcuts-mpv", daemon=True).start()
    return process


def mpv_command(path: str, command: list, timeout: float = IPC_TIMEOUT_S) -> object:
    """Send one JSON IPC command to mpv and return its ``data``."""
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(path)
        message = {"command": command, "request_id": 1}
        connection.sendall(json.dumps(message).encode("utf-8") + b"\n")
        buffer = b""
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("mpv did not answer")
            connection.settimeout(left)
            chunk = connection.recv(65536)
            if not chunk:
                raise ConnectionError("mpv closed the connection")
            buffer += chunk
            if len(buffer) > MAX_IPC_REPLY:
                raise ConnectionError("reply too large")
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                try:
                    reply = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(reply, dict) or reply.get("request_id") != 1:
                    continue   # an event
                if reply.get("error") != "success":
                    raise ConnectionError(f"mpv: {reply.get('error')}")
                return reply.get("data")


def find_mpris(config_home: str | None = None) -> bool:
    config = config_home or os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return any(glob.glob(pattern.format(config=config)) for pattern in _MPRIS_GLOBS)


def private_socket_path(runtime_dir: str | None) -> str | None:
    """``$XDG_RUNTIME_DIR/blueferry-shortcuts/mpv-<random>.sock`` in a checked
    0700 directory, or None when there is no safe place. A new name per
    player: an old mpv that is still quitting removes its own socket only."""
    if not runtime_dir or not os.path.isabs(runtime_dir):
        return None
    directory = os.path.join(runtime_dir, SOCKET_DIR)
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        pass
    except OSError:
        return None
    try:
        info = os.lstat(directory)
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        return None
    if stat.S_IMODE(info.st_mode) != 0o700:
        try:
            os.chmod(directory, 0o700)
        except OSError:
            return None
    path = os.path.join(directory, f"mpv-{secrets.token_hex(6)}.sock")
    # sun_path holds 108 bytes including the final NUL.
    return path if len(path.encode()) < 108 else None


class Player:
    """mpv for links from the iPhone; thread-safe."""

    def __init__(
        self,
        *,
        spawn: Spawn = spawn_detached,
        ipc: Ipc = mpv_command,
        which: Callable[[str], str | None] = shutil.which,
        mpris: Callable[[], bool] = find_mpris,
        runtime_dir: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        on_change: Callable[[], None] = lambda: None,
    ) -> None:
        self._spawn = spawn
        self._ipc = ipc
        self._which = which
        self._mpris = mpris
        self._runtime_dir = (runtime_dir if runtime_dir is not None
                             else os.environ.get("XDG_RUNTIME_DIR", ""))
        self._clock = clock
        self.on_change = on_change
        self._lock = threading.Lock()
        self._process: Process | None = None
        self._socket: str | None = None
        self._plays: collections.deque[float] = collections.deque()
        self._host = ""

    # ---- state --------------------------------------------------------------

    def tools(self) -> Tools:
        mpv = self._which("mpv")
        ytdlp = self._which("yt-dlp") or self._which("youtube-dl")
        return Tools(mpv, ytdlp, self._mpris())

    def playing(self) -> bool:
        with self._lock:
            return self._alive()

    @property
    def host(self) -> str:
        """Host of what plays now (shown on the card), never the full link."""
        with self._lock:
            return self._host if self._alive() else ""

    def _alive(self) -> bool:
        return self._process is not None and self._process.poll() is None

    # ---- commands -----------------------------------------------------------

    def play(self, url: str, host: str, options: PlayOptions) -> bool:
        """Play ``url``; True when it replaced what was playing."""
        tools = self.tools()
        if tools.mpv is None:
            raise PlayerError("mpv-missing")
        with self._lock:
            now = self._clock()
            while self._plays and now - self._plays[0] >= 60:
                self._plays.popleft()
            if len(self._plays) >= PLAYS_PER_MINUTE:
                raise PlayerError("play-rate-limited")
            self._plays.append(now)
            fmt = QUALITIES.get(options.quality, QUALITIES[DEFAULT_QUALITY])
            if self._alive() and self._socket and self._replace(url, fmt, options):
                self._host = host
                return True
            self._stop_locked()
            self._socket = private_socket_path(self._runtime_dir)
            argv = [tools.mpv, "--no-terminal", "--force-window=immediate", "--idle=no",
                    "--ytdl=yes", f"--ytdl-format={fmt}"]
            if self._socket:
                argv.append(f"--input-ipc-server={self._socket}")
            if options.fullscreen:
                argv.append("--fullscreen")
            if options.quality == "audio":
                argv.append("--no-video")
            argv += list(options.extra)
            argv += ["--", url]
            try:
                self._process = self._spawn(argv, self._exited)
            except OSError:
                self._process = None
                raise PlayerError("mpv-failed") from None
            self._host = host
        log.info("playback started")
        self.on_change()
        return False

    def _command(self, command: list) -> object:
        """One IPC command; the socket is tightened to 0600 on first use."""
        assert self._socket is not None
        try:
            if stat.S_IMODE(os.lstat(self._socket).st_mode) != 0o600:
                os.chmod(self._socket, 0o600)
        except FileNotFoundError:
            pass
        return self._ipc(self._socket, command)

    def _replace(self, url: str, fmt: str, options: PlayOptions) -> bool:
        try:
            self._command(["set_property", "ytdl-format", fmt])
            self._command(["set_property", "fullscreen", options.fullscreen])
            self._command(["set_property", "vid", "no" if options.quality == "audio" else "auto"])
            self._command(["loadfile", url, "replace"])
            self._command(["set_property", "pause", False])
        except (OSError, ValueError):
            log.debug("mpv IPC failed; starting a new player")
            return False
        return True

    def toggle_pause(self) -> bool:
        """Pause or resume; returns whether it is paused now."""
        with self._lock:
            if not self._alive():
                raise PlayerError("not-playing")
            if not self._socket:
                raise PlayerError("player-unreachable")
            try:
                self._command(["cycle", "pause"])
                paused = self._command(["get_property", "pause"])
            except (OSError, ValueError):
                raise PlayerError("player-unreachable") from None
        return paused is True

    def stop(self) -> bool:
        """Quit the player; False when nothing was playing."""
        with self._lock:
            if not self._alive():
                return False
            self._stop_locked()
        self.on_change()
        return True

    def _stop_locked(self) -> None:
        process, self._process = self._process, None
        self._host = ""
        if process is None or process.poll() is not None:
            return
        if self._socket:
            try:
                self._command(["quit"])
                return
            except (OSError, ValueError):
                pass
        try:
            process.terminate()
        except OSError:
            pass

    def _exited(self) -> None:
        self.on_change()
