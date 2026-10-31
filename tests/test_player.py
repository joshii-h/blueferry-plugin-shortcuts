"""Play on PC: the player with a fake spawn and fake IPC, the real IPC client
against a fake mpv socket, and the HTTPS endpoints with a fake player."""
from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import stat
import tempfile
import threading
import time

import pytest
from test_http import Harness

from blueferry_shortcuts import __main__ as cli
from blueferry_shortcuts.player import (
    PLAYS_PER_MINUTE,
    QUALITIES,
    MpvError,
    Player,
    PlayerError,
    PlayOptions,
    check_options,
    mpv_command,
    private_socket_path,
    remove_stale_sockets,
    runtime_command,
)
from blueferry_shortcuts.settings import Settings, SettingsStore

SECRET_PATH = "/watch?v=geheim4711&list=privat"


class FakeProcess:
    def __init__(self) -> None:
        self.code: int | None = None
        self.terminated = False

    def poll(self) -> int | None:
        return self.code

    def terminate(self) -> None:
        self.terminated = True
        self.code = -15


class FakeSpawn:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.processes: list[FakeProcess] = []
        self.on_exit = []
        self.fail = fail

    def __call__(self, argv, on_exit):
        if self.fail:
            raise FileNotFoundError("mpv")
        self.calls.append(list(argv))
        self.on_exit.append(on_exit)
        self.processes.append(FakeProcess())
        return self.processes[-1]


class FakeIpc:
    def __init__(self) -> None:
        self.commands: list[tuple[str, list]] = []
        self.paused = False
        self.broken = False
        self.refused: set[str] = set()    # command names mpv answers with an error

    def __call__(self, path, command):
        if self.broken:
            raise ConnectionRefusedError("no mpv")
        if command[0] in self.refused:
            raise MpvError("mpv: property unavailable")
        self.commands.append((path, command))
        if command == ["cycle", "pause"]:
            self.paused = not self.paused
        if command == ["get_property", "pause"]:
            return self.paused
        return None


def _player(tmp_path, *, mpv="/usr/bin/mpv", ytdlp="/usr/bin/yt-dlp", spawn=None, ipc=None,
            runtime=True, clock=None, which=None, socket_wait=0.0):
    tools = {"mpv": mpv, "yt-dlp": ytdlp}
    runtime_dir = _short_dir(tmp_path)
    return Player(
        spawn=spawn or FakeSpawn(), ipc=ipc or FakeIpc(), which=which or tools.get,
        mpris=lambda: False, runtime_dir=str(runtime_dir) if runtime else "",
        clock=clock or (lambda: 0.0), socket_wait=socket_wait,
    )


_SHORT_DIRS: list[str] = []


def _short_dir(tmp_path):
    """A runtime directory short enough for a socket path (108 bytes)."""
    link = tmp_path / "run"
    if not link.exists():
        _SHORT_DIRS.append(tempfile.mkdtemp(prefix="bfs-", dir="/tmp"))
        link.symlink_to(_SHORT_DIRS[-1])
    return link.resolve()


@pytest.fixture(autouse=True)
def _remove_short_dirs():
    yield
    while _SHORT_DIRS:
        shutil.rmtree(_SHORT_DIRS.pop(), ignore_errors=True)


# ---- options -----------------------------------------------------------------------

def test_only_allowlisted_options_pass() -> None:
    assert check_options("") == ()
    assert check_options(" --volume=60  --hwdec=auto --mute=yes --screen=1 --profile=tv ") == (
        "--volume=60", "--hwdec=auto", "--mute=yes", "--screen=1", "--profile=tv")
    for bad in ("--script=/tmp/x.lua", "--input-ipc-server=/tmp/s", "--volume=101",
                "--include=/etc/passwd", "--hwdec=auto;rm", "-v", "--ytdl-raw-options=exec=x",
                "--log-file=/tmp/l", "--input-conf=/tmp/c", "--speed=9", "file.mkv",
                "--volume=60 --o=/tmp/out.mkv"):
        with pytest.raises(ValueError):
            check_options(bad)
    with pytest.raises(ValueError):
        check_options(" ".join(["--mute=yes"] * 9))
    with pytest.raises(ValueError):
        check_options("--mute=yes " * 40)


def test_settings_keep_only_valid_play_values(tmp_path) -> None:
    store = SettingsStore(tmp_path / "c", tmp_path / "s")
    store.directory.mkdir(parents=True, mode=0o700)
    raw = {"play_on_pc": True, "play_quality": "8k", "play_options": "--script=/tmp/x",
           "play_fullscreen": False}
    (store.config_path).write_text(json.dumps(raw))
    os.chmod(store.config_path, 0o600)
    settings = store.load()
    assert settings.play_on_pc is True and settings.play_fullscreen is False
    assert settings.play_quality == "best" and settings.play_options == ""
    assert Settings().play_on_pc is False


# ---- player ------------------------------------------------------------------------

def test_spawn_uses_an_argument_list_with_double_dash(tmp_path) -> None:
    spawn = FakeSpawn()
    player = _player(tmp_path, spawn=spawn)
    url = "https://www.youtube.com/watch?v=abc;$(touch /tmp/pwned)"
    options = PlayOptions(fullscreen=True, quality="720p", extra=("--volume=50",))
    assert player.play(url, "www.youtube.com", options) is False
    argv = spawn.calls[-1]
    assert argv[0] == "/usr/bin/mpv"
    assert argv[-2:] == ["--", url]
    assert "--fullscreen" in argv and "--volume=50" in argv
    assert f"--ytdl-format={QUALITIES['720p']}" in argv
    ipc = [a for a in argv if a.startswith("--input-ipc-server=")]
    assert len(ipc) == 1
    path = ipc[0].split("=", 1)[1]
    directory = os.path.dirname(path)
    assert directory.startswith(str(_short_dir(tmp_path)))
    assert stat.S_IMODE(os.lstat(directory).st_mode) == 0o700
    assert player.playing() and player.host == "www.youtube.com"


def test_audio_quality_and_window_mode(tmp_path) -> None:
    spawn = FakeSpawn()
    player = _player(tmp_path, spawn=spawn)
    player.play("https://example.org/a.mp3", "example.org", PlayOptions(False, "audio"))
    argv = spawn.calls[-1]
    assert "--no-video" in argv and "--fullscreen" not in argv


def test_new_link_replaces_through_ipc(tmp_path) -> None:
    spawn, ipc = FakeSpawn(), FakeIpc()
    player = _player(tmp_path, spawn=spawn, ipc=ipc)
    player.play("https://a.example/1", "a.example", PlayOptions())
    assert player.play("https://b.example/2", "b.example", PlayOptions()) is True
    assert len(spawn.calls) == 1
    sent = [command for _path, command in ipc.commands]
    assert ["loadfile", "https://b.example/2", "replace"] in sent
    assert player.host == "b.example"


def test_broken_ipc_restarts_the_player(tmp_path) -> None:
    spawn, ipc = FakeSpawn(), FakeIpc()
    player = _player(tmp_path, spawn=spawn, ipc=ipc)
    player.play("https://a.example/1", "a.example", PlayOptions())
    first_socket = next(a for a in spawn.calls[0] if a.startswith("--input-ipc-server="))
    ipc.broken = True
    assert player.play("https://b.example/2", "b.example", PlayOptions()) is False
    assert spawn.processes[0].terminated and len(spawn.calls) == 2
    second_socket = next(a for a in spawn.calls[1] if a.startswith("--input-ipc-server="))
    assert first_socket != second_socket


def test_pause_and_stop(tmp_path) -> None:
    spawn, ipc = FakeSpawn(), FakeIpc()
    player = _player(tmp_path, spawn=spawn, ipc=ipc)
    with pytest.raises(PlayerError, match="not-playing"):
        player.toggle_pause()
    assert player.stop() is False
    player.play("https://a.example/1", "a.example", PlayOptions())
    assert player.toggle_pause() is True
    assert player.toggle_pause() is False
    assert player.stop() is True
    assert ipc.commands[-1][1] == ["quit"]
    assert not player.playing() and player.host == ""


def test_player_exit_is_noticed(tmp_path) -> None:
    spawn = FakeSpawn()
    player = _player(tmp_path, spawn=spawn)
    changes = []
    player.on_change = lambda: changes.append(1)
    player.play("https://a.example/1", "a.example", PlayOptions())
    spawn.processes[0].code = 0
    spawn.on_exit[0]()
    assert not player.playing() and changes


def test_without_runtime_dir_there_is_no_socket(tmp_path) -> None:
    spawn = FakeSpawn()
    player = _player(tmp_path, spawn=spawn, runtime=False)
    player.play("https://a.example/1", "a.example", PlayOptions())
    assert not any(a.startswith("--input-ipc-server") for a in spawn.calls[0])
    with pytest.raises(PlayerError, match="player-unreachable"):
        player.toggle_pause()
    player.play("https://b.example/1", "b.example", PlayOptions())
    assert spawn.processes[0].terminated and len(spawn.calls) == 2


def test_missing_mpv_and_failed_start(tmp_path) -> None:
    player = _player(tmp_path, mpv=None)
    with pytest.raises(PlayerError, match="mpv-missing"):
        player.play("https://a.example/1", "a.example", PlayOptions())
    player = _player(tmp_path, spawn=FakeSpawn(fail=True))
    with pytest.raises(PlayerError, match="mpv-failed"):
        player.play("https://a.example/1", "a.example", PlayOptions())


def test_play_rate_limit(tmp_path) -> None:
    now = [0.0]
    player = _player(tmp_path, clock=lambda: now[0])
    for _ in range(PLAYS_PER_MINUTE):
        player.play("https://a.example/1", "a.example", PlayOptions())
    with pytest.raises(PlayerError, match="play-rate-limited"):
        player.play("https://a.example/1", "a.example", PlayOptions())
    now[0] = 61.0
    player.play("https://a.example/1", "a.example", PlayOptions())


def test_socket_directory_must_be_private(tmp_path) -> None:
    assert private_socket_path("") is None
    assert private_socket_path("relative") is None
    run = _short_dir(tmp_path)
    (run / "blueferry-shortcuts").mkdir(mode=0o755)
    path = private_socket_path(str(run))
    assert path is not None and path.endswith(".sock")
    assert stat.S_IMODE(os.lstat(run / "blueferry-shortcuts").st_mode) == 0o700
    other = tmp_path / "other"
    other.mkdir()
    (other / "blueferry-shortcuts").symlink_to(tmp_path)
    assert private_socket_path(str(other)) is None


def test_ipc_client_against_a_fake_mpv(tmp_path) -> None:
    path = str(_short_dir(tmp_path) / "mpv.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)
    received = []

    def serve() -> None:
        connection, _ = server.accept()
        with connection:
            line = connection.makefile("rb").readline()
            request = json.loads(line)
            received.append(request)
            connection.sendall(b'{"event":"pause"}\n')
            reply = {"request_id": request["request_id"], "error": "success", "data": True}
            connection.sendall(json.dumps(reply).encode() + b"\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert mpv_command(path, ["get_property", "pause"]) is True
    thread.join(5)
    server.close()
    assert received[0]["command"] == ["get_property", "pause"]


def test_tools_are_cached_until_refreshed(tmp_path) -> None:
    lookups = []

    def which(name):
        lookups.append(name)
        return {"mpv": "/usr/bin/mpv"}.get(name)

    player = _player(tmp_path, which=which)
    for _ in range(5):
        assert player.tools().mpv == "/usr/bin/mpv"
    first = len(lookups)
    assert first and player.tools().ytdlp is None and len(lookups) == first
    player.play("https://a.example/1", "a.example", PlayOptions())
    assert len(lookups) == 2 * first      # play looks again
    player.refresh_tools()
    assert len(lookups) == 3 * first


def test_card_state_does_not_wait_for_a_slow_ipc(tmp_path) -> None:
    release, entered = threading.Event(), threading.Event()

    class SlowIpc(FakeIpc):
        def __call__(self, path, command):
            if command[0] == "loadfile":
                entered.set()
                release.wait(10)
            return super().__call__(path, command)

    player = _player(tmp_path, ipc=SlowIpc())
    player.play("https://a.example/1", "a.example", PlayOptions())
    worker = threading.Thread(
        target=player.play, args=("https://b.example/2", "b.example", PlayOptions()))
    worker.start()
    try:
        assert entered.wait(5)
        started = time.monotonic()
        assert player.playing() and player.host == "a.example"
        assert player.tools().mpv == "/usr/bin/mpv"
        assert time.monotonic() - started < 0.5
    finally:
        release.set()
        worker.join(5)
    assert player.host == "b.example"


def test_commands_wait_briefly_for_a_new_socket(tmp_path) -> None:
    spawn = FakeSpawn()
    player = _player(tmp_path, spawn=spawn, socket_wait=1.0)
    player.play("https://a.example/1", "a.example", PlayOptions())
    path = next(a for a in spawn.calls[0]
                if a.startswith("--input-ipc-server=")).split("=", 1)[1]
    timer = threading.Timer(0.2, lambda: open(path, "w").close())
    timer.start()
    started = time.monotonic()
    assert player.toggle_pause() is True
    assert 0.15 <= time.monotonic() - started < 1.0
    timer.join()
    # The socket is there now: replacing does not restart mpv.
    assert player.play("https://b.example/2", "b.example", PlayOptions()) is True
    assert len(spawn.calls) == 1


def test_replace_applies_the_extra_options(tmp_path) -> None:
    ipc = FakeIpc()
    player = _player(tmp_path, ipc=ipc)
    player.play("https://a.example/1", "a.example", PlayOptions())
    ipc.refused = {"apply-profile"}
    options = PlayOptions(False, "720p", ("--volume=40", "--no-border", "--ontop",
                                          "--profile=tv"))
    assert player.play("https://b.example/2", "b.example", options) is True
    sent = [command for _path, command in ipc.commands]
    assert ["set_property", "fullscreen", False] in sent
    assert ["set_property", "ytdl-format", QUALITIES["720p"]] in sent
    assert ["set", "volume", "40"] in sent and ["set", "border", "no"] in sent
    assert ["set", "ontop", "yes"] in sent
    assert sent.index(["set", "volume", "40"]) < sent.index(
        ["loadfile", "https://b.example/2", "replace"])
    assert runtime_command("--profile=tv") == ["apply-profile", "tv"]
    assert runtime_command("--mute=yes") == ["set", "mute", "yes"]


def test_exit_removes_the_socket(tmp_path) -> None:
    spawn = FakeSpawn()
    player = _player(tmp_path, spawn=spawn)
    player.play("https://a.example/1", "a.example", PlayOptions())
    path = next(a for a in spawn.calls[0]
                if a.startswith("--input-ipc-server=")).split("=", 1)[1]
    open(path, "w").close()
    spawn.processes[0].code = -11
    spawn.on_exit[0]()
    assert not os.path.exists(path)
    spawn.on_exit[0]()        # already gone: no error


def test_stale_sockets_are_removed_live_ones_stay(tmp_path) -> None:
    directory = _short_dir(tmp_path)
    stale, live = str(directory / "mpv-stale.sock"), str(directory / "mpv-live.sock")
    dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dead.bind(stale)
    dead.close()                  # the file stays, nobody listens
    listening = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listening.bind(live)
    listening.listen(1)
    try:
        remove_stale_sockets(str(directory))
        assert not os.path.exists(stale) and os.path.exists(live)
    finally:
        listening.close()


# ---- HTTPS endpoints ---------------------------------------------------------------

@pytest.fixture
def play_harness(tmp_path):
    made = []

    def make(spawn=None, ipc=None, mpv="/usr/bin/mpv", resolve_host=None, **settings):
        spawn, ipc = spawn or FakeSpawn(), ipc or FakeIpc()
        player = _player(tmp_path, spawn=spawn, ipc=ipc, mpv=mpv)
        harness = Harness(tmp_path, player=player, resolve_host=resolve_host, **settings)
        harness.spawn, harness.ipc = spawn, ipc
        made.append(harness)
        return harness

    yield make
    for harness in made:
        harness.close()


def test_play_is_off_by_default(play_harness) -> None:
    h = play_harness()
    assert h.request("POST", "/play", {"url": "https://example.org/v"})[0] == 403
    assert h.request("POST", "/pause", b"")[0] == 403
    assert h.request("POST", "/stop", b"")[0] == 403
    assert h.spawn.calls == []
    assert not any(item["id"] == "play" for item in h.host.items())


def test_play_needs_the_token(play_harness) -> None:
    h = play_harness(play_on_pc=True)
    assert h.request("POST", "/play", {"url": "https://example.org/v"}, token=False)[0] == 401
    assert h.spawn.calls == []


def test_play_pause_stop_over_https(play_harness, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    h = play_harness(play_on_pc=True, play_quality="1080p", play_fullscreen=False,
                     play_options="--volume=40")
    url = "https://user:pw@www.youtube.com" + SECRET_PATH
    status, _t, body = h.request("POST", "/play", {"url": url})
    assert status == 200 and json.loads(body) == {"ok": True, "replaced": False}
    argv = h.spawn.calls[-1]
    assert argv[-2:] == ["--", "https://www.youtube.com" + SECRET_PATH]
    assert "--volume=40" in argv and "--fullscreen" not in argv
    assert f"--ytdl-format={QUALITIES['1080p']}" in argv
    title, text, *_rest = h.host.notifications[-1]
    assert title == "Wird am PC abgespielt" and text == "www.youtube.com"
    item = next(item for item in h.host.items() if item["id"] == "play")
    assert item["subtitle"] == "www.youtube.com"
    assert [a["id"] for a in item["actions"]] == ["pause", "stop"]
    # Plain text bodies (the share sheet as text) work too, and replace.
    status, _t, body = h.request("POST", "/play", b"https://vimeo.com/1",
                                 content_type="text/plain")
    assert status == 200 and json.loads(body)["replaced"] is True
    status, _t, body = h.request("POST", "/pause", b"{}", content_type="application/json")
    assert status == 200 and json.loads(body) == {"ok": True, "paused": True}
    assert h.request("POST", "/stop", b"")[0] == 200
    assert h.request("POST", "/pause", b"")[0] == 409
    assert "geheim4711" not in caplog.text and "privat" not in caplog.text


def test_play_refuses_bad_urls(play_harness) -> None:
    h = play_harness(play_on_pc=True)
    for bad in ("-o/tmp/x", "--script=/tmp/evil.lua", "file:///etc/passwd", "ytdl://x",
                "javascript:alert(1)", "https://", "https://exa mple.org/",
                "https://example.org/" + "a" * 2100, "av://lavfi:sine"):
        status, _t, _b = h.request("POST", "/play", {"url": bad})
        assert status in (400, 413), bad
    assert h.request("GET", "/play")[0] == 405
    assert h.spawn.calls == []


def test_card_card_actions_and_missing_tools(play_harness) -> None:
    h = play_harness(play_on_pc=True)
    item = next(item for item in h.host.items() if item["id"] == "play")
    assert item["title"] == "Am PC abspielen bereit"
    h.request("POST", "/play", {"url": "https://example.org/v.mp4"})
    assert h.host.invoke("play", "pause")["ok"] is True
    assert h.ipc.paused is True
    assert h.host.invoke("play", "stop")["ok"] is True
    assert not h.service._player.playing()
    h.close()
    h = play_harness(play_on_pc=True, mpv=None)
    item = next(item for item in h.host.items() if item["id"] == "play")
    assert item["icon"] == "dialog-warning"
    assert "mpv" in h.service.status()["detail"]
    assert h.request("POST", "/play", {"url": "https://example.org/v"})[0] == 503


def test_plugin_stop_quits_the_player(play_harness) -> None:
    h = play_harness(play_on_pc=True)
    h.request("POST", "/play", {"url": "https://example.org/v.mp4"})
    h.close()
    assert not h.service._player.playing()
    assert h.ipc.commands[-1][1] == ["quit"]


def test_play_refuses_links_to_the_pc_itself(play_harness) -> None:
    resolved = {"intranet.example": ["192.168.1.20"], "evil.example": ["127.0.0.1"]}
    h = play_harness(play_on_pc=True,
                     resolve_host=lambda host: resolved.get(host, ["93.184.215.14"]))
    for bad in ("http://127.0.0.1:47801/clipboard", "http://[::1]/", "http://localhost/",
                "http://169.254.169.254/latest/meta-data/", "http://evil.example/v"):
        status, _t, body = h.request("POST", "/play", {"url": bad})
        assert (status, json.loads(body)) == (400, {"error": "url-not-public"}), bad
    assert h.spawn.calls == []
    # The home network stays allowed: Jellyfin, a NAS.
    assert h.request("POST", "/play", {"url": "http://intranet.example:8096/v"})[0] == 200
    assert h.request("POST", "/play", {"url": "http://192.168.1.5/v.mp4"})[0] == 200


def test_play_settings_in_the_form(play_harness) -> None:
    h = play_harness()
    with pytest.raises(Exception, match="not an allowed option"):
        h.service.apply_config({**h.service.config_values(), "token": None,
                                "play_options": "--script=/tmp/x.lua"})
    h.service.apply_config({**h.service.config_values(), "token": None, "play_on_pc": True,
                            "play_quality": "720p", "play_options": "--mute=yes"})
    stored = h.store.load()
    assert stored.play_on_pc and stored.play_quality == "720p"
    assert stored.play_options == "--mute=yes"


def test_cli_status_reports_the_tools(capsys) -> None:
    player = Player(which={"mpv": "/usr/bin/mpv"}.get, mpris=lambda: True, runtime_dir="")
    cli.print_play_status(Settings(play_on_pc=True), player)
    out = capsys.readouterr().out
    assert "Play on PC: on" in out and "/usr/bin/mpv" in out
    assert "yt-dlp:   missing" in out and "media keys" in out
