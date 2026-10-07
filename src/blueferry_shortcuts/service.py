"""The plugin process: HTTPS endpoint plus the ``card`` and ``notify`` surfaces.

Threads: D-Bus calls arrive on the GLib main loop; HTTPS requests on the
server's connection threads; settings changes on the plugin worker.
Signals (``CardChanged``, ``Notify``) are always emitted from the main
loop through ``_to_main``. Shared state sits behind one lock.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import dbus.service
from blueferry.plugin_api.config import ConfigError
from blueferry.plugin_api.manifest import PluginManifest
from blueferry.plugin_api.service import PluginCallError, PluginService
from blueferry_plugin_kit import netaddr
from blueferry_plugin_kit.clipboard import Clipboard
from blueferry_plugin_kit.lanserver.tls import CertificateStore, Material

from blueferry_shortcuts.server import HttpsBridge
from blueferry_shortcuts.settings import (
    Settings,
    SettingsError,
    SettingsStore,
    certificate_store,
    new_token,
    valid_token,
)
from blueferry_shortcuts.surfaces import (
    NOTIFY_ITEM,
    SURFACES_INTERFACE,
    Action,
    CardItem,
    card_json,
    language,
    result,
    texts,
)

log = logging.getLogger(__name__)

MAX_LINKS = 20
REVEAL_SECONDS = 120
MAINTAIN_SECONDS = 60
MAX_ARGS = 4096


def _size(count: int) -> str:
    if count >= 1024 * 1024:
        return f"{count / (1024 * 1024):.1f} MB"
    return f"{max(1, round(count / 1024))} KB"


def _host_of(url: str) -> str:
    host = urlsplit(url).hostname or ""
    return f"[{host}]" if ":" in host else host


def battery_icon(level: int, charging: bool) -> str:
    name = (
        "battery-empty" if level < 5 else "battery-caution" if level < 15
        else "battery-low" if level < 35 else "battery-good" if level < 90
        else "battery-full"
    )
    return name + ("-charging" if charging else "")


def mask_token(token: str) -> str:
    head, _, tail = token.rpartition("-")
    if not head:
        return "•" * max(0, len(token) - 4) + token[-4:]
    return "".join("-" if ch == "-" else "•" for ch in head) + "-" + tail


class ShortcutsService(PluginService):
    def __init__(
        self,
        manifest: PluginManifest,
        bus: Any = None,
        *,
        settings: SettingsStore | None = None,
        certificates: CertificateStore | None = None,
        clipboard: Clipboard | None = None,
        bridge_factory: Callable[[Any], HttpsBridge] = HttpsBridge,
        resolve: Callable[[str, bool], str] = netaddr.resolve,
        local_addresses: Callable[[], list[str]] = netaddr.local_addresses,
        route_tunnel: Callable[[], tuple[str, bool] | None] = netaddr.default_route_tunnel,
        lang: str | None = None,
        wall_clock: Callable[[], float] = time.time,
        **kwargs: Any,
    ) -> None:
        super().__init__(manifest, bus, **kwargs)
        self._store = settings or SettingsStore()
        self._certificates = certificates or certificate_store(self._store.directory)
        self._clipboard = clipboard or Clipboard()
        self._bridge = bridge_factory(self)
        self._resolve = resolve
        self._local_addresses = local_addresses
        self._route_tunnel = route_tunnel
        self._t = texts(lang or language())
        self._now = wall_clock
        self._lock = threading.RLock()
        self._settings = Settings()
        self._token = ""
        self._material: Material | None = None
        self._host = ""
        self._error = ""
        self._show_setup = False
        self._revealed_at: float | None = None
        self._reveal_timer: threading.Timer | None = None
        self._links: OrderedDict[str, str] = OrderedDict()
        self._link_counter = 0
        self._battery: dict[str, object] | None = None
        self._stopping = threading.Event()
        self._cert_mtime: float | None = None
        state = self._store.load_state().get("battery")
        if isinstance(state, dict) and {"level", "charging", "at"} <= state.keys():
            self._battery = state

    # ---- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Load the settings and serve; record a reason when that fails."""
        try:
            settings = self._store.load()
            token = self._store.token()
        except (SettingsError, OSError) as error:
            with self._lock:
                self._error = str(error)
            self._card_changed()
            return
        with self._lock:
            self._settings, self._token = settings, token
        try:
            self._serve(settings)
        except (netaddr.AddressError, OSError, ValueError) as error:
            reason = _reason(error)
            with self._lock:
                repeated, self._error = self._error == reason, reason
            if not repeated:  # maintain() retries every minute
                log.warning("HTTPS endpoint not started: %s", reason)
        self._card_changed()

    def start_maintenance(self) -> None:
        def loop() -> None:
            while not self._stopping.wait(MAINTAIN_SECONDS):
                try:
                    self.maintain()
                except Exception:
                    log.debug("maintenance failed", exc_info=True)

        threading.Thread(target=loop, name="blueferry-shortcuts-maintain", daemon=True).start()

    def maintain(self) -> None:
        """Follow a changed interface address and renew the certificate."""
        with self._lock:
            settings, host = self._settings, self._host
        try:
            wanted = self._resolve(settings.bind_address, settings.allow_all_interfaces)
        except netaddr.AddressError as error:
            if host:
                self._bridge.stop()
                with self._lock:
                    self._host, self._error = "", str(error)
                self._card_changed()
            return
        if wanted != host:
            log.info("listen address changed; restarting the endpoint")
            self.start()
            return
        material = self._certificates.ensure(self._cert_addresses(wanted))
        if material.cert_path.stat().st_mtime != self._cert_mtime:
            self._cert_mtime = material.cert_path.stat().st_mtime
            self._bridge.reload_context(material.server_context())

    def stop(self) -> None:
        self._stopping.set()
        self._bridge.stop()
        with self._lock:
            if self._reveal_timer is not None:
                self._reveal_timer.cancel()
                self._reveal_timer = None

    def _cert_addresses(self, host: str) -> list[str]:
        return self._local_addresses() if netaddr.is_wildcard(host) else [host]

    def _serve(self, settings: Settings) -> None:
        host = self._resolve(settings.bind_address, settings.allow_all_interfaces)
        material = self._certificates.ensure(self._cert_addresses(host))
        self._bridge.start(host, settings.port, material.server_context())
        self._cert_mtime = material.cert_path.stat().st_mtime
        with self._lock:
            self._material, self._host, self._error = material, host, ""
        log.info("HTTPS endpoint listening on port %d", settings.port)

    def url(self) -> str:
        with self._lock:
            host, port = self._host, self._settings.port
        if not host:
            return ""
        if netaddr.is_wildcard(host):
            addresses = self._local_addresses()
            host = next((a for a in addresses if not a.startswith("127.")), "localhost")
        shown = f"[{host}]" if ":" in host else host
        return f"https://{shown}:{port}"

    # ---- Endpoints (HTTPS threads) ------------------------------------------

    def token(self) -> str:
        with self._lock:
            return self._token

    def allow_clipboard_read(self) -> bool:
        with self._lock:
            return self._settings.allow_clipboard_read

    def accept_images(self) -> bool:
        with self._lock:
            return self._settings.accept_images

    def ca_pem(self) -> bytes:
        with self._lock:
            return self._material.ca_pem if self._material else b""

    def on_clipboard_text(self, text: str) -> None:
        self._clipboard.copy_text(text)
        self._notify(self._t["clipboard_title"],
                     self._t["clipboard_text"].format(count=len(text)), "edit-paste")

    def on_clipboard_image(self, data: bytes, mime: str) -> None:
        self._clipboard.copy(data, mime)
        body = self._t["clipboard_image"].format(
            kind=mime.split("/", 1)[1].upper(), size=_size(len(data)),
        )
        self._notify(self._t["clipboard_title"], body, "edit-paste")

    def read_clipboard(self, limit: int) -> str | None:
        return self._clipboard.read_text(limit)

    def on_link(self, url: str) -> None:
        with self._lock:
            self._link_counter += 1
            action_id = f"open-{self._link_counter}"
            self._links[action_id] = url
            while len(self._links) > MAX_LINKS:
                self._links.popitem(last=False)
        # The notification shows only the host: paths and queries may hold
        # tokens or personal data and stay on the screen (and in the
        # notification history). The full URL waits in _links for "Open".
        self._notify(self._t["link_title"], _host_of(url), "internet-web-browser",
                     self._t["open"], action_id)

    def on_battery(self, level: int, charging: bool | None) -> None:
        """``charging`` None: keep the last known state (a timed report cannot tell)."""
        with self._lock:
            if charging is None:
                charging = bool(self._battery and self._battery.get("charging"))
            battery = {"level": level, "charging": charging, "at": int(self._now())}
            self._battery = battery
        try:
            self._store.save_state({"battery": battery})
        except (SettingsError, OSError):
            log.debug("could not keep the battery state")
        self._card_changed()

    # ---- signals ---------------------------------------------------------------

    def _notify(self, title: str, body: str, icon: str,
                action_label: str = "", action_id: str = "") -> None:
        self._to_main(lambda: self.Notify(title, body, icon, action_label, action_id))

    def _card_changed(self) -> None:
        self._to_main(self.CardChanged)

    @dbus.service.signal(SURFACES_INTERFACE, signature="")
    def CardChanged(self) -> None:
        """Content-free: the host calls GetCardItems again."""

    @dbus.service.signal(SURFACES_INTERFACE, signature="sssss")
    def Notify(self, title, body, icon, action_label, action_id) -> None:
        """A desktop notification through the host's notification policy."""

    # ---- card ------------------------------------------------------------------

    def card_items(self) -> list[CardItem]:
        t = self._t
        url = self.url()
        with self._lock:
            error, show, battery = self._error, self._show_setup, self._battery
            material, token = self._material, self._token
            revealed = (
                self._revealed_at is not None
                and time.monotonic() - self._revealed_at < REVEAL_SECONDS
            )
        items: list[CardItem] = []
        if battery is not None:
            level, charging = int(battery["level"]), bool(battery["charging"])
            title = t["battery"].format(level=level) + (t["charging"] if charging else "")
            items.append(CardItem(
                "battery", battery_icon(level, charging), title,
                t["as_of"].format(time=self._when(int(battery["at"]))),
            ))
        subtitle = (t["listening"].format(url=url) if url
                    else t["stopped"].format(reason=error or "…"))
        toggle = (Action("hide_setup", t["hide_setup"], "view-hidden") if show
                  else Action("show_setup", t["show_setup"], "view-visible", "primary"))
        items.append(CardItem(
            "bridge", "phone" if url else "dialog-warning", t["bridge"], subtitle,
            (toggle, Action("new_token", t["new_token"], "view-refresh")),
        ))
        hint = self._vpn_hint()
        if hint is not None:
            items.append(hint)
        if show:
            if url:
                items.append(CardItem("setup_url", "network-server", t["url"], url))
            items.append(CardItem(
                "setup_token", "dialog-password", t["token"],
                token if revealed else mask_token(token),
                (Action("hide", t["hide"], "view-hidden") if revealed
                 else Action("reveal", t["reveal"], "view-visible"),),
            ))
            if material is not None:
                items.append(CardItem(
                    "setup_fingerprint", "security-high", t["fingerprint"], material.fingerprint,
                ))
                if url:
                    items.append(CardItem(
                        "setup_ca", "application-certificate", t["ca"],
                        t["ca_hint"].format(url=url),
                    ))
        return items

    def _vpn_hint(self) -> CardItem | None:
        """Warn when a VPN carries the default route (automatic choice only)."""
        with self._lock:
            automatic = not self._settings.bind_address
        if not automatic:
            return None
        try:
            tunnel = self._route_tunnel()
        except OSError:
            return None
        if tunnel is None:
            return None
        name, lan_found = tunnel
        text = self._t["vpn_lan" if lan_found else "vpn_only"].format(vpn=name)
        return CardItem("vpn", "network-vpn", self._t["vpn_title"], text)

    def _when(self, epoch: int) -> str:
        moment = dt.datetime.fromtimestamp(epoch)
        today = dt.datetime.fromtimestamp(self._now()).date()
        return moment.strftime("%H:%M") if moment.date() == today else moment.strftime(
            self._t["date"],
        )

    def invoke(self, item_id: str, action_id: str) -> dict[str, object]:
        t = self._t
        if item_id == NOTIFY_ITEM:
            with self._lock:
                url = self._links.get(action_id)
            return result(True, None, url) if url else result(False, t["link_gone"])
        if item_id == "bridge" and action_id in ("show_setup", "hide_setup"):
            with self._lock:
                self._show_setup = action_id == "show_setup"
                self._revealed_at = None
        elif item_id == "bridge" and action_id == "new_token":
            try:
                token = self._store.set_token(new_token())
            except (SettingsError, OSError) as error:
                return result(False, str(error))
            with self._lock:
                self._token, self._revealed_at = token, None
            self._card_changed()
            return result(True, t["new_token_done"])
        elif item_id == "setup_token" and action_id in ("reveal", "hide"):
            with self._lock:
                self._revealed_at = time.monotonic() if action_id == "reveal" else None
                # One timer at most: each reveal restarts it instead of
                # piling up threads that refresh the card.
                if self._reveal_timer is not None:
                    self._reveal_timer.cancel()
                    self._reveal_timer = None
                if action_id == "reveal":
                    self._reveal_timer = threading.Timer(REVEAL_SECONDS + 1, self._card_changed)
                    self._reveal_timer.daemon = True
                    self._reveal_timer.start()
        else:
            return result(False, t["unknown_action"])
        self._card_changed()
        return result(True)

    @dbus.service.method(
        SURFACES_INTERFACE, in_signature="", out_signature="s", sender_keyword="sender",
    )
    def GetCardItems(self, sender=None) -> str:
        self.admit(sender)
        return json.dumps(card_json(self.card_items()), ensure_ascii=False)

    @dbus.service.method(
        SURFACES_INTERFACE, in_signature="sss", out_signature="s", sender_keyword="sender",
    )
    def InvokeAction(self, item_id, action_id, args_json, sender=None) -> str:
        self.admit(sender)
        item_id, action_id = str(item_id)[:64], str(action_id)[:64]
        args = str(args_json)
        if len(args) > MAX_ARGS:
            return json.dumps(result(False, "arguments too large"))
        try:
            json.loads(args or "{}")
        except ValueError:
            return json.dumps(result(False, "arguments are not JSON"))
        return json.dumps(self.invoke(item_id, action_id), ensure_ascii=False)

    # ---- Plugin1 ---------------------------------------------------------------

    def status(self) -> dict[str, object]:
        url = self.url()
        with self._lock:
            error = self._error
        if url:
            return {"state": "ok", "detail": f"listening on {url}"}
        return {"state": "error", "detail": error or "not started"}

    def config_values(self) -> dict[str, object]:
        with self._lock:
            settings, token = self._settings, self._token
        if not token:
            try:
                settings, token = self._store.load(), self._store.token()
            except (SettingsError, OSError) as error:
                raise PluginCallError(str(error)) from None
        return {
            "bind_address": settings.bind_address,
            "allow_all_interfaces": settings.allow_all_interfaces,
            "port": settings.port,
            "token": bool(token),
            "allow_clipboard_read": settings.allow_clipboard_read,
            "accept_images": settings.accept_images,
        }

    def apply_config(self, values: dict[str, object]) -> None:
        bind = str(values.get("bind_address") or "").strip()
        allow_all = values.get("allow_all_interfaces") is True
        reason = netaddr.check_setting(bind, allow_all)
        if reason:
            raise ConfigError("bind_address", reason)
        token = values.get("token")
        if token is not None and not valid_token(str(token)):
            raise ConfigError("token", "must be 16 to 128 printable characters without spaces")
        port = values.get("port")
        new = Settings(
            bind_address=bind,
            allow_all_interfaces=allow_all,
            port=port if isinstance(port, int) and not isinstance(port, bool) else 47801,
            allow_clipboard_read=values.get("allow_clipboard_read") is True,
            accept_images=values.get("accept_images") is True,
        )
        with self._lock:
            old, host = self._settings, self._host
        if (new.bind_address, new.allow_all_interfaces, new.port) != (
            old.bind_address, old.allow_all_interfaces, old.port,
        ) or not host:
            try:
                self._serve(new)
            except (netaddr.AddressError, OSError, ValueError) as error:
                field = "bind_address" if isinstance(error, netaddr.AddressError) else "port"
                if host:
                    try:
                        self._serve(old)
                    except (netaddr.AddressError, OSError, ValueError):
                        with self._lock:
                            self._host = ""
                raise ConfigError(field, _reason(error)) from None
        try:
            self._store.save(new)
            if token is not None:
                self._store.set_token(str(token))
        except (SettingsError, OSError) as error:
            raise ConfigError("", f"could not store the settings: {error}") from None
        with self._lock:
            self._settings = new
            if token is not None:
                self._token = str(token)
        self._card_changed()


def _reason(error: Exception) -> str:
    if isinstance(error, OSError):
        if error.errno == 98:
            return "the port is already in use"
        if error.errno == 99:
            return "the address is not on this PC"
        if error.errno == 13:
            return "permission denied for this port"
        return error.strerror or type(error).__name__
    return str(error)
