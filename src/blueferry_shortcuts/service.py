"""The plugin process: HTTPS endpoint plus the ``card`` and ``notify`` surfaces.

Threads: D-Bus calls arrive on the GLib main loop; HTTPS requests on the
server's connection threads; settings changes on the plugin worker.
Signals (``CardChanged``, ``Notify``) are always emitted from the main
loop through ``_to_main``. Shared state sits behind one lock.
"""
from __future__ import annotations

import datetime as dt
import http.client
import json
import logging
import socket
import ssl
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import dbus.service
from blueferry.plugin_api.config import ConfigError
from blueferry.plugin_api.config_flow import ConfigTestResult
from blueferry.plugin_api.manifest import PluginManifest
from blueferry.plugin_api.service import PluginCallError, PluginService
from blueferry_plugin_kit import netaddr
from blueferry_plugin_kit.clipboard import Clipboard
from blueferry_plugin_kit.configtest import failed, passed
from blueferry_plugin_kit.lanserver.tls import CertificateStore, Material

from blueferry_shortcuts import pages
from blueferry_shortcuts.localpage import LocalPage
from blueferry_shortcuts.netguard import (
    Decision,
    Network,
    NetworkManagerNetworks,
    Networks,
    approvable,
    decide,
)
from blueferry_shortcuts.pairing import (
    SetupSessions,
    ca_common_name,
    mobileconfig,
    qr_svg,
)
from blueferry_shortcuts.server import HttpsBridge
from blueferry_shortcuts.settings import (
    DEFAULT_HTTP_PORT,
    DEFAULT_SHORTCUT_URL,
    Settings,
    SettingsError,
    SettingsStore,
    certificate_store,
    new_token,
    probe_store,
    valid_shortcut_url,
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
PROBE_TIMEOUT_S = 5
# Keep "last connected" on disk at most this often.
SEEN_SAVE_SECONDS = 60
# TLS alerts that mean "this client does not trust the certificate".
_CERT_REASONS = ("unknown_ca", "certificate_unknown", "bad_certificate")


def _thread(work: Callable[[], None]) -> None:
    threading.Thread(target=work, name="blueferry-shortcuts-work", daemon=True).start()


def _size(count: int) -> str:
    if count >= 1024 * 1024:
        return f"{count / (1024 * 1024):.1f} MB"
    return f"{max(1, round(count / 1024))} KB"


def _host_of(url: str) -> str:
    host = urlsplit(url).hostname or ""
    return f"[{host}]" if ":" in host else host


def strip_userinfo(url: str) -> tuple[str, bool]:
    """``url`` without ``user:password@`` in front of the host, and whether
    there was one. Everything else stays exactly as sent."""
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url, False
    start = len(parts.scheme) + 3     # "<scheme>://", as check_url guarantees
    host = parts.netloc.rpartition("@")[2]
    return url[:start] + host + url[start + len(parts.netloc):], True


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
        networks: Networks | None = None,
        run_async: Callable[[Callable[[], None]], None] = _thread,
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
        self._lang = lang or language()
        self._t = texts(self._lang)
        self._now = wall_clock
        self._networks = networks or NetworkManagerNetworks()
        self._run_async = run_async
        self._probe_certificates = probe_store(self._store.directory)
        self._sessions = SetupSessions()
        self._page = LocalPage(self._render_pc_page)
        self._progress = {"opened": False, "trusted": False, "tested": False}
        self._decision = Decision(False, "off")
        self._http_lock = threading.Lock()
        self._seen: dict[str, float] = {}       # "at", "secure_at" (epoch)
        self._seen_saved = 0.0
        self._cert_failure_at: float | None = None
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
        saved = self._store.load_state()
        state = saved.get("battery")
        if isinstance(state, dict) and {"level", "charging", "at"} <= state.keys():
            self._battery = state
        seen = saved.get("seen")
        if isinstance(seen, dict):
            self._seen = {key: float(value) for key, value in seen.items()
                          if key in ("at", "secure_at") and isinstance(value, (int, float))
                          and not isinstance(value, bool)}

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
        # NetworkManager answers over D-Bus: never on the main loop.
        self._run_async(self.update_plain_http)

    def start_maintenance(self) -> None:
        def loop() -> None:
            while not self._stopping.wait(MAINTAIN_SECONDS):
                try:
                    self.maintain()
                except Exception:
                    log.debug("maintenance failed", exc_info=True)

        threading.Thread(target=loop, name="blueferry-shortcuts-maintain", daemon=True).start()
        self._networks.watch(lambda: self._run_async(self.update_plain_http))

    def maintain(self) -> None:
        """Follow a changed interface address and network, renew the
        certificate, end the setup helpers when they are no longer needed."""
        if not self._sessions.active():
            self._bridge.stop_probe()
        self._page.stop_if_idle()
        self._reload_networks()
        self.update_plain_http()
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
        self._page.stop()
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
        return self._url_for(host, port)

    def _url_for(self, host: str, port: int) -> str:
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
        # Links with user info (https://user:pw@host/) carry credentials;
        # BlueFerry refuses to open them, and a browser would keep them in
        # its history. Hand the link on without them and say so; the site
        # then asks for the sign-in itself.
        url, removed = strip_userinfo(url)
        with self._lock:
            self._link_counter += 1
            action_id = f"open-{self._link_counter}"
            self._links[action_id] = url
            while len(self._links) > MAX_LINKS:
                self._links.popitem(last=False)
        # The notification shows only the host: paths and queries may hold
        # tokens or personal data and stay on the screen (and in the
        # notification history). The full URL waits in _links for "Open".
        body = (self._t["link_userinfo"].format(host=_host_of(url)) if removed
                else _host_of(url))
        if removed:
            log.info("link received; sign-in data removed")
        self._notify(self._t["link_title"], body, "internet-web-browser",
                     self._t["open"], action_id)

    def on_battery(self, level: int, charging: bool | None) -> None:
        """``charging`` None: keep the last known state (a timed report cannot tell)."""
        with self._lock:
            if charging is None:
                charging = bool(self._battery and self._battery.get("charging"))
            battery = {"level": level, "charging": charging, "at": int(self._now())}
            self._battery = battery
        self._save_state()
        self._card_changed()

    def on_authorized(self, secure: bool) -> None:
        now = self._now()
        with self._lock:
            self._seen["at"] = now
            if secure:
                self._seen["secure_at"] = now
            save = now - self._seen_saved >= SEEN_SAVE_SECONDS
            if save:
                self._seen_saved = now
        if save:
            self._save_state()
            self._card_changed()

    def on_handshake_failed(self, reason: str) -> None:
        if not any(part in reason for part in _CERT_REASONS):
            return
        with self._lock:
            first = self._cert_failure_at is None
            self._cert_failure_at = self._now()
        if first:
            self._card_changed()

    def on_probe(self) -> None:
        with self._lock:
            known = self._progress["trusted"]
            self._progress["trusted"] = True
            self._cert_failure_at = None
        if not known:
            self._card_changed()

    def ca_profile(self, lang: str) -> bytes:
        with self._lock:
            material = self._material
        if material is None:
            return b""
        return mobileconfig(material.ca_pem, material.fingerprint, lang)

    def redeem_setup(self, nonce: str) -> str | None:
        session = self._sessions.redeem(nonce)
        if session is not None:
            with self._lock:
                self._progress["opened"] = True
            log.info("setup link opened on a phone")
            self._card_changed()
        return session

    def setup_session_valid(self, session: str) -> bool:
        return self._sessions.valid(session)

    def setup_view(self, secure: bool) -> pages.SetupView:
        secure_url = self.url()
        plain_url = self.plain_url()
        with self._lock:
            material, token, settings = self._material, self._token, self._settings
            host = self._host
        probe = self._bridge.probe_address
        probe_url = ""
        if probe is not None and host:
            probe_url = f"{self._url_for(host, probe[1])}/probe"
        return pages.SetupView(
            address=secure_url if secure or not plain_url else plain_url,
            secure_address=secure_url,
            token=token,
            ca_name=ca_common_name(material.ca_pem) if material else "",
            fingerprint=material.fingerprint if material else "",
            probe_url=probe_url,
            shortcut_url=settings.shortcut_url or DEFAULT_SHORTCUT_URL,
            plain_http=bool(plain_url),
            clipboard_read=settings.allow_clipboard_read,
        )

    def on_setup_test(self) -> None:
        with self._lock:
            self._progress["tested"] = True
        self._notify(self._t["connected_title"], self._t["connected_body"], "phone")
        self._card_changed()

    def _save_state(self) -> None:
        with self._lock:
            state: dict[str, object] = {"seen": dict(self._seen)}
            if self._battery is not None:
                state["battery"] = self._battery
        try:
            self._store.save_state(state)
        except (SettingsError, OSError):
            log.debug("could not keep the state")

    # ---- setup -----------------------------------------------------------------

    def begin_setup(self) -> dict[str, object]:
        """Card action "Set up iPhone": a new link, the probe, the PC page."""
        url = self.url()
        if not url:
            with self._lock:
                error = self._error
            return result(False, self._t["setup_needs_endpoint"].format(reason=error or "…"))
        self._new_link()
        try:
            page = self._page.url()
        except OSError as error:
            return result(False, _reason(error))
        return result(True, None, page)

    def _new_link(self) -> None:
        self._sessions.nonce(renew=True)
        with self._lock:
            self._progress = {"opened": False, "trusted": False, "tested": False}
        self._start_probe()

    def _start_probe(self) -> None:
        with self._lock:
            host, port = self._host, self._settings.port
        if not host or port >= 65535:
            return
        try:
            material = self._probe_certificates.ensure(self._cert_addresses(host))
            self._bridge.start_probe(host, port + 1, material.server_context())
        except (OSError, ValueError) as error:
            log.info("trust check not available: %s", _reason(error))

    def _render_pc_page(self, _accept_language: str, renew: bool) -> tuple[bytes, str]:
        if renew:
            self._new_link()
        url = self.url()
        with self._lock:
            progress, error, decision = dict(self._progress), self._error, self._decision
        if not url:
            view = pages.PcView("", "", "", error or "…", "", **progress)
            return pages.pc_page(self._lang, view)
        if not self._sessions.pending() and not progress["opened"]:
            self._new_link()           # expired unused: offer a fresh one
        if not self._sessions.pending():
            return pages.pc_page(self._lang, pages.PcView("", "", "", "", "", **progress))
        if self._bridge.probe_address is None:
            self._start_probe()
        nonce, left = self._sessions.nonce()
        plain = self.plain_url()
        link = f"{plain or url}/setup/{nonce}"
        until = time.strftime("%H:%M", time.localtime(time.time() + left))
        view = pages.PcView(link, qr_svg(link), until, "", decision.name if plain else "",
                            **progress)
        return pages.pc_page(self._lang, view)

    # ---- plain HTTP (opt-in, approved networks) -----------------------------------

    def plain_url(self) -> str:
        address = self._bridge.plain_address
        if address is None:
            return ""
        return "http" + self._url_for(address[0], address[1])[len("https"):]

    def _reload_networks(self) -> None:
        """Pick up approvals changed through the CLI."""
        try:
            stored = self._store.load()
        except (SettingsError, OSError):
            return
        with self._lock:
            self._settings = self._settings.changed(http_networks=stored.http_networks)

    def update_plain_http(self) -> None:
        """Worker thread: open or close the plain-HTTP listener for the network."""
        with self._http_lock:
            with self._lock:
                settings, host = self._settings, self._host
            current = self._networks.current() if settings.allow_http else None
            decision = decide(settings.allow_http, settings.http_networks, current)
            if decision.active and host:
                wanted = (host, settings.http_port)
                if self._bridge.plain_address != wanted:
                    try:
                        self._bridge.start_plain(host, settings.http_port)
                        log.info("plain HTTP listening on port %d", settings.http_port)
                    except OSError as error:
                        decision = Decision(False, "bind", _reason(error))
            if not (decision.active and host) and self._bridge.plain_address is not None:
                self._bridge.stop_plain()
                log.info("plain HTTP stopped (%s)", decision.reason)
            with self._lock:
                changed, self._decision = decision != self._decision, decision
            if changed:
                self._card_changed()

    def approve_current_network(self) -> list[Network]:
        """Approve the current default-route networks (never open Wi-Fi)."""
        current = self._networks.current()
        chosen = approvable(current)
        if not chosen:
            return []
        with self._lock:
            settings = self._settings
        approved = dict(settings.http_networks)
        for network in chosen:
            approved[network.uuid] = network.name
        new = settings.changed(http_networks=tuple(approved.items()))
        self._store.save(new)
        with self._lock:
            self._settings = new
        self.update_plain_http()
        return chosen

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
                  else Action("show_setup", t["show_setup"], "view-visible"))
        items.append(CardItem(
            "bridge", "phone" if url else "dialog-warning", t["bridge"], subtitle,
            (Action("setup_iphone", t["setup_iphone"], "smartphone", "primary"), toggle,
             Action("new_token", t["new_token"], "view-refresh")),
        ))
        if url:
            items.append(self._state_item())
        plain = self._plain_item()
        if plain is not None:
            items.append(plain)
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
        return items

    def _state_item(self) -> CardItem:
        """Not set up / certificate probably missing / last connected."""
        t = self._t
        with self._lock:
            seen, failure = dict(self._seen), self._cert_failure_at
        if failure is not None and failure > seen.get("secure_at", 0.0):
            return CardItem("state", "security-low", t["state_cert"],
                            t["state_cert_hint"].format(time=self._when(int(failure))))
        if "at" not in seen:
            return CardItem("state", "dialog-information", t["state_new"], t["state_new_hint"])
        secure = seen.get("secure_at") == seen["at"]
        return CardItem(
            "state", "network-wireless-encrypted" if secure else "network-wireless",
            t["state_seen"].format(ago=self._ago(seen["at"])),
            t["seen_secure" if secure else "seen_plain"],
        )

    def _plain_item(self) -> CardItem | None:
        t = self._t
        with self._lock:
            allowed, decision = self._settings.allow_http, self._decision
        if not allowed:
            return None
        if decision.active:
            return CardItem("plain", "security-medium",
                            t["plain_active"].format(name=decision.name),
                            t["plain_active_hint"].format(url=self.plain_url()))
        if decision.reason == "foreign":
            return CardItem(
                "plain", "security-high", t["plain_foreign"],
                t["plain_foreign_hint"].format(name=decision.name),
                (Action("allow_network", t["allow_network"], "network-wireless"),),
            )
        key = {"open-wifi": "plain_open", "no-nm": "plain_no_nm",
               "no-network": "plain_no_network", "bind": "plain_bind"}.get(decision.reason)
        if key is None:      # "off": not evaluated yet
            return None
        return CardItem("plain", "security-high", t[key],
                        t[key + "_hint"].format(name=decision.name))

    def _ago(self, epoch: float) -> str:
        t = self._t
        seconds = max(0, int(self._now() - epoch))
        if seconds < 60:
            return t["just_now"]
        if seconds < 3600:
            return t["min_ago"].format(n=seconds // 60)
        if seconds < 24 * 3600:
            return t["h_ago"].format(n=seconds // 3600)
        return t["on_date"].format(date=self._when(int(epoch)))

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
        if item_id == "bridge" and action_id == "setup_iphone":
            return self.begin_setup()
        if item_id == "plain" and action_id == "allow_network":
            with self._lock:
                decision = self._decision
            if decision.reason != "foreign":
                return result(False, t["allow_network_none"])

            def approve() -> None:
                try:
                    self.approve_current_network()
                except (SettingsError, OSError):
                    log.warning("could not store the approved network")
                self._card_changed()

            # NetworkManager answers over D-Bus: not on the main loop.
            self._run_async(approve)
            return result(True, t["allow_network_done"].format(name=decision.name))
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
            "allow_http": settings.allow_http,
            "http_port": settings.http_port,
            "http_networks": ", ".join(name for _uuid, name in settings.http_networks),
            "shortcut_url": settings.shortcut_url,
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
        port = port if isinstance(port, int) and not isinstance(port, bool) else 47801
        http_port = values.get("http_port")
        http_port = (http_port if isinstance(http_port, int) and not isinstance(http_port, bool)
                     else DEFAULT_HTTP_PORT)
        allow_http = values.get("allow_http") is True
        if allow_http and http_port in (port, port + 1):
            raise ConfigError("http_port", "use a port other than the HTTPS port and the next one")
        shortcut_url = str(values.get("shortcut_url") or "").strip()
        if not valid_shortcut_url(shortcut_url):
            raise ConfigError("shortcut_url", "must be an iCloud shortcut link "
                              "(https://www.icloud.com/shortcuts/…)")
        with self._lock:
            old, host = self._settings, self._host
        networks = old.http_networks
        if values.get("http_networks") is not None:
            # The field lists the approved networks; deleting a name removes it.
            kept = {part.strip() for part in str(values["http_networks"]).split(",")}
            networks = tuple((uuid, name) for uuid, name in networks if name in kept)
        if allow_http and not old.allow_http:
            networks = self._approve_on_enable(networks)
        new = Settings(
            bind_address=bind,
            allow_all_interfaces=allow_all,
            port=port,
            allow_clipboard_read=values.get("allow_clipboard_read") is True,
            accept_images=values.get("accept_images") is True,
            allow_http=allow_http,
            http_port=http_port,
            http_networks=networks,
            shortcut_url=shortcut_url,
        )
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
        self.update_plain_http()
        self._card_changed()

    def _approve_on_enable(
        self, networks: tuple[tuple[str, str], ...],
    ) -> tuple[tuple[str, str], ...]:
        """Turning plain HTTP on approves the network the PC is in now."""
        current = self._networks.current()
        if current is None:
            raise ConfigError("allow_http", "needs NetworkManager to recognise the home network")
        chosen = approvable(current)
        if not chosen:
            if any(network.open_wifi for network in current):
                raise ConfigError("allow_http", "this is an open Wi-Fi; it is never approved")
            raise ConfigError("allow_http", "no network connection to approve")
        approved = dict(networks)
        for network in chosen:
            approved[network.uuid] = network.name
        return tuple(approved.items())

    def test_config(self, values: dict[str, object]) -> ConfigTestResult:
        """Worker thread. "Test connection": nothing is stored or restarted.

        With the address and port the endpoint already serves, ask it for
        ``/ca.crt`` like the iPhone would; otherwise check that the
        address and port can be bound. The address is shown in the answer
        (it is what the shortcut needs) but never logged.
        """
        bind = str(values.get("bind_address") or "").strip()
        allow_all = values.get("allow_all_interfaces") is True
        reason = netaddr.check_setting(bind, allow_all)
        if reason:
            raise ConfigError("bind_address", reason)
        token = values.get("token")
        if token is not None and not valid_token(str(token)):
            raise ConfigError("token", "must be 16 to 128 printable characters without spaces")
        port = values.get("port")
        port = port if isinstance(port, int) and not isinstance(port, bool) else 47801
        try:
            host = self._resolve(bind, allow_all)
        except netaddr.AddressError as error:
            raise ConfigError("bind_address", str(error)) from None
        url = self._url_for(host, port)
        with self._lock:
            running = self._host == host and self._settings.port == port
        if running:
            problem = self._probe(url)
            if problem is None:
                return passed(f"Reachable at {url}.")
            return failed(f"The endpoint at {url} did not answer ({problem}).")
        try:
            self._try_bind(host, port)
        except OSError as error:
            raise ConfigError("port", _reason(error)) from None
        return passed(f"{url} is free; save to start listening there.")

    def _probe(self, url: str) -> str | None:
        """None when the own endpoint serves its CA over trusted TLS."""
        parts = urlsplit(url)
        try:
            context = ssl.create_default_context(cafile=str(self._certificates.ca_cert_path))
            connection = http.client.HTTPSConnection(
                parts.hostname, parts.port, context=context, timeout=PROBE_TIMEOUT_S,
            )
            try:
                connection.request("GET", "/ca.crt")
                status = connection.getresponse().status
            finally:
                connection.close()
        except ssl.SSLError:
            return "certificate"
        except (OSError, http.client.HTTPException):
            return "no connection"
        return None if status == 200 else f"HTTP {status}"

    @staticmethod
    def _try_bind(host: str, port: int) -> None:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((host, port))


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
