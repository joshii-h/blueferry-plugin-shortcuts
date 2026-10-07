"""Plugin API 1.2 surfaces (``card``, ``notify``) as this plugin uses them.

All 1.2 methods and signals live on the existing ``Plugin1`` interface at
the plugin's object path (spec: "D-Bus placement"); there are no separate
card or notify interfaces. The limits follow the 1.2 spec.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from blueferry.plugin_api import PLUGIN_INTERFACE

# GetCardItems, InvokeAction, CardChanged and Notify are Plugin1 members.
SURFACES_INTERFACE = PLUGIN_INTERFACE

MAX_ITEMS = 8
MAX_ACTIONS = 3
MAX_TITLE = 80
MAX_SUBTITLE = 160
MAX_LABEL = 40
NOTIFY_ITEM = "notify"


def _clip(text: str, limit: int) -> str:
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass(frozen=True, slots=True)
class Action:
    id: str
    label: str
    icon: str | None = None
    kind: str = "button"   # "button" or "primary"

    def to_json(self) -> dict[str, object]:
        return {"id": self.id, "label": _clip(self.label, MAX_LABEL), "icon": self.icon,
                "kind": self.kind}


@dataclass(frozen=True, slots=True)
class CardItem:
    id: str
    icon: str
    title: str
    subtitle: str | None = None
    actions: tuple[Action, ...] = field(default_factory=tuple)

    def to_json(self) -> dict[str, object]:
        return {
            "id": self.id, "icon": self.icon, "title": _clip(self.title, MAX_TITLE),
            "subtitle": None if self.subtitle is None else _clip(self.subtitle, MAX_SUBTITLE),
            "actions": [action.to_json() for action in self.actions[:MAX_ACTIONS]],
        }


def card_json(items: list[CardItem]) -> dict[str, object]:
    return {"items": [item.to_json() for item in items[:MAX_ITEMS]]}


def result(ok: bool, message: str | None = None, open_uri: str | None = None) -> dict[str, object]:
    return {"ok": ok, "message": message, "open_uri": open_uri}


# ---- texts --------------------------------------------------------------

_TEXTS = {
    "en": {
        "bridge": "Shortcuts bridge",
        "listening": "Listening on {url}",
        "stopped": "Not running: {reason}",
        "show_setup": "Show setup data",
        "hide_setup": "Hide setup data",
        "new_token": "New token",
        "new_token_done": "New token created. Update it in your shortcuts.",
        "token": "Token",
        "reveal": "Reveal",
        "hide": "Hide",
        "url": "URL",
        "fingerprint": "Certificate fingerprint (SHA-256)",
        "setup_iphone": "Set up iPhone",
        "setup_needs_endpoint": "The endpoint is not running: {reason}",
        "state_new": "iPhone not set up yet",
        "state_new_hint": "Choose “Set up iPhone” and scan the QR code",
        "state_cert": "Certificate probably missing on the iPhone",
        "state_cert_hint": "The iPhone refused the connection ({time}). "
                           "“Set up iPhone” installs the certificate.",
        "state_seen": "iPhone last connected {ago}",
        "seen_secure": "Encrypted (HTTPS)",
        "seen_plain": "Unencrypted (HTTP)",
        "just_now": "just now",
        "min_ago": "{n} min ago",
        "h_ago": "{n} h ago",
        "on_date": "on {date}",
        "plain_active": "Unencrypted active in “{name}”",
        "plain_active_hint": "{url} · reading the PC clipboard needs HTTPS",
        "plain_foreign": "Unencrypted paused: foreign network",
        "plain_foreign_hint": "“{name}” is not approved for unencrypted connections",
        "plain_open": "Unencrypted paused: open Wi-Fi",
        "plain_open_hint": "“{name}” has no password; open networks are never approved",
        "plain_no_nm": "Unencrypted not available",
        "plain_no_nm_hint": "Needs NetworkManager to recognise your home network",
        "plain_no_network": "Unencrypted paused: no network",
        "plain_no_network_hint": "No connection with a default route",
        "plain_bind": "Unencrypted not running",
        "plain_bind_hint": "{name}",
        "allow_network": "Approve this network",
        "allow_network_done": "“{name}” approved for unencrypted connections.",
        "allow_network_none": "This network cannot be approved (open Wi-Fi or none).",
        "connected_title": "iPhone connected ✅",
        "connected_body": "The setup worked.",
        "battery": "iPhone battery {level} %",
        "charging": " ⚡ charging",
        "as_of": "As of {time}",
        "clipboard_title": "Clipboard from iPhone",
        "clipboard_text": "{count} characters",
        "clipboard_image": "Image ({kind}, {size})",
        "link_title": "Link from iPhone",
        "link_userinfo": "{host} · sign-in data removed from the link",
        "open": "Open",
        "link_gone": "The link is no longer available",
        "unknown_action": "Unknown action",
        "vpn_title": "VPN carries the default route",
        "vpn_lan": "{vpn} is a VPN; listening on the LAN interface instead",
        "vpn_only": "Only {vpn} (a VPN) has a default route; the iPhone may not "
                    "reach this address. Set an interface in the settings.",
        "date": "%b %d, %H:%M",
    },
    "de": {
        "bridge": "Kurzbefehle-Brücke",
        "listening": "Bereit auf {url}",
        "stopped": "Nicht aktiv: {reason}",
        "show_setup": "Einrichtungsdaten anzeigen",
        "hide_setup": "Einrichtungsdaten ausblenden",
        "new_token": "Token neu erzeugen",
        "new_token_done": "Neues Token erzeugt. Bitte in den Kurzbefehlen ersetzen.",
        "token": "Token",
        "reveal": "Aufdecken",
        "hide": "Verbergen",
        "url": "URL",
        "fingerprint": "Zertifikats-Fingerprint (SHA-256)",
        "setup_iphone": "iPhone einrichten",
        "setup_needs_endpoint": "Der Empfang läuft nicht: {reason}",
        "state_new": "iPhone noch nicht eingerichtet",
        "state_new_hint": "„iPhone einrichten“ wählen und den QR-Code scannen",
        "state_cert": "Zertifikat fehlt vermutlich auf dem iPhone",
        "state_cert_hint": "Das iPhone hat die Verbindung abgelehnt ({time}). "
                           "„iPhone einrichten“ installiert das Zertifikat.",
        "state_seen": "iPhone zuletzt verbunden {ago}",
        "seen_secure": "Verschlüsselt (HTTPS)",
        "seen_plain": "Unverschlüsselt (HTTP)",
        "just_now": "gerade eben",
        "min_ago": "vor {n} Min.",
        "h_ago": "vor {n} Std.",
        "on_date": "am {date}",
        "plain_active": "Unverschlüsselt aktiv in „{name}“",
        "plain_active_hint": "{url} · PC-Zwischenablage lesen nur über HTTPS",
        "plain_foreign": "Unverschlüsselt pausiert – fremdes Netz",
        "plain_foreign_hint": "„{name}“ ist für unverschlüsselte Verbindungen nicht freigegeben",
        "plain_open": "Unverschlüsselt pausiert – offenes WLAN",
        "plain_open_hint": "„{name}“ hat kein Passwort; offene Netze werden nie freigegeben",
        "plain_no_nm": "Unverschlüsselt nicht verfügbar",
        "plain_no_nm_hint": "Braucht NetworkManager, um dein Heimnetz zu erkennen",
        "plain_no_network": "Unverschlüsselt pausiert – kein Netz",
        "plain_no_network_hint": "Keine Verbindung mit Standardroute",
        "plain_bind": "Unverschlüsselt nicht aktiv",
        "plain_bind_hint": "{name}",
        "allow_network": "Dieses Netz freigeben",
        "allow_network_done": "„{name}“ für unverschlüsselte Verbindungen freigegeben.",
        "allow_network_none": "Dieses Netz kann nicht freigegeben werden "
                              "(offenes WLAN oder keins).",
        "connected_title": "iPhone verbunden ✅",
        "connected_body": "Die Einrichtung hat geklappt.",
        "battery": "iPhone-Akku {level} %",
        "charging": " ⚡ lädt",
        "as_of": "Stand {time}",
        "clipboard_title": "Zwischenablage vom iPhone",
        "clipboard_text": "{count} Zeichen",
        "clipboard_image": "Bild ({kind}, {size})",
        "link_title": "Link vom iPhone",
        "link_userinfo": "{host} · Anmeldedaten aus dem Link entfernt",
        "open": "Öffnen",
        "link_gone": "Der Link ist nicht mehr verfügbar",
        "unknown_action": "Unbekannte Aktion",
        "vpn_title": "VPN trägt die Standardroute",
        "vpn_lan": "{vpn} ist ein VPN; Empfang stattdessen auf der LAN-Schnittstelle",
        "vpn_only": "Nur {vpn} (ein VPN) hat eine Standardroute; das iPhone erreicht "
                    "diese Adresse vielleicht nicht. Schnittstelle in den Einstellungen setzen.",
        "date": "%d.%m. %H:%M",
    },
}


def language(environ: dict[str, str] | None = None) -> str:
    environ = dict(os.environ) if environ is None else environ
    for key in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        value = environ.get(key, "")
        if value:
            return "de" if value.split(":", 1)[0].lower().startswith("de") else "en"
    return "en"


def texts(lang: str) -> dict[str, str]:
    return _TEXTS.get(lang, _TEXTS["en"])
