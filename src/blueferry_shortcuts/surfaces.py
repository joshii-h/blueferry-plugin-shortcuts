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
        "ca": "Certificate for the iPhone",
        "ca_hint": "Open {url}/ca.crt in Safari, then trust it in Settings",
        "battery": "iPhone battery {level} %",
        "charging": " ⚡ charging",
        "as_of": "As of {time}",
        "clipboard_title": "Clipboard from iPhone",
        "clipboard_text": "{count} characters",
        "clipboard_image": "Image ({kind}, {size})",
        "link_title": "Link from iPhone",
        "open": "Open",
        "link_gone": "The link is no longer available",
        "unknown_action": "Unknown action",
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
        "ca": "Zertifikat fürs iPhone",
        "ca_hint": "{url}/ca.crt in Safari öffnen, dann in den Einstellungen vertrauen",
        "battery": "iPhone-Akku {level} %",
        "charging": " ⚡ lädt",
        "as_of": "Stand {time}",
        "clipboard_title": "Zwischenablage vom iPhone",
        "clipboard_text": "{count} Zeichen",
        "clipboard_image": "Bild ({kind}, {size})",
        "link_title": "Link vom iPhone",
        "open": "Öffnen",
        "link_gone": "Der Link ist nicht mehr verfügbar",
        "unknown_action": "Unbekannte Aktion",
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
