"""A minimal stand-in for BlueFerry's side of the 1.2 surfaces.

It records ``CardChanged`` and ``Notify`` signals, fetches card items and
invokes actions the way the core does, and checks every reply against the
limits of PLUGIN-SURFACES-v1.2 (items, actions, string lengths, open_uri).
"""
from __future__ import annotations

import json
import re
import threading
from urllib.parse import urlsplit

_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class SpecViolation(AssertionError):
    pass


def _text(value: object, limit: int, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or len(value) > limit:
        raise SpecViolation(f"bad text {value!r} (limit {limit})")
    if any(not ch.isprintable() for ch in value):
        raise SpecViolation(f"control characters in {value!r}")


def check_card(reply: str) -> list[dict]:
    data = json.loads(reply)
    if set(data) != {"items"} or not isinstance(data["items"], list):
        raise SpecViolation("card reply must be {items: [...]}")
    items = data["items"]
    if len(items) > 8:
        raise SpecViolation("more than 8 items")
    for item in items:
        if set(item) != {"id", "icon", "title", "subtitle", "actions"}:
            raise SpecViolation(f"item keys {sorted(item)}")
        if not _ID.fullmatch(item["id"]):
            raise SpecViolation("item id")
        _text(item["icon"], 128)
        _text(item["title"], 80)
        _text(item["subtitle"], 160, optional=True)
        if not isinstance(item["actions"], list) or len(item["actions"]) > 3:
            raise SpecViolation("at most 3 actions")
        for action in item["actions"]:
            if set(action) != {"id", "label", "icon", "kind"}:
                raise SpecViolation(f"action keys {sorted(action)}")
            if not _ID.fullmatch(action["id"]) or action["kind"] not in ("button", "primary"):
                raise SpecViolation("action id or kind")
            _text(action["label"], 40)
            _text(action["icon"], 128, optional=True)
    return items


def check_result(reply: str) -> dict:
    data = json.loads(reply)
    if set(data) != {"ok", "message", "open_uri"} or not isinstance(data["ok"], bool):
        raise SpecViolation(f"result keys {sorted(data)}")
    uri = data["open_uri"]
    if uri is not None and urlsplit(uri).scheme not in ("http", "https", "file"):
        raise SpecViolation(f"open_uri {uri!r}")
    return data


class FakeHost:
    def __init__(self, service) -> None:
        self.service = service
        self.lock = threading.Lock()
        self.card_changed = 0
        self.notifications: list[tuple[str, str, str, str, str]] = []
        # Instance attributes shadow the dbus-decorated signal methods.
        service.CardChanged = self._card_changed
        service.Notify = self._notify

    def _card_changed(self) -> None:
        with self.lock:
            self.card_changed += 1

    def _notify(self, title, body, icon, action_label, action_id) -> None:
        for value in (title, body, icon, action_label, action_id):
            if not isinstance(value, str):
                raise SpecViolation("Notify takes five strings")
        with self.lock:
            self.notifications.append((title, body, icon, action_label, action_id))

    def items(self) -> list[dict]:
        return check_card(self.service.GetCardItems(sender=":1.host"))

    def item(self, item_id: str) -> dict:
        return next(item for item in self.items() if item["id"] == item_id)

    def invoke(self, item_id: str, action_id: str, args: str = "{}") -> dict:
        return check_result(self.service.InvokeAction(item_id, action_id, args, sender=":1.host"))

    def click_notification(self, index: int = -1) -> dict:
        _title, _body, _icon, _label, action_id = self.notifications[index]
        return self.invoke("notify", action_id)
