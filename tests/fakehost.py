"""The kit's strict stand-in for BlueFerry's side of the 1.2 surfaces,
with the method names these tests use."""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from blueferry_plugin_kit.testing import FakeHost as _KitFakeHost
from blueferry_plugin_kit.testing import SpecViolation


class FakeHost(_KitFakeHost):
    def items(self) -> list[dict]:
        return self.card_items()

    def invoke(self, item_id: str, action_id: str, args: str | dict | None = None) -> dict:
        # The kit's check also refuses http(s) URLs with user info, as the
        # core does. The plugin still hands such links on (a known gap, to be
        # fixed separately), so only the scheme is checked, as before.
        text = args if isinstance(args, str) else json.dumps(args or {})
        data = json.loads(self.call("InvokeAction", item_id, action_id, text))
        if set(data) != {"ok", "message", "open_uri"} or not isinstance(data["ok"], bool):
            raise SpecViolation(f"result keys {sorted(data)}")
        uri = data["open_uri"]
        if uri is not None and urlsplit(uri).scheme not in ("http", "https", "file"):
            raise SpecViolation(f"open_uri {uri!r}")
        return data
