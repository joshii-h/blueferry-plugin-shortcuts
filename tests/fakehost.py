"""The kit's strict stand-in for BlueFerry's side of the plugin API, with
the method names these tests use."""
from __future__ import annotations

from blueferry_plugin_kit.testing import FakeHost as _KitFakeHost


class FakeHost(_KitFakeHost):
    def items(self) -> list[dict]:
        return self.card_items()
