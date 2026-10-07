"""A stand-in for NetworkManager: tests never reach the system bus."""
from __future__ import annotations

from blueferry_shortcuts.netguard import Network

HOME = Network("1b4e28ba-2fa1-11d2-883f-0016d3cca427", "Zuhause", True)
TWIN = Network("6fa459ea-ee8a-3ca4-894e-db77e160355e", "Zuhause", True)
CAFE_OPEN = Network("0e8400e2-9b1d-41d4-a716-446655440000", "Café", True, open_wifi=True)


class FakeNetworks:
    def __init__(self, current=None, available: bool = True) -> None:
        self.networks = list(current) if current is not None else [HOME]
        self.available = available
        self.callbacks = []

    def current(self):
        return list(self.networks) if self.available else None

    def watch(self, callback) -> None:
        self.callbacks.append(callback)

    def change(self, networks) -> None:
        """Switch networks and fire the NetworkManager signal."""
        self.networks = list(networks)
        for callback in self.callbacks:
            callback()
