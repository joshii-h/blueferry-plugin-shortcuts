"""Which network the PC is in, for the opt-in plain-HTTP listener.

Plain HTTP is only acceptable in a network the user approved: at home, not
in a café. A network is identified by its NetworkManager connection profile
(UUID), not by its SSID: an evil twin called "Home" is a different profile.
Rules (see :func:`decide`):

1. HTTP listens only while an approved profile carries a default route.
2. Open Wi-Fi (no ``802-11-wireless-security``, ``key-mgmt`` ``none`` (WEP)
   or ``owe``) is never accepted, not even when approved.
3. Changes (NetworkManager ``StateChanged``/``PropertiesChanged``) are
   followed at once; the plugin's minute timer is the fallback.
4. Without NetworkManager plain HTTP is not available.

All D-Bus calls here block (with a timeout) and run on worker threads,
never on the GLib main loop. Nothing is logged about the networks.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

log = logging.getLogger(__name__)

NM = "org.freedesktop.NetworkManager"
NM_PATH = "/org/freedesktop/NetworkManager"
PROPERTIES = "org.freedesktop.DBus.Properties"
CALL_TIMEOUT_S = 5
OPEN_KEY_MGMT = {"", "none", "owe"}


@dataclass(frozen=True, slots=True)
class Network:
    """One active NetworkManager connection."""

    uuid: str
    name: str
    default_route: bool
    open_wifi: bool = False


class Networks(Protocol):
    def current(self) -> list[Network] | None:
        """The active connections; None when NetworkManager is not reachable."""

    def watch(self, callback: Callable[[], None]) -> None:
        """Call ``callback`` (on the main loop) when the networks may have changed."""


@dataclass(frozen=True, slots=True)
class Decision:
    """Whether plain HTTP may listen, and why (``reason`` is a text key)."""

    active: bool
    reason: str     # off, active, no-nm, open-wifi, foreign, no-network
    name: str = ""  # the approved profile in use, or the foreign one


def decide(
    allowed: bool, approved: Sequence[tuple[str, str]], current: list[Network] | None,
) -> Decision:
    if not allowed:
        return Decision(False, "off")
    if current is None:
        return Decision(False, "no-nm")
    routed = [network for network in current if network.default_route]
    if any(network.open_wifi for network in current):
        name = next(network.name for network in current if network.open_wifi)
        return Decision(False, "open-wifi", name)
    if not routed:
        return Decision(False, "no-network")
    uuids = {uuid for uuid, _name in approved}
    for network in routed:
        if network.uuid in uuids:
            return Decision(True, "active", network.name)
    return Decision(False, "foreign", routed[0].name)


def approvable(current: list[Network] | None) -> list[Network]:
    """The default-route networks that may be approved now (never open Wi-Fi)."""
    if not current or any(network.open_wifi for network in current):
        return []
    return [network for network in current if network.default_route]


def is_open_wifi(settings: dict[str, Any]) -> bool:
    connection = settings.get("connection") or {}
    if str(connection.get("type", "")) != "802-11-wireless":
        return False
    security = settings.get("802-11-wireless-security")
    if not security:
        return True
    return str(security.get("key-mgmt", "")).casefold() in OPEN_KEY_MGMT


class NetworkManagerNetworks:
    """:class:`Networks` through NetworkManager on the system bus."""

    def __init__(self, bus_factory: Callable[[], Any] | None = None) -> None:
        self._bus_factory = bus_factory
        self._bus: Any = None

    def _system_bus(self) -> Any:
        if self._bus is None:
            if self._bus_factory is not None:
                self._bus = self._bus_factory()
            else:
                import dbus

                self._bus = dbus.SystemBus()
        return self._bus

    def current(self) -> list[Network] | None:
        try:
            import dbus
        except ImportError:
            return None
        try:
            bus = self._system_bus()
            manager = bus.get_object(NM, NM_PATH)
            actives = manager.Get(NM, "ActiveConnections", dbus_interface=PROPERTIES,
                                  timeout=CALL_TIMEOUT_S)
            found: list[Network] = []
            for path in actives:
                active = bus.get_object(NM, path).GetAll(
                    f"{NM}.Connection.Active", dbus_interface=PROPERTIES,
                    timeout=CALL_TIMEOUT_S,
                )
                profile = bus.get_object(NM, active["Connection"]).GetSettings(
                    dbus_interface=f"{NM}.Settings.Connection", timeout=CALL_TIMEOUT_S,
                )
                found.append(Network(
                    uuid=str(active.get("Uuid", "")),
                    name=str(active.get("Id", "")),
                    default_route=bool(active.get("Default")) or bool(active.get("Default6")),
                    open_wifi=is_open_wifi(profile),
                ))
            return found
        except (dbus.DBusException, KeyError, TypeError):
            log.debug("NetworkManager not reachable")
            return None

    def watch(self, callback: Callable[[], None]) -> None:
        try:
            bus = self._system_bus()
            bus.add_signal_receiver(
                lambda *_args: callback(), signal_name="StateChanged",
                dbus_interface=NM, bus_name=NM, path=NM_PATH,
            )
            bus.add_signal_receiver(
                lambda *_args: callback(), signal_name="PropertiesChanged",
                dbus_interface=PROPERTIES, bus_name=NM, path=NM_PATH,
            )
        except Exception:
            log.debug("cannot follow NetworkManager; checking every minute only")
