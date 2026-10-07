"""Which local address to listen on.

The default is the IPv4 address of the interface that carries the default
route: that is the LAN the iPhone shares with the PC. A VPN or tunnel
interface (wg*, tun*, tap*, ppp*, or a custom name of that type) is passed
over for a LAN interface with a default route, and the card says so. The setting may name
an address or an interface instead. A wildcard address (0.0.0.0, ::) is
refused unless the user opted in, so the endpoint never appears on every
network the PC joins by accident.
"""
from __future__ import annotations

import fcntl
import ipaddress
import re
import socket
import struct
from collections.abc import Callable
from pathlib import Path

SIOCGIFADDR = 0x8915
_IFNAME = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")
_RTF_UP = 0x1


class AddressError(Exception):
    """No address to listen on; the message is shown in the card."""


_TUNNEL_PREFIXES = ("wg", "tun", "tap", "ppp")
# ARPHRD_NONE (WireGuard, tun) and ARPHRD_PPP in /sys/class/net/*/type.
_TUNNEL_TYPES = frozenset({65534, 512})
SYSFS_NET = Path("/sys/class/net")


def is_tunnel(name: str, sysfs: Path = SYSFS_NET) -> bool:
    """A VPN or tunnel interface: by name (wg*, tun*, tap*, ppp*) or, for
    custom names such as a NetworkManager WireGuard profile, by its type."""
    if name.startswith(_TUNNEL_PREFIXES):
        return True
    if not _IFNAME.fullmatch(name):
        return False
    base = sysfs / name
    if (base / "tun_flags").exists():
        return True
    try:
        kind = int((base / "type").read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return False
    return kind in _TUNNEL_TYPES


def default_routes(route_table: str | None = None) -> list[str]:
    """Interfaces with an IPv4 default route, lowest metric first."""
    if route_table is None:
        try:
            route_table = Path("/proc/net/route").read_text(encoding="ascii", errors="replace")
        except OSError:
            return []
    found: list[tuple[int, str]] = []
    for line in route_table.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        name, destination, _gateway, flags, *_rest = parts
        try:
            if int(destination, 16) != 0 or not int(flags, 16) & _RTF_UP:
                continue
            mask = int(parts[7], 16)
            metric = int(parts[6])
        except ValueError:
            continue
        if mask == 0:
            found.append((metric, name))
    return [name for _metric, name in sorted(found)]


def default_route_interface(
    route_table: str | None = None, tunnel: Callable[[str], bool] = is_tunnel,
) -> str | None:
    """The interface of the IPv4 default route with the lowest metric,
    preferring LAN interfaces: when a VPN carries the default route, the
    iPhone still talks to the PC over the physical network."""
    routes = default_routes(route_table)
    lan = [name for name in routes if not tunnel(name)]
    return (lan or routes or [None])[0]


def default_route_tunnel(
    route_table: str | None = None, tunnel: Callable[[str], bool] = is_tunnel,
) -> tuple[str, bool] | None:
    """``(tunnel, lan_found)`` when a VPN or tunnel carries the default
    route; ``lan_found`` tells whether a LAN interface was used instead."""
    routes = default_routes(route_table)
    if not routes or not tunnel(routes[0]):
        return None
    return routes[0], any(not tunnel(name) for name in routes)


def interface_address(name: str) -> str | None:
    """The primary IPv4 address of an interface, or None."""
    if not _IFNAME.fullmatch(name):
        return None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            packed = fcntl.ioctl(
                probe.fileno(), SIOCGIFADDR, struct.pack("256s", name.encode("ascii")[:15]),
            )
        except OSError:
            return None
    return socket.inet_ntoa(packed[20:24])


def is_wildcard(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_unspecified
    except ValueError:
        return False


def check_setting(value: str, allow_all: bool) -> str | None:
    """A reason why ``value`` is not a valid listen setting, else None."""
    value = value.strip()
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        if _IFNAME.fullmatch(value):
            return None
        return "must be an IP address or an interface name"
    if address.is_unspecified and not allow_all:
        return "listening on all interfaces needs 'Allow all interfaces'"
    if address.is_multicast:
        return "must not be a multicast address"
    return None


def resolve(
    setting: str,
    allow_all: bool,
    *,
    default_interface: Callable[[], str | None] = default_route_interface,
    address_of: Callable[[str], str | None] = interface_address,
) -> str:
    """The concrete address to bind; raise AddressError with a reason."""
    setting = setting.strip()
    reason = check_setting(setting, allow_all)
    if reason:
        raise AddressError(reason)
    if not setting:
        interface = default_interface()
        if interface is None:
            raise AddressError("no default route; set an address or interface")
        address = address_of(interface)
        if address is None:
            raise AddressError(f"interface {interface} has no IPv4 address")
        return address
    try:
        ipaddress.ip_address(setting.split("%", 1)[0])
        return setting
    except ValueError:
        address = address_of(setting)
        if address is None:
            raise AddressError(f"interface {setting} has no IPv4 address")
        return address


def local_addresses() -> list[str]:
    """IPv4 addresses of all interfaces (for the certificate when bound to 0.0.0.0)."""
    found: list[str] = []
    for _index, name in socket.if_nameindex():
        address = interface_address(name)
        if address and address not in found:
            found.append(address)
    return found
