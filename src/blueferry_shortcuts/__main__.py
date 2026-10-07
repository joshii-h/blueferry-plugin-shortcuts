"""``blueferry-shortcuts serve|setup|show|status|networks|forget``."""
from __future__ import annotations

import argparse
import logging
import os
import shlex
import shutil
import sys
from pathlib import Path

from blueferry.plugin_api.manifest import ManifestError, default_directories
from blueferry.plugin_api.service import run
from blueferry_plugin_kit import netaddr

from blueferry_shortcuts import PLUGIN_ID, load_manifest, manifest_text
from blueferry_shortcuts.netguard import NetworkManagerNetworks, Networks, approvable
from blueferry_shortcuts.settings import (
    SettingsError,
    SettingsStore,
    certificate_store,
    probe_store,
)

ENTRY_POINT = "blueferry-shortcuts"
# The endpoint must stay reachable for the iPhone; never idle out.
NEVER_IDLE = 10**9


def _data_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")


def _config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")


def _command() -> list[str]:
    """How the bus and BlueFerry should start this plugin."""
    beside = Path(sys.executable).parent / ENTRY_POINT
    if beside.is_file() and os.access(beside, os.X_OK):
        return [str(beside)]
    installed = shutil.which(ENTRY_POINT)
    if installed:
        return [installed]
    import blueferry.plugin_api as api

    roots = [
        str(Path(__file__).resolve().parents[1]),
        str(Path(api.__file__).resolve().parents[2]),
    ]
    return [
        "/usr/bin/env", "PYTHONPATH=" + ":".join(dict.fromkeys(roots)),
        sys.executable, "-m", "blueferry_shortcuts",
    ]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.chmod(0o644)
    os.replace(temporary, path)


def install_activation(data_home: Path | None = None) -> list[Path]:
    """Write the user manifest and D-Bus service file unless the system has them."""
    data_home = data_home or _data_home()
    template = load_manifest()
    written: list[Path] = []
    system = [d for d in default_directories() if not str(d).startswith(str(data_home))]
    if not any((directory / f"{PLUGIN_ID}.plugin").exists() for directory in system):
        command = _command()
        text = manifest_text().replace(
            "Exec=blueferry-shortcuts serve", "Exec=" + shlex.join([*command, "serve"]),
        ).replace("Cli=blueferry-shortcuts", "Cli=" + shlex.join(command))
        load_manifest(text)  # never install something clients would ignore
        target = data_home / "blueferry" / "plugins" / f"{PLUGIN_ID}.plugin"
        _write(target, text)
        written.append(target)
        service = data_home / "dbus-1" / "services" / f"{template.bus_name}.service"
        _write(service, "[D-BUS Service]\nName={}\nExec={}\n".format(
            template.bus_name, shlex.join([*command, "serve"]),
        ))
        written.append(service)
    return written


def install_autostart(config_home: Path | None = None) -> Path:
    """Start the endpoint with the desktop session (XDG autostart)."""
    target = (config_home or _config_home()) / "autostart" / f"{PLUGIN_ID}.desktop"
    _write(target, (
        "[Desktop Entry]\nType=Application\nName=BlueFerry iOS Shortcuts bridge\n"
        f"Exec={shlex.join([*_command(), 'serve'])}\n"
        "NoDisplay=true\nX-KDE-autostart-phase=2\n"
    ))
    return target


def show(store: SettingsStore | None = None) -> int:
    store = store or SettingsStore()
    try:
        settings = store.load()
        token = store.token()
    except (SettingsError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    try:
        host = netaddr.resolve(settings.bind_address, settings.allow_all_interfaces)
        addresses = netaddr.local_addresses() if netaddr.is_wildcard(host) else [host]
        material = certificate_store(store.directory).ensure(addresses)
    except (netaddr.AddressError, OSError, ValueError) as error:
        print(f"No listen address: {error}", file=sys.stderr)
        return 1
    if netaddr.is_wildcard(host):
        host = next((a for a in addresses if not a.startswith("127.")), "localhost")
    shown = f"[{host}]" if ":" in host else host
    print(f"URL:         https://{shown}:{settings.port}")
    print(f"Token:       {token}")
    print(f"Header:      Authorization: Bearer {token}")
    print(f"Certificate: https://{shown}:{settings.port}/ca.crt (open in Safari on the iPhone)")
    print(f"SHA-256:     {material.fingerprint}")
    print(f"Read PC clipboard: {'on' if settings.allow_clipboard_read else 'off'}; "
          f"images: {'on' if settings.accept_images else 'off'}")
    if settings.allow_http:
        names = ", ".join(name for _uuid, name in settings.http_networks) or "none"
        print(f"Plain HTTP:  http://{shown}:{settings.http_port} in approved networks: {names}")
    print('Easiest: "Set up iPhone" on the BlueFerry card shows a QR code for the iPhone.')
    return 0


def networks(action: str, name: str | None, store: SettingsStore | None = None,
             source: Networks | None = None) -> int:
    """List, approve or remove the networks approved for plain HTTP."""
    store = store or SettingsStore()
    try:
        settings = store.load()
    except (SettingsError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    approved = dict(settings.http_networks)
    if action == "list":
        if not approved:
            print("No network is approved for plain HTTP.")
        for uuid, label in approved.items():
            print(f"{label}\t{uuid}")
        print(f"Plain HTTP is {'on' if settings.allow_http else 'off'}.")
        return 0
    if action == "allow-current":
        current = (source or NetworkManagerNetworks()).current()
        if current is None:
            print("NetworkManager is not reachable; plain HTTP needs it.", file=sys.stderr)
            return 1
        chosen = approvable(current)
        if not chosen:
            print("This network cannot be approved (open Wi-Fi or no connection).",
                  file=sys.stderr)
            return 1
        for network in chosen:
            approved[network.uuid] = network.name
            print(f"Approved {network.name}")
    else:
        matches = [uuid for uuid, label in approved.items() if name in (uuid, label)]
        if not matches:
            print(f"Not approved: {name}", file=sys.stderr)
            return 1
        for uuid in matches:
            print(f"Removed {approved.pop(uuid)}")
    store.save(settings.changed(http_networks=tuple(approved.items())))
    print("The running plugin follows within a minute.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=ENTRY_POINT, description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve", help="serve on the session bus and the LAN")
    set_up = commands.add_parser("setup", help="install activation and show the setup data")
    set_up.add_argument("--autostart", action="store_true",
                        help="also start the endpoint with the desktop session")
    commands.add_parser("show", help="print URL, token and certificate fingerprint")
    commands.add_parser("status", help="show the settings")
    nets = commands.add_parser("networks", help="networks approved for plain HTTP")
    nets.add_argument("action", choices=("list", "allow-current", "remove"), nargs="?",
                      default="list")
    nets.add_argument("name", nargs="?", help="name or UUID to remove")
    commands.add_parser("forget", help="remove token, settings and certificates")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if args.command == "setup":
        for path in install_activation():
            print(f"Installed {path}")
        if args.autostart:
            print(f"Installed {install_autostart()}")
        return show()
    if args.command == "show":
        return show()
    if args.command == "networks":
        if args.action == "remove" and not args.name:
            parser.error("networks remove needs a name or UUID")
        return networks(args.action, args.name)
    if args.command == "forget":
        store = SettingsStore()
        store.forget()
        probe_store(store.directory).forget()
        certificate_store(store.directory).forget()
        print("Removed the token, settings and certificates.")
        return 0
    if args.command == "status":
        try:
            settings = SettingsStore().load()
        except SettingsError as error:
            print(error)
            return 1
        print(f"Listen on: {settings.bind_address or 'interface of the default route'}, "
              f"port {settings.port}")
        return 0
    try:
        manifest = load_manifest()
    except ManifestError as error:
        print(error, file=sys.stderr)
        return 1
    from blueferry_shortcuts.service import ShortcutsService

    def make(bus):
        service = ShortcutsService(manifest, bus)

        def begin() -> None:
            service.start()
            service.start_maintenance()

        # Runs once the main loop runs, i.e. only after the bus name is ours.
        service._to_main(begin)
        return service

    return run(make, idle_seconds=NEVER_IDLE)


if __name__ == "__main__":
    sys.exit(main())
