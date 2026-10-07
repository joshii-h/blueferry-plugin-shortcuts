"""BlueFerry plugin: a small LAN HTTPS endpoint for iOS Shortcuts.

Shortcuts on the iPhone send the clipboard, links and the battery level to
the PC (and may fetch the PC clipboard). The plugin shows them through the
generic plugin surfaces of plugin API 1.2 (``card`` and ``notify``); the
settings form uses the 1.3 additions (sections, examples, "Test connection").

Imports only ``blueferry.plugin_api`` from BlueFerry.
"""
from __future__ import annotations

import dataclasses
import re
from importlib import resources

PLUGIN_ID = "io.weirdware.blueferry.shortcuts"
__version__ = "0.2.2"

CAPABILITIES = ("card", "notify")
API_MINOR = 3


def manifest_text() -> str:
    return (
        resources.files(__name__).joinpath(f"{PLUGIN_ID}.plugin").read_text(encoding="utf-8")
    )


def load_manifest(text: str | None = None):
    """Parse the manifest, also with a ``blueferry.plugin_api`` older than 1.2.

    An older parser drops ``card`` and ``notify`` as unknown and then
    refuses a manifest without capabilities. The plugin itself implements
    both surfaces, so it validates everything else with the installed
    parser and keeps its own capability list.
    """
    from blueferry.plugin_api import KNOWN_CAPABILITIES
    from blueferry.plugin_api.manifest import parse_manifest

    text = manifest_text() if text is None else text
    if all(capability in KNOWN_CAPABILITIES for capability in CAPABILITIES):
        return parse_manifest(text)
    probe = re.sub(r"(?m)^Capabilities=.*$", "Capabilities=photos;", text, count=1)
    manifest = parse_manifest(probe)
    fields = {field.name for field in dataclasses.fields(manifest)}
    changes: dict[str, object] = {"capabilities": CAPABILITIES}
    if "api_minor" in fields:
        changes["api_minor"] = API_MINOR
    return dataclasses.replace(manifest, **changes)
