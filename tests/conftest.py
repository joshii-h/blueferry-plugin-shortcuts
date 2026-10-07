"""Keep tests away from the user's configuration, state and session bus."""
from __future__ import annotations

from blueferry_plugin_kit.testing import isolate_environment

# No test may reach a real bus or display: everything runs in-process.
isolate_environment(
    "blueferry-shortcuts-tests-", keep=("DISPLAY",), bus_name="blueferry-shortcuts-tests",
)
