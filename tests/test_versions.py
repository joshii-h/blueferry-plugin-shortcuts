from __future__ import annotations

from pathlib import Path

from blueferry_plugin_kit.testing import check_versions

from blueferry_shortcuts import __version__


def test_manifest_pyproject_and_package_agree() -> None:
    check_versions(Path(__file__).resolve().parent.parent, __version__)
