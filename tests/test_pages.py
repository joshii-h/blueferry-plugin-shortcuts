"""The setup pages: language, escaping and a strict CSP without external resources."""
from __future__ import annotations

import base64
import hashlib
import re

from blueferry_shortcuts.pages import (
    SCRIPT,
    STYLE,
    PcView,
    SetupView,
    csp,
    expired_page,
    home_page,
    language,
    other_ios_browser,
    pc_page,
    setup_page,
)

VIEW = SetupView(
    address="https://192.168.1.4:47801", secure_address="https://192.168.1.4:47801",
    token="abcd-efgh-jkmn-pqrs-tuvw-xyz2", ca_name='BlueFerry <CA> "x"',
    fingerprint="AA:BB", probe_url="https://192.168.1.4:47802/probe",
    shortcut_url="https://www.icloud.com/shortcuts/0123456789abcdef0123456789abcdef",
    plain_http=False, clipboard_read=False,
)


def _sha(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()


def test_accept_language() -> None:
    assert language("de-CH,de;q=0.9,en;q=0.8") == "de"
    assert language("en-US,en;q=0.9,de;q=0.8") == "en"
    assert language("fr-FR,de;q=0.5") == "de"
    assert language("") == "en" and language("de;q=abc,en") == "en"


def test_csp_allows_only_the_own_style_and_script() -> None:
    policy = csp(script=True, connect=("https://192.168.1.4:47802/probe",))
    assert "default-src 'none'" in policy and "frame-ancestors 'none'" in policy
    assert f"'sha256-{_sha(STYLE)}'" in policy and f"'sha256-{_sha(SCRIPT)}'" in policy
    assert "unsafe" not in policy and "script-src" not in csp(script=False)


def test_setup_page_escapes_and_links_nothing_external() -> None:
    page, policy = setup_page("de", VIEW)
    text = page.decode()
    assert "<script>" + SCRIPT + "</script>" in text and "<style>" + STYLE + "</style>" in text
    assert 'BlueFerry &lt;CA&gt; &quot;x&quot;' in text and "<CA>" not in text
    assert VIEW.token in text and "Zertifikatsvertrauenseinstellungen" in text
    assert "Kurzbefehl „BlueFerry“ hinzufügen" in text and VIEW.shortcut_url in text
    assert "optional, empfohlen" not in text
    sources = re.findall(r'(?:src|href)="([^"]+)"', text)
    assert sources == ["/ca.mobileconfig", VIEW.shortcut_url]
    assert "connect-src 'self' https://192.168.1.4:47802/probe" in policy


def test_setup_page_in_plain_mode_and_without_a_shortcut_link() -> None:
    view = SetupView(**{**{f: getattr(VIEW, f) for f in VIEW.__slots__},
                        "address": "http://192.168.1.4:47800", "plain_http": True,
                        "shortcut_url": "", "probe_url": ""})
    text = setup_page("en", view)[0].decode()
    assert "optional, recommended" in text and "Skip for now" in text
    assert "not set up on the PC yet" in text and "http://192.168.1.4:47800" in text
    assert 'data-secure-address="https://192.168.1.4:47801"' in text
    assert '<p class="value" id="address" aria-labelledby="address-label">http://' in text
    assert "local network" in text and "the test in step 3" in text


def test_plain_pages_hold_no_secrets() -> None:
    assert "Set up iPhone" in home_page("en").decode()
    assert "iPhone einrichten" in home_page("de").decode()
    assert "zehn Minuten" in expired_page("de").decode()


def test_pc_page_states() -> None:
    view = PcView(link="https://192.168.1.4:47801/setup/n0nce", qr="<svg></svg>",
                  valid_until="14:32", error="", plain_network="", opened=True,
                  trusted=False, tested=False)
    page, policy = pc_page("de", view)
    text = page.decode()
    assert "<svg></svg>" in text and "Gültig bis 14:32" in text and "Details einblenden" in text
    assert "✅ Auf dem iPhone geöffnet" in text and "○ Zertifikat vertraut" in text
    assert 'http-equiv="refresh"' in text and "script-src" not in policy
    used = pc_page("de", PcView("", "", "", "", "", True, True, True))[0].decode()
    assert "Neuer Code" in used and "<svg" not in used
    failed = pc_page("en", PcView("", "", "", "port <in use>", "", False, False, False))[0]
    assert b"port &lt;in use&gt;" in failed
    plain = pc_page("en", PcView("http://x/setup/n", "<svg/>", "1", "", "Home", 0, 0, 0))[0]
    assert "active in “Home”" in plain.decode()


SAFARI = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
          "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1")
FIREFOX = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
           "(KHTML, like Gecko) FxiOS/140.0 Mobile/15E148 Safari/605.1.15")


def test_other_ios_browsers_are_recognised() -> None:
    assert other_ios_browser(SAFARI) == ""
    assert other_ios_browser(FIREFOX) == "Firefox"
    assert other_ios_browser(SAFARI.replace("Version/18.0", "CriOS/130.0")) == "Chrome"
    assert other_ios_browser(SAFARI.replace("Version/18.0", "EdgiOS/130.0")) == "Edge"
    # An in-app browser (WKWebView without the Safari token) cannot install profiles either.
    assert other_ios_browser(SAFARI.split(" Version/")[0]) == "*"
    assert other_ios_browser("Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0") == ""
    assert other_ios_browser("") == ""


def test_setup_page_sends_other_browsers_to_safari() -> None:
    text = setup_page("de", VIEW, "Firefox")[0].decode()
    assert "Diese Seite ist in Firefox offen" in text and "Profil in Safari öffnen" in text
    sources = re.findall(r'(?:src|href)="([^"]+)"', text)
    # No download link Firefox could choke on: Safari gets the absolute profile URL.
    assert "/ca.mobileconfig" not in sources
    assert sources[0] == "x-safari-https://192.168.1.4:47801/ca.mobileconfig"
    assert ">https://192.168.1.4:47801/ca.mobileconfig</p>" in text
    assert 'data-copy="profile"' in text and "Details einblenden" in text
    generic = setup_page("en", VIEW, "*")[0].decode()
    assert "open in another browser than Safari" in generic
    plain_view = SetupView(**{**{f: getattr(VIEW, f) for f in VIEW.__slots__},
                              "address": "http://192.168.1.4:47800", "plain_http": True})
    plain = setup_page("en", plain_view, "Chrome")[0].decode()
    assert 'href="x-safari-http://192.168.1.4:47800/ca.mobileconfig"' in plain
    assert "Show Details" not in plain          # no certificate warning over plain HTTP


def test_setup_page_fits_a_phone() -> None:
    text = setup_page("en", VIEW)[0].decode()
    assert 'name="viewport" content="width=device-width,initial-scale=1"' in text
    # Long values wrap instead of running off the screen.
    assert "word-break:break-all" in STYLE and "overflow-wrap:break-word" in STYLE
    assert "prefers-color-scheme:dark" in STYLE and "min-height:50px" in STYLE
    assert "<input" not in text and f">{VIEW.token}</p>" in text
