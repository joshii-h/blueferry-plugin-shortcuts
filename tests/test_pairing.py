"""One-time links, setup sessions, the profile and the QR code."""
from __future__ import annotations

import plistlib
import ssl

from blueferry_plugin_kit.lanserver.tls import CertificateStore

from blueferry_shortcuts.pairing import (
    NONCE_SECONDS,
    SESSION_SECONDS,
    SetupSessions,
    cookie_value,
    mobileconfig,
    qr_svg,
    set_cookie,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_a_nonce_is_random_reused_until_spent_and_spent_once() -> None:
    clock = Clock()
    sessions = SetupSessions(clock)
    nonce, left = sessions.nonce()
    assert len(nonce) >= 22 and left == NONCE_SECONDS
    assert sessions.nonce()[0] == nonce and sessions.pending()
    assert SetupSessions(clock).nonce()[0] != nonce
    assert sessions.redeem("wrong") is None and sessions.redeem("") is None
    session = sessions.redeem(nonce)
    assert session and sessions.valid(session)
    assert sessions.redeem(nonce) is None, "spent"
    assert not sessions.pending() and sessions.active()
    assert sessions.nonce()[0] != nonce


def test_nonces_and_sessions_expire() -> None:
    clock = Clock()
    sessions = SetupSessions(clock)
    nonce, _ = sessions.nonce()
    clock.now += NONCE_SECONDS
    assert sessions.redeem(nonce) is None and not sessions.active()
    nonce, _ = sessions.nonce()
    assert nonce and sessions.nonce(renew=True)[0] != nonce
    session = sessions.redeem(sessions.nonce()[0])
    clock.now += SESSION_SECONDS - 1
    assert sessions.valid(session)
    clock.now += 1
    assert not sessions.valid(session) and not sessions.active()
    assert not sessions.valid("") and not sessions.valid("x" * 43)


def test_cookie_helpers() -> None:
    assert cookie_value("a=1; bfsetup=abc ; c=3") == "abc"
    assert cookie_value("") == "" and cookie_value("bfsetupx=1") == ""
    header = set_cookie("abc", secure=True)
    assert "HttpOnly" in header and "Secure" in header and "Path=/setup" in header
    assert "Secure" not in set_cookie("abc", secure=False)


def test_profile_carries_the_ca_and_a_stable_uuid(tmp_path) -> None:
    material = CertificateStore(tmp_path, ca_name="BlueFerry Shortcuts CA").ensure(["127.0.0.1"])
    data = mobileconfig(material.ca_pem, material.fingerprint, "de")
    profile = plistlib.loads(data)
    payload = profile["PayloadContent"][0]
    assert payload["PayloadType"] == "com.apple.security.root"
    assert payload["PayloadContent"] == ssl.PEM_cert_to_DER_cert(material.ca_pem.decode())
    assert payload["PayloadDisplayName"].startswith("BlueFerry Shortcuts CA (")
    assert profile["PayloadDisplayName"].startswith("BlueFerry: Verbindung")
    assert "Zertifikatsvertrauenseinstellungen" in profile["PayloadDescription"]
    again = plistlib.loads(mobileconfig(material.ca_pem, material.fingerprint, "en"))
    assert again["PayloadUUID"] == profile["PayloadUUID"]
    assert b"PRIVATE" not in data


def test_qr_code_is_plain_svg() -> None:
    svg = qr_svg("https://192.168.1.4:47801/setup/abc")
    assert svg.startswith("<svg") and "<script" not in svg and "style=" not in svg
