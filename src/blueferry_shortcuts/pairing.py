"""The guided iPhone setup: one-time links, setup sessions, profile and QR code.

"Set up iPhone" on the card creates a **one-time link**
(``https://<LAN address>:<port>/setup/<nonce>``) that the PC shows as a QR
code. The nonce is 128 random bits, valid for ten minutes and spent by the
first request that uses it; that request gets a **setup session** (a
random cookie, 30 minutes) and is redirected to ``/setup``, so the nonce
leaves the address bar and the history. Only a valid session sees the
token. Comparisons run in constant time; wrong nonces and sessions count as
failed logins in the server's rate limiter.

The certificate is offered as a ``.mobileconfig`` profile with a clear name
(iOS shows profiles more plainly than raw ``.crt`` downloads). It is not
signed, so iOS labels it "Not Verified"; the setup page says why that is
expected here.
"""
from __future__ import annotations

import hmac
import plistlib
import secrets
import ssl
import threading
import time
import uuid
from collections.abc import Callable

NONCE_SECONDS = 10 * 60
SESSION_SECONDS = 30 * 60
MAX_SESSIONS = 4
NONCE_BYTES = 16
SESSION_BYTES = 32
COOKIE = "bfsetup"
PROFILE_ID = "io.weirdware.blueferry.shortcuts"


class SetupSessions:
    """The current one-time link and the sessions it opened (thread-safe)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._nonce: str | None = None
        self._nonce_until = 0.0
        self._sessions: dict[str, float] = {}

    def nonce(self, *, renew: bool = False) -> tuple[str, float]:
        """The unused nonce and the seconds it stays valid; a new one when
        there is none, it expired, or ``renew``."""
        with self._lock:
            now = self._clock()
            if renew or self._nonce is None or now >= self._nonce_until:
                self._nonce = secrets.token_urlsafe(NONCE_BYTES)
                self._nonce_until = now + NONCE_SECONDS
            return self._nonce, self._nonce_until - now

    def pending(self) -> bool:
        """Whether an unused, valid nonce exists."""
        with self._lock:
            return self._nonce is not None and self._clock() < self._nonce_until

    def redeem(self, given: str) -> str | None:
        """Spend ``given``; return a new session id, or None."""
        with self._lock:
            now = self._clock()
            expected = self._nonce or secrets.token_urlsafe(NONCE_BYTES)
            match = hmac.compare_digest(given.encode("utf-8", "replace"),
                                        expected.encode("ascii"))
            if not match or self._nonce is None or now >= self._nonce_until:
                return None
            self._nonce = None
            self._forget_old(now)
            while len(self._sessions) >= MAX_SESSIONS:
                self._sessions.pop(next(iter(self._sessions)))
            session = secrets.token_urlsafe(SESSION_BYTES)
            self._sessions[session] = now + SESSION_SECONDS
            return session

    def valid(self, session: str) -> bool:
        if not session:
            return False
        with self._lock:
            now = self._clock()
            self._forget_old(now)
            given = session.encode("utf-8", "replace")
            found = False
            for known in self._sessions:
                found |= hmac.compare_digest(given, known.encode("ascii"))
            return found

    def active(self) -> bool:
        """A link or a session is alive (the trust probe runs meanwhile)."""
        with self._lock:
            now = self._clock()
            self._forget_old(now)
            return bool(self._sessions) or (
                self._nonce is not None and now < self._nonce_until
            )

    def clear(self) -> None:
        with self._lock:
            self._nonce = None
            self._sessions.clear()

    def _forget_old(self, now: float) -> None:
        for session in [s for s, until in self._sessions.items() if now >= until]:
            del self._sessions[session]


def cookie_value(header: str) -> str:
    """The setup session from a ``Cookie`` header (empty when missing)."""
    for part in header.split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE:
            return value.strip()[:128]
    return ""


def set_cookie(session: str, secure: bool) -> str:
    flags = "; Secure" if secure else ""
    return (f"{COOKIE}={session}; Path=/setup; Max-Age={SESSION_SECONDS}; HttpOnly; "
            f"SameSite=Lax{flags}")


def ca_common_name(ca_pem: bytes) -> str:
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    certificate = x509.load_pem_x509_certificate(ca_pem)
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(names[0].value) if names else "BlueFerry Shortcuts CA"


def mobileconfig(ca_pem: bytes, fingerprint: str, lang: str) -> bytes:
    """An unsigned configuration profile with the CA as its only payload.

    The UUIDs derive from the CA's fingerprint, so installing it again
    replaces the earlier profile instead of adding a second one.
    """
    der = ssl.PEM_cert_to_DER_cert(ca_pem.decode("ascii"))
    name = ca_common_name(ca_pem)
    profile_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{PROFILE_ID}/profile/{fingerprint}"))
    payload_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{PROFILE_ID}/ca/{fingerprint}"))
    if lang == "de":
        display = f"BlueFerry: Verbindung zu deinem PC ({name})"
        description = (
            "Erlaubt dem iPhone, verschlüsselt mit BlueFerry auf deinem PC zu sprechen. "
            "Das Zertifikat wurde auf deinem PC erzeugt. Danach unter Einstellungen > "
            "Allgemein > Info > Zertifikatsvertrauenseinstellungen einschalten."
        )
    else:
        display = f"BlueFerry: connection to your PC ({name})"
        description = (
            "Lets this iPhone talk to BlueFerry on your PC over an encrypted connection. "
            "The certificate was created on your PC. Afterwards switch it on under "
            "Settings > General > About > Certificate Trust Settings."
        )
    profile = {
        "PayloadContent": [{
            "PayloadType": "com.apple.security.root",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"{PROFILE_ID}.ca.{payload_uuid}",
            "PayloadUUID": payload_uuid,
            "PayloadDisplayName": name,
            "PayloadCertificateFileName": "blueferry-shortcuts-ca.cer",
            "PayloadContent": der,
        }],
        "PayloadDisplayName": display,
        "PayloadDescription": description,
        "PayloadIdentifier": f"{PROFILE_ID}.profile.{profile_uuid}",
        "PayloadOrganization": "BlueFerry",
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1,
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)


def qr_svg(text: str) -> str:
    """An inline SVG QR code (no styles, no scripts)."""
    import segno

    return str(segno.make(text, error="m").svg_inline(scale=6, border=3, light="#fff"))
