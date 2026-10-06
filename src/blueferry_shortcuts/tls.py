"""A private certificate authority and the server certificate it signs.

iOS only trusts a self-signed certificate for Shortcuts after it was
installed as a profile and enabled under Certificate Trust Settings, and
that list only offers authority certificates. So the plugin creates a
small local CA once (ten years) and from it a server certificate for the
current listen address (397 days, renewed automatically). The iPhone
trusts the CA once; a new IP address or a renewal needs nothing on the
phone. The fingerprint shown in BlueFerry is the CA's SHA-256, which iOS
shows in the profile details for comparison.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from blueferry_shortcuts.settings import read_private, write_private

CA_DAYS = 3650
SERVER_DAYS = 397
RENEW_BEFORE = dt.timedelta(days=30)
MAX_PEM = 64 * 1024


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def fingerprint(certificate: x509.Certificate) -> str:
    digest = certificate.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _names(addresses: list[str]) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = []
    for address in addresses:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(address.split("%", 1)[0])))
        except ValueError:
            continue
    host = socket.gethostname().split(".", 1)[0]
    if host and host.isascii() and all(ch.isalnum() or ch == "-" for ch in host):
        names.append(x509.DNSName(host.lower() + ".local"))
    names.append(x509.DNSName("localhost"))
    return names


@dataclass(frozen=True, slots=True)
class Material:
    ca_pem: bytes
    fingerprint: str
    cert_path: Path
    key_path: Path

    def server_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.cert_path), str(self.key_path))
        return context


class CertificateStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    @property
    def ca_cert_path(self) -> Path:
        return self.directory / "ca.pem"

    @property
    def ca_key_path(self) -> Path:
        return self.directory / "ca-key.pem"

    @property
    def cert_path(self) -> Path:
        return self.directory / "server.pem"

    @property
    def key_path(self) -> Path:
        return self.directory / "server-key.pem"

    def _load_ca(self) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None:
        try:
            certificate = x509.load_pem_x509_certificate(read_private(self.ca_cert_path, MAX_PEM))
            key = serialization.load_pem_private_key(
                read_private(self.ca_key_path, MAX_PEM), None,
            )
        except (OSError, ValueError):
            return None
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            return None
        if certificate.not_valid_after_utc - RENEW_BEFORE < _now():
            return None
        return certificate, key

    def _new_ca(self) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
        key = ec.generate_private_key(ec.SECP256R1())
        host = socket.gethostname().split(".", 1)[0][:30] or "PC"
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"BlueFerry Shortcuts CA ({host})"),
        ])
        now = _now()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        write_private(self.ca_key_path, _key_pem(key))
        write_private(self.ca_cert_path, certificate.public_bytes(serialization.Encoding.PEM))
        # A new CA invalidates the old server certificate.
        self.cert_path.unlink(missing_ok=True)
        return certificate, key

    def _server_ok(self, ca: x509.Certificate, addresses: list[str]) -> bool:
        try:
            certificate = x509.load_pem_x509_certificate(read_private(self.cert_path, MAX_PEM))
            read_private(self.key_path, MAX_PEM)
        except (OSError, ValueError):
            return False
        if certificate.issuer != ca.subject:
            return False
        if certificate.not_valid_after_utc - RENEW_BEFORE < _now():
            return False
        try:
            names = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName,
            ).value.get_values_for_type(x509.IPAddress)
        except x509.ExtensionNotFound:
            return False
        wanted = set()
        for address in addresses:
            try:
                wanted.add(ipaddress.ip_address(address.split("%", 1)[0]))
            except ValueError:
                continue
        return wanted <= set(names)

    def _new_server(
        self, ca: x509.Certificate, ca_key: ec.EllipticCurvePrivateKey, addresses: list[str],
    ) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        now = _now()
        first = addresses[0] if addresses else "localhost"
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, first)]))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=SERVER_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False,
            )
            .add_extension(x509.SubjectAlternativeName(_names(addresses)), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        write_private(self.key_path, _key_pem(key))
        write_private(self.cert_path, certificate.public_bytes(serialization.Encoding.PEM))

    def ensure(self, addresses: list[str]) -> Material:
        """Create or renew what is missing; return the paths and the CA fingerprint."""
        loaded = self._load_ca()
        ca, ca_key = loaded if loaded is not None else self._new_ca()
        if not self._server_ok(ca, addresses):
            self._new_server(ca, ca_key, addresses)
        return Material(
            ca_pem=ca.public_bytes(serialization.Encoding.PEM),
            fingerprint=fingerprint(ca),
            cert_path=self.cert_path,
            key_path=self.key_path,
        )

    def ca_fingerprint(self) -> str | None:
        loaded = self._load_ca()
        return fingerprint(loaded[0]) if loaded else None

    def forget(self) -> None:
        for path in (self.ca_cert_path, self.ca_key_path, self.cert_path, self.key_path):
            path.unlink(missing_ok=True)
