"""TLS and certificate inspection with the standard library plus `cryptography` for the certificate fields."""

from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .checks import Finding

TLS_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"


@dataclass
class TLSInfo:
    host: str
    port: int
    protocol: str = ""
    cipher: str = ""
    trusted: bool = False
    error: str = ""
    subject: str = ""
    issuer: str = ""
    sans: list[str] = field(default_factory=list)
    not_before: datetime | None = None
    not_after: datetime | None = None
    key_type: str = ""
    key_bits: int = 0
    signature_hash: str = ""
    legacy_accepted: list[str] = field(default_factory=list)   # e.g. ["TLSv1", "TLSv1.1"]
    legacy_probed: bool = False                                 # False when the local OpenSSL refuses to try


def _connect(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> tuple[ssl.SSLSocket, bytes]:
    sock = socket.create_connection((host, port), timeout=timeout)
    tls = ctx.wrap_socket(sock, server_hostname=host)
    return tls, tls.getpeercert(binary_form=True) or b""


def inspect(host: str, port: int = 443, verify: bool | str = True, timeout: float = 10.0,
            probe_legacy: bool = True) -> TLSInfo:
    info = TLSInfo(host, port)
    ctx = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    if verify is False:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    der = b""
    try:
        tls, der = _connect(host, port, ctx, timeout)
        info.trusted = verify is not False
        info.protocol, info.cipher = tls.version() or "", (tls.cipher() or ("",))[0]
        tls.close()
    except ssl.SSLCertVerificationError as e:
        info.error = e.verify_message if hasattr(e, "verify_message") else str(e)
    except (ssl.SSLError, OSError) as e:
        info.error = str(e)
        return info
    if not info.trusted:
        # Fetch the certificate anyway so expiry and subject can still be reported.
        loose = ssl.create_default_context()
        loose.check_hostname = False
        loose.verify_mode = ssl.CERT_NONE
        try:
            tls, der = _connect(host, port, loose, timeout)
            info.protocol, info.cipher = tls.version() or "", (tls.cipher() or ("",))[0]
            tls.close()
        except (ssl.SSLError, OSError) as e:
            info.error = info.error or str(e)
            return info
    if der:
        cert = x509.load_der_x509_certificate(der)
        info.subject = cert.subject.rfc4514_string()
        info.issuer = cert.issuer.rfc4514_string()
        info.not_before, info.not_after = cert.not_valid_before_utc, cert.not_valid_after_utc
        try:
            info.sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.DNSName)
        except x509.ExtensionNotFound:
            info.sans = []
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            info.key_type, info.key_bits = "RSA", key.key_size
        elif isinstance(key, ec.EllipticCurvePublicKey):
            info.key_type, info.key_bits = "EC", key.curve.key_size
        else:
            info.key_type = type(key).__name__.replace("PublicKey", "")
        info.signature_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
    if probe_legacy:
        for name, version in (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            legacy.check_hostname = False
            legacy.verify_mode = ssl.CERT_NONE
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)  # probing old versions is the point
                    legacy.minimum_version = legacy.maximum_version = version
                legacy.set_ciphers("DEFAULT:@SECLEVEL=0")
                tls, _ = _connect(host, port, legacy, timeout)
                tls.close()
                info.legacy_accepted.append(name)
                info.legacy_probed = True
            except ssl.SSLError as e:
                text = str(e).lower()
                if "no protocols available" in text or "unsupported protocol" in text or "unsupported" in text:
                    continue  # the local OpenSSL build refuses this version; nothing learned about the server
                info.legacy_probed = True  # the server refused: good
            except (OSError, ValueError):
                continue
    return info


def check_tls(info: TLSInfo, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(UTC)
    out: list[Finding] = []
    if info.error and not info.protocol:
        return [Finding("tls.unreachable", "info", "TLS handshake failed",
                        "The scanner could not complete a TLS connection, so certificate checks were skipped.",
                        evidence=info.error[:300])]
    if not info.trusted:
        out.append(Finding("tls.untrusted", "high", "Certificate is not trusted",
                           "Browsers will show a security warning. The certificate is self-signed, issued by an "
                           "unknown authority, incomplete (missing intermediate) or for a different host name.",
                           evidence=f"{info.error[:200]}; subject {info.subject}; SANs {', '.join(info.sans[:5])}",
                           remediation="Install a certificate from a trusted authority that covers this host name, "
                                       "with the full chain.", references=[TLS_REF]))
    if info.not_after:
        days = (info.not_after - now).days
        if days < 0:
            out.append(Finding("tls.expired", "critical", "Certificate has expired",
                               "Every browser blocks the site with a full-page warning.",
                               evidence=f"notAfter {info.not_after:%Y-%m-%d}", remediation="Renew the certificate "
                               "now and automate renewal.", references=[TLS_REF]))
        elif days <= 14:
            out.append(Finding("tls.expiring", "high", f"Certificate expires in {days} days",
                               "Once it expires the site is blocked by browsers.",
                               evidence=f"notAfter {info.not_after:%Y-%m-%d}",
                               remediation="Renew now and automate renewal (certbot or the provider's tooling).",
                               references=[TLS_REF]))
        elif days <= 30:
            out.append(Finding("tls.expiring", "medium", f"Certificate expires in {days} days",
                               "Renewal should already be scheduled.", evidence=f"notAfter {info.not_after:%Y-%m-%d}",
                               remediation="Renew and automate renewal.", references=[TLS_REF]))
    if info.not_before and info.not_before > now:
        out.append(Finding("tls.notyet", "critical", "Certificate is not yet valid",
                           "The validity period starts in the future; browsers reject it.",
                           evidence=f"notBefore {info.not_before:%Y-%m-%d}", remediation="Check the server clock "
                           "and the certificate's dates.", references=[TLS_REF]))
    if info.protocol and info.protocol not in ("TLSv1.2", "TLSv1.3"):
        out.append(Finding("tls.protocol", "high", f"Negotiated {info.protocol}",
                           "Versions below TLS 1.2 have known weaknesses and are rejected by modern clients.",
                           evidence=f"{info.protocol} {info.cipher}", remediation="Enable TLS 1.2 and 1.3 only.",
                           references=[TLS_REF]))
    if info.legacy_accepted:
        out.append(Finding("tls.legacy", "medium", f"Server still accepts {', '.join(info.legacy_accepted)}",
                           "Old protocol versions let a network attacker downgrade a connection to a weaker "
                           "cipher suite.", evidence=f"accepted: {', '.join(info.legacy_accepted)}",
                           remediation="Set the minimum protocol to TLS 1.2 (`ssl_protocols TLSv1.2 TLSv1.3;` in "
                                       "nginx, `SSLProtocol -all +TLSv1.2 +TLSv1.3` in Apache).",
                           references=[TLS_REF]))
    if info.key_type == "RSA" and info.key_bits and info.key_bits < 2048:
        out.append(Finding("tls.key", "medium", f"RSA key is only {info.key_bits} bits",
                           "Keys below 2048 bits are considered breakable.", evidence=f"RSA {info.key_bits}",
                           remediation="Reissue with RSA 2048 or more, or an EC P-256 key.", references=[TLS_REF]))
    if info.signature_hash and info.signature_hash.lower() in ("sha1", "md5"):
        out.append(Finding("tls.signature", "medium", f"Certificate signed with {info.signature_hash.upper()}",
                           "Weak signature algorithms allow forged certificates.", evidence=info.signature_hash,
                           remediation="Reissue the certificate with SHA-256.", references=[TLS_REF]))
    if info.protocol == "TLSv1.2":
        out.append(Finding("tls.no13", "info", "TLS 1.3 not negotiated",
                           "TLS 1.3 is faster and removes legacy options; TLS 1.2 is still acceptable.",
                           evidence=f"{info.protocol} {info.cipher}", remediation="Enable TLS 1.3 on the server.",
                           references=[TLS_REF]))
    return out
