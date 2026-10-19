from datetime import UTC, datetime, timedelta

from vulnscope.tls import TLSInfo, check_tls, inspect

NOW = datetime(2026, 10, 19, tzinfo=UTC)


def info(**kw) -> TLSInfo:
    base = dict(host="h", port=443, protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", trusted=True,
                not_before=NOW - timedelta(days=10), not_after=NOW + timedelta(days=60), key_type="EC", key_bits=256,
                signature_hash="sha256")
    return TLSInfo(**(base | kw))


def checks(fs):
    return {f.check: f.severity for f in fs}


def test_healthy_certificate_is_quiet():
    assert check_tls(info(), NOW) == []
    assert checks(check_tls(info(protocol="TLSv1.2"), NOW)) == {"tls.no13": "info"}


def test_expiry_windows():
    assert checks(check_tls(info(not_after=NOW - timedelta(days=1)), NOW))["tls.expired"] == "critical"
    assert checks(check_tls(info(not_after=NOW + timedelta(days=10)), NOW))["tls.expiring"] == "high"
    assert checks(check_tls(info(not_after=NOW + timedelta(days=25)), NOW))["tls.expiring"] == "medium"
    assert checks(check_tls(info(not_before=NOW + timedelta(days=1)), NOW))["tls.notyet"] == "critical"


def test_trust_protocol_key_and_signature():
    assert checks(check_tls(info(trusted=False, error="self-signed certificate"), NOW))["tls.untrusted"] == "high"
    assert checks(check_tls(info(protocol="TLSv1.1"), NOW))["tls.protocol"] == "high"
    assert checks(check_tls(info(legacy_accepted=["TLSv1"]), NOW))["tls.legacy"] == "medium"
    assert checks(check_tls(info(key_type="RSA", key_bits=1024), NOW))["tls.key"] == "medium"
    assert checks(check_tls(info(signature_hash="sha1"), NOW))["tls.signature"] == "medium"
    assert checks(check_tls(TLSInfo("h", 443, error="connection refused"), NOW)) == {"tls.unreachable": "info"}


def test_inspect_real_self_signed_server(tls_target, self_signed):
    cert, _ = self_signed
    untrusted = inspect("localhost", tls_target.port, verify=True, probe_legacy=False)
    assert not untrusted.trusted and "self" in untrusted.error.lower() and untrusted.protocol.startswith("TLSv1.")
    assert untrusted.subject == "CN=localhost" and "localhost" in untrusted.sans and untrusted.key_bits == 2048
    assert untrusted.key_type == "RSA" and untrusted.not_after is not None
    trusted = inspect("localhost", tls_target.port, verify=str(cert), probe_legacy=True)
    assert trusted.trusted and trusted.error == "" and trusted.legacy_accepted == []
    assert checks(check_tls(trusted)).keys() <= {"tls.no13"}
