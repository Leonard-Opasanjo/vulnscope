import asyncio

import pytest

from vulnscope.scanner import ScanError, Scanner, normalise, same_site


def run(coro):
    return asyncio.run(coro)


def test_normalise_and_same_site():
    assert normalise("example.com") == "https://example.com/"
    assert normalise(" http://a.b/x?y=1#frag ") == "http://a.b/x?y=1"
    with pytest.raises(ScanError):
        normalise("ftp://x")
    with pytest.raises(ScanError):
        normalise("https://")
    assert same_site("example.com", "www.example.com") and same_site("www.example.com", "example.com")
    assert not same_site("example.com", "evil.com") and not same_site("example.com", "notexample.com")


def test_insecure_target_scores_f(insecure_target):
    result = run(Scanner(probe_legacy=False).scan(insecure_target.url))
    keys = {f.key for f in result.findings}
    assert keys >= {"transport.plain", "headers.csp", "headers.framing", "headers.nosniff", "headers.referrer",
                    "headers.server", "headers.x-powered-by", "cookies.httponly:session", "cookies.samesite:prefs",
                    "exposure.listing:/files/", "exposure.file:/.git/HEAD", "exposure.file:/.env",
                    "exposure.file:/phpinfo.php", "cors.reflect", "methods.trace"}
    sev = {f.key: f.severity for f in result.findings}
    assert sev["transport.plain"] == "info"  # loopback
    assert sev["exposure.file:/.env"] == "critical" and sev["cors.reflect"] == "high" and sev["methods.trace"] == "medium"
    assert result.grade == "F" and result.score == 0
    assert result.http_status == 200 and result.title == "Acme Intranet" and result.server.startswith("Apache")
    assert 15 <= result.requests <= 40 and result.tls is None and result.finished_at is not None


def test_secure_target_scores_a(secure_target):
    result = run(Scanner(probe_legacy=False).scan(secure_target.url))
    assert {f.key for f in result.findings} == {"transport.plain"}  # only the "local plain HTTP" note
    assert result.grade == "A" and result.score == 100


def test_https_target_with_untrusted_then_trusted_cert(tls_target, self_signed):
    cert, _ = self_signed
    result = run(Scanner(probe_legacy=False).scan(tls_target.url))
    keys = {f.key: f.severity for f in result.findings}
    assert keys.get("tls.untrusted") == "high" and result.tls["trusted"] is False
    assert "headers.csp" not in keys  # the other checks still ran, unverified
    result = run(Scanner(verify=str(cert), probe_legacy=False).scan(tls_target.url))
    keys = {f.key: f.severity for f in result.findings}
    assert "tls.untrusted" not in keys and result.tls["trusted"] is True and result.tls["key_bits"] == 2048
    assert set(keys) <= {"tls.no13"} and result.grade == "A"


def test_unreachable_target():
    with pytest.raises(ScanError, match="could not connect"):
        run(Scanner().scan("http://127.0.0.1:9"))


def test_request_budget_is_respected(insecure_target):
    result = run(Scanner(max_requests=5, probe_legacy=False).scan(insecure_target.url))
    assert result.requests <= 5 and result.findings  # fewer checks, but a result


def test_to_dict(insecure_target):
    d = run(Scanner(probe_legacy=False).scan(insecure_target.url)).to_dict()
    assert d["grade"] == "F" and d["counts"]["critical"] == 2 and d["findings"][0]["status"] == "open"
    assert d["started_at"] <= d["finished_at"]
