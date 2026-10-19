import pytest

from vulnscope.checks import (
    DEDUCTIONS,
    Finding,
    check_cookies,
    check_cors,
    check_file,
    check_headers,
    check_listing,
    check_methods,
    check_transport,
    grade,
    parse_csp,
    score,
)

GOOD = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()", "Server": "nginx",
}


def checks(findings):
    return {f.check for f in findings}


def test_finding_validation_and_key():
    assert Finding("x", "low", "t", "d").key == "x"
    assert Finding("x", "low", "t", "d", key="x:1").key == "x:1"
    with pytest.raises(ValueError):
        Finding("x", "severe", "t", "d")


def test_score_and_grade():
    assert score([]) == 100 and grade(100) == "A"
    fs = [Finding("a", "critical", "t", "d"), Finding("b", "high", "t", "d"), Finding("c", "info", "t", "d")]
    assert score(fs) == 100 - DEDUCTIONS["critical"] - DEDUCTIONS["high"]
    assert grade(89) == "B" and grade(75) == "B" and grade(60) == "C" and grade(40) == "D" and grade(39) == "F"
    assert score([Finding("a", "critical", "t", "d")] * 3) == 0


def test_good_headers_produce_nothing():
    assert check_headers(GOOD, "https") == []


def test_missing_headers():
    out = check_headers({"Server": "Apache/2.4.29 (Ubuntu)", "X-Powered-By": "PHP/7.2"}, "https")
    assert checks(out) >= {"headers.hsts", "headers.csp", "headers.nosniff", "headers.framing", "headers.referrer",
                           "headers.permissions", "headers.server", "headers.x-powered-by"}
    sev = {f.check: f.severity for f in out}
    assert sev["headers.csp"] == "medium" and sev["headers.framing"] == "medium" and sev["headers.server"] == "low"
    assert "headers.hsts" not in checks(check_headers({}, "http"))  # HSTS only matters over HTTPS


def test_hsts_values_and_csp_quality():
    h = dict(GOOD, **{"Strict-Transport-Security": "max-age=300"})
    assert {f.check for f in check_headers(h, "https")} == {"headers.hsts.max-age"}
    h = dict(GOOD, **{"Strict-Transport-Security": "max-age=31536000"})
    assert {f.check for f in check_headers(h, "https")} == {"headers.hsts.subdomains"}
    h = dict(GOOD, **{"Content-Security-Policy": "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'"})
    assert any(f.check == "headers.csp.weak" and "inline" in f.title for f in check_headers(h, "https"))
    h = dict(GOOD, **{"Content-Security-Policy": "script-src 'unsafe-inline' 'nonce-x'; frame-ancestors 'none'"})
    assert "headers.csp.weak" not in checks(check_headers(h, "https"))  # nonce makes unsafe-inline inert
    h = dict(GOOD, **{"Content-Security-Policy": "img-src 'self'"})
    out = check_headers(h, "https")
    assert "headers.csp.weak" in checks(out) and "headers.framing" in checks(out)
    assert parse_csp("default-src 'self'; script-src a b;") == {"default-src": ["'self'"], "script-src": ["a", "b"]}


def test_cookies():
    out = check_cookies(["session=abc; Path=/", "ok=1; Secure; HttpOnly; SameSite=Lax",
                         "cross=1; SameSite=None; HttpOnly"], "https")
    keyed = {f.key: f.severity for f in out}
    assert keyed == {"cookies.secure:session": "medium", "cookies.httponly:session": "medium",
                     "cookies.samesite:session": "low", "cookies.secure:cross": "medium",
                     "cookies.samesite:cross": "medium"}
    assert "cookies.secure:session" not in {f.key for f in check_cookies(["session=abc"], "http")}
    assert check_cookies(["=bad"], "https") == []


def test_listing_and_files():
    assert check_listing("/files/", 200, "<html><title>Index of /files/</title>").severity == "high"
    assert check_listing("/files/", 200, "<title>Directory listing for /files/</title>") is not None
    assert check_listing("/files/", 200, "<title>Files</title><p>Index of things</p>") is None
    assert check_listing("/files/", 403, "<title>Index of /files/</title>") is None
    assert check_file("/.git/HEAD", 200, "ref: refs/heads/main\n").severity == "critical"
    assert check_file("/.env", 200, "# config\nAPP_SECRET=x\n").severity == "critical"
    assert check_file("/.env", 200, "<html>Not found but 200</html>") is None  # soft 404 is not a finding
    assert check_file("/phpinfo.php", 200, "<title>phpinfo()</title>").severity == "high"
    assert check_file("/.DS_Store", 200, "\x00\x00\x00\x01Bud1").severity == "low"
    assert check_file("/.git/HEAD", 404, "ref: refs/heads/main") is None


def test_cors():
    o = "https://vulnscope-probe.invalid"
    assert check_cors(o, {}) == []
    (f,) = check_cors(o, {"Access-Control-Allow-Origin": o, "Access-Control-Allow-Credentials": "true"})
    assert f.severity == "high" and f.check == "cors.reflect"
    assert check_cors(o, {"Access-Control-Allow-Origin": o})[0].severity == "medium"
    assert check_cors(o, {"Access-Control-Allow-Origin": "*"})[0].severity == "info"
    assert check_cors(o, {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})[0].severity == "high"
    assert check_cors(o, {"Access-Control-Allow-Origin": "null"})[0].severity == "medium"
    assert check_cors(o, {"Access-Control-Allow-Origin": "https://app.example"}) == []


def test_methods_and_transport():
    assert check_methods(None, None, "") == []
    assert check_methods("GET, TRACE", None, "")[0].severity == "low"
    assert check_methods("GET, TRACE", 200, "TRACE / HTTP/1.1\r\nHost: x")[0].severity == "medium"
    assert check_methods("GET", 405, "")== []
    assert check_transport("http", "example.com", None)[0].severity == "high"
    assert check_transport("http", "127.0.0.1", None)[0].severity == "info"
    assert check_transport("https", "example.com", (301, "https://example.com/")) == []
    assert check_transport("https", "example.com", (200, None))[0].check == "transport.redirect"
    assert check_transport("https", "example.com", None) == []
