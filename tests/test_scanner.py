import asyncio

import httpx
import pytest

from vulnscope.scanner import ScanError, Scanner, normalise, same_site
from vulnscope.tls import TLSInfo


def run(coro):
    return asyncio.run(coro)


def mocked(handler, **kw) -> Scanner:
    """A scanner whose HTTP requests go to `handler` instead of the network."""
    s = Scanner(probe_legacy=False, **kw)
    s._client = lambda verify: httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return s


def test_normalise_and_same_site():
    assert normalise("example.com") == "https://example.com/"
    assert normalise(" http://a.b/x?y=1#frag ") == "http://a.b/x?y=1"
    with pytest.raises(ScanError):
        normalise("ftp://x")
    with pytest.raises(ScanError):
        normalise("https://")
    assert same_site("example.com", "www.example.com") and same_site("www.example.com", "example.com")
    assert not same_site("example.com", "evil.com") and not same_site("example.com", "notexample.com")
    assert not same_site("shop.co.uk", "co.uk") and not same_site("a.example.com", "b.example.com")


def test_redirects_stay_on_the_named_host():
    hosts = []

    def handler(req):
        hosts.append(req.url.host)
        hop = {"shop.example.test": "http://example.test/",        # parent domain: not followed
               "example.test": "http://www.example.test/",         # www twin: followed
               "www.example.test": "http://evil.test/"}            # another site: not followed
        if req.method == "GET" and req.url.path == "/" and req.url.host in hop:
            return httpx.Response(302, headers={"location": hop[req.url.host]})
        return httpx.Response(404)

    r = run(mocked(handler).scan("http://shop.example.test/"))
    assert r.final_url == "http://shop.example.test/" and set(hosts) == {"shop.example.test"}
    hosts.clear()
    r = run(mocked(handler).scan("http://example.test/"))
    assert r.final_url == "http://www.example.test/" and set(hosts) == {"example.test", "www.example.test"}

    def chain(req):  # / -> /1 -> /2 -> ... forever
        p = req.url.path.strip("/")
        if req.method == "GET" and (p == "" or p.isdigit()):
            return httpx.Response(302, headers={"location": f"/{int(p or 0) + 1}"})
        return httpx.Response(404)

    r = run(mocked(chain).scan("http://chain.test/"))
    assert r.final_url == "http://chain.test/5" and r.http_status == 302  # five hops, and the URL matches the response


def test_cookie_set_on_two_hops_is_one_finding():
    def handler(req):
        if req.url.path == "/":
            return httpx.Response(302, headers=[("location", "/en/"), ("set-cookie", "lang=en; Path=/")])
        if req.url.path == "/en/":
            return httpx.Response(200, headers=[("set-cookie", "lang=en; Path=/")], text="<title>x</title>")
        return httpx.Response(404)

    keys = [f.key for f in run(mocked(handler).scan("http://site.test/")).findings]
    assert "cookies.httponly:lang" in keys and len(keys) == len(set(keys))


def test_large_responses_are_read_only_in_part():
    pulled = []

    async def body():
        yield b"<title>Big</title>"
        for _ in range(1000):  # 64 MB if read to the end
            pulled.append(1)
            yield b"x" * 65536

    r = run(mocked(lambda req: httpx.Response(200, content=body())).scan("http://big.test/"))
    assert r.title == "Big" and len(pulled) <= r.requests


def test_slow_target_hits_the_deadline(monkeypatch):
    async def drip():  # a byte at a time, never long enough apart to trip a read timeout
        while True:
            yield b"x"
            await asyncio.sleep(0.05)

    monkeypatch.setattr("vulnscope.scanner.SCAN_DEADLINE", 0.3)
    with pytest.raises(ScanError, match="did not finish"):
        run(mocked(lambda req: httpx.Response(200, content=drip())).scan("http://slow.test/"))


def test_ipv6_https_target(monkeypatch):
    urls = []

    def handler(req):
        urls.append(str(req.url))
        return httpx.Response(200, text="<title>v6</title>")

    monkeypatch.setattr("vulnscope.scanner.inspect", lambda host, port, *a: TLSInfo(host, port, error="not probed"))
    r = run(mocked(handler).scan("https://[2001:db8::1]/"))
    assert "http://[2001:db8::1]/" in urls and r.title == "v6"


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


def test_insecure_flag_does_not_invent_an_untrusted_certificate(tls_target, self_signed, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(self_signed[0]))  # the system store now trusts the test certificate
    result = run(Scanner(verify=False, probe_legacy=False).scan(tls_target.url))
    assert result.tls["trusted"] is True and "tls.untrusted" not in {f.key for f in result.findings}


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
