"""Run the passive checks against one URL with a small, polite request budget."""

from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from . import USER_AGENT
from .checks import (
    LISTING_PATHS,
    SENSITIVE_FILES,
    SEVERITIES,
    Finding,
    check_cookies,
    check_cors,
    check_file,
    check_headers,
    check_listing,
    check_methods,
    check_transport,
    grade,
    score,
)
from .tls import TLSInfo, check_tls, inspect

PROBE_ORIGIN = "https://vulnscope-probe.invalid"
MAX_HOPS = 5
MAX_BODY = 64 * 1024  # bytes kept from each response; the checks look at the first 50,000 characters at most
SCAN_DEADLINE = 120.0  # seconds for a whole scan: a server that drips bytes never trips the per-read timeout
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


class ScanError(Exception):
    """The target could not be scanned at all (bad URL, unreachable)."""


@dataclass
class ScanResult:
    url: str
    started_at: datetime
    final_url: str = ""
    finished_at: datetime | None = None
    http_status: int | None = None
    title: str = ""
    server: str = ""
    requests: int = 0
    findings: list[Finding] = field(default_factory=list)
    tls: dict | None = None

    @property
    def score(self) -> int:
        return score(self.findings)

    @property
    def grade(self) -> str:
        return grade(self.score)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "final_url": self.final_url,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "finished_at": self.finished_at.isoformat(timespec="seconds") if self.finished_at else None,
            "http_status": self.http_status, "title": self.title, "server": self.server,
            "requests": self.requests, "score": self.score, "grade": self.grade, "tls": self.tls,
            "counts": {s: sum(f.severity == s for f in self.findings) for s in SEVERITIES},
            "findings": [{**asdict(f), "status": "open", "note": ""} for f in self.findings],
        }


def normalise(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ScanError("the target must be an http:// or https:// URL with a host name")
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


def same_site(a: str, b: str) -> bool:
    """True when host b is a or its www. twin. Redirects anywhere else, subdomains and parents included, are not
    followed: on shared hosting a parent domain or another subdomain belongs to someone else."""
    return a.lower().removeprefix("www.") == b.lower().removeprefix("www.")


def _tls_dict(info: TLSInfo) -> dict:
    d = asdict(info)
    for k in ("not_before", "not_after"):
        d[k] = d[k].isoformat(timespec="seconds") if d[k] else None
    return d


class Scanner:
    def __init__(self, *, verify: bool | str = True, timeout: float = 10.0, max_requests: int = 40,
                 concurrency: int = 4, probe_legacy: bool = True):
        self.verify, self.timeout, self.max_requests = verify, timeout, max_requests
        self.concurrency, self.probe_legacy = concurrency, probe_legacy

    def _client(self, verify: bool | str) -> httpx.AsyncClient:
        if isinstance(verify, str):
            verify = ssl.create_default_context(cafile=verify)
        return httpx.AsyncClient(verify=verify, timeout=self.timeout, follow_redirects=False,
                                 headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
                                 limits=httpx.Limits(max_connections=self.concurrency))

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, result: ScanResult,
                       **kw) -> httpx.Response | None:
        if result.requests >= self.max_requests:
            return None
        result.requests += 1
        try:
            return await self._send(client, method, url, **kw)
        except httpx.HTTPError:
            return None

    @staticmethod
    async def _send(client: httpx.AsyncClient, method: str, url: str, **kw) -> httpx.Response:
        """Send one request and keep at most MAX_BODY bytes of the body, so a huge response cannot fill memory."""
        async with client.stream(method, url, **kw) as r:
            body = b""
            async for chunk in r.aiter_bytes():
                body += chunk
                if len(body) >= MAX_BODY:
                    break
        r.headers.pop("content-encoding", None)  # the body below is already decoded
        return httpx.Response(r.status_code, headers=r.headers, content=body[:MAX_BODY], request=r.request)

    async def _follow(self, client: httpx.AsyncClient, url: str, result: ScanResult):
        """GET with manual redirects that stay on the named host. Returns (response, set-cookies, url)."""
        cookies: list[str] = []
        start = urlsplit(url).hostname or ""
        for hop in range(MAX_HOPS + 1):
            result.requests += 1
            r = await self._send(client, "GET", url)
            cookies += r.headers.get_list("set-cookie")
            location = r.headers.get("location")
            if r.is_redirect and location and hop < MAX_HOPS:
                nxt = urljoin(url, location)
                # Compared with the host the user named, not the previous hop, so a chain cannot drift away.
                if urlsplit(nxt).scheme in ("http", "https") and same_site(start, urlsplit(nxt).hostname or ""):
                    url = nxt
                    continue
            return r, cookies, url
        return r, cookies, url

    async def scan(self, url: str) -> ScanResult:
        try:
            async with asyncio.timeout(SCAN_DEADLINE):
                return await self._scan(url)
        except TimeoutError as e:
            raise ScanError(f"the scan did not finish within {SCAN_DEADLINE:g} seconds") from e

    async def _scan(self, url: str) -> ScanResult:
        url = normalise(url)
        result = ScanResult(url=url, started_at=datetime.now(UTC))
        client = self._client(self.verify)
        try:
            try:
                final, cookies, final_url = await self._follow(client, url, result)
            except httpx.ConnectError as e:
                if "certificate" not in str(e).lower():
                    raise ScanError(f"could not connect to {url}: {e}") from e
                # Untrusted certificate: the TLS check will report it; continue unverified for the other checks.
                await client.aclose()
                client = self._client(False)
                final, cookies, final_url = await self._follow(client, url, result)
            except httpx.HTTPError as e:
                raise ScanError(f"request to {url} failed: {e}") from e

            p = urlsplit(final_url)
            scheme, host = p.scheme, p.hostname or ""
            port = p.port or (443 if scheme == "https" else 80)
            base = f"{scheme}://{p.netloc}"
            result.final_url, result.http_status = final_url, final.status_code
            result.server = final.headers.get("server", "")
            m = _TITLE.search(final.text[:50000])
            result.title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""

            findings: list[Finding] = []
            http_probe = None
            if scheme == "https" and port == 443:
                plain = f"http://[{host}]/" if ":" in host else f"http://{host}/"  # IPv6 needs brackets
                r = await self._request(client, "GET", plain, result)
                if r is not None:
                    http_probe = (r.status_code, r.headers.get("location"))
            findings += check_transport(scheme, host, http_probe)
            findings += check_headers(final.headers, scheme)
            findings += check_cookies(cookies, scheme)

            listing = check_listing("/", final.status_code, final.text)
            if listing:
                findings.append(listing)
            sem = asyncio.Semaphore(self.concurrency)

            async def fetch(path: str):
                async with sem:
                    return path, await self._request(client, "GET", base + path, result)

            paths = [x for x in LISTING_PATHS if x != "/"] + list(SENSITIVE_FILES)
            for path, r in await asyncio.gather(*(fetch(x) for x in paths)):
                if r is None:
                    continue
                f = (check_listing if path in LISTING_PATHS else check_file)(path, r.status_code, r.text)
                if f:
                    findings.append(f)

            r = await self._request(client, "GET", final_url, result, headers={"Origin": PROBE_ORIGIN})
            if r is not None:
                findings += check_cors(PROBE_ORIGIN, r.headers)
            allow, trace_status, trace_body = None, None, ""
            r = await self._request(client, "OPTIONS", final_url, result)
            if r is not None:
                allow = r.headers.get("allow")
            r = await self._request(client, "TRACE", final_url, result)
            if r is not None:
                trace_status, trace_body = r.status_code, r.text[:2000]
            findings += check_methods(allow, trace_status, trace_body)

            if scheme == "https":
                # --insecure only lets the HTTP checks go on; trust is still judged against the system store.
                verify = True if self.verify is False else self.verify
                info = await asyncio.to_thread(inspect, host, port, verify, self.timeout, self.probe_legacy)
                result.tls = _tls_dict(info)
                findings += check_tls(info)

            # One finding per key: a cookie set on two redirect hops is one problem, not two deductions.
            unique = {f.key: f for f in findings}.values()
            result.findings = sorted(unique, key=lambda f: (SEVERITIES.index(f.severity), f.check))
            result.finished_at = datetime.now(UTC)
            return result
        finally:
            await client.aclose()
