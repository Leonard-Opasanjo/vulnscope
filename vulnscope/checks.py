"""Passive checks: observed responses in, findings out. Plus the scoring model."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
DEDUCTIONS = {"critical": 40, "high": 20, "medium": 10, "low": 4, "info": 0}
OWASP_HEADERS = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
SIX_MONTHS = 15552000


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    key: str = ""  # stable identity of this finding on a target, for carrying remediation status across scans

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        self.key = self.key or self.check


def score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(DEDUCTIONS[f.severity] for f in findings))


def grade(points: int) -> str:
    return "A" if points >= 90 else "B" if points >= 75 else "C" if points >= 60 else "D" if points >= 40 else "F"


def _lower(headers) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def parse_csp(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for directive in value.split(";"):
        parts = directive.split()
        if parts:
            out[parts[0].lower()] = parts[1:]
    return out


def check_headers(headers, scheme: str) -> list[Finding]:
    h = _lower(headers)
    out: list[Finding] = []
    if scheme == "https":
        hsts = h.get("strict-transport-security")
        if hsts is None:
            out.append(Finding("headers.hsts", "medium", "Strict-Transport-Security header missing",
                               "Browsers will still try plain HTTP first on later visits, which lets an attacker on "
                               "the network downgrade or intercept the first request.",
                               remediation="Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
                                           "once every subdomain is served over HTTPS.",
                               references=[MDN + "Strict-Transport-Security", OWASP_HEADERS]))
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < SIX_MONTHS:
                out.append(Finding("headers.hsts.max-age", "low", "HSTS max-age shorter than six months",
                                   "A short max-age limits the protection to recent visitors.", evidence=hsts,
                                   remediation="Raise max-age to at least 15552000 (180 days); 31536000 is common.",
                                   references=[MDN + "Strict-Transport-Security"]))
            elif "includesubdomains" not in hsts.lower():
                out.append(Finding("headers.hsts.subdomains", "info", "HSTS does not cover subdomains",
                                   "Subdomains can still be reached over plain HTTP.", evidence=hsts,
                                   remediation="Add `includeSubDomains` once all subdomains support HTTPS.",
                                   references=[MDN + "Strict-Transport-Security"]))
    csp = h.get("content-security-policy")
    if csp is None:
        out.append(Finding("headers.csp", "medium", "Content-Security-Policy header missing",
                           "Without a CSP, any injected script runs with the page's full privileges. A policy is "
                           "the main browser-side defence against cross-site scripting.",
                           remediation="Start with a report-only policy, then enforce one with `default-src 'self'` "
                                       "and nonces or hashes for inline scripts.",
                           references=[MDN + "Content-Security-Policy", OWASP_HEADERS]))
    else:
        d = parse_csp(csp)
        src = d.get("script-src", d.get("default-src"))
        if src is None:
            out.append(Finding("headers.csp.weak", "low", "CSP has neither default-src nor script-src",
                               "The policy does not restrict where scripts load from.", evidence=csp[:300],
                               remediation="Add a `default-src` or `script-src` directive.",
                               references=[MDN + "Content-Security-Policy"]))
        elif "'unsafe-inline'" in src and not any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                                                 for s in src):
            out.append(Finding("headers.csp.weak", "low", "CSP allows inline scripts",
                               "`'unsafe-inline'` in the script policy means injected inline script still runs.",
                               evidence=csp[:300],
                               remediation="Move inline scripts to files or allow them with nonces or hashes.",
                               references=[MDN + "Content-Security-Policy"]))
        elif "*" in src:
            out.append(Finding("headers.csp.weak", "low", "CSP allows scripts from any origin",
                               "A wildcard script source gives almost no protection.", evidence=csp[:300],
                               remediation="List the origins scripts actually come from.",
                               references=[MDN + "Content-Security-Policy"]))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(Finding("headers.nosniff", "low", "X-Content-Type-Options header missing",
                           "Browsers may guess content types, which turns some uploads into executable script.",
                           remediation="Send `X-Content-Type-Options: nosniff`.",
                           references=[MDN + "X-Content-Type-Options"]))
    if "x-frame-options" not in h and "frame-ancestors" not in (csp or "").lower():
        out.append(Finding("headers.framing", "medium", "No protection against clickjacking",
                           "The page can be framed by any site, so clicks can be hijacked through an invisible "
                           "overlay.",
                           remediation="Send `X-Frame-Options: DENY` or a CSP with `frame-ancestors 'none'`.",
                           references=[MDN + "X-Frame-Options", OWASP_HEADERS]))
    if "referrer-policy" not in h:
        out.append(Finding("headers.referrer", "low", "Referrer-Policy header missing",
                           "Full URLs, which may contain tokens or identifiers, leak to third parties in the "
                           "Referer header.",
                           remediation="Send `Referrer-Policy: strict-origin-when-cross-origin`.",
                           references=[MDN + "Referrer-Policy"]))
    if "permissions-policy" not in h:
        out.append(Finding("headers.permissions", "info", "Permissions-Policy header missing",
                           "Browser features such as camera, microphone and geolocation are not restricted.",
                           remediation="Send `Permissions-Policy: camera=(), microphone=(), geolocation=()` and "
                                       "extend as needed.",
                           references=[MDN + "Permissions-Policy"]))
    server = h.get("server", "")
    if re.search(r"\d+\.\d+", server):
        out.append(Finding("headers.server", "low", "Server header reveals the software version",
                           "Version numbers let an attacker look up known vulnerabilities for exactly that build.",
                           evidence=f"Server: {server}",
                           remediation="Set `ServerTokens Prod` (Apache), `server_tokens off` (nginx) or the "
                                       "equivalent so the header carries no version.",
                           references=[OWASP_HEADERS]))
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if name in h:
            out.append(Finding(f"headers.{name}", "low", f"{name} header reveals the technology stack",
                               "Advertising the framework and version helps an attacker pick an exploit.",
                               evidence=f"{name}: {h[name]}",
                               remediation=f"Remove the {name} header in the application or the reverse proxy.",
                               references=[OWASP_HEADERS]))
    return out


def _cookie_attrs(raw: str) -> tuple[str, dict[str, str | bool]]:
    first, *rest = raw.split(";")
    name = first.split("=", 1)[0].strip()
    attrs: dict[str, str | bool] = {}
    for part in rest:
        k, _, v = part.strip().partition("=")
        attrs[k.lower()] = v.strip() if v else True
    return name, attrs


def check_cookies(set_cookies: list[str], scheme: str) -> list[Finding]:
    out: list[Finding] = []
    ref = [MDN + "Set-Cookie", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"]
    for raw in set_cookies:
        name, attrs = _cookie_attrs(raw)
        if not name:
            continue
        if scheme == "https" and "secure" not in attrs:
            out.append(Finding("cookies.secure", "medium", f"Cookie {name} is sent without the Secure flag",
                               "The browser will also send this cookie over plain HTTP, where it can be read on "
                               "the network.", evidence=raw[:200], key=f"cookies.secure:{name}",
                               remediation="Add the `Secure` attribute.", references=ref))
        if "httponly" not in attrs:
            out.append(Finding("cookies.httponly", "medium", f"Cookie {name} is readable by JavaScript",
                               "Without HttpOnly, any cross-site scripting flaw can steal the cookie.",
                               evidence=raw[:200], key=f"cookies.httponly:{name}",
                               remediation="Add the `HttpOnly` attribute to cookies that scripts do not need.",
                               references=ref))
        samesite = attrs.get("samesite")
        if not samesite:
            out.append(Finding("cookies.samesite", "low", f"Cookie {name} has no SameSite attribute",
                               "Browsers apply a default, but an explicit value is the only reliable protection "
                               "against cross-site request forgery.", evidence=raw[:200],
                               key=f"cookies.samesite:{name}",
                               remediation="Add `SameSite=Lax` (or `Strict` for sensitive sessions).",
                               references=ref))
        elif str(samesite).lower() == "none" and "secure" not in attrs:
            out.append(Finding("cookies.samesite", "medium", f"Cookie {name} uses SameSite=None without Secure",
                               "Browsers reject this combination or treat the cookie as insecure.",
                               evidence=raw[:200], key=f"cookies.samesite:{name}",
                               remediation="Add `Secure` whenever `SameSite=None` is used.", references=ref))
    return out


LISTING_PATHS = ("/", "/static/", "/assets/", "/images/", "/img/", "/uploads/", "/files/", "/backup/",
                 "/js/", "/css/")
_LISTING = re.compile(r"<title>\s*(?:Index of|Directory listing for)|>\s*Parent Directory\s*<", re.I)


def check_listing(path: str, status: int, body: str) -> Finding | None:
    if status == 200 and _LISTING.search(body[:50000]):
        return Finding("exposure.listing", "high", f"Directory listing enabled at {path}",
                       "The web server shows the contents of the directory, which reveals file names, backups "
                       "and anything uploaded by mistake.", evidence=f"GET {path} -> 200 with an index page",
                       key=f"exposure.listing:{path}",
                       remediation="Disable automatic indexes (`Options -Indexes` in Apache, `autoindex off` "
                                   "in nginx) and add an index file where a directory must be browsable.",
                       references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_"
                                   "Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
                                   "04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"])
    return None


SENSITIVE_FILES: dict[str, tuple[str, str, str]] = {
    # path: (severity, title, regex that the body must match; a 200 alone is not enough)
    "/.git/HEAD": ("critical", "Git repository exposed", r"^(ref: refs/|[0-9a-f]{40})"),
    "/.env": ("critical", "Environment file exposed", r"(?m)^[A-Za-z_][A-Za-z0-9_]*=\S"),
    "/phpinfo.php": ("high", "phpinfo() page exposed", r"phpinfo\(\)|PHP Version"),
    "/server-status": ("medium", "Apache server-status page exposed", r"Apache Server Status"),
    "/.DS_Store": ("low", "macOS .DS_Store file exposed", r"^\x00\x00\x00\x01Bud1"),
}


def check_file(path: str, status: int, body: str) -> Finding | None:
    severity, title, pattern = SENSITIVE_FILES[path]
    if status == 200 and re.search(pattern, body[:20000]):
        return Finding("exposure.file", severity, f"{title} at {path}",
                       {"critical": "The file gives away source code, credentials or configuration.",
                        "high": "The page lists configuration, paths, modules and environment of the server.",
                        "medium": "The page reveals internal request details and client addresses.",
                        "low": "The file reveals directory contents and file names."}[severity],
                       evidence=f"GET {path} -> 200, content matches {title.lower()}", key=f"exposure.file:{path}",
                       remediation="Remove the file from the web root and block access to dotfiles and tooling "
                                   "paths in the server configuration. Rotate anything the file contained.",
                       references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"])
    return None


def check_cors(origin: str, headers) -> list[Finding]:
    h = _lower(headers)
    acao = h.get("access-control-allow-origin")
    creds = h.get("access-control-allow-credentials", "").lower() == "true"
    ref = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
           "https://portswigger.net/web-security/cors"]
    if acao is None:
        return []
    if acao == origin:
        if creds:
            return [Finding("cors.reflect", "high", "CORS reflects any origin with credentials",
                            "Any website can make authenticated requests to this site from a visitor's browser "
                            "and read the responses.", evidence=f"Origin: {origin} -> "
                            f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: true",
                            remediation="Allow only a fixed list of trusted origins; never reflect the request "
                                        "origin together with credentials.", references=ref)]
        return [Finding("cors.reflect", "medium", "CORS reflects any origin",
                        "Any website can read responses from this site, though without the visitor's cookies.",
                        evidence=f"Origin: {origin} -> Access-Control-Allow-Origin: {acao}",
                        remediation="Allow only the origins that need access.", references=ref)]
    if acao == "*":
        if creds:
            return [Finding("cors.wildcard", "high", "CORS wildcard with credentials",
                            "The combination is invalid in browsers but signals a misconfigured policy.",
                            evidence="Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                            remediation="Use an explicit origin list.", references=ref)]
        return [Finding("cors.wildcard", "info", "CORS allows any origin without credentials",
                        "Fine for public, unauthenticated APIs; a problem if responses are user-specific.",
                        evidence="Access-Control-Allow-Origin: *",
                        remediation="Restrict the origins if the resource is not public.", references=ref)]
    if acao == "null":
        return [Finding("cors.null", "medium", "CORS allows the null origin",
                        "Sandboxed iframes and local files send `Origin: null`, which attackers can produce.",
                        evidence="Access-Control-Allow-Origin: null",
                        remediation="Never allow the null origin.", references=ref)]
    return []


def check_methods(allow: str | None, trace_status: int | None, trace_body: str) -> list[Finding]:
    out: list[Finding] = []
    ref = ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
           "02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"]
    if trace_status == 200 and "TRACE /" in trace_body:
        out.append(Finding("methods.trace", "medium", "HTTP TRACE is enabled",
                           "TRACE echoes the request, including cookies and authorisation headers, which can be "
                           "abused through cross-site tracing.", evidence="TRACE / -> 200 with the request echoed",
                           remediation="Disable TRACE (`TraceEnable off` in Apache; most other servers reject it "
                                       "by default).", references=ref))
    elif allow and "TRACE" in allow.upper():
        out.append(Finding("methods.trace", "low", "HTTP TRACE is advertised",
                           "The Allow header lists TRACE.", evidence=f"Allow: {allow}",
                           remediation="Disable TRACE.", references=ref))
    return out


def check_transport(scheme: str, host: str, http_probe: tuple[int, str | None] | None) -> list[Finding]:
    loopback = host in ("localhost", "127.0.0.1", "::1") or host.startswith("127.")
    if scheme == "http":
        if loopback:
            return [Finding("transport.plain", "info", "Target served over plain HTTP (local address)",
                            "Fine for a local test target; a public site must use HTTPS.",
                            remediation="Serve production over HTTPS only.")]
        return [Finding("transport.plain", "high", "Site served over plain HTTP",
                        "Everything, including logins and cookies, crosses the network unencrypted and can be "
                        "read or altered by anyone on the path.",
                        remediation="Obtain a certificate (Let's Encrypt is free), serve HTTPS, redirect HTTP to "
                                    "it and add HSTS.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/"
                                    "Transport_Layer_Security_Cheat_Sheet.html"])]
    if http_probe is not None:
        status, location = http_probe
        if not (status in (301, 302, 307, 308) and (location or "").lower().startswith("https://")):
            return [Finding("transport.redirect", "medium", "HTTP does not redirect to HTTPS",
                            "Visitors who type the address without https:// stay on the insecure version.",
                            evidence=f"GET http://{host}/ -> {status}" + (f" Location: {location}" if location
                                                                        else ""),
                            remediation="Redirect every HTTP request to the HTTPS URL with a 301.",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/"
                                        "Transport_Layer_Security_Cheat_Sheet.html"])]
    return []
