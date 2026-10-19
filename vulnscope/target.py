"""A deliberately misconfigured HTTP test target, and its hardened twin, for safe practice.

`vulnscope target` serves it on localhost. Nothing here is a real secret.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, Response
from starlette.routing import Route

INDEX = """<!doctype html><html><head><meta charset="utf-8"><title>Acme Intranet</title></head>
<body><h1>Acme Intranet</h1><p>A deliberately misconfigured test target for VulnScope.</p>
<p><a href="/files/">Files</a></p></body></html>"""
LISTING = """<!doctype html><html><head><title>Index of /files/</title></head><body><h1>Index of /files/</h1>
<table><tr><td><a href="../">Parent Directory</a></td></tr>
<tr><td><a href="backup-2026.zip">backup-2026.zip</a></td></tr>
<tr><td><a href="staff.csv">staff.csv</a></td></tr></table></body></html>"""
SECURE_HEADERS = {
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "server": "Acme",
}


class _Headers(BaseHTTPMiddleware):
    def __init__(self, app, secure: bool):
        super().__init__(app)
        self.secure = secure

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if self.secure:
            for k, v in SECURE_HEADERS.items():
                response.headers[k] = v
        else:
            response.headers["server"] = "Apache/2.4.29 (Ubuntu)"
            response.headers["x-powered-by"] = "PHP/7.2.24"
            origin = request.headers.get("origin")
            if origin:  # reflects any origin, with credentials
                response.headers["access-control-allow-origin"] = origin
                response.headers["access-control-allow-credentials"] = "true"
        return response


def make_app(secure: bool = False) -> Starlette:
    async def index(request: Request) -> Response:
        if request.method == "OPTIONS":
            return Response(status_code=204, headers={"allow": "GET, HEAD, OPTIONS" + ("" if secure else ", TRACE")})
        if request.method == "TRACE":
            if secure:
                return Response(status_code=405)
            echo = "TRACE / HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in request.headers.items())
            return Response(echo, media_type="message/http")
        response = HTMLResponse(INDEX)
        if secure:
            response.set_cookie("session", "not-a-real-session", httponly=True, secure=True, samesite="strict")
        else:
            response.headers.append("set-cookie", "session=not-a-real-session; Path=/")
            response.headers.append("set-cookie", "prefs=dark; Path=/")
        return response

    def exposed(body: str, media_type: str = "text/plain"):
        async def endpoint(request: Request) -> Response:
            if secure:
                return PlainTextResponse("Not Found", status_code=404)
            return Response(body, media_type=media_type)
        return endpoint

    routes = [
        Route("/", index, methods=["GET", "HEAD", "OPTIONS", "TRACE"]),
        Route("/files/", exposed(LISTING, "text/html")),
        Route("/.env", exposed("APP_SECRET=not-a-real-secret\nDB_PASSWORD=example-only\n")),
        Route("/.git/HEAD", exposed("ref: refs/heads/main\n")),
        Route("/phpinfo.php", exposed("<html><head><title>phpinfo()</title></head><body><h1>PHP Version 7.2.24"
                                      "</h1></body></html>", "text/html")),
    ]
    app = Starlette(routes=routes)
    app.add_middleware(_Headers, secure=secure)
    return app


def serve(host: str = "127.0.0.1", port: int = 8099, secure: bool = False) -> None:
    import uvicorn

    uvicorn.run(make_app(secure), host=host, port=port, log_level="warning", server_header=False)
