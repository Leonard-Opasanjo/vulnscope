"""The dashboard: start scans, read findings, track remediation, download reports."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from .db import STATUSES, Store
from .report import env, find_browser, render_report, to_json, to_pdf
from .scanner import ScanError, Scanner, normalise

app = FastAPI(title="VulnScope", docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
templates = Jinja2Templates(env=env)
SECURITY_HEADERS = {
    "content-security-policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                               "form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cache-control": "no-store",
}


def store() -> Store:
    if not hasattr(app.state, "store"):
        app.state.store = Store(os.environ.get("VULNSCOPE_DB", "vulnscope.db"))
    return app.state.store


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


async def run_scan(scan_id: int, url: str, verify: bool | str) -> None:
    db = store()
    db.start_scan(scan_id)
    try:
        db.finish_scan(scan_id, await Scanner(verify=verify).scan(url))
    except Exception as e:  # any failure is recorded on the scan, never raised into the server
        db.fail_scan(scan_id, f"{type(e).__name__}: {e}")


def _page(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return _page(request, "index.html", targets=store().list_targets())


@app.post("/scans")
def create_scan(request: Request, background: BackgroundTasks, url: str = Form(...),
                authorized: str | None = Form(None)):
    if authorized != "yes":
        return _page(request, "error.html", title="Authorisation required",
                     message="Confirm that you own the target or have written permission to test it.",
                     status_code=400)
    try:
        url = normalise(url)
    except ScanError as e:
        return _page(request, "error.html", title="Invalid target", message=str(e), status_code=400)
    db = store()
    active = db.active_scan(url)
    if active:
        return RedirectResponse(f"/scans/{active}", status_code=303)
    scan_id = db.create_scan(url)
    background.add_task(run_scan, scan_id, url, True)
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


def _scan_or_404(scan_id: int) -> dict:
    scan = store().get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    return scan


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_page(request: Request, scan_id: int):
    scan = _scan_or_404(scan_id)
    return _page(request, "scan.html", scan=scan, diff=store().diff(scan_id), statuses=STATUSES,
                 pdf_available=find_browser() is not None)


@app.post("/findings/{finding_id}/status")
def set_status(finding_id: int, status: str = Form(...), note: str = Form("")):
    if store().get_finding(finding_id) is None:
        raise HTTPException(404, "finding not found")
    try:
        scan_id = store().set_finding_status(finding_id, status, note)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return RedirectResponse(f"/scans/{scan_id}#finding-{finding_id}", status_code=303)


@app.get("/targets/{target_id}", response_class=HTMLResponse)
def target_page(request: Request, target_id: int):
    target = store().get_target(target_id)
    if target is None:
        raise HTTPException(404, "target not found")
    return _page(request, "target.html", target=target, scans=store().list_scans(target_id))


@app.get("/scans/{scan_id}/report.html", response_class=HTMLResponse)
def report_html(scan_id: int):
    return HTMLResponse(render_report(_scan_or_404(scan_id)))


@app.get("/scans/{scan_id}/report.json")
def report_json(scan_id: int):
    return Response(to_json(_scan_or_404(scan_id)), media_type="application/json")


@app.get("/scans/{scan_id}/report.pdf")
def report_pdf(scan_id: int, background: BackgroundTasks):
    scan = _scan_or_404(scan_id)
    if find_browser() is None:
        raise HTTPException(501, "PDF export needs Chromium or Chrome installed on the server")
    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    try:
        to_pdf(render_report(scan), path)
    except RuntimeError as e:
        os.unlink(path)
        raise HTTPException(500, str(e)) from e
    background.add_task(os.unlink, path)
    return FileResponse(path, media_type="application/pdf", filename=f"vulnscope-scan-{scan_id}.pdf")


@app.get("/api/targets")
def api_targets():
    return store().list_targets()


@app.get("/api/scans/{scan_id}")
def api_scan(scan_id: int):
    return JSONResponse(content=_scan_or_404(scan_id))


@app.get("/healthz")
def healthz():
    return {"ok": True}


def serve(host: str = "127.0.0.1", port: int = 8000, db: str | None = None) -> None:
    import uvicorn

    if db:
        os.environ["VULNSCOPE_DB"] = str(Path(db))
    uvicorn.run(app, host=host, port=port, log_level="info")
