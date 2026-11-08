import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime

import pytest

from vulnscope import report, web
from vulnscope.checks import Finding
from vulnscope.cli import main
from vulnscope.db import Store
from vulnscope.scanner import Scanner, ScanResult


def start_scan(client, url, authorized="yes"):
    data = {"url": url}
    if authorized:
        data["authorized"] = authorized
    return client.post("/scans", data=data, follow_redirects=False)


def test_dashboard_end_to_end(client, insecure_target):
    assert "VulnScope" in client.get("/").text
    r = start_scan(client, insecure_target.url)
    assert r.status_code == 303 and r.headers["location"] == "/scans/1"
    page = client.get("/scans/1")
    assert page.status_code == 200 and "Acme Intranet" in page.text and "grade F" in page.text
    assert "Git repository exposed" in page.text and "exposure.file" in page.text
    for h in ("content-security-policy", "x-frame-options", "x-content-type-options"):
        assert h in page.headers  # the dashboard sends the headers it checks for
    fid = client.get("/api/scans/1").json()["findings"][0]["id"]
    r = client.post(f"/findings/{fid}/status", data={"status": "in_progress", "note": "ticket 42"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/scans/1#finding-{fid}"
    assert client.get("/api/scans/1").json()["findings"][0]["note"] == "ticket 42"
    assert client.post(f"/findings/{fid}/status", data={"status": "bogus"}).status_code == 400
    assert client.post("/findings/999/status", data={"status": "fixed"}).status_code == 404
    # second scan carries the status and shows a diff section
    start_scan(client, insecure_target.url)
    page2 = client.get("/scans/2").text
    assert "Since scan 1" in page2 and "no change in findings" in page2
    assert client.get("/api/scans/2").json()["findings"][0]["status"] == "in_progress"
    history = client.get("/targets/1").text
    assert "#1" in history and "#2" in history
    assert client.get("/").text.count("Rescan") == 1
    report = client.get("/scans/2/report.html").text
    assert "VulnScope security assessment" in report and "Method and limits" in report
    doc = client.get("/scans/2/report.json").json()
    assert doc["tool"] == "vulnscope" and doc["grade"] == "F"
    assert client.get("/api/targets").json()[0]["scans"] == 2
    assert client.get("/healthz").json() == {"ok": True}


def test_dashboard_rejects_unauthorised_and_bad_input(client):
    assert start_scan(client, "http://127.0.0.1:1", authorized=None).status_code == 400
    assert start_scan(client, "ftp://nope").status_code == 400
    assert client.get("/scans/42").status_code == 404 and client.get("/targets/42").status_code == 404


def test_failed_scan_is_recorded(client):
    start_scan(client, "http://127.0.0.1:9")
    page = client.get("/scans/1")
    assert "Scan failed" in page.text and "could not connect" in page.text


@pytest.mark.skipif(shutil.which("chromium") is None and shutil.which("google-chrome") is None, reason="no browser")
def test_pdf_export(client, secure_target, tmp_path):
    start_scan(client, secure_target.url)
    r = client.get("/scans/1/report.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")


def test_cli_scan_and_report(insecure_target, tmp_path, capsys):
    db = tmp_path / "cli.db"
    rc = main(["scan", insecure_target.url, "--db", str(db)])
    assert rc == 2 and "--authorized" in capsys.readouterr().err
    rc = main(["scan", insecure_target.url, "--authorized", "--db", str(db), "--no-legacy-probe",
               "--html", str(tmp_path / "r.html"), "--json", str(tmp_path / "r.json")])
    out = capsys.readouterr().out
    assert rc == 0 and "grade F" in out and "saved as scan 1" in out and "exposure.file" in out
    assert "<title>VulnScope report" in (tmp_path / "r.html").read_text()
    assert json.loads((tmp_path / "r.json").read_text())["findings"]
    rc = main(["report", "1", "--db", str(db), "--json", str(tmp_path / "again.json")])
    assert rc == 0 and json.loads((tmp_path / "again.json").read_text())["id"] == 1
    assert main(["report", "7", "--db", str(db)]) == 2
    rc = main(["scan", insecure_target.url, "--authorized", "--no-save", "--no-legacy-probe"])
    assert rc == 0 and "saved as" not in capsys.readouterr().out
    assert main(["scan", "http://127.0.0.1:9", "--authorized", "--db", str(db)]) == 2


def test_module_entry_point():
    r = subprocess.run([sys.executable, "-m", "vulnscope.cli", "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and "vulnscope 0." in r.stdout


def test_dashboard_refuses_cross_site_posts(client):
    form = {"url": "http://127.0.0.1:9", "authorized": "yes"}
    for headers in ({"origin": "https://evil.example"}, {"origin": "null"}, {"referer": "https://evil.example/x"}):
        assert client.post("/scans", data=form, headers=headers).status_code == 403
    assert client.post("/findings/1/status", data={"status": "fixed"},
                       headers={"origin": "https://evil.example"}).status_code == 403
    r = client.post("/scans", data=form, headers={"origin": "http://127.0.0.1"}, follow_redirects=False)
    assert r.status_code == 303  # the dashboard's own form still works


def test_dashboard_answers_only_to_known_host_names(client, monkeypatch):
    assert client.get("/api/targets", headers={"host": "rebind.attacker.example"}).status_code == 400
    assert client.get("/api/targets", headers={"host": "localhost:8000"}).status_code == 200
    monkeypatch.setattr(web, "ALLOWED_HOSTS", ["127.0.0.1", "localhost"])
    monkeypatch.setattr("uvicorn.run", lambda *a, **kw: None)
    web.serve("10.0.0.5", 8000)
    assert web.ALLOWED_HOSTS == ["127.0.0.1", "localhost", "10.0.0.5"]  # `serve --host` is allowed too


def test_api_schema_replaces_swagger(client):
    assert client.get("/api/docs").status_code == 404
    assert client.get("/api/openapi.json").json()["info"]["title"] == "VulnScope"
    assert 'href="/api/openapi.json"' in client.get("/").text


def test_interrupted_scan_does_not_block_rescans(client, tmp_path, monkeypatch):
    db = tmp_path / "old.db"
    old = Store(db)
    stuck = old.create_scan("http://127.0.0.1:9/")
    old.start_scan(stuck)  # the server died during this scan
    del web.app.state.store
    monkeypatch.setenv("VULNSCOPE_DB", str(db))
    r = start_scan(client, "http://127.0.0.1:9/")
    assert r.headers["location"] != f"/scans/{stuck}" and old.get_scan(stuck)["status"] == "failed"


def test_cli_never_leaves_a_scan_running(tmp_path, monkeypatch):
    async def crash(self, url):
        raise RuntimeError("boom")

    monkeypatch.setattr(Scanner, "scan", crash)
    assert main(["scan", "http://127.0.0.1:9", "--authorized", "--db", str(tmp_path / "c.db")]) == 2
    assert Store(tmp_path / "c.db").get_scan(1)["status"] == "failed"


def test_cli_and_dashboard_share_the_target_key(insecure_target, tmp_path):
    db = tmp_path / "k.db"
    assert main(["scan", insecure_target.url, "--authorized", "--db", str(db), "--no-legacy-probe"]) == 0
    assert main(["scan", "ftp://nope", "--authorized", "--db", str(db)]) == 2  # refused before anything is saved
    assert [t["url"] for t in Store(db).list_targets()] == [insecure_target.url + "/"]


def test_pdf_export_runs_one_at_a_time(client, monkeypatch):
    monkeypatch.setattr(web, "find_browser", lambda: "chrome")
    web.app.state.store.create_scan("https://t.example/")
    assert web.PDF_SLOT.acquire(blocking=False)
    try:
        assert client.get("/scans/1/report.pdf").status_code == 429
    finally:
        web.PDF_SLOT.release()


def test_pdf_failure_is_reported(monkeypatch, tmp_path):
    def fail(cmd, **kw):  # a timeout before any output leaves stderr as None; a missing binary raises OSError
        raise subprocess.TimeoutExpired(cmd, 120) if cmd[0] == "chrome-a" else FileNotFoundError(cmd[0])

    monkeypatch.setattr(report, "find_browsers", lambda: ["chrome-a", "chrome-b"])
    monkeypatch.setattr(report.subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="chrome-a.*timed out.*chrome-b"):
        report.to_pdf("<p>x</p>", tmp_path / "x.pdf")


def test_scanned_content_is_escaped(client):
    evil = '"><script>alert(1)</script>'
    db = web.app.state.store
    sid = db.create_scan("https://xss.test/")
    db.finish_scan(sid, ScanResult(url="https://xss.test/", started_at=datetime.now(UTC), final_url=evil, title=evil,
                                   server=evil, findings=[Finding("x", "low", f"Cookie {evil}", "d", evidence=evil)]))
    db.set_finding_status(db.get_scan(sid)["findings"][0]["id"], "open", evil)
    pages = (client.get(f"/scans/{sid}").text, client.get(f"/scans/{sid}/report.html").text,
             report.render_report(db.get_scan(sid)))
    for html in pages:
        assert "<script>alert(1)" not in html and "&lt;script&gt;alert(1)" in html
