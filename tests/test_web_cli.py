import json
import shutil
import subprocess
import sys

import pytest

from vulnscope.cli import main


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
