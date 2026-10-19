from datetime import UTC, datetime

import pytest

from vulnscope.checks import Finding
from vulnscope.db import Store
from vulnscope.scanner import ScanResult


def result(*findings, url="https://t.example/"):
    r = ScanResult(url=url, started_at=datetime.now(UTC), final_url=url, http_status=200, title="T", server="x",
                   requests=5, findings=list(findings))
    r.finished_at = datetime.now(UTC)
    return r


def finish(store, url, *findings):
    sid = store.create_scan(url)
    store.start_scan(sid)
    store.finish_scan(sid, result(*findings, url=url))
    return sid


def test_scan_lifecycle_and_reads(tmp_path):
    s = Store(tmp_path / "x.db")
    sid = finish(s, "https://t.example/", Finding("headers.csp", "medium", "CSP missing", "d"),
                 Finding("cookies.httponly", "medium", "cookie", "d", key="cookies.httponly:session"))
    scan = s.get_scan(sid)
    assert scan["status"] == "done" and scan["grade"] == "B" and scan["score"] == 80 and scan["url"] == "https://t.example/"
    assert [f["key"] for f in scan["findings"]] == ["cookies.httponly:session", "headers.csp"]
    assert scan["counts"]["medium"] == 2 and scan["open"] == 2
    assert s.get_scan(999) is None
    targets = s.list_targets()
    assert len(targets) == 1 and targets[0]["last"]["grade"] == "B" and targets[0]["scans"] == 1
    assert s.list_scans(targets[0]["id"])[0]["counts"] == {"medium": 2}
    assert s.active_scan("https://t.example/") is None
    queued = s.create_scan("https://t.example/")
    assert s.active_scan("https://t.example/") == queued
    s.fail_scan(queued, "boom")
    assert s.get_scan(queued)["status"] == "failed" and s.get_scan(queued)["error"] == "boom"


def test_status_carry_over_and_diff(tmp_path):
    s = Store(tmp_path / "x.db")
    url = "https://t.example/"
    a = finish(s, url, Finding("headers.csp", "medium", "CSP missing", "d"), Finding("headers.referrer", "low", "ref", "d"),
               Finding("headers.nosniff", "low", "nosniff", "d"))
    ids = {f["key"]: f["id"] for f in s.get_scan(a)["findings"]}
    s.set_finding_status(ids["headers.csp"], "accepted", "Policy ships next quarter")
    s.set_finding_status(ids["headers.referrer"], "fixed", "Done in nginx")
    with pytest.raises(ValueError):
        s.set_finding_status(ids["headers.nosniff"], "bogus", "")
    # Second scan: csp still there (status carried), referrer still there (regression), nosniff gone, new framing finding
    b = finish(s, url, Finding("headers.csp", "medium", "CSP missing", "d"), Finding("headers.referrer", "low", "ref", "d"),
               Finding("headers.framing", "medium", "framing", "d"))
    by_key = {f["key"]: f for f in s.get_scan(b)["findings"]}
    assert by_key["headers.csp"]["status"] == "accepted" and by_key["headers.csp"]["note"] == "Policy ships next quarter"
    assert by_key["headers.referrer"]["status"] == "open" and "Reappeared" in by_key["headers.referrer"]["note"]
    assert by_key["headers.framing"]["status"] == "open"
    diff = s.diff(b)
    assert diff["previous"] == a and diff["new"] == ["framing"] and diff["resolved"] == ["nosniff"]
    assert s.diff(a) == {"new": [], "resolved": [], "previous": None}
    assert s.get_scan(b)["open"] == 2
