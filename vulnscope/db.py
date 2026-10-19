"""SQLite store: targets, scans, findings and their remediation status."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from .checks import SEVERITIES
from .scanner import ScanResult

STATUSES = ("open", "in_progress", "fixed", "accepted")
SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY, url TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES targets(id), status TEXT NOT NULL,
    started_at TEXT NOT NULL, finished_at TEXT, final_url TEXT, http_status INTEGER, title TEXT, server TEXT,
    requests INTEGER NOT NULL DEFAULT 0, score INTEGER, grade TEXT, error TEXT, tls_json TEXT);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id), key TEXT NOT NULL,
    check_id TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '', references_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'open', note TEXT NOT NULL DEFAULT '', updated_at TEXT);
CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS scans_target ON scans(target_id);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        return c

    # targets and scans -------------------------------------------------------------------------
    def target_id(self, url: str) -> int:
        with self._conn() as c:
            c.execute("INSERT OR IGNORE INTO targets (url, created_at) VALUES (?, ?)", (url, _now()))
            return c.execute("SELECT id FROM targets WHERE url = ?", (url,)).fetchone()["id"]

    def create_scan(self, url: str) -> int:
        tid = self.target_id(url)
        with self._conn() as c:
            cur = c.execute("INSERT INTO scans (target_id, status, started_at) VALUES (?, 'queued', ?)", (tid, _now()))
            return cur.lastrowid

    def active_scan(self, url: str) -> int | None:
        with self._conn() as c:
            row = c.execute("SELECT s.id FROM scans s JOIN targets t ON t.id = s.target_id "
                            "WHERE t.url = ? AND s.status IN ('queued', 'running') ORDER BY s.id DESC",
                            (url,)).fetchone()
            return row["id"] if row else None

    def start_scan(self, scan_id: int) -> None:
        with self._conn() as c:
            c.execute("UPDATE scans SET status = 'running', started_at = ? WHERE id = ?", (_now(), scan_id))

    def fail_scan(self, scan_id: int, error: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE scans SET status = 'failed', finished_at = ?, error = ? WHERE id = ?",
                      (_now(), error[:1000], scan_id))

    def finish_scan(self, scan_id: int, result: ScanResult) -> None:
        with self._conn() as c:
            tid = c.execute("SELECT target_id FROM scans WHERE id = ?", (scan_id,)).fetchone()["target_id"]
            prev = c.execute("SELECT id FROM scans WHERE target_id = ? AND status = 'done' AND id < ? "
                             "ORDER BY id DESC LIMIT 1", (tid, scan_id)).fetchone()
            carried: dict[str, sqlite3.Row] = {}
            if prev:
                carried = {r["key"]: r for r in c.execute("SELECT key, status, note FROM findings WHERE scan_id = ?",
                                                          (prev["id"],))}
            c.execute("UPDATE scans SET status = 'done', finished_at = ?, final_url = ?, http_status = ?, title = ?, "
                      "server = ?, requests = ?, score = ?, grade = ?, tls_json = ? WHERE id = ?",
                      (_now(), result.final_url, result.http_status, result.title, result.server, result.requests,
                       result.score, result.grade, json.dumps(result.tls) if result.tls else None, scan_id))
            for f in result.findings:
                status, note = "open", ""
                old = carried.get(f.key)
                if old is not None:
                    if old["status"] in ("accepted", "in_progress"):
                        status, note = old["status"], old["note"]
                    elif old["status"] == "fixed":
                        note = "Reappeared after being marked fixed on an earlier scan."
                c.execute("INSERT INTO findings (scan_id, key, check_id, severity, title, description, evidence, "
                          "remediation, references_json, status, note, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                          (scan_id, f.key, f.check, f.severity, f.title, f.description, f.evidence, f.remediation,
                           json.dumps(f.references), status, note, _now()))

    # reads -------------------------------------------------------------------------------------
    def get_scan(self, scan_id: int) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT s.*, t.url, t.id AS target_id FROM scans s JOIN targets t ON t.id = s.target_id "
                            "WHERE s.id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            findings = [self._finding(r) for r in c.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id",
                                                            (scan_id,))]
            findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["check"], f["id"]))
        scan = dict(row)
        scan["tls"] = json.loads(scan.pop("tls_json") or "null")
        scan["findings"] = findings
        scan["counts"] = {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES}
        scan["open"] = sum(f["status"] in ("open", "in_progress") for f in findings)
        return scan

    @staticmethod
    def _finding(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["check"] = d.pop("check_id")
        d["references"] = json.loads(d.pop("references_json") or "[]")
        return d

    def get_finding(self, finding_id: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            return self._finding(r) if r else None

    def set_finding_status(self, finding_id: int, status: str, note: str) -> int:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        with self._conn() as c:
            c.execute("UPDATE findings SET status = ?, note = ?, updated_at = ? WHERE id = ?",
                      (status, note.strip()[:2000], _now(), finding_id))
            return c.execute("SELECT scan_id FROM findings WHERE id = ?", (finding_id,)).fetchone()["scan_id"]

    def list_targets(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT t.id, t.url, COUNT(s.id) AS scans, MAX(s.id) AS last_scan_id FROM targets t "
                "LEFT JOIN scans s ON s.target_id = t.id GROUP BY t.id ORDER BY MAX(s.started_at) DESC, t.id DESC"
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                last = c.execute("SELECT id, status, grade, score, finished_at, started_at FROM scans "
                                 "WHERE target_id = ? ORDER BY id DESC LIMIT 1", (r["id"],)).fetchone()
                d["last"] = dict(last) if last else None
                out.append(d)
            return out

    def list_scans(self, target_id: int) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM scans WHERE target_id = ? ORDER BY id DESC", (target_id,)).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d.pop("tls_json", None)
                d["counts"] = {s: n for s, n in c.execute(
                    "SELECT severity, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY severity", (r["id"],))}
                out.append(d)
            return out

    def get_target(self, target_id: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
            return dict(r) if r else None

    def diff(self, scan_id: int) -> dict:
        """Finding keys that are new in this scan and those resolved since the previous finished scan."""
        with self._conn() as c:
            s = c.execute("SELECT target_id FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if not s:
                return {"new": [], "resolved": [], "previous": None}
            prev = c.execute("SELECT id FROM scans WHERE target_id = ? AND status = 'done' AND id < ? "
                             "ORDER BY id DESC LIMIT 1", (s["target_id"], scan_id)).fetchone()
            if not prev:
                return {"new": [], "resolved": [], "previous": None}
            now = {r["key"]: r["title"] for r in c.execute("SELECT key, title FROM findings WHERE scan_id = ?",
                                                           (scan_id,))}
            before = {r["key"]: r["title"] for r in c.execute("SELECT key, title FROM findings WHERE scan_id = ?",
                                                              (prev["id"],))}
        return {"new": [now[k] for k in now if k not in before],
                "resolved": [before[k] for k in before if k not in now], "previous": prev["id"]}
