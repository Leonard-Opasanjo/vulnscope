"""Command line: scan a URL, serve the dashboard, run the practice target, re-export a stored report."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from . import __version__
from .report import render_report, to_json, to_pdf
from .scanner import ScanError, Scanner


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulnscope", description="Passive web security scanner for sites you are "
                                                                "authorised to test")
    p.add_argument("--version", action="version", version=f"vulnscope {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan one URL and print the findings")
    s.add_argument("url")
    s.add_argument("--authorized", action="store_true",
                   help="confirm you own the target or have written permission to test it (required)")
    s.add_argument("--html", metavar="FILE", help="write the HTML report")
    s.add_argument("--json", metavar="FILE", help="write the JSON report")
    s.add_argument("--pdf", metavar="FILE", help="write a PDF report (needs Chromium or Chrome installed)")
    s.add_argument("--db", metavar="PATH", default=os.environ.get("VULNSCOPE_DB", "vulnscope.db"),
                   help="SQLite database that keeps scan history (default %(default)s)")
    s.add_argument("--no-save", action="store_true", help="do not record this scan in the database")
    s.add_argument("--ca-bundle", metavar="FILE", help="trust this CA bundle instead of the system store")
    s.add_argument("--insecure", action="store_true", help="skip certificate verification entirely")
    s.add_argument("--timeout", type=float, default=10.0, metavar="SECONDS")
    s.add_argument("--no-legacy-probe", action="store_true", help="do not test whether TLS 1.0/1.1 are accepted")

    v = sub.add_parser("serve", help="run the dashboard")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8000)
    v.add_argument("--db", metavar="PATH", default=os.environ.get("VULNSCOPE_DB", "vulnscope.db"))

    t = sub.add_parser("target", help="run the deliberately misconfigured practice target")
    t.add_argument("--host", default="127.0.0.1")
    t.add_argument("--port", type=int, default=8099)
    t.add_argument("--secure", action="store_true", help="serve the hardened version instead")

    r = sub.add_parser("report", help="re-export a stored scan as HTML, JSON or PDF")
    r.add_argument("scan_id", type=int)
    r.add_argument("--html", metavar="FILE")
    r.add_argument("--json", metavar="FILE")
    r.add_argument("--pdf", metavar="FILE")
    r.add_argument("--db", metavar="PATH", default=os.environ.get("VULNSCOPE_DB", "vulnscope.db"))
    return p


def _export(scan: dict, html: str | None, json_path: str | None, pdf: str | None) -> None:
    if html:
        Path(html).write_text(render_report(scan), encoding="utf-8")
        print(f"html report written to {html}")
    if json_path:
        Path(json_path).write_text(to_json(scan), encoding="utf-8")
        print(f"json written to {json_path}")
    if pdf:
        if to_pdf(render_report(scan), pdf):
            print(f"pdf written to {pdf}")
        else:
            print("pdf skipped: no Chromium or Chrome found on this machine", file=sys.stderr)


def _print(scan: dict) -> None:
    print(f"{scan['url']} -> grade {scan['grade']} (score {scan['score']}/100), {len(scan['findings'])} findings, "
          f"{scan['requests']} requests")
    for f in scan["findings"]:
        print(f"  {f['severity']:<8} {f['check']:<22} {f['title']}")


def scan_cmd(args: argparse.Namespace) -> int:
    if not args.authorized:
        print("error: pass --authorized to confirm you own the target or have written permission to test it",
              file=sys.stderr)
        return 2
    verify: bool | str = False if args.insecure else (args.ca_bundle or True)
    scanner = Scanner(verify=verify, timeout=args.timeout, probe_legacy=not args.no_legacy_probe)
    if args.no_save:
        result = asyncio.run(scanner.scan(args.url))
        scan = result.to_dict()
    else:
        from .db import Store

        db = Store(args.db)
        scan_id = db.create_scan(args.url if "://" in args.url else "https://" + args.url)
        db.start_scan(scan_id)
        try:
            db.finish_scan(scan_id, asyncio.run(scanner.scan(args.url)))
        except ScanError as e:
            db.fail_scan(scan_id, str(e))
            raise
        scan = db.get_scan(scan_id)
        print(f"saved as scan {scan_id} in {args.db}")
    _print(scan)
    _export(scan, args.html, args.json, args.pdf)
    return 0


def report_cmd(args: argparse.Namespace) -> int:
    from .db import Store

    scan = Store(args.db).get_scan(args.scan_id)
    if scan is None:
        raise ScanError(f"scan {args.scan_id} not found in {args.db}")
    _print(scan)
    _export(scan, args.html, args.json, args.pdf)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "scan":
            return scan_cmd(args)
        if args.command == "report":
            return report_cmd(args)
        if args.command == "serve":
            from .web import serve

            serve(args.host, args.port, args.db)
            return 0
        from .target import serve as serve_target

        serve_target(args.host, args.port, args.secure)
        return 0
    except (ScanError, OSError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
