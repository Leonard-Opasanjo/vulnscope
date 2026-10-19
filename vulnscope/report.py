"""Reports: HTML from a template, JSON, and PDF through a locally installed Chromium when one exists."""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404: used only to run a local Chromium with a fixed argument list
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from . import REPO_URL, __version__
from .checks import SEVERITIES

env = Environment(loader=PackageLoader("vulnscope", "templates"), autoescape=select_autoescape(["html"]))
env.globals.update(version=__version__, repo_url=REPO_URL, severities=SEVERITIES)
# Chrome first: on some systems (GitHub's Ubuntu runners) `chromium` is a snap wrapper that cannot run headless.
BROWSERS = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome")


def render_report(scan: dict) -> str:
    return env.get_template("report.html").render(scan=scan, generated=datetime.now(UTC))


def to_json(scan: dict) -> str:
    return json.dumps({"tool": "vulnscope", "version": __version__, **scan}, indent=2, default=str)


def find_browsers() -> list[str]:
    return [p for name in BROWSERS if (p := shutil.which(name))]


def find_browser() -> str | None:
    return next(iter(find_browsers()), None)


def to_pdf(html: str, pdf_path: str | Path) -> bool:
    """Print the HTML report to PDF with a local headless Chrome or Chromium.

    Returns False when no browser is installed; raises RuntimeError when every installed browser fails.
    """
    browsers = find_browsers()
    if not browsers:
        return False
    errors = []
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "report.html"
        src.write_text(html, encoding="utf-8")
        for browser in browsers:
            try:
                subprocess.run([browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",  # nosec B603
                                f"--print-to-pdf={Path(pdf_path).resolve()}", src.as_uri()],
                               check=True, capture_output=True, timeout=120)
                return True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                errors.append(f"{browser}: {getattr(e, 'stderr', b'')[-300:]!r}")
    raise RuntimeError("PDF export failed: " + "; ".join(errors))
