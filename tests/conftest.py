import socket
import subprocess
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from vulnscope.target import make_app


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    """Run an ASGI app with uvicorn in a thread for the duration of a test."""

    def __init__(self, app, ssl: tuple[Path, Path] | None = None):
        self.port = free_port()
        kw = {"ssl_certfile": str(ssl[0]), "ssl_keyfile": str(ssl[1])} if ssl else {}
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error", server_header=False,
                                                  **kw))
        self.scheme = "https" if ssl else "http"
        self.url = f"{self.scheme}://localhost:{self.port}"

    def __enter__(self):
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("server did not start")

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=5)


@pytest.fixture(scope="session")
def insecure_target():
    with Server(make_app(secure=False)) as s:
        yield s


@pytest.fixture(scope="session")
def secure_target():
    with Server(make_app(secure=True)) as s:
        yield s


@pytest.fixture(scope="session")
def self_signed(tmp_path_factory) -> tuple[Path, Path]:
    """A self-signed certificate for localhost made with the openssl CLI."""
    d = tmp_path_factory.mktemp("cert")
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "90", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True)
    return cert, key


@pytest.fixture(scope="session")
def tls_target(self_signed):
    with Server(make_app(secure=True), ssl=self_signed) as s:
        yield s


@pytest.fixture
def client(tmp_path, monkeypatch):
    """FastAPI test client with a fresh database; background tasks run inline."""
    from fastapi.testclient import TestClient

    from vulnscope import web
    from vulnscope.db import Store

    web.app.state.store = Store(tmp_path / "test.db")
    with TestClient(web.app) as c:
        yield c
    del web.app.state.store


def fetch(url: str, **kw) -> httpx.Response:
    return httpx.get(url, **kw)
