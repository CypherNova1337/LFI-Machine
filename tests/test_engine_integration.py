"""
End-to-end integration test.

Spins up a deliberately-vulnerable local HTTP server that emulates a classic
``include($_GET['page'])`` bug, then runs the full engine against it and asserts
that inclusion is detected with high confidence and the correct working payload.
No external network access is required.
"""
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from lfimachine.core.engine import Engine, ScanConfig
from lfimachine.core.http import HttpClient
from lfimachine.core.target import Target
from lfimachine.utils.logger import Logger

FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)


class _VulnHandler(BaseHTTPRequestHandler):
    """Simulates a naive LFI: strips leading ../ traversal then 'reads' a file."""

    def log_message(self, *args):  # silence
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        page = params.get("page", [""])[0]

        # Emulate a real filesystem: any path resolving to etc/passwd wins,
        # regardless of how many ../ segments precede it.
        normalised = page.replace("\\", "/")
        body = None
        if normalised.endswith("etc/passwd") or normalised == "/etc/passwd":
            body = FAKE_PASSWD
        elif normalised in ("", "home", "index"):
            body = "<html><body>Welcome to the home page</body></html>"

        if body is None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html><body>Page not found in app</body></html>")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.end_headers()
        self.wfile.write(body.encode())


@pytest.fixture()
def vuln_server():
    server = HTTPServer(("127.0.0.1", 0), _VulnHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_engine_detects_lfi(vuln_server):
    client = HttpClient(timeout=5, retries=0)
    config = ScanConfig(threads=1, max_depth=6, stop_on_first=True)
    engine = Engine(client, config, Logger("quiet"))

    target = Target(url=f"{vuln_server}/index.php?page=home")
    report = engine.scan(target)
    client.close()

    assert report.vulnerable, "engine should flag the vulnerable endpoint"
    lfi = [f for f in report.findings if f.technique == "path-traversal"]
    assert lfi, "expected a path-traversal finding"
    top = lfi[0]
    assert top.confidence >= 0.5
    assert "etc/passwd" in top.payload
    assert top.os_guess == "linux"
    assert report.fingerprint.php is True  # detected via X-Powered-By


def test_engine_reports_clean_on_safe_endpoint(vuln_server):
    """A parameter that never reaches the filesystem must not false-positive."""

    class _SafeHandler(_VulnHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            # Echo the input (reflection) but never disclose files.
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            q = params.get("q", [""])[0]
            self.wfile.write(f"<html>results for {q}</html>".encode())

    server = HTTPServer(("127.0.0.1", 0), _SafeHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = HttpClient(timeout=5, retries=0)
        engine = Engine(client, ScanConfig(threads=1, max_depth=4), Logger("quiet"))
        report = engine.scan(Target(url=f"http://127.0.0.1:{port}/search?q=test"))
        client.close()
        assert not report.vulnerable, "reflected input must not trigger a finding"
    finally:
        server.shutdown()


def test_engine_prunes_uniform_error_endpoint():
    """A parameter that always returns the same error page should be pruned
    fast, well under the full per-probe budget."""

    class _UniformHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            parsed = urlparse(self.path)
            page = parse_qs(parsed.query).get("page", [""])[0]
            body = ("<html>home</html>" if page in ("", "home", "index")
                    else "<html>file not found</html>")
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = HTTPServer(("127.0.0.1", 0), _UniformHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = HttpClient(timeout=5, retries=0)
        engine = Engine(client, ScanConfig(threads=8), Logger("quiet"))
        report = engine.scan(Target(url=f"http://127.0.0.1:{port}/index.php?page=home"))
        client.close()
        assert not report.vulnerable
        # Full budget would be ~1200 * 3 probes; pruning must cut this hard.
        assert report.requests_sent < 800, (
            f"pruning did not engage: {report.requests_sent} requests")
    finally:
        server.shutdown()

