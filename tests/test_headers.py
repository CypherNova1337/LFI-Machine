"""Tests for header analysis, adaptation signals and the progress tracker."""
import io

from lfimachine.core import headers
from lfimachine.utils.progress import Progress, _strip_ansi


def test_detects_cloudflare_waf():
    ins = headers.analyze({"Server": "cloudflare", "CF-RAY": "abc-LAX"})
    assert ins.waf == "Cloudflare"
    assert ins.waf_present
    assert ins.cdn == "Cloudflare"


def test_detects_modsecurity_by_value():
    ins = headers.analyze({"Server": "Apache/2.4 mod_security/2.9"})
    assert ins.waf == "ModSecurity"


def test_no_waf_on_plain_server():
    ins = headers.analyze({"Server": "nginx/1.20", "X-Powered-By": "PHP/8.1"})
    assert ins.waf is None
    assert ins.powered_by == "PHP/8.1"
    assert "x-powered-by" in ins.interesting


def test_missing_security_headers_reported():
    ins = headers.analyze({"Server": "nginx"})
    assert "content-security-policy" in ins.missing_security


def test_spoof_headers_cover_common_source_ip_headers():
    ins = headers.analyze({})
    spoof = ins.spoof_headers("10.0.0.5")
    assert spoof["X-Forwarded-For"] == "10.0.0.5"
    assert "True-Client-IP" in spoof


def test_progress_writes_and_stops_without_tty():
    buf = io.StringIO()  # not a tty -> heartbeat/silent mode, must not crash
    p = Progress(enabled=True, stream=buf, count_fn=lambda: 42)
    p.activity("path-traversal")
    p.point("page · etc/passwd")
    p.start()
    p.write_line("[+] hello")
    p.stop()
    assert "[+] hello" in buf.getvalue()


def test_strip_ansi():
    assert _strip_ansi("\033[31mred\033[0m") == "red"
