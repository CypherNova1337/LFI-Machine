"""Unit tests for payload generation, encoding, signatures and detection."""
import base64

from lfimachine.core import detector
from lfimachine.core.http import Response
from lfimachine.payloads import encoders, signatures, traversal_gen


def _resp(text, status=200):
    return Response(status, text, len(text), 0.01, {}, "http://t/", None)


def test_encoders_roundtrip_and_dedup():
    variants = encoders.variants("../../etc/passwd", ["plain", "url", "url"], is_path=True)
    names = [n for n, _ in variants]
    assert "plain" in names
    # duplicate encoder name collapses to a single distinct payload
    assert len([p for _, p in variants]) == len({p for _, p in variants})


def test_encoder_url_encodes_dots():
    out = encoders.encode("../etc/passwd", "url_dots_slashes")
    assert "%2e%2e" in out and "%2f" in out


def test_traversal_generator_depths_and_dedup():
    payloads = list(traversal_gen.generate("etc/passwd", min_depth=1, max_depth=3))
    assert any(p.count("../") >= 3 for p in payloads)
    assert len(payloads) == len(set(payloads))  # no duplicates
    assert any(p.endswith("%00") for p in payloads)  # null-byte variant present


def test_signature_matches_passwd():
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    hits = signatures.match_signatures(body)
    names = {h.name for h in hits}
    assert "etc_passwd" in names
    assert signatures.guess_os(hits) == "linux"


def test_signature_matches_win_ini():
    body = "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n"
    hits = signatures.match_signatures(body)
    assert signatures.guess_os(hits) == "windows"


def test_detector_confirms_real_passwd():
    body = "root:x:0:0:root:/root:/bin/bash\n"
    det = detector.analyse(_resp(body), None, "../../etc/passwd",
                           expected_signature="etc_passwd")
    assert det.confirmed
    assert det.confidence >= 0.5
    assert det.os_guess == "linux"


def test_detector_rejects_plain_html():
    body = "<html><body>Welcome home</body></html>"
    det = detector.analyse(_resp(body), None, "home")
    assert not det.confirmed


def test_wrapper_confirm_rejects_reflected_error():
    """A failed wrapper whose payload is echoed in a PHP warning must NOT be
    reported as code execution (real bug found against live PHP)."""
    from lfimachine.techniques.wrappers import WrapperRceTechnique
    t = WrapperRceTechnique()
    marker = "LFIMXdeadbeef"
    # expect:// unavailable -> PHP warning reflects the payload incl. the marker
    warned = _resp(
        f"<br /><b>Warning</b>: include(): Failed opening 'expect://echo "
        f"{marker}' for inclusion in /var/www/index.php on line 4<br />"
    )
    assert not t._confirm_echo(warned, marker)
    # genuine execution: bare marker, no PHP error, no reflected 'echo MARKER'
    executed = _resp(f"<html>{marker}</html>")
    assert t._confirm_echo(executed, marker)
