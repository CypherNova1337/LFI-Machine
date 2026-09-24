"""Tests for parameter discovery."""
from lfimachine.core import discovery
from lfimachine.core.http import Response


class _StubClient:
    def __init__(self, html):
        self._html = html
        self.request_count = 0

    def request(self, method, url, **kw):
        self.request_count += 1
        return Response(200, self._html, len(self._html), 0.01, {}, url, None)


def test_augment_query_url_adds_missing_params():
    url = discovery.augment_query_url("http://t/app.php?a=1", ["a", "page", "file"])
    assert "a=1" in url
    assert "page=1" in url and "file=1" in url


def test_discover_from_links_and_forms():
    html = """
    <html><body>
      <a href="view.php?page=home">home</a>
      <a href="/read.php?doc=1&lang=en">doc</a>
      <a href="http://evil.example/x?secret=1">offsite</a>
      <form action="load.php" method="POST">
        <input name="file"><input name="token">
      </form>
    </body></html>
    """
    client = _StubClient(html)
    points = discovery.discover(client, "http://t/index.php", use_wordlist=False)
    names = {p.param for p in points}
    assert {"page", "doc", "lang", "file", "token"} <= names
    # Off-site link parameters must not be harvested.
    assert "secret" not in names


def test_discover_wordlist_toggle():
    client = _StubClient("<html></html>")
    without = discovery.discover(client, "http://t/i.php", use_wordlist=False)
    with_wl = discovery.discover(client, "http://t/i.php", use_wordlist=True)
    assert len(with_wl) > len(without)
    assert any(p.source == "wordlist" and p.param == "page" for p in with_wl)
