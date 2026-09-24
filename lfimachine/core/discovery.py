"""
Parameter discovery.

When you point the tool at a bare URL, the interesting injection point is often
not in the URL you have — it's a parameter the app uses elsewhere. This module
mines candidate parameters from:

* the query string of the target URL,
* same-host links (``<a href>``) on the fetched page,
* ``<form>`` fields (name + method + action), and
* a built-in wordlist of parameter names commonly bound to file inclusion.

It returns discovered points so the engine can test parameters the operator
never had to enumerate by hand.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set

from lfimachine.core.http import HttpClient

# Parameter names frequently wired to include()/readfile()/fopen() paths.
COMMON_LFI_PARAMS = [
    "file", "page", "path", "include", "inc", "document", "doc", "view",
    "template", "tpl", "lang", "language", "locale", "dir", "folder", "root",
    "download", "read", "load", "content", "cat", "board", "detail", "show",
    "site", "type", "conf", "config", "settings", "layout", "module", "pdf",
    "img", "image", "style", "css", "theme", "name", "action", "do", "cmd",
]


@dataclass
class DiscoveredPoint:
    param: str
    method: str = "GET"           # GET (query) or POST (form)
    location: str = "query"       # "query" | "form"
    action: str = ""              # form action URL, if any
    source: str = "url"           # how it was found (url/link/form/wordlist)


class _HtmlMiner(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: List[str] = []
        self.forms: List[Dict] = []
        self._form: Optional[Dict] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""),
                          "method": (a.get("method") or "GET").upper(),
                          "fields": []}
        elif tag in ("input", "select", "textarea") and self._form is not None:
            if a.get("name"):
                self._form["fields"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _same_host(base: str, link: str) -> Optional[str]:
    try:
        joined = urllib.parse.urljoin(base, link)
    except ValueError:
        return None
    b, j = urllib.parse.urlsplit(base), urllib.parse.urlsplit(joined)
    if j.netloc and j.netloc != b.netloc:
        return None
    return joined


def discover(
    client: HttpClient,
    url: str,
    *,
    use_wordlist: bool = True,
    max_links: int = 40,
) -> List[DiscoveredPoint]:
    points: Dict[tuple, DiscoveredPoint] = {}

    def add(p: DiscoveredPoint) -> None:
        points.setdefault((p.param, p.location, p.method), p)

    parsed = urllib.parse.urlsplit(url)
    for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        add(DiscoveredPoint(name, "GET", "query", source="url"))

    resp = client.request("GET", url)
    if resp.ok and resp.text:
        miner = _HtmlMiner()
        try:
            miner.feed(resp.text)
        except Exception:
            pass

        for href in miner.hrefs[:max_links]:
            joined = _same_host(url, href)
            if not joined:
                continue
            q = urllib.parse.urlsplit(joined).query
            for name, _ in urllib.parse.parse_qsl(q, keep_blank_values=True):
                add(DiscoveredPoint(name, "GET", "query", action=joined, source="link"))

        for form in miner.forms:
            action = _same_host(url, form["action"]) or url
            for field_name in form["fields"]:
                add(DiscoveredPoint(field_name, form["method"],
                                    "form" if form["method"] == "POST" else "query",
                                    action=action, source="form"))

    if use_wordlist:
        for name in COMMON_LFI_PARAMS:
            add(DiscoveredPoint(name, "GET", "query", source="wordlist"))

    return list(points.values())


def augment_query_url(url: str, params: List[str], value: str = "1") -> str:
    """Return ``url`` with any missing query parameters added (benign value)."""
    parsed = urllib.parse.urlsplit(url)
    existing = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    have = {k for k, _ in existing}
    merged = list(existing) + [(p, value) for p in params if p not in have]
    new_q = urllib.parse.urlencode(merged)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, new_q, parsed.fragment)
    )
