"""
HTTP client wrapper.

Wraps ``requests`` with connection pooling, retries with backoff, optional
proxying (Burp/ZAP), custom headers/cookies, TLS control, rate limiting and a
rotating User-Agent pool. Every response is normalised into a lightweight
``Response`` object so the rest of the engine never touches ``requests``
directly.
"""
from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "lfimachine requires the 'requests' package. Install with: pip install requests"
    ) from exc

try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass


USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


@dataclass
class Response:
    status_code: int
    text: str
    length: int
    elapsed: float
    headers: Dict[str, str]
    url: str
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


class HttpClient:
    def __init__(
        self,
        *,
        timeout: float = 12.0,
        proxy: Optional[str] = None,
        verify_tls: bool = False,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
        rate_limit: float = 0.0,
        retries: int = 2,
        random_agent: bool = False,
        max_body: int = 2_000_000,
        auth: Optional[tuple] = None,
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.rate_limit = rate_limit
        self.retries = retries
        self.random_agent = random_agent
        self.max_body = max_body
        self.auth = auth

        self._session = requests.Session()
        adapter = HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=0)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}

        self._base_headers = {
            "User-Agent": USER_AGENTS[0],
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
        if headers:
            self._base_headers.update(headers)
        if cookies:
            self._base_headers["Cookie"] = cookies

        self._last_request = 0.0
        self._lock = threading.Lock()
        self.request_count = 0

    def _throttle(self) -> None:
        if self.rate_limit <= 0:
            return
        with self._lock:
            wait = self.rate_limit - (time.time() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.time()

    def _headers(self, extra: Optional[Dict[str, str]]) -> Dict[str, str]:
        h = dict(self._base_headers)
        if self.random_agent:
            h["User-Agent"] = random.choice(USER_AGENTS)
        if extra:
            h.update(extra)
        return h

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, str]] = None,
        data=None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = False,
    ) -> Response:
        self._throttle()
        last_err = "unknown error"
        for attempt in range(self.retries + 1):
            try:
                with self._lock:
                    self.request_count += 1
                resp = self._session.request(
                    method.upper(),
                    url,
                    params=params,
                    data=data,
                    headers=self._headers(headers),
                    timeout=self.timeout,
                    verify=self.verify_tls,
                    allow_redirects=allow_redirects,
                    stream=True,
                    auth=self.auth,
                )
                raw = resp.raw.read(self.max_body, decode_content=True)
                text = raw.decode(resp.encoding or "utf-8", errors="replace")
                resp.close()
                return Response(
                    status_code=resp.status_code,
                    text=text,
                    length=len(text),
                    elapsed=resp.elapsed.total_seconds(),
                    headers=dict(resp.headers),
                    url=str(resp.url),
                )
            except requests.RequestException as exc:
                last_err = f"{type(exc).__name__}: {exc}"
                if attempt < self.retries:
                    time.sleep(min(2 ** attempt * 0.5, 4.0))
                continue
        return Response(0, "", 0, 0.0, {}, url, error=last_err)

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass
