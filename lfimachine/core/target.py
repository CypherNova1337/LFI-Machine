"""
Target and injection-point modelling.

An ``InjectionPoint`` knows how to render an arbitrary payload into a concrete
HTTP request. Supported locations: query-string parameters, POST body
parameters, cookies, arbitrary headers, and a path placeholder marked with a
``FUZZ`` token.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from lfimachine.core.http import HttpClient, Response

FUZZ = "FUZZ"


@dataclass
class InjectionPoint:
    method: str
    url: str                       # may contain FUZZ for path injection
    location: str                  # "query" | "body" | "cookie" | "header" | "path"
    parameter: str                 # name of the param/cookie/header ("" for path)
    base_params: Dict[str, str] = field(default_factory=dict)
    base_data: Dict[str, str] = field(default_factory=dict)
    base_cookies: Dict[str, str] = field(default_factory=dict)
    base_headers: Dict[str, str] = field(default_factory=dict)
    original_value: str = ""

    def describe(self) -> str:
        loc = self.location
        if loc == "path":
            return f"{self.method} path-FUZZ {self.url}"
        return f"{self.method} {loc}:{self.parameter}"

    def send(self, client: HttpClient, payload: str) -> Response:
        url = self.url
        params = dict(self.base_params)
        data = dict(self.base_data) if self.base_data else None
        headers: Dict[str, str] = {}

        if self.location == "query":
            params[self.parameter] = payload
        elif self.location == "body":
            data = dict(self.base_data)
            data[self.parameter] = payload
        elif self.location == "cookie":
            jar = dict(self.base_cookies)
            jar[self.parameter] = payload
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        elif self.location == "header":
            headers[self.parameter] = payload
        elif self.location == "path":
            url = self.url.replace(FUZZ, urllib.parse.quote(payload, safe="/%.:"))
        else:  # pragma: no cover
            raise ValueError(f"unknown injection location: {self.location}")

        if self.base_headers:
            merged = dict(self.base_headers)
            merged.update(headers)
            headers = merged

        return client.request(
            self.method,
            url,
            params=params if params else None,
            data=data,
            headers=headers or None,
        )


@dataclass
class Target:
    url: str
    method: str = "GET"
    data: Optional[str] = None       # raw POST body "a=1&b=2"
    cookies: Optional[str] = None
    extra_headers: Dict[str, str] = field(default_factory=dict)

    def _parse_pairs(self, blob: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for k, v in urllib.parse.parse_qsl(blob, keep_blank_values=True):
            out[k] = v
        return out

    def injection_points(
        self,
        *,
        test_params: Optional[List[str]] = None,
        include_cookies: bool = False,
        include_headers: Optional[List[str]] = None,
    ) -> List[InjectionPoint]:
        """
        Enumerate candidate injection points. If ``FUZZ`` appears in the URL,
        that single path point is returned. Otherwise every query parameter
        (and POST parameter / cookie / header, when applicable) becomes a point.
        """
        points: List[InjectionPoint] = []

        if FUZZ in self.url:
            points.append(
                InjectionPoint(
                    method=self.method,
                    url=self.url,
                    location="path",
                    parameter="",
                    base_headers=dict(self.extra_headers),
                    base_cookies=self._parse_pairs(self.cookies or ""),
                )
            )
            return points

        parsed = urllib.parse.urlsplit(self.url)
        query = self._parse_pairs(parsed.query)
        base_url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, "", "")
        )
        body = self._parse_pairs(self.data) if self.data else {}
        cookie_jar = self._parse_pairs(self.cookies or "")

        wanted = set(test_params) if test_params else None

        for name, value in query.items():
            if wanted and name not in wanted:
                continue
            points.append(
                InjectionPoint(
                    method=self.method,
                    url=base_url,
                    location="query",
                    parameter=name,
                    base_params={k: v for k, v in query.items()},
                    base_cookies=cookie_jar,
                    base_headers=dict(self.extra_headers),
                    original_value=value,
                )
            )

        for name, value in body.items():
            if wanted and name not in wanted:
                continue
            points.append(
                InjectionPoint(
                    method=self.method if self.method != "GET" else "POST",
                    url=base_url,
                    location="body",
                    parameter=name,
                    base_params={k: v for k, v in query.items()},
                    base_data={k: v for k, v in body.items()},
                    base_cookies=cookie_jar,
                    base_headers=dict(self.extra_headers),
                    original_value=value,
                )
            )

        if include_cookies:
            for name, value in cookie_jar.items():
                if wanted and name not in wanted:
                    continue
                points.append(
                    InjectionPoint(
                        method=self.method,
                        url=base_url,
                        location="cookie",
                        parameter=name,
                        base_params={k: v for k, v in query.items()},
                        base_cookies=cookie_jar,
                        base_headers=dict(self.extra_headers),
                        original_value=value,
                    )
                )

        for header_name in include_headers or []:
            points.append(
                InjectionPoint(
                    method=self.method,
                    url=base_url,
                    location="header",
                    parameter=header_name,
                    base_params={k: v for k, v in query.items()},
                    base_cookies=cookie_jar,
                    base_headers=dict(self.extra_headers),
                )
            )

        return points
