"""
Response-header auto-analysis.

Before and during a scan, the response headers say a lot about how to attack a
target: which WAF or CDN sits in front of it, what technology is behind it, how
caching behaves, and which security controls are (not) present. This module
turns raw headers into:

* human-readable **insights** (surfaced as informational findings), and
* **adaptation signals** the engine acts on automatically — e.g. enabling
  tougher encoders and IP-spoofing request headers when a WAF is detected.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# name -> (is_cdn, [conditions]). A condition is (header_regex, value_regex|None);
# the product is flagged if ANY of its conditions matches a response header. A
# value_regex of None means "this header being present is enough" — only used for
# vendor-specific headers that never appear otherwise (e.g. cf-ray).
_WAF_SIGNATURES: List[Tuple[str, bool, List[Tuple[str, Optional[str]]]]] = [
    ("Cloudflare", True, [(r"^cf-ray$", None), (r"^cf-cache-status$", None),
                          (r"^server$", r"cloudflare")]),
    ("Akamai", True, [(r"^x-akamai-", None), (r"^akamai-", None),
                      (r"^server$", r"akamai")]),
    ("Imperva Incapsula", False, [(r"^x-iinfo$", None), (r"^x-cdn$", r"incap|imperva")]),
    ("Sucuri", False, [(r"^x-sucuri", None), (r"^server$", r"sucuri")]),
    ("AWS WAF / CloudFront", True, [(r"^x-amz-cf-", None), (r"^x-amzn-", None)]),
    ("F5 BIG-IP", False, [(r"^x-waf-", None), (r"^x-cnection$", None),
                          (r"^server$", r"big-?ip")]),
    ("Barracuda", False, [(r"^barra", None)]),
    ("ModSecurity", False, [(r"^server$", r"mod_security|modsecurity")]),
    ("Wallarm", False, [(r"^server$", r"wallarm|nginx-wallarm")]),
    ("Fastly", True, [(r"^x-served-by$", r"cache"), (r"^x-fastly", None),
                      (r"^fastly-", None), (r"^server$", r"fastly")]),
]

_SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

# Request headers that WAFs / apps often trust for the client's source address.
# Rotating a benign internal-looking value here can bypass IP-based rules.
IP_SPOOF_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Client-IP",
    "X-Host",
    "X-Forwarded-Host",
    "True-Client-IP",
    "CF-Connecting-IP",
]

# Headers some apps use to override the routed path/resource — candidate
# injection points for path-based inclusion.
PATH_OVERRIDE_HEADERS = [
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "Referer",
    "X-Forwarded-Path",
]


@dataclass
class HeaderInsights:
    waf: Optional[str] = None
    cdn: Optional[str] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    caching: bool = False
    missing_security: List[str] = field(default_factory=list)
    interesting: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    @property
    def waf_present(self) -> bool:
        return self.waf is not None

    def spoof_headers(self, ip: str = "127.0.0.1") -> Dict[str, str]:
        """A set of source-address headers to blend into requests when evading
        IP-based filtering."""
        return {h: ip for h in IP_SPOOF_HEADERS}


def analyze(headers: Dict[str, str]) -> HeaderInsights:
    ins = HeaderInsights()
    lower = {k.lower(): v for k, v in headers.items()}

    ins.server = lower.get("server")
    ins.powered_by = lower.get("x-powered-by")

    for name, is_cdn, conditions in _WAF_SIGNATURES:
        matched = False
        for hpat, vpat in conditions:
            hre = re.compile(hpat, re.IGNORECASE)
            for hk, hv in lower.items():
                if not hre.search(hk):
                    continue
                if vpat and not re.search(vpat, hv, re.IGNORECASE):
                    continue
                matched = True
                break
            if matched:
                break
        if matched:
            if is_cdn:
                ins.cdn = ins.cdn or name
            ins.waf = ins.waf or name
            break

    if lower.get("cf-cache-status") or "cache" in lower.get("x-cache", "").lower():
        ins.caching = True

    ins.missing_security = [h for h in _SECURITY_HEADERS if h not in lower]

    for leak in ("x-powered-by", "x-aspnet-version", "x-generator",
                 "x-drupal-cache", "x-runtime", "via"):
        if leak in lower:
            ins.interesting[leak] = lower[leak]

    if ins.waf:
        ins.notes.append(
            f"{ins.waf} detected — enabling tougher encoders and source-IP "
            "spoofing headers to improve payload survival."
        )
    if ins.caching:
        ins.notes.append("Response caching in play — vary payloads to avoid "
                         "cached negatives.")
    return ins
