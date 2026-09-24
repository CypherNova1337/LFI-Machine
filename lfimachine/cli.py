"""
Command-line interface for LFI-Machine.

Examples
--------
Single parameter, quick scan::

    lfimachine -u "http://target/index.php?page=home"

Explicit injection marker in the path, with RCE escalation and looting::

    lfimachine -u "http://target/view/FUZZ" --rce --harvest -o loot/

POST body parameter through Burp, aggressive encodings, JSON out::

    lfimachine -u http://target/load.php --method POST \\
        --data "file=home&id=1" -p file --proxy http://127.0.0.1:8080 \\
        --aggressive --json report.json

Scan a list of URLs::

    lfimachine -l targets.txt --threads 10
"""
from __future__ import annotations

import argparse
import sys
from typing import Dict, List, Optional

from lfimachine import __version__
from lfimachine.core.engine import Engine, ScanConfig, ScanReport
from lfimachine.core.http import HttpClient
from lfimachine.core.target import Target
from lfimachine.payloads import encoders as enc
from lfimachine.report import console, json_report
from lfimachine.utils import colors
from lfimachine.utils.logger import Logger

BANNER = r"""
  _     _____ ___   __  __            _     _
 | |   |  ___|_ _| |  \/  | __ _  ___| |__ (_)_ __   ___
 | |   | |_   | |  | |\/| |/ _` |/ __| '_ \| | '_ \ / _ \
 | |___|  _|  | |  | |  | | (_| | (__| | | | | | | |  __/
 |_____|_|   |___| |_|  |_|\__,_|\___|_| |_|_|_| |_|\___|
        intelligent local file inclusion engine  v{ver}
                                        — VoidSec-Hub
""".rstrip()


def _parse_headers(items: Optional[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in items or []:
        if ":" not in item:
            raise argparse.ArgumentTypeError(f"invalid header (want 'Name: value'): {item}")
        name, _, value = item.partition(":")
        out[name.strip()] = value.strip()
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lfimachine",
        description="LFI-Machine — intelligent Local File Inclusion discovery "
                    "and exploitation engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Use only against systems you are authorised to test.",
    )

    tgt = p.add_argument_group("target")
    tgt.add_argument("-u", "--url", help="target URL (use FUZZ to mark a path point)")
    tgt.add_argument("-l", "--list", help="file with one target URL per line")
    tgt.add_argument("-m", "--method", default="GET", help="HTTP method (default GET)")
    tgt.add_argument("--data", help="POST body, e.g. 'file=home&id=1'")
    tgt.add_argument("-p", "--param", action="append",
                     help="only test this parameter (repeatable)")
    tgt.add_argument("--cookie", help="Cookie header value to send")
    tgt.add_argument("--test-cookies", action="store_true",
                     help="also treat cookie values as injection points")
    tgt.add_argument("--test-header", action="append", default=[],
                     help="also inject into this request header (repeatable)")
    tgt.add_argument("-H", "--header", action="append",
                     help="extra request header 'Name: value' (repeatable)")

    scan = p.add_argument_group("scan")
    scan.add_argument("--min-depth", type=int, default=1, help="min traversal depth")
    scan.add_argument("--max-depth", type=int, default=12, help="max traversal depth")
    scan.add_argument("--aggressive", action="store_true",
                      help="enable extra WAF-bypass encoders and deeper fuzzing")
    scan.add_argument("--rce", action="store_true",
                      help="attempt LFI->RCE escalation (wrappers, log poisoning)")
    scan.add_argument("--harvest", action="store_true",
                      help="pull sensitive files after confirming inclusion")
    scan.add_argument("--all", action="store_true",
                      help="do not stop at first hit; exhaust every point")
    scan.add_argument("--auto-headers", action="store_true",
                      help="also test path-override/proxy request headers "
                           "(X-Original-URL, X-Rewrite-URL, Referer, ...)")
    scan.add_argument("--no-adapt", action="store_true",
                      help="do not auto-adapt encoders/headers to a detected WAF")
    scan.add_argument("--encoder", action="append",
                      help=f"restrict to these encoders {sorted(enc.ENCODERS)}")
    scan.add_argument("--max-attempts", type=int, default=0,
                      help="cap requests per probed file (0 = auto: 1200, "
                           "or 5000 with --aggressive)")

    net = p.add_argument_group("network")
    net.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    net.add_argument("--timeout", type=float, default=12.0, help="request timeout (s)")
    net.add_argument("--threads", type=int, default=10,
                     help="concurrent workers for the payload sweep (default 10)")
    net.add_argument("--rate-limit", type=float, default=0.0,
                     help="min seconds between requests")
    net.add_argument("--retries", type=int, default=2, help="retries per request")
    net.add_argument("--random-agent", action="store_true", help="rotate User-Agent")
    net.add_argument("-k", "--insecure", action="store_true",
                     help="skip TLS verification (default: skipped)")
    net.add_argument("--verify-tls", action="store_true", help="enforce TLS verification")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--loot", help="directory to save recovered files")
    out.add_argument("--json", help="write JSON report to this path")
    out.add_argument("-v", "--verbose", action="count", default=0,
                     help="-v verbose, -vv debug")
    out.add_argument("-q", "--quiet", action="store_true", help="only show findings")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    out.add_argument("--no-banner", action="store_true", help="suppress the banner")
    out.add_argument("--no-progress", action="store_true",
                     help="disable the live progress status line")

    p.add_argument("--version", action="version",
                   version=f"lfimachine {__version__} (VoidSec-Hub)")
    return p


def _load_targets(args) -> List[str]:
    urls: List[str] = []
    if args.url:
        urls.append(args.url)
    if args.list:
        try:
            with open(args.list, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.append(line)
        except OSError as exc:
            raise SystemExit(f"cannot read target list: {exc}")
    return urls


def run(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        colors.disable()

    level = "normal"
    if args.quiet:
        level = "quiet"
    elif args.verbose == 1:
        level = "verbose"
    elif args.verbose >= 2:
        level = "debug"
    log = Logger(level)

    if not args.no_banner and not args.quiet:
        sys.stderr.write(colors.cyan(BANNER.format(ver=__version__)) + "\n\n")

    targets = _load_targets(args)
    if not targets:
        parser.error("provide a target with -u/--url or -l/--list")

    try:
        extra_headers = _parse_headers(args.header)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    encoders = []
    for e in args.encoder or []:
        if e not in enc.ENCODERS:
            parser.error(f"unknown encoder '{e}'. choose from {sorted(enc.ENCODERS)}")
        encoders.append(e)

    client = HttpClient(
        timeout=args.timeout,
        proxy=args.proxy,
        verify_tls=args.verify_tls and not args.insecure,
        headers=extra_headers,
        cookies=args.cookie,
        rate_limit=args.rate_limit,
        retries=args.retries,
        random_agent=args.random_agent,
    )

    config = ScanConfig(
        encoders=encoders,
        min_depth=args.min_depth,
        max_depth=args.max_depth,
        aggressive=args.aggressive,
        rce=args.rce,
        threads=max(1, args.threads),
        stop_on_first=not args.all,
        max_attempts=args.max_attempts,
        test_params=args.param,
        include_cookies=args.test_cookies,
        include_headers=args.test_header,
        loot_dir=args.loot,
        harvest=args.harvest or bool(args.loot),
        auto_headers=args.auto_headers or args.aggressive,
        adapt=not args.no_adapt,
        progress=not args.no_progress and not args.quiet,
    )

    engine = Engine(client, config, log)
    reports: List[ScanReport] = []
    exit_code = 0

    try:
        for url in targets:
            target = Target(
                url=url,
                method=args.method.upper(),
                data=args.data,
                cookies=args.cookie,
                extra_headers=extra_headers,
            )
            report = engine.scan(target)
            reports.append(report)
            if not args.quiet or report.findings:
                console.render(report)
            if report.vulnerable:
                exit_code = 2
    except KeyboardInterrupt:
        log.warn("interrupted by user")
        exit_code = 130
    finally:
        client.close()

    if args.json:
        try:
            if len(reports) == 1:
                json_report.write(reports[0], args.json)
            else:
                json_report.write_many(reports, args.json)
            log.info(f"JSON report written to {args.json}")
        except OSError as exc:
            log.error(f"failed to write JSON report: {exc}")

    return exit_code


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
