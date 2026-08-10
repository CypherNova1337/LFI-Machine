# LFI-Machine

**An intelligent Local File Inclusion discovery and exploitation engine.**

Most LFI tools spray a static list of `../../../etc/passwd` payloads and grep
the response for `root:`. LFI-Machine takes a different approach: it *reasons*
about the target. It fingerprints the stack, models normal vs. error behaviour,
adapts traversal depth, negotiates WAF-bypass encodings, confirms disclosure
with structural content signatures, and then escalates a confirmed inclusion to
source-code theft and remote code execution — reusing the exact working payload
it already discovered.

Built and maintained by **VoidSec-Hub**.

---

## Why it's different

| Capability | Typical LFI fuzzers | LFI-Machine |
|---|---|---|
| Detection | substring match on `root:` | structural signatures + behavioural **baseline/differential** analysis |
| False positives | reflected payloads flagged as vulns | reflection-aware scoring, error-page suppression |
| Traversal | fixed depth list | **adaptive depth**, multi-separator, breadth-first convergence |
| WAF bypass | none / one encoding | pluggable **encoder pipeline** (URL, double-URL, overlong UTF-8, dot-truncation, …) |
| Targeting | blind payload flood | **OS/tech fingerprinting** picks probes and wrappers |
| Source theft | manual | automatic `php://filter` base64 disclosure + **secret sniffing** |
| RCE | manual | `data://`, `php://input`, `expect://`, **PHP filter chains**, **log & `/proc/self/environ` poisoning** — all self-verified |
| Confidence | binary | per-finding **0–100% confidence score** |
| Output | stdout | coloured console **+ JSON/JSONL** for CI |

Every escalation is **verified before it is reported** — RCE findings are only
raised when a uniquely-marked payload is proven to have *executed*, so the
report contains impact you can trust, not guesses.

---

## Installation

```bash
git clone https://github.com/VoidSec-Hub/LFI-Machine.git
cd LFI-Machine
pip install .            # installs the `lfimachine` command
# or, without installing:
pip install -r requirements.txt
python -m lfimachine --help
```

Requires Python 3.8+ and `requests`.

---

## Quick start

```bash
# Test a single query parameter
lfimachine -u "http://target/index.php?page=home"

# Mark an injection point explicitly anywhere in the URL with FUZZ
lfimachine -u "http://target/view/FUZZ"

# Full send: escalate to RCE and loot sensitive files
lfimachine -u "http://target/index.php?page=home" --rce --harvest -o loot/

# POST body parameter, through Burp, with aggressive encoders + JSON report
lfimachine -u http://target/load.php -m POST --data "file=home&id=1" \
    -p file --proxy http://127.0.0.1:8080 --aggressive --json report.json

# Sweep a list of targets, 10 at a time
lfimachine -l targets.txt --threads 10 --json out.jsonl
```

### Example output

```
[+] LFI confirmed via path-traversal: GET query:page -> etc/passwd (encoder=plain, conf=0.99)

════════════════════════════════════════════════════════════════════
 Scan report — http://target/index.php?page=home
════════════════════════════════════════════════════════════════════
 Target profile : linux / apache / php
 Verdict        : VULNERABLE — 3 finding(s)

[1] CRITICAL Remote Code Execution via PHP filter chain
     technique  : php-filter-chain-rce
     confidence : 95%
     payload    : php://filter/convert.iconv.UTF8.CSISO2022KR|...|convert.base64-decode/resource=php://temp

[2] HIGH     PHP source disclosure — config.php
     technique  : php-filter-source
     secrets    : db_password, db_user, db_host

[3] HIGH     Local File Inclusion — etc/passwd disclosed
     technique  : path-traversal
     confidence : 99%
```

---

## How it works

```
                  ┌─────────────┐
   target ──────► │ fingerprint │  Server / X-Powered-By / cookies / errors
                  └──────┬──────┘  → OS + language → tailored probes
                         ▼
                  ┌─────────────┐
                  │  baseline   │  benign + invalid probes → length bands,
                  └──────┬──────┘  error fingerprint, reflection detection
                         ▼
                  ┌─────────────┐
                  │ path-       │  adaptive depth × separators × encoders,
                  │ traversal   │  scored by the differential detector
                  └──────┬──────┘
                         ▼  (inclusion confirmed → working payload cached)
        ┌────────────────┼─────────────────────────────┐
        ▼                ▼                               ▼
  php://filter     LFI → RCE                      file harvesting
  source theft     • filter chains                pull configs / keys /
  + secret sniff   • data:// php://input          logs, save to loot dir
                   • expect://
                   • log & /proc/self/environ
                     poisoning
```

The detection stage caches the precise traversal prefix and encoder that
worked. Every escalation technique reuses it, so the tool never rediscovers the
vulnerability and stays fast and quiet.

---

## Options

```
Target:
  -u, --url URL           target URL (use FUZZ to mark a path injection point)
  -l, --list FILE         file with one target URL per line
  -m, --method METHOD     HTTP method (default GET)
  --data DATA             POST body, e.g. 'file=home&id=1'
  -p, --param NAME        only test this parameter (repeatable)
  --cookie VALUE          Cookie header to send
  --test-cookies          also treat cookie values as injection points
  --test-header NAME      also inject into this request header (repeatable)
  -H, --header 'K: V'     extra request header (repeatable)

Scan:
  --min-depth N / --max-depth N   traversal depth range (default 1..12)
  --aggressive            enable extra WAF-bypass encoders and deeper fuzzing
  --rce                   attempt LFI->RCE (wrappers, filter chains, log poison)
  --harvest               pull sensitive files after confirming inclusion
  --all                   don't stop at first hit; exhaust every point
  --encoder NAME          restrict to specific encoders (repeatable)

Network:
  --proxy URL             route through Burp/ZAP
  --timeout S / --retries N / --rate-limit S / --threads N
  --random-agent          rotate the User-Agent
  -k, --insecure          skip TLS verification (default)
  --verify-tls            enforce TLS verification

Output:
  -o, --loot DIR          save recovered files here
  --json PATH             write a JSON (or JSONL for many targets) report
  -v / -vv                verbose / debug
  -q, --quiet             only print findings
  --no-color / --no-banner
```

Exit codes: `0` clean, `2` vulnerable target found, `130` interrupted.

---

## JSON report

`--json` emits a structured document (one JSON object per target, JSONL when
scanning a list) with the fingerprint, stats, and every finding including
payload, encoder, confidence, matched signatures and evidence — ready to feed a
pipeline or ticketing system.

---

## Development

```bash
pip install -e ".[dev]"
pytest            # unit + end-to-end tests (spins up a local mock vuln server)
```

The test suite includes an integration test that stands up a deliberately
vulnerable HTTP endpoint and asserts the full engine detects it — and, just as
importantly, that a merely-reflective endpoint is **not** flagged.

---

## Legal & ethics

LFI-Machine is a security-testing tool for **authorised** assessments only —
penetration tests with a signed scope, bug-bounty targets within policy, CTFs,
and lab environments you own. Using it against systems you do not have explicit
permission to test is illegal. You are responsible for how you use it. The
authors accept no liability for misuse.

---

## License

MIT © VoidSec-Hub
