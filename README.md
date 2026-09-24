# LFI-Machine

Finds file-inclusion bugs by reasoning about the target, not by spraying `../../etc/passwd`.

![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=flat-square)

## What it does

A page loads content based on something you control:

```
https://site.example/view?page=about
```

If the code hands that value to the filesystem without checking it, `page` can
be pointed somewhere else — a config file, a credentials file, a log. That's
Local File Inclusion, and it ranges from an information leak to full code
execution depending on what you can reach.

Most LFI tools work one way: send a list of `../../../etc/passwd` variations,
grep the response for `root:`. That misses almost everything real. The traversal
depth is wrong, a WAF eats the payload, the target is Windows, or the file is
returned base64-encoded through a PHP wrapper and never contains the string
you're grepping for.

LFI-Machine works the problem instead. It fingerprints the stack to know which
files are worth asking for, learns what a normal response and an error look like
so it can tell them apart, adjusts traversal depth rather than guessing, and
tries encodings until one survives the filter. It confirms a hit by recognising
the *structure* of what came back — a passwd file has a shape — instead of
matching a substring.

Once inclusion is confirmed it can go further: pull source code through PHP
filter chains, and attempt code execution via wrappers or log poisoning.

## Why you'd use it

- **Confirms by structure, not substring**, so base64 and encoded responses
  still register.
- **Adapts depth and encoding** rather than firing a fixed payload list.
- **Reads the perimeter.** It analyses response headers to identify the WAF/CDN
  and stack, then adapts — broader encodings and source-IP headers when a filter
  is in the way.
- **Shows its work.** A live status line tells you what it's trying right now —
  technique, file, request count and rate — so a run is never a silent wait.
- **Knows the difference between error and empty**, having learned the target's
  normal behaviour first.
- **Escalates** — source theft and RCE attempts reuse the exact payload that
  already worked.
- **Tests cookies and headers too**, not only query parameters — including
  path-override headers like `X-Original-URL` with `--auto-headers`.

## Install

```bash
git clone https://github.com/CypherNova1337/LFI-Machine
cd LFI-Machine
pip install -r requirements.txt
pip install .
```

Needs Python 3.8 or newer.

## Usage

```bash
lfimachine -u 'https://site.example/view?page=about'
```

It tests every parameter it finds. Mark a specific spot with `FUZZ` if you want
to be exact:

```bash
lfimachine -u 'https://site.example/view?page=FUZZ'
```

**Only one parameter**

```bash
lfimachine -u 'https://site.example/view?page=about&id=1' -p page
```

**A list of targets**

```bash
lfimachine -l urls.txt -o loot/
```

**Behind a login**

```bash
lfimachine -u 'https://site.example/view?page=about' --cookie 'session=abc123'
```

**Test cookies and headers as injection points**

```bash
lfimachine -u https://site.example/view --test-cookies --test-header X-Forwarded-For
```

**Push harder when a filter is in the way**

```bash
lfimachine -u 'https://site.example/view?page=FUZZ' --aggressive
```

**Go after source and RCE once you have a hit**

```bash
lfimachine -u 'https://site.example/view?page=FUZZ' --harvest --rce
```

**Through Burp**

```bash
lfimachine -u 'https://site.example/view?page=FUZZ' --proxy http://127.0.0.1:8080
```

## Options

| Flag | Default | What it does |
|---|---|---|
| `-u` | — | Target URL; `FUZZ` marks a path point |
| `-l` | — | File of target URLs |
| `-m` | `GET` | HTTP method |
| `--data` | — | POST body |
| `-p` | all | Test only this parameter (repeatable) |
| `--cookie` | — | Cookie header to send |
| `--test-cookies` | off | Treat cookie values as injection points |
| `--test-header` | — | Also inject into this header (repeatable) |
| `-H` | — | Extra header (repeatable) |
| `--min-depth` / `--max-depth` | — | Traversal depth range |
| `--aggressive` | off | Extra WAF-bypass encoders and deeper fuzzing |
| `--rce` | off | Attempt escalation to code execution |
| `--harvest` | off | Pull sensitive files after confirming inclusion |
| `--all` | off | Don't stop at the first hit |
| `--auto-headers` | off | Also test path-override/proxy headers (`X-Original-URL`, `X-Rewrite-URL`, `Referer`, …) |
| `--no-adapt` | — | Don't auto-adapt encoders/headers to a detected WAF |
| `--encoder` | all | Restrict to specific encoders |
| `--max-attempts` | auto | Cap requests per probed file (auto: 1200, or 5000 with `--aggressive`) |
| `--threads` | 10 | Concurrent workers for the payload sweep |
| `--rate-limit` | — | Requests per second cap |
| `--retries` | — | Retries per request |
| `--random-agent` | off | Rotate User-Agent |
| `--proxy` | — | Proxy URL, e.g. Burp |
| `-k` / `--verify-tls` | — | Skip / enforce TLS verification |
| `-o` | — | Loot directory |
| `--json` | — | Write results as JSON |
| `--no-progress` | — | Disable the live status line |
| `-v` / `-q` | — | More / less output |

## Good to know

- **`--rce` and `--harvest` write to the target.** Log poisoning leaves entries
  behind. Know that before you run it on someone's production box.
- **`--aggressive` is loud.** Many more requests, many more encodings. Fine on a
  lab, obvious in a SOC.
- **A confirmed inclusion isn't automatically high severity.** Reading a public
  template file is a different finding from reading credentials — check what you
  actually reached before writing it up.
- **Windows targets need different files.** Fingerprinting handles most of it,
  but if a target is unusual you may need to supply paths yourself.

## Authorised use

Only against systems you own or have written permission to test. Reading files
off a server you don't own is unauthorised access regardless of how easy the bug
was to find.

## License

MIT — see [LICENSE](LICENSE).
