"""Minimal ANSI colour helper with auto-detection and NO_COLOR support."""
from __future__ import annotations

import os
import sys

_ENABLED = (
    sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM") != "dumb"
)


def disable() -> None:
    global _ENABLED
    _ENABLED = False


def force() -> None:
    global _ENABLED
    _ENABLED = True


_CODES = {
    "reset": "0",
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
    "grey": "90",
    "bright_red": "91",
    "bright_green": "92",
    "bright_yellow": "93",
}


def paint(text: str, *styles: str) -> str:
    if not _ENABLED or not styles:
        return text
    prefix = "".join(f"\033[{_CODES[s]}m" for s in styles if s in _CODES)
    return f"{prefix}{text}\033[0m"


def red(t: str) -> str:
    return paint(t, "red")


def green(t: str) -> str:
    return paint(t, "green")


def yellow(t: str) -> str:
    return paint(t, "yellow")


def cyan(t: str) -> str:
    return paint(t, "cyan")


def bold(t: str) -> str:
    return paint(t, "bold")


def grey(t: str) -> str:
    return paint(t, "grey")
