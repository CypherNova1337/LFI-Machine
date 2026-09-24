"""Tiny leveled logger used across the engine."""
from __future__ import annotations

import sys
import threading
import time

from lfimachine.utils import colors

_LEVELS = {"quiet": 0, "normal": 1, "verbose": 2, "debug": 3}
_lock = threading.Lock()


class Logger:
    def __init__(self, level: str = "normal") -> None:
        self.level = _LEVELS.get(level, 1)
        self._start = time.time()
        self._sink = None  # optional callable(str) that owns the terminal line

    def attach_sink(self, sink) -> None:
        """Route persistent output through a Progress writer so the live status
        line is cleared before each log line and repainted after."""
        self._sink = sink

    def _emit(self, tag: str, msg: str, min_level: int, stream=sys.stderr) -> None:
        if self.level < min_level:
            return
        line = f"{tag} {msg}"
        with _lock:
            if self._sink is not None:
                self._sink(line)
            else:
                stream.write(line + "\n")
                stream.flush()

    def info(self, msg: str) -> None:
        self._emit(colors.cyan("[*]"), msg, 1)

    def good(self, msg: str) -> None:
        self._emit(colors.green("[+]"), msg, 1)

    def warn(self, msg: str) -> None:
        self._emit(colors.yellow("[!]"), msg, 1)

    def error(self, msg: str) -> None:
        self._emit(colors.red("[x]"), msg, 0)

    def verbose(self, msg: str) -> None:
        self._emit(colors.grey("[.]"), colors.grey(msg), 2)

    def debug(self, msg: str) -> None:
        self._emit(colors.grey("[d]"), colors.grey(msg), 3)
