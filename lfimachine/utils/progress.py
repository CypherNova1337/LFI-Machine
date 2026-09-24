"""
Live progress tracking.

Gives the operator a continuously-updated view of what the engine is doing:
current technique, target file, depth and encoder, plus total requests, live
request rate and elapsed time. On a TTY it repaints a single status line in
place; when output is redirected it emits a periodic heartbeat instead. Persistent
log lines are printed *above* the status line without corrupting it.
"""
from __future__ import annotations

import sys
import threading
import time
from typing import Callable, Optional

from lfimachine.utils import colors

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class Progress:
    def __init__(self, enabled: bool = True, stream=None, count_fn: Optional[Callable[[], int]] = None):
        self.stream = stream or sys.stderr
        tty = getattr(self.stream, "isatty", lambda: False)()
        self.live = enabled and tty
        self.heartbeat = enabled and not tty
        self.enabled = enabled
        self._count_fn = count_fn or (lambda: 0)

        self._activity = "starting"
        self._point = ""
        self._start = time.time()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._line_len = 0
        self._last_count = 0
        self._last_time = self._start
        self._rate = 0.0
        self._last_beat = 0.0

    # ---- wiring -----------------------------------------------------------
    def set_count_fn(self, fn: Callable[[], int]) -> None:
        self._count_fn = fn

    def point(self, text: str) -> None:
        with self._lock:
            self._point = text

    def activity(self, text: str) -> None:
        with self._lock:
            self._activity = text

    # ---- rendering --------------------------------------------------------
    def _compose(self, frame: str) -> str:
        elapsed = time.time() - self._start
        mins, secs = divmod(int(elapsed), 60)
        count = self._count_fn()
        parts = [
            colors.cyan(frame),
            colors.bold(self._activity),
        ]
        if self._point:
            parts.append(colors.grey(self._point))
        stats = f"{count} reqs · {self._rate:.0f}/s · {mins:d}:{secs:02d}"
        return f"{' '.join(parts)}  {colors.grey(stats)}"

    def _clear(self) -> None:
        if self._line_len:
            self.stream.write("\r" + " " * self._line_len + "\r")
            self._line_len = 0

    def _update_rate(self) -> None:
        now = time.time()
        count = self._count_fn()
        dt = now - self._last_time
        if dt >= 0.4:
            self._rate = (count - self._last_count) / dt
            self._last_count = count
            self._last_time = now

    def _loop(self) -> None:
        i = 0
        while not self._stop.is_set():
            self._update_rate()
            with self._lock:
                if self.live:
                    frame = _SPINNER[i % len(_SPINNER)]
                    line = self._compose(frame)
                    self._clear()
                    # Truncate to a sane width to avoid wrapping.
                    visible = line
                    self.stream.write(visible)
                    self.stream.flush()
                    # crude visible-length estimate (strip ANSI)
                    self._line_len = len(_strip_ansi(visible))
                elif self.heartbeat:
                    now = time.time()
                    if now - self._last_beat >= 3.0:
                        self._last_beat = now
                        elapsed = int(now - self._start)
                        self.stream.write(
                            f"[..] {self._activity} {self._point} · "
                            f"{self._count_fn()} reqs · {self._rate:.0f}/s · {elapsed}s\n"
                        )
                        self.stream.flush()
            i += 1
            self._stop.wait(0.12)

    # ---- lifecycle --------------------------------------------------------
    def write_line(self, text: str) -> None:
        """Emit a persistent line without clobbering the live status line."""
        with self._lock:
            if self.live:
                self._clear()
            self.stream.write(text + "\n")
            self.stream.flush()

    def start(self) -> "Progress":
        if self.enabled and self._thread is None:
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.5)
        with self._lock:
            self._clear()


def _strip_ansi(text: str) -> str:
    out = []
    i = 0
    while i < len(text):
        if text[i] == "\033":
            while i < len(text) and text[i] != "m":
                i += 1
            i += 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)
