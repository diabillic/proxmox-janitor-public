"""Small JSON state file so decisions survive restarts (seen items, cooldowns, last states)."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from typing import Any


class State:
    SECTIONS = ("notified", "schedule", "window", "over", "grown", "kuma")

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()  # the scheduler and the worker thread both write
        self.data: dict[str, dict[str, Any]] = {s: {} for s in self.SECTIONS}
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    loaded = json.load(fh)
                for s in self.SECTIONS:
                    self.data[s] = loaded.get(s, {})
            except (OSError, ValueError):
                pass  # corrupt state just means everything looks new once

    def save(self) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        with self.lock:
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state-")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=1, sort_keys=True)
            os.replace(tmp, self.path)

    def __getitem__(self, section: str) -> dict[str, Any]:
        return self.data[section]

    def within(self, section: str, key: str, hours: float, now: float | None = None) -> bool:
        ts = self.data[section].get(key)
        return ts is not None and (now or time.time()) - ts < hours * 3600

    def mark(self, section: str, key: str, now: float | None = None) -> None:
        self.data[section][key] = now or time.time()

    def expire(self, section: str, hours: float, now: float | None = None) -> None:
        cutoff = (now or time.time()) - hours * 3600
        sec = self.data[section]
        for k in [k for k, ts in sec.items() if isinstance(ts, (int, float)) and ts < cutoff]:
            del sec[k]
