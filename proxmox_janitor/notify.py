"""Notifications: Discord embeds, or any Apprise URL as markdown (see notice.py)."""

from __future__ import annotations

import logging
import time
from typing import Callable

from .bus import push_alert
from .findings import Finding
from .notice import ICON, Message, Outbox, Section, digest
from .state import State

log = logging.getLogger(__name__)

AUTHOR = "Proxmox janitor"
FOREVER_HOURS = 24 * 365 * 10

# Digest sections, in display order (findings are filed under one each).
PROBLEMS = "❌ Problems"
CPU = "🔥 Sustained high CPU"
MEM = "🧠 Sustained high memory"
DISK = "💾 Disks"
RESTART = "🔁 Restart or reboot needed"
PENDING = "🗓️ Patched in the next maintenance window"
SKIPPED = "⏸️ Not checked"
ORDER = [PROBLEMS, CPU, MEM, DISK, RESTART, PENDING, SKIPPED]
NOTES = {RESTART: "Done in the next maintenance window, or ask Hermes to patch it sooner."}

HEALTH_PREFIXES = ("cpu:", "mem:", "disk:")
KIND_LABEL = {"lxc": "CT", "qemu": "VM"}


def is_health(key: str) -> bool:
    return key.startswith(HEALTH_PREFIXES)


def labels(kind: str, ident: str, name: str, node: str) -> tuple[str, str]:
    """A node or guest named in plain text, and in markdown (name in bold, then where it lives)."""
    if kind == "node":
        return f"node {name}", f"**{name}** · host"
    where = f"{KIND_LABEL.get(kind, kind)} {ident} on {node}"
    return f"{name} ({where})", f"**{name}** · {where}"


class Notifier:
    def __init__(self, urls: list[str], renotify_hours: int, state: State, bot_url: str = "", bot_token: str = "",
                 footer: str = ""):
        self.renotify_hours = renotify_hours
        self.state = state
        self.bot_url, self.bot_token = bot_url, bot_token  # assistant first, Apprise as fallback
        self.outbox = Outbox(urls)
        self.footer = footer

    def send(self, findings: list[Finding], complete: bool = True, in_scope: Callable[[str], bool] | None = None,
             owns: Callable[[str], bool] | None = None, waiting: set[str] = frozenset()) -> None:
        """One digest: new items, reminders every renotify_hours, and items that cleared.

        owns(key) picks the findings this digest is responsible for (health and patch digests
        share one dedupe store). complete=False (some targets couldn't be checked) suppresses
        "cleared". in_scope(key) false means the target isn't checked any more: forgotten silently.
        waiting holds keys still unresolved but put off this time (e.g. until the window is done):
        neither new nor cleared.
        """
        with self.state.lock:
            notified = self.state["notified"]
            now = time.time()
            for k in [k for k in notified if in_scope and not in_scope(k)]:
                del notified[k]
            mine = {k: v for k, v in notified.items() if owns is None or owns(k)}
            current = ({f.key for f in findings} if complete else set(mine) | {f.key for f in findings}) | waiting

            due = []
            for f in findings:
                prev = notified.get(f.key)
                hours = FOREVER_HOURS if f.once else self.renotify_hours
                if prev is None or now - prev["ts"] >= hours * 3600:
                    due.append(f)

            cleared = [v["summary"] for k, v in mine.items()
                       if k not in current and not v.get("once") and v.get("severity") in ("warning", "error")]
            for k in [k for k in mine if k not in current]:
                del notified[k]

            if not due and not cleared:
                return
            msg = digest(AUTHOR, due, cleared, order=ORDER, notes=NOTES, footer=self.footer)
            if not self._deliver(msg, due):
                return  # not delivered: leave them due so the next check tries again
            for f in due:
                notified[f.key] = {"ts": now, "summary": f.summary, "severity": f.severity, "once": f.once}

    def report(self, title: str, lines: list[str]) -> bool:
        """A one-off message, e.g. the results of a maintenance window (lines start with their own icon)."""
        level = "error" if any(line.startswith("❌") for line in lines) else \
            "warning" if any("⚠️" in line for line in lines) else "ok"
        sections = [Section("", [line], bullets=False) for line in lines]  # a blank line between results
        return self._deliver(Message(f"{ICON[level]} {title}", level, sections, AUTHOR, self.footer), [])

    def _deliver(self, msg: Message, findings: list[Finding]) -> bool:
        """False only if a configured target failed (no targets at all counts as delivered)."""
        body = msg.markdown()
        log.info("%s\n%s", msg.title, body)
        if self.bot_url and push_alert(self.bot_url, self.bot_token, "janitor", msg.title, body, findings, None):
            return True
        return self.outbox.send(msg)
