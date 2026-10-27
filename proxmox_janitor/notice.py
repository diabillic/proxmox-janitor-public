"""Formatted notifications, shared by the agents.

A Message is a title plus sections (a bold heading, an optional note, then lines). Discord webhook
URLs get it as an embed: colour bar by level, agent name above the title, sections with spacing,
timestamp in the footer, posted under the agent's own name and service icon (not the webhook's
defaults). Every other Apprise URL (ntfy, Pushover, email, ...) gets the same content as markdown
text.
The same file is shared by every agent: keep the copies identical.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import apprise
import requests

log = logging.getLogger(__name__)

COLOR = {"error": 0xE74C3C, "warning": 0xE67E22, "info": 0x3498DB, "ok": 0x2ECC71}
ICON = {"error": "❌", "warning": "⚠️", "info": "ℹ️", "ok": "✅"}
PAGE = 3800  # characters per embed description; Discord allows 4096 per embed and 6000 per message
WEBHOOK = re.compile(r"^https://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+/?$")
FIXED, CLEARED = "fixed", "cleared"
# Who Discord shows as the sender: the agent, named like its container (proxmox_janitor -> proxmox-janitor).
AGENT_NAME = (__package__ or "agent").split(".")[0].replace("_", "-")
# The sender's avatar: the icon of the service the agent looks after (dashboard-icons, via jsDelivr).
ICONS = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons@main/png/{}.png"
SERVICES = {"sonarr": "sonarr", "radarr": "radarr", "unraid": "unraid", "proxmox": "proxmox",
            "patch": "proxmox", "dockerfile": "docker", "crowdsec": "crowdsec"}
AVATAR = next((ICONS.format(icon) for prefix, icon in SERVICES.items() if AGENT_NAME.startswith(prefix)), "")


@dataclass
class Section:
    heading: str
    lines: list[str]
    note: str = ""  # one italic line under the heading, e.g. what to do about these
    bullets: bool = True


@dataclass
class Message:
    title: str
    level: str = "info"  # error | warning | info | ok: colour and default icon
    sections: list[Section] = field(default_factory=list)
    author: str = ""  # e.g. "Proxmox janitor", shown small above the title
    footer: str = ""

    def blocks(self) -> list[str]:
        out = []
        for s in self.sections:
            head = ([f"**{s.heading}**"] if s.heading else []) + ([f"*{s.note}*"] if s.note else [])
            out.append("\n".join(head + [f"• {line}" if s.bullets else line for line in s.lines]))
        return out

    def markdown(self) -> str:
        return "\n\n".join(self.blocks())

    def pages(self, limit: int = PAGE) -> list[str]:
        """The body cut at section, then line, boundaries so each page fits one embed."""
        pages, cur = [], ""
        for block in self.blocks():
            lines = [line if len(line) <= limit else line[: limit - 1] + "…" for line in block.split("\n")]
            pieces = ["\n".join(lines)] if len(block) <= limit else lines  # whole section if it fits
            for i, piece in enumerate(pieces):
                sep = "\n\n" if i == 0 else "\n"  # blank line between sections
                if cur and len(cur) + len(sep) + len(piece) > limit:
                    pages.append(cur)
                    cur = piece
                else:
                    cur = f"{cur}{sep}{piece}" if cur else piece
        return pages + [cur] if cur else pages or [""]

    def embeds(self) -> list[dict]:
        pages, now = self.pages(), datetime.now(timezone.utc).isoformat()
        out = []
        for i, page in enumerate(pages, 1):
            title = self.title if len(pages) == 1 else f"{self.title} ({i}/{len(pages)})"
            embed = {"title": title[:256], "description": page, "color": COLOR.get(self.level, COLOR["info"]),
                     "timestamp": now}
            if self.author:
                embed["author"] = {"name": self.author[:256]}
            if self.footer:
                embed["footer"] = {"text": self.footer[:2048]}
            out.append(embed)
        return out


class Outbox:
    """Delivers Messages: embeds to Discord webhooks, markdown to everything else via Apprise."""

    def __init__(self, urls: list[str], kind: str = "notification", username: str = AGENT_NAME,
                 avatar: str = AVATAR):
        self.username, self.avatar = username[:80], avatar  # 80: Discord's limit
        self.webhooks = [u for u in urls if WEBHOOK.match(u.split("?", 1)[0])]
        self.apobj = apprise.Apprise()
        for url in urls:
            if url not in self.webhooks and not self.apobj.add(url):
                log.warning("Ignoring invalid %s URL (scheme %s)", kind, url.split(":", 1)[0])

    def __len__(self) -> int:
        return len(self.webhooks) + len(self.apobj)

    def send(self, msg: Message) -> bool:
        """False if any target failed (no targets at all counts as delivered)."""
        ok = True
        for url in self.webhooks:
            for embed in msg.embeds():
                payload = {"embeds": [embed], "allowed_mentions": {"parse": []}}
                if self.username:
                    payload["username"] = self.username
                if self.avatar:
                    payload["avatar_url"] = self.avatar
                ok = _post_webhook(url, payload) and ok
        if len(self.apobj):
            title = f"{msg.author}: {msg.title}" if msg.author else msg.title
            ok = bool(self.apobj.notify(title=title, body=msg.markdown(),
                                        body_format=apprise.NotifyFormat.MARKDOWN)) and ok
        if not ok:
            log.warning("One or more notification targets failed")
        return ok


def _post_webhook(url: str, payload: dict) -> bool:
    for _ in range(3):
        try:
            r = requests.post(url, json=payload, params={"wait": "true"}, timeout=15)
        except requests.RequestException as exc:
            log.warning("Discord webhook failed: %s", type(exc).__name__)
            return False
        if r.status_code == 429:  # rate limited: wait as told, then retry
            time.sleep(min(float(r.json().get("retry_after", 1)), 10))
            continue
        if r.ok:
            return True
        log.warning("Discord webhook rejected the message: HTTP %s %s", r.status_code, r.text[:200])
        return False
    return False


def digest(author: str, findings: list, cleared: list[str] = (), diagnosis: str | None = None,
           order: list[str] = (), notes: dict[str, str] | None = None, footer: str = "",
           fixed_heading: str = "✅ Fixed") -> Message:
    """One message for a set of findings, grouped into sections.

    A finding's section is its `section` attribute if it has one, else by state: fixed, then
    error, warning, info. Its line is its `line` attribute (markdown) or its summary. `order`
    lists custom sections in display order; `notes` adds a line under a section heading;
    `fixed_heading` renames the fixed section (e.g. for a dry run).
    """
    names = {FIXED: fixed_heading, "error": "❌ Problems", "warning": "⚠️ Needs attention",
             "info": "ℹ️ For your information", CLEARED: "✅ Cleared"}
    rank = {FIXED: 0, "error": 1, "warning": 2, "info": 3}
    groups: dict[str, list[str]] = {}
    levels = set()
    for f in sorted(findings, key=lambda f: rank.get(_state(f), 9)):
        state = _state(f)
        levels.add("ok" if state == FIXED else f.severity)
        groups.setdefault(getattr(f, "section", "") or names[state], []).append(getattr(f, "line", "") or f.summary)
    if cleared:
        levels.add("ok")
        groups[names[CLEARED]] = list(cleared)

    keys = list(order) + [k for k in groups if k not in order]
    sections = [Section(k, groups[k], (notes or {}).get(k, "")) for k in keys if k in groups]
    if diagnosis:
        sections.append(Section("🧠 Diagnosis", [diagnosis], bullets=False))

    level = next((lv for lv in ("error", "warning", "ok", "info") if lv in levels), "info")
    attention = sum(1 for f in findings if f.severity in ("error", "warning") and _state(f) != FIXED)
    fixed = sum(1 for f in findings if _state(f) == FIXED)
    parts = ([f"{attention} need{'s' if attention == 1 else ''} attention"] if attention else []) \
        + ([f"{fixed} fixed"] if fixed else []) + ([f"{len(cleared)} cleared"] if cleared else [])
    title = f"{ICON[level]} {', '.join(parts) if parts else 'Update'}"
    return Message(title, level, sections, author, footer)


def _state(f) -> str:
    return FIXED if getattr(f, "resolved", False) else f.severity
