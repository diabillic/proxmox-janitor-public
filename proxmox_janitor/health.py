"""Container health: the agent's loops check in here, and `python -m <package>.health` (the image's
HEALTHCHECK) fails when one of them is overdue or an endpoint the agent serves stops answering.

Each loop calls beat(name, within) every time round, promising to be back within that many seconds;
endpoint() registers a URL that must answer 200. Both are small files in HEALTH_DIR (container-local,
cleared by reset() at startup), so the check needs nothing from the running process but the files.
The same file is shared by every agent: keep the copies identical.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import time
import urllib.request

log = logging.getLogger(__name__)
PACKAGE = (__package__ or "agent").split(".")[0]


def _dir() -> str:
    return os.environ.get("HEALTH_DIR") or os.path.join(tempfile.gettempdir(), f"{PACKAGE}-health")


def _write(name: str, data: dict) -> None:
    try:
        os.makedirs(_dir(), exist_ok=True)
        path = os.path.join(_dir(), name.replace("/", "_") + ".json")
        with open(path + ".tmp", "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(path + ".tmp", path)
    except OSError as exc:  # health reporting must never break the agent
        log.debug("Couldn't record health for %s: %s", name, exc)


def reset() -> None:
    """Forget loops from a previous run (call once at startup, before the loops start)."""
    try:
        for entry in os.scandir(_dir()):
            os.unlink(entry.path)
    except OSError:
        pass


def beat(loop: str, within: float) -> None:
    """`loop` is alive and will beat again within `within` seconds."""
    _write(f"loop-{loop}", {"loop": loop, "at": time.time(), "deadline": time.time() + within})


def endpoint(name: str, url: str) -> None:
    """`url` must answer HTTP 200 for the agent to be healthy."""
    _write(f"url-{name}", {"endpoint": name, "url": url})


def check(timeout: float = 5) -> tuple[list[str], list[str]]:
    """(problems, fine): what's wrong, and what was checked and is fine."""
    problems, fine, now = [], [], time.time()
    try:
        entries = sorted(e.path for e in os.scandir(_dir()) if e.name.endswith(".json"))
    except OSError:
        entries = []
    for path in entries:
        try:
            with open(path, encoding="utf-8") as fh:
                item = json.load(fh)
        except (OSError, ValueError):
            continue  # being replaced right now
        if "loop" in item:
            late = now - item["deadline"]
            if late > 0:
                problems.append(f"{item['loop']}: overdue by {late:.0f}s (last ran {now - item['at']:.0f}s ago)")
            else:
                fine.append(f"{item['loop']} ran {now - item['at']:.0f}s ago")
        elif "url" in item:
            try:
                with urllib.request.urlopen(item["url"], timeout=timeout) as resp:
                    status = resp.status
            except Exception as exc:  # refused, timed out, HTTP error
                problems.append(f"{item['endpoint']}: {getattr(exc, 'reason', None) or exc}")
                continue
            (fine if status == 200 else problems).append(f"{item['endpoint']}: HTTP {status}")
    if not entries:
        problems.append("nothing has checked in yet")
    return problems, fine


def main() -> None:
    problems, fine = check()
    print("; ".join(problems) if problems else "healthy: " + "; ".join(fine))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
