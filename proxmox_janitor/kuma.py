"""Uptime Kuma: a Docker container monitor for every agent on every Docker host.

Every KUMA_SYNC_MINUTES the janitor asks each Docker host which containers agent-deploy runs there
(agent-redeploy-ssh `containers`), and makes sure every agent (kind=agent; apps such as Uptime
Kuma itself aren't agents) has a "Docker Container" monitor in Uptime Kuma on that host's Docker
host entry, by container name, with the same settings and notification as the rest. New agents get
theirs within one sync; existing monitors are never changed or deleted.

Uptime Kuma has no REST API for this, so it talks socket.io like the web UI: login, then the
lists the server pushes (monitorList, notificationList, dockerHostList), then "add".

One-time setup (notification + Docker hosts), run inside the janitor container:
  echo "$WEBHOOK" | python -m proxmox_janitor.kuma setup --docker-host docker1=tcp://proxy:2375 ...
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import time

from . import health
from .config import Config
from .pve import Remote, RemoteError

log = logging.getLogger(__name__)

MANAGED = "Added by the Proxmox janitor: a container monitor for this agent."


class KumaError(Exception):
    pass


class KumaClient:
    def __init__(self, url: str, username: str, password: str, timeout: int = 30):
        self.url, self.username, self.password, self.timeout = url, username, password, timeout
        self.monitors: dict = {}
        self.notifications: list = []
        self.docker_hosts: list = []
        self._got = {"monitorList": threading.Event(), "notificationList": threading.Event(),
                     "dockerHostList": threading.Event()}
        self.sio = None

    def __enter__(self) -> "KumaClient":
        import socketio  # only needed when Uptime Kuma is configured

        self.sio = socketio.Client(reconnection=False)
        for event, attr in (("monitorList", "monitors"), ("notificationList", "notifications"),
                            ("dockerHostList", "docker_hosts")):
            self.sio.on(event, self._keeper(event, attr))
        try:
            self.sio.connect(self.url, transports=["websocket"], wait_timeout=self.timeout)
            res = self.sio.call("login", {"username": self.username, "password": self.password, "token": ""},
                                timeout=self.timeout) or {}
        except Exception as exc:  # socket.io raises several kinds
            self.close()
            raise KumaError(f"couldn't reach Uptime Kuma at {self.url}: {type(exc).__name__} {exc}".rstrip()) from None
        if not res.get("ok"):
            self.close()
            why = "the account has 2FA, which the janitor can't answer" if res.get("tokenRequired") else (res.get("msg") or res)
            raise KumaError(f"Uptime Kuma login failed: {why}")
        deadline = time.time() + self.timeout
        for ev in self._got.values():
            if not ev.wait(max(0.1, deadline - time.time())):
                self.close()
                raise KumaError("Uptime Kuma didn't send its lists after login")
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _keeper(self, event: str, attr: str):
        def keep(data):
            setattr(self, attr, data)
            self._got[event].set()
        return keep

    def close(self) -> None:
        if self.sio is not None:
            try:
                self.sio.disconnect()
            except Exception:
                pass

    def _call(self, event: str, *args) -> dict:
        res = self.sio.call(event, args if len(args) > 1 else args[0], timeout=self.timeout) or {}
        if not res.get("ok"):
            raise KumaError(f"{event} failed: {res.get('msg') or res}")
        return res

    def add_monitor(self, monitor: dict) -> int:
        return self._call("add", monitor)["monitorID"]

    def add_notification(self, notification: dict) -> dict:
        return self._call("addNotification", notification, None)

    def add_docker_host(self, docker_host: dict) -> dict:
        return self._call("addDockerHost", docker_host, None)


def monitor_for(container: str, name: str, docker_host_id: int, notification_id: int | None, cfg: Config) -> dict:
    """A Docker Container monitor with the shared settings."""
    return {
        "type": "docker", "name": name, "docker_container": container, "docker_host": docker_host_id,
        "interval": cfg.kuma_interval, "retryInterval": cfg.kuma_interval, "resendInterval": 0,
        "maxretries": cfg.kuma_retries, "active": True, "upsideDown": False, "description": MANAGED,
        "accepted_statuscodes": ["200-299"], "conditions": [], "kafkaProducerBrokers": [],
        "kafkaProducerSaslOptions": {"mechanism": "None"}, "rabbitmqNodes": [],
        "notificationIDList": {str(notification_id): True} if notification_id else {},
    }


def plan(agents: dict[str, list[str]], kuma: KumaClient, cfg: Config) -> tuple[list[dict], list[str]]:
    """Monitors to add for `agents` ({docker host: [container, ...]}), and problems to report."""
    hosts = {h.get("name"): h.get("id") for h in kuma.docker_hosts}
    notif = next((n.get("id") for n in kuma.notifications if n.get("name") == cfg.kuma_notification), None)
    problems = [] if notif else [f"Uptime Kuma has no notification called {cfg.kuma_notification!r}"]
    have = {(m.get("docker_host"), m.get("docker_container")) for m in kuma.monitors.values() if m.get("type") == "docker"}
    names = {m.get("name") for m in kuma.monitors.values()}
    todo = []
    for host, containers in agents.items():
        kuma_host = cfg.kuma_docker_hosts.get(host, host)
        if kuma_host not in hosts:
            if containers:
                problems.append(f"Uptime Kuma has no Docker host called {kuma_host!r} (for {host})")
            continue
        for c in containers:
            if (hosts[kuma_host], c) in have:
                continue
            name = c if c not in names else f"{c} ({host})"
            todo.append(monitor_for(c, name, hosts[kuma_host], notif, cfg))
            names.add(name)
    return todo, problems


class KumaSync:
    def __init__(self, docker: Remote, cfg: Config, notifier, state, client=KumaClient):
        self.docker, self.cfg, self.notifier, self.state, self.client = docker, cfg, notifier, state, client

    def agents(self) -> dict[str, list[str]]:
        out = {}
        for host in self.cfg.docker_hosts:
            res = self.docker.call(host, "containers", timeout=60)
            out[host] = sorted(c["name"] for c in res.get("containers") or [] if c.get("kind", "agent") == "agent")
        return out

    def run_once(self) -> list[str]:
        """Add whatever is missing; returns the result lines (also posted when something was added)."""
        try:
            agents = self.agents()
            with self.client(self.cfg.kuma_url, self.cfg.kuma_username, self.cfg.kuma_password) as kuma:
                todo, problems = plan(agents, kuma, self.cfg)
                added = []
                for m in todo:
                    kuma.add_monitor(m)
                    added.append(f"📟 Added an Uptime Kuma monitor for **{m['docker_container']}** "
                                 f"(container on {next(h for h, cs in agents.items() if m['docker_container'] in cs)}).")
        except (RemoteError, KumaError) as exc:
            problems, added = [str(exc)], []
        self._report(added, problems)
        return added + [f"⚠️ {p}" for p in problems]

    def _report(self, added: list[str], problems: list[str]) -> None:
        seen = self.state["kuma"]
        if added:
            self.notifier.report("Uptime Kuma monitors", added)
        key = "; ".join(problems)
        if problems and seen.get("problems") != key:  # each distinct problem once
            if self.notifier.report("Uptime Kuma sync", [f"⚠️ {p}" for p in problems]):
                seen["problems"] = key
        elif not problems and seen.pop("problems", None):
            self.notifier.report("Uptime Kuma sync", ["✅ Syncing monitors works again."])
        self.state.save()

    def loop(self) -> None:
        while True:
            health.beat("kuma sync", self.cfg.kuma_sync_minutes * 60 + 10 * 60)
            try:
                self.run_once()
            except Exception:  # keep syncing
                log.exception("Uptime Kuma sync failed")
            time.sleep(self.cfg.kuma_sync_minutes * 60)


def setup(cfg: Config, webhook: str, docker_hosts: dict[str, str], username: str) -> list[str]:
    """Create the shared notification and the Docker host entries if they don't exist yet."""
    done = []
    with KumaClient(cfg.kuma_url, cfg.kuma_username, cfg.kuma_password) as kuma:
        if not any(n.get("name") == cfg.kuma_notification for n in kuma.notifications):
            kuma.add_notification({"name": cfg.kuma_notification, "type": "discord", "discordWebhookUrl": webhook,
                                   "discordUsername": username, "discordChannelType": "channel",
                                   "isDefault": False, "applyExisting": False})
            done.append(f"notification {cfg.kuma_notification}")
        existing = {h.get("name") for h in kuma.docker_hosts}
        for name, daemon in docker_hosts.items():
            if name not in existing:
                kuma.add_docker_host({"name": name, "dockerType": "tcp", "dockerDaemon": daemon})
                done.append(f"docker host {name} ({daemon})")
    return done


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m proxmox_janitor.kuma")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup", help="create the notification (webhook on stdin) and Docker hosts, then sync")
    s.add_argument("--docker-host", action="append", default=[], metavar="NAME=tcp://HOST:PORT")
    s.add_argument("--discord-username", default="Uptime Kuma")
    sub.add_parser("sync", help="add any missing agent monitors now")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cfg = Config.from_env()
    if not cfg.kuma_url:
        raise SystemExit("KUMA_URL, KUMA_USERNAME and KUMA_PASSWORD must be set")
    if args.cmd == "setup":
        webhook = sys.stdin.readline().strip()
        if not webhook.startswith("https://"):
            raise SystemExit("pipe the Discord webhook URL on stdin")
        hosts = dict(h.split("=", 1) for h in args.docker_host)
        for line in setup(cfg, webhook, hosts, args.discord_username) or ["nothing to create"]:
            print("created:", line)
    import tempfile

    from .notify import Notifier
    from .state import State
    state = State(tempfile.mktemp(suffix=".json"))  # not the running janitor's state file
    docker = Remote(cfg.docker_hosts, cfg.ssh_key, cfg.known_hosts, user="deploy")
    for line in KumaSync(docker, cfg, Notifier(cfg.notify_urls, cfg.renotify_hours, state), state).run_once() or ["in sync"]:
        print(line)


if __name__ == "__main__":
    main()
