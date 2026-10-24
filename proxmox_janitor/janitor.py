"""Patching, restarts and the weekly maintenance window.

The window runs three phases, one step at a time, and records every step in the state file:
  1. every guest: pre-patch snapshot, apt full-upgrade, restart if it needs one, drop the snapshot
  2. every Docker host: rebuild every agent container (fresh base image + apt full-upgrade)
  3. every node: apt full-upgrade, then a reboot if needed (quorate, all nodes online, one at a time),
     and guests that were running are started again if they didn't come back on their own
The janitor runs inside one of the guests, on one of the nodes and as one of the containers, so
everything that would restart it comes last in its phase, and the step is marked before it
happens: after the restart the janitor finds the unfinished window and carries on.
"""

from __future__ import annotations

import itertools
import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .config import DAYS, Config
from .findings import Finding
from .notify import PENDING, PROBLEMS, RESTART, SKIPPED, Notifier, is_health
from .pve import Cluster, Remote, RemoteError
from .state import State

log = logging.getLogger(__name__)

KIND_LABEL = {"lxc": "CT", "qemu": "VM"}
WAIT_GUEST = 600  # seconds for a restarted guest to run again
WAIT_NODE = 1800  # for a rebooted node to rejoin
WAIT_REDEPLOY = 5400  # for every agent on a Docker host to be rebuilt


@dataclass
class Target:
    key: str  # node:<name> | guest:<vmid>
    kind: str  # node | lxc | qemu
    ident: str  # node name or VMID
    name: str
    node: str
    tags: list[str] = field(default_factory=list)
    status: str = "running"  # running | stopped | excluded | ...
    supported: bool = True  # has apt
    updates: list[dict] = field(default_factory=list)
    removals: list[str] = field(default_factory=list)
    restart_needed: bool = False
    reasons: list[str] = field(default_factory=list)
    update_error: str = ""
    error: str = ""

    @property
    def label(self) -> str:
        if self.kind == "node":
            return f"node {self.name}"
        return f"{self.name} ({KIND_LABEL.get(self.kind, self.kind)} {self.ident} on {self.node})"

    @property
    def md(self) -> str:
        """Markdown label for notifications: the name in bold, then where it lives."""
        if self.kind == "node":
            return f"**{self.name}** · host"
        return f"**{self.name}** · {KIND_LABEL.get(self.kind, self.kind)} {self.ident} on {self.node}"

    @property
    def priority(self) -> str:
        if self.kind == "node":
            return "host"
        return next((t for t in self.tags if t.endswith("-priority")), "untagged")

    @property
    def security_count(self) -> int:
        return sum(1 for u in self.updates if u.get("security"))

    def summary(self) -> dict:
        return {"target": self.ident, "name": self.name, "kind": self.kind, "node": self.node,
                "priority": self.priority, "status": self.status, "updates": len(self.updates),
                "security_updates": self.security_count, "removals": self.removals,
                "restart_needed": self.restart_needed, "restart_reasons": self.reasons,
                "error": self.error or self.update_error}


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def schedule_due(cfg: Config, last: dict, now: datetime) -> list[str]:
    """Which scheduled runs are due at local time `now`: "check" daily, "window" weekly."""
    due, today, hhmm = [], now.date().isoformat(), now.strftime("%H:%M")
    if hhmm >= cfg.check_time and last.get("check") != today:
        due.append("check")
    start = now.replace(hour=int(cfg.window_time[:2]), minute=int(cfg.window_time[3:]), second=0, microsecond=0)
    if (DAYS[now.weekday()] == cfg.window_day and start <= now < start + timedelta(hours=cfg.window_hours)
            and last.get("window") != today):
        due.append("window")
    return due


class Janitor:
    def __init__(self, cluster: Cluster, docker: Remote, cfg: Config, notifier: Notifier, state: State,
                 runtime=None, sleep=time.sleep, clock=time.time):
        self.cluster, self.docker, self.cfg, self.notifier, self.state = cluster, docker, cfg, notifier, state
        self.runtime, self.sleep, self.clock = runtime, sleep, clock
        self.targets: dict[str, Target] = {}
        self.inventory: dict = {}
        self.last_check_at: float | None = None
        self.jobs: list[dict] = []
        self.queue: queue.Queue = queue.Queue()
        self.ops = threading.Lock()  # one change at a time: the window, a request, or a disk grow
        self._ids = itertools.count(1)
        self._lock = threading.Lock()  # guards targets/jobs for the bus threads

    # --- checking ---

    def _excluded(self, vmid: str, name: str) -> bool:
        return vmid in self.cfg.exclude or name in self.cfg.exclude

    @staticmethod
    def _fill(t: Target, facts: dict) -> None:
        t.supported = facts.get("supported", True)
        t.updates, t.removals = facts.get("updates") or [], facts.get("removals") or []
        t.restart_needed, t.reasons = bool(facts.get("restart_needed")), facts.get("reasons") or []
        t.update_error = facts.get("update_error") or ""
        if facts.get("running") is False:
            t.status = "stopped"

    def guest_target(self, g: dict) -> Target:
        vmid, name = str(g["vmid"]), g.get("name") or str(g["vmid"])
        tags = [x for x in str(g.get("tags") or "").replace(",", ";").split(";") if x]
        t = Target(f"guest:{vmid}", g.get("type", "lxc"), vmid, name, g.get("node", "?"), tags,
                   status=g.get("status") or "unknown")
        if self._excluded(vmid, name):
            t.status = "excluded"
        elif t.node not in self.cfg.nodes:
            t.error = f"its node {t.node} isn't in PVE_NODES"
        elif t.status == "running":
            try:
                self._fill(t, self.cluster.call(t.node, "guest-check", vmid))
            except RemoteError as exc:
                t.error = str(exc)
        return t

    def check(self) -> list[Finding]:
        """Refresh every node and guest, publish findings, and return them."""
        try:
            inv = self.cluster.inventory()
        except RemoteError as exc:
            findings = [Finding("check:inventory", f"Couldn't list the cluster's guests: {exc}", "error",
                                section=PROBLEMS)]
            self._publish(findings, complete=False)
            return findings

        targets: dict[str, Target] = {}
        for node in self.cfg.nodes:
            t = Target(f"node:{node}", "node", node, node, node)
            try:
                self._fill(t, self.cluster.call(node, "node-check"))
            except RemoteError as exc:
                t.error = str(exc)
            targets[t.key] = t
        for g in sorted(inv.get("guests") or [], key=lambda g: int(g["vmid"])):
            if not g.get("template"):
                t = self.guest_target(g)
                targets[t.key] = t

        with self._lock:
            self.targets, self.inventory, self.last_check_at = targets, inv, self.clock()
        findings = self.findings(targets.values(), quorate=inv.get("quorate", True))
        self._publish(findings, complete=not any(t.error for t in targets.values()))
        return findings

    def window_text(self) -> str:
        return f"{self.cfg.window_day.title()} {self.cfg.window_time}"

    def findings(self, targets, quorate: bool = True) -> list[Finding]:
        out = [] if quorate else [Finding("cluster:quorum", "The Proxmox cluster is not quorate.", "error",
                                          section=PROBLEMS)]
        for t in targets:
            if t.status == "excluded":
                continue
            if t.error:
                out.append(Finding(f"error:{t.key}", f"Couldn't check {t.label}: {t.error}",
                                   section=PROBLEMS, line=f"{t.md} — couldn't check: {t.error}"))
                continue
            if t.status == "stopped":
                out.append(Finding(f"stopped:{t.key}", f"{t.label} is stopped, so it isn't checked or patched.",
                                   "info", once=True, section=SKIPPED, line=f"{t.md} — stopped"))
                continue
            if not t.supported:
                out.append(Finding(f"unsupported:{t.key}", f"{t.label} has no apt, so the janitor can't patch it.",
                                   "info", once=True, section=SKIPPED, line=f"{t.md} — no apt, can't be patched"))
                continue
            if t.update_error:
                out.append(Finding(f"apt:{t.key}", f"apt can't refresh its package lists on {t.label}: {t.update_error}",
                                   section=PROBLEMS,
                                   line=f"{t.md} — apt can't refresh its package lists: {t.update_error}"))
            if t.updates:
                count = plural(len(t.updates), "update") + (f" ({t.security_count} security)" if t.security_count else "")
                out.append(Finding(f"updates:{t.key}", f"{t.label}: {count}, to be applied in the {self.window_text()} "
                                                       "maintenance window.",
                                   "info", once=True, section=PENDING, line=f"{t.md} — {count}"))
            if t.restart_needed:
                what = "reboot" if t.kind in ("node", "qemu") else "restart"
                why = "; ".join(t.reasons)
                out.append(Finding(f"restart:{t.key}", f"{t.label} needs a {what} ({why}); it gets one in the "
                                                       f"{self.window_text()} maintenance window.",
                                   "info", once=True, section=RESTART, line=f"{t.md} — {what}: {why}"))
        return out

    def _publish(self, findings: list[Finding], complete: bool) -> None:
        checked = set(self.targets)

        def in_scope(key: str) -> bool:  # "updates:guest:104" belongs to target "guest:104"
            if is_health(key):
                return True
            target = key.split(":", 1)[1] if ":" in key else ""
            return not target.startswith(("guest:", "node:")) or target in checked

        self.notifier.send(findings, complete=complete, in_scope=in_scope, owns=lambda k: not is_health(k))
        self.state.save()
        if self.runtime:
            self.runtime.record(findings, None)

    # --- guests ---

    def is_self(self, t: Target) -> bool:
        return t.kind != "node" and t.ident == self.cfg.self_guest

    def self_node(self) -> str | None:
        for g in self.inventory.get("guests") or []:
            if str(g.get("vmid")) == self.cfg.self_guest:
                return g.get("node")
        return None

    def _wait_guest(self, t: Target) -> bool:
        deadline = self.clock() + WAIT_GUEST
        self.sleep(15)
        while self.clock() < deadline:
            try:
                st = self.cluster.call(t.node, "guest-status", t.ident, timeout=90)
                if st.get("running") and (t.kind != "qemu" or st.get("agent")):
                    return True
            except RemoteError:
                pass
            self.sleep(10)
        return False

    def _drop_snapshot(self, t: Target, snap: str | None) -> str:
        if not snap or self.cfg.keep_snapshots:
            return f" Snapshot {snap} kept." if snap else ""
        try:
            self.cluster.call(t.node, "guest-delsnapshot", t.ident, snap, timeout=900)
            return ""
        except RemoteError as exc:
            return f" (Couldn't delete snapshot {snap}: {exc})"

    def patch_guest(self, t: Target, step: dict | None = None) -> str:
        """Snapshot, patch, check, restart if needed. The snapshot is the rollback point: deleted once
        everything succeeded, kept whenever something didn't. For the janitor's own guest the step is
        marked "rebooting" before the restart, which takes the janitor down with it."""
        done, snap = "no updates", None
        if t.updates:
            try:
                snap = self.cluster.call(t.node, "guest-snapshot", t.ident, str(self.cfg.snapshot_keep),
                                         timeout=900)["snapshot"]
            except RemoteError as exc:
                return f"❌ {t.md}: not patched, the pre-patch snapshot failed: {exc}"
            kept = f"Snapshot {snap} kept for rollback."
            try:
                res = self.cluster.call(t.node, "guest-patch", t.ident, timeout=3700)
            except RemoteError as exc:
                return f"❌ {t.md}: patching failed: {exc}. {kept}"
            if not res.get("ok"):
                tail = (res.get("log") or "").strip().splitlines()[-3:]
                return f"❌ {t.md}: apt exited {res.get('rc')}. {kept} Last output: {' / '.join(tail)}"
            done = f"{plural(len(t.updates), 'update')} applied"
        kept = f" Snapshot {snap} kept for rollback." if snap else ""
        try:
            after = self.cluster.call(t.node, "guest-check", t.ident)
        except RemoteError as exc:
            return f"⚠️ {t.md}: {done}, but the follow-up check failed: {exc}.{kept}"
        if not after.get("restart_needed"):
            return f"✅ {t.md}: {done}." + self._drop_snapshot(t, snap)
        why = "; ".join(after.get("reasons") or [])
        if not self.cfg.reboot_guests:
            return f"✅ {t.md}: {done}. ⚠️ It needs a restart ({why}); restarts are turned off." + \
                self._drop_snapshot(t, snap)
        if self.is_self(t) and step is not None:
            note = self._drop_snapshot(t, snap)  # the janitor won't be here to do it afterwards
            step.update(status="rebooting", result=f"✅ {t.md}: {done}, then restarted ({why}).{note}")
            self.state.save()
        try:
            self.cluster.call(t.node, "guest-reboot", t.ident, timeout=120)
        except RemoteError as exc:
            return f"⚠️ {t.md}: {done}, but the restart failed: {exc}.{kept}"
        if self.is_self(t):
            self.sleep(WAIT_GUEST)  # the restart takes this process down; still here means it didn't happen
            return f"⚠️ {t.md}: {done}; the janitor's own guest was asked to restart but kept running."
        if not self._wait_guest(t):
            return f"❌ {t.md}: {done}, restarted, but it isn't running again after {WAIT_GUEST // 60} min.{kept}"
        return f"✅ {t.md}: {done}, then restarted ({why})." + self._drop_snapshot(t, snap)

    # --- docker hosts ---

    def redeploy(self, host: str, step: dict | None = None) -> str:
        """Rebuild every agent container on one Docker host and wait for the result. The run is its
        own unit on the host, so it finishes even when it replaces the janitor's container."""
        step = step if step is not None else {}
        if not step.get("started_at"):
            res = self.docker.call(host, "redeploy-start", timeout=60)
            step.update(status="running", started_at=self.clock() if res.get("started") else step.get("started_at", 0))
            self.state.save()
        deadline = self.clock() + WAIT_REDEPLOY
        while True:
            self.sleep(20)
            st = self.docker.call(host, "redeploy-status", timeout=60)
            if st.get("finished") and st.get("started", 0) >= step["started_at"] - 120:
                break
            if self.clock() > deadline:
                return f"❌ **{host}**: the container rebuild didn't finish within {WAIT_REDEPLOY // 60} min."
        results = st.get("results") or {}
        if not results:
            return f"✅ **{host}**: no agent containers to rebuild."
        failed = {n: r for n, r in results.items() if not r.get("ok")}
        if failed:
            name, r = next(iter(failed.items()))
            tail = " / ".join((r.get("log") or "").splitlines()[-2:])
            return (f"❌ **{host}**: rebuilt {len(results) - len(failed)} of {len(results)} agents; failed: "
                    f"{', '.join(failed)} (the previous container keeps running). {name}: {tail}")
        return f"✅ **{host}**: rebuilt {plural(len(results), 'agent')} fully patched ({', '.join(sorted(results))})."

    # --- nodes ---

    def patch_node(self, t: Target) -> tuple[str, list[str]]:
        """apt full-upgrade on a node: the result line, and why it needs a reboot (if it does)."""
        try:
            res = self.cluster.call(t.node, "node-patch", timeout=3700)
        except RemoteError as exc:
            return f"❌ {t.md}: {exc}", []
        if not res.get("ok"):
            tail = (res.get("log") or "").strip().splitlines()[-3:]
            return f"❌ {t.md}: apt exited {res.get('rc')}. Last output: {' / '.join(tail)}", []
        return f"✅ {t.md}: {plural(len(t.updates), 'update')} applied.", res.get("reasons") or []

    def _node_state(self, node: str) -> dict | None:
        others = [n for n in self.cfg.nodes if n != node]
        try:
            inv = self.cluster.inventory(prefer=others)
        except RemoteError:
            return None
        self.inventory = inv
        return next((n for n in inv.get("nodes") or [] if n.get("node") == node), None)

    def reboot_node(self, t: Target, step: dict) -> str:
        """Reboot a node (the step records which guests were running), wait for it to rejoin, then
        start whatever was running and didn't come back on its own."""
        if step.get("status") != "rebooting":
            self._node_state(t.node)  # fresh: which guests are running right now
            step["restore"] = [str(g["vmid"]) for g in self.inventory.get("guests") or []
                               if g.get("node") == t.node and g.get("status") == "running" and not g.get("template")]
            step.update(status="rebooting", reboot_at=self.clock())
            self.state.save()
            if t.node == self.self_node():
                self.notifier.report("Maintenance window: rebooting " + t.name,
                                     [f"🔁 {t.md}: rebooting now. The janitor runs on it and finishes the window "
                                      "when it's back."])
            self.cluster.call(t.node, "node-reboot", timeout=120)
            if t.node == self.self_node():
                self.sleep(WAIT_NODE)
                return f"⚠️ {t.md}: asked to reboot, but the janitor (running on it) never went down."
            self.sleep(60)
        deadline = self.clock() + WAIT_NODE
        while True:
            n = self._node_state(t.node)
            if n and n.get("status") == "online" and (n.get("uptime") or 0) < self.clock() - step["reboot_at"] + 120:
                break
            if self.clock() > deadline:
                return f"❌ {t.md}: rebooted, but it hasn't rejoined the cluster after {WAIT_NODE // 60} min."
            self.sleep(20)
        self.sleep(120)  # guests set to start on boot start on their own
        started, failed = [], []
        for vmid in step.get("restore") or []:
            try:
                if self.cluster.call(t.node, "guest-start", vmid, timeout=360).get("started"):
                    started.append(vmid)
            except RemoteError as exc:
                failed.append(f"{vmid} ({exc})")
        line = f"✅ {t.md}: rebooted ({'; '.join(step.get('reasons') or [])})."
        if started:
            line += f" Started {', '.join(started)} again (they don't start on boot)."
        if failed:
            line = "⚠️" + line[1:] + f" Couldn't start {', '.join(failed)}."
        return line

    # --- the maintenance window ---

    def plan_steps(self) -> list[dict]:
        """Every step of a window from the last check, the janitor's own guest/host/node last in each phase."""
        guests = [t for t in self.targets.values()
                  if t.kind != "node" and t.status == "running" and t.supported and not t.error
                  and (t.updates or t.restart_needed)]
        guests.sort(key=lambda t: (self.is_self(t), t.node, int(t.ident)))
        steps = [{"kind": "guest", "id": t.ident, "status": "pending"} for t in guests]
        if self.cfg.redeploy:
            me = next((g.get("name") for g in self.inventory.get("guests") or []
                       if str(g.get("vmid")) == self.cfg.self_guest), None)
            steps += [{"kind": "redeploy", "id": h, "status": "pending"}
                      for h in sorted(self.cfg.docker_hosts, key=lambda h: h == me)]
        here = self.self_node()
        nodes = [t for t in self.targets.values() if t.kind == "node" and not t.error and (t.updates or t.restart_needed)]
        nodes.sort(key=lambda t: t.node == here)
        steps += [{"kind": "node", "id": t.node, "status": "pending"} for t in nodes]
        return steps

    def run_window(self, resume: bool = False) -> list[str]:
        win = self.state["window"]
        if not (resume and win.get("steps") and not win.get("finished")):
            self.check()
            win.clear()
            win.update(started=self.clock(), steps=self.plan_steps(), finished=None)
            self.state.save()
            log.info("Maintenance window: %d step(s)", len(win["steps"]))
        elif not self.targets:
            self.check()  # resumed in a fresh process: refresh facts first
        for step in win["steps"]:
            if step["status"] == "done":
                continue
            try:
                step["result"] = self._run_step(step)
            except RemoteError as exc:
                step["result"] = f"❌ {step['kind']} {step['id']}: {exc}"
            step["status"] = "done"
            self.state.save()
        win["finished"] = self.clock()
        self.state.save()
        self.check()  # refresh status and clear what got done
        lines = [s["result"] for s in win["steps"] if s.get("result")] or ["Nothing needed doing."]
        self.notifier.report("Maintenance window", lines)
        return lines

    def _run_step(self, step: dict) -> str:
        if step["kind"] == "redeploy":
            return self.redeploy(step["id"], step)
        if step["kind"] == "guest":
            t = self.targets.get(f"guest:{step['id']}")
            if t is None:
                return f"⏭️ guest {step['id']}: no longer in the cluster."
            if step["status"] == "rebooting":  # resumed after the janitor's own guest restarted
                return step.get("result") or f"✅ {t.md}: restarted."
            step["status"] = "running"
            self.state.save()
            if t.status != "running" or t.error:
                return f"⏭️ {t.md}: skipped ({t.error or t.status})."
            return self.patch_guest(t, step)
        t = self.targets.get(f"node:{step['id']}")
        if t is None:
            return f"⏭️ node {step['id']}: not configured any more."
        if step["status"] != "rebooting":
            step["status"] = "running"
            self.state.save()
            line, reasons = self.patch_node(t) if t.updates else (f"✅ {t.md}: no updates.", t.reasons)
            step.update(patched=line, reasons=reasons or t.reasons)
            if not (step["reasons"] and self.cfg.reboot_nodes) or line.startswith("❌"):
                return line + (f" ⚠️ It needs a reboot ({'; '.join(step['reasons'])}); node reboots are off."
                               if step["reasons"] and not line.startswith("❌") else "")
        return step.get("patched", "") + " " + self.reboot_node(t, step)

    # --- jobs (one at a time, on the worker thread) ---

    def submit(self, kind: str, idents: list[str], requested_by: str) -> dict:
        job = {"id": next(self._ids), "kind": kind, "targets": idents, "requested_by": requested_by,
               "state": "queued", "queued_at": self.clock(), "results": []}
        with self._lock:
            self.jobs = (self.jobs + [job])[-20:]
        self.queue.put(job)
        return {k: job[k] for k in ("id", "kind", "targets", "state")}

    def run_job(self, job: dict) -> None:
        job["state"], job["started_at"] = "running", self.clock()
        try:
            with self.ops:
                if job["kind"] == "check":
                    self.check()
                elif job["kind"] in ("window", "resume"):
                    job["results"] = self.run_window(resume=job["kind"] == "resume")
                else:
                    self._run_request(job)
            job["state"] = "done"
        except Exception as exc:  # keep the worker alive; report and move on
            log.exception("Job %s failed", job["id"])
            job["state"], job["results"] = "failed", job["results"] + [f"❌ {exc}"]
            self.notifier.report(f"Job {job['id']} failed", job["results"])
        job["finished_at"] = self.clock()

    def _run_request(self, job: dict) -> None:
        self.check()  # act on fresh facts
        if job["kind"] == "redeploy":
            for host in job["targets"]:
                job["results"].append(self.redeploy(host))
        else:
            for key in job["targets"]:
                t = self.targets.get(key)
                if t is None:
                    job["results"].append(f"⏭️ {key}: not found any more.")
                elif t.kind == "node":
                    job["results"].append(self.patch_node(t)[0] + (
                        f" ⚠️ It needs a reboot ({'; '.join(t.reasons)}); that happens in the maintenance window."
                        if t.reasons else ""))
                elif t.status != "running" or t.error:
                    job["results"].append(f"⏭️ {t.md}: skipped ({t.error or t.status}).")
                elif self.is_self(t):
                    job["results"].append(f"⏭️ {t.md}: the janitor's own guest is only patched in the maintenance window.")
                else:
                    job["results"].append(self.patch_guest(t))
        self.notifier.report(f"Requested {job['kind']} run", job["results"] or ["Nothing to do."])
        self.check()

    def worker(self) -> None:
        while True:
            self.run_job(self.queue.get())

    # --- agent bus ---

    def _find(self, ident: str) -> Target:
        ident = str(ident).strip()
        with self._lock:
            for t in self.targets.values():
                if ident in (t.ident, t.name, t.key):
                    return t
        raise ValueError(f"no checked node or guest called {ident!r}; run agent_run_check first if it's new")

    def status(self) -> dict:
        with self._lock:
            targets = [t.summary() for t in self.targets.values()]
            jobs = [{k: j.get(k) for k in ("id", "kind", "targets", "state")} for j in self.jobs[-5:]]
        win = self.state["window"]
        return {"last_check_seconds_ago": None if self.last_check_at is None else int(self.clock() - self.last_check_at),
                "schedule": f"check daily at {self.cfg.check_time}; maintenance window {self.window_text()} "
                            f"({self.cfg.timezone}): every guest, then every agent container, then every node",
                "window": {"in_progress": bool(win.get("steps") and not win.get("finished")),
                           "steps": [{k: s.get(k) for k in ("kind", "id", "status", "result")} for s in win.get("steps") or []]},
                "targets": targets, "recent_jobs": jobs}

    def list_updates(self, target: str) -> dict:
        t = self._find(target)
        return {**t.summary(), "packages": t.updates}

    def job_status(self, job_id: int | None = None) -> dict | list:
        with self._lock:
            jobs = [dict(j) for j in self.jobs]
        if job_id is None:
            return jobs[-5:]
        for j in jobs:
            if j["id"] == int(job_id):
                return j
        raise ValueError(f"no job {job_id}")

    def request_guests(self, vmids: list[int]) -> dict:
        if not vmids:
            raise ValueError("give at least one VMID")
        keys = []
        for v in vmids:
            t = self._find(str(v))
            if t.kind == "node":
                raise ValueError(f"{v} is a node; use patch_node")
            if t.status != "running" or t.error or not t.supported:
                raise ValueError(f"{t.label} can't be patched now ({t.error or t.status if t.supported else 'no apt'})")
            keys.append(t.key)
        return {**self.submit("guests", keys, "agent bus"),
                "message": "Queued. Results are posted to the notification channel; job_status shows progress."}

    def request_node(self, node: str) -> dict:
        t = self._find(node)
        if t.kind != "node":
            raise ValueError(f"{node} is a guest; use patch_guests")
        return {**self.submit("node", [t.key], "agent bus"),
                "message": "Queued. Patches only; a needed reboot happens in the maintenance window."}

    def request_redeploy(self, host: str = "all") -> dict:
        hosts = list(self.cfg.docker_hosts) if host in ("", "all") else [host]
        unknown = [h for h in hosts if h not in self.cfg.docker_hosts]
        if unknown or not hosts:
            raise ValueError(f"unknown Docker host {', '.join(unknown) or host!r}; known: {', '.join(self.cfg.docker_hosts)}")
        return {**self.submit("redeploy", hosts, "agent bus"),
                "message": "Queued. Every agent container on those hosts is rebuilt fully patched; results follow."}
