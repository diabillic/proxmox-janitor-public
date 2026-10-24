import importlib.machinery
import importlib.util
import json
import pathlib
import re
import subprocess
from datetime import datetime

import pytest

from proxmox_janitor.config import Config
from proxmox_janitor.findings import Finding
from proxmox_janitor.janitor import Janitor, Target, schedule_due
from proxmox_janitor.monitor import GIB, Monitor, grow_gb
from proxmox_janitor.notify import CPU, DISK, PENDING, RESTART, Notifier, is_health
from proxmox_janitor.pve import Cluster, Remote, RemoteError
from proxmox_janitor.state import State

ROOT = pathlib.Path(__file__).resolve().parent.parent

UPD = [{"pkg": "libc6", "from": "2.41-12", "to": "2.41-12+deb13u1", "security": True},
       {"pkg": "curl", "from": "8.14.1-1", "to": "8.14.1-2", "security": False}]

GUESTS = [
    {"vmid": 101, "name": "web", "node": "pve2", "type": "lxc", "status": "running", "tags": "low-priority;web"},
    {"vmid": 102, "name": "dns", "node": "pve1", "type": "lxc", "status": "running", "tags": "high-priority"},
    {"vmid": 200, "name": "docker1", "node": "pve1", "type": "qemu", "status": "running", "tags": "high-priority"},
    {"vmid": 103, "name": "off", "node": "pve2", "type": "lxc", "status": "stopped", "tags": ""},
    {"vmid": 900, "name": "tmpl", "node": "pve1", "type": "lxc", "status": "stopped", "template": 1},
]


class Killed(Exception):
    """Stands in for the janitor's process dying when it restarts its own guest or node."""


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeCluster:
    """Stands in for Cluster: canned answers per request, a call log, and simple reboot physics."""

    def __init__(self, guests, clock, checks=None, fail=None, need_restart=(), node_reboot=()):
        self.guests = [dict(g) for g in guests]
        self.clock, self.checks, self.fail = clock, checks or {}, fail or {}
        self.need_restart, self.node_reboot = set(need_restart), set(node_reboot)
        self.calls, self.patched, self.rebooted_at = [], set(), {}
        self.disks: dict[str, dict] = {}

    def nodes(self):
        out = []
        for n in ("pve1", "pve2"):
            up = self.clock() - self.rebooted_at[n] if n in self.rebooted_at else 10 ** 6
            out.append({"node": n, "status": "online", "cpu": 0.1, "maxcpu": 8, "mem": 1, "maxmem": 4, "uptime": up})
        return out

    def inventory(self, prefer=()):
        return {"quorate": True, "guests": [dict(g) for g in self.guests], "nodes": self.nodes()}

    def call(self, node, request, *args, timeout=900):
        self.calls.append((node, request, *args))
        if (request, *args[:1]) in self.fail:
            raise RemoteError(f"{node}: {self.fail[(request, *args[:1])]}")
        vmid = args[0] if args else None
        if request == "node-check":
            done = node in self.patched
            return {"updates": [] if done else list(UPD), "restart_needed": done and node in self.node_reboot,
                    "reasons": ["running kernel a, newest installed b"] if done and node in self.node_reboot else []}
        if request == "node-patch":
            self.patched.add(node)
            return {"ok": True, "rc": 0, "log": "done",
                    "reasons": ["running kernel a, newest installed b"] if node in self.node_reboot else []}
        if request == "node-reboot":
            self.rebooted_at[node] = self.clock() + 20
            for g in self.guests:  # everything starts on boot except 102
                if g["node"] == node and g["vmid"] == 102:
                    g["status"] = "stopped"
            return {"rebooting": True}
        if request == "guest-check":
            facts = dict(self.checks.get(vmid, {"updates": list(UPD), "restart_needed": False, "reasons": []}))
            if vmid in self.patched:
                facts["updates"] = []
                facts["restart_needed"] = vmid in self.need_restart
                facts["reasons"] = ["processes still use replaced libraries: nginx"] if vmid in self.need_restart else []
            return facts
        if request == "guest-snapshot":
            return {"snapshot": "prepatch-20261025-030000", "deleted": []}
        if request == "guest-patch":
            self.patched.add(vmid)
            return {"ok": True, "rc": 0, "log": "done"}
        if request in ("guest-reboot", "guest-delsnapshot"):
            return {"ok": True}
        if request == "guest-status":
            return {"running": True, "agent": True}
        if request == "guest-start":
            g = next(g for g in self.guests if str(g["vmid"]) == vmid)
            started = g["status"] != "running"
            g["status"] = "running"
            return {"started": started}
        if request == "guest-disks":
            return self.disks.get(vmid, {"volumes": []})
        if request == "guest-grow":
            vol = self.disks[vmid]["volumes"][0]
            fs = vol["filesystems"][0]
            fs["total"] += int(args[2]) * GIB
            return {"volumes": [vol]}
        return {"ok": True}

    def requests(self, vmid):
        return [c[1] for c in self.calls if len(c) > 2 and c[2] == vmid]


class FakeDocker:
    def __init__(self, clock, agents=("sonarr-agent",)):
        self.clock, self.agents, self.calls, self.started = clock, list(agents), [], None

    def call(self, host, request, timeout=60):
        self.calls.append((host, request))
        if request == "redeploy-start":
            self.started = self.clock()
            return {"started": True}
        return {"started": self.started, "finished": self.started + 30,
                "results": {a: {"ok": True, "log": ""} for a in self.agents}}


class FakeNotifier:
    def __init__(self):
        self.sent, self.reports = [], []

    def send(self, findings, complete=True, in_scope=None, owns=None):
        self.sent.append((findings, complete))

    def report(self, title, lines):
        self.reports.append((title, lines))
        return True


def cfg(tmp_path, **kw):
    c = Config(nodes={"pve1": "192.0.2.11", "pve2": "192.0.2.12"}, docker_hosts={"docker1": "192.0.2.21"},
               self_guest="200", state_path=str(tmp_path / "s.json"))
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def janitor(tmp_path, clock, cluster=None, docker=None, **kw):
    cluster = cluster or FakeCluster(GUESTS, clock)
    n = FakeNotifier()
    j = Janitor(cluster, docker or FakeDocker(clock), cfg(tmp_path, **kw), n, State(str(tmp_path / "s.json")),
                sleep=clock.sleep, clock=clock)
    return j, cluster, n


# --- checks ---

def test_check_files_updates_for_the_window(tmp_path):
    clock = Clock()
    j, c, n = janitor(tmp_path, clock)
    fs = {f.key: f for f in j.check()}
    assert fs["updates:guest:101"].section == PENDING and fs["updates:guest:101"].once
    assert "Sun 03:00 maintenance window" in fs["updates:guest:102"].summary  # every priority, no approval
    assert fs["updates:node:pve1"].severity == "info"
    assert fs["stopped:guest:103"].severity == "info" and not any("900" in k for k in fs)


def test_schedule(tmp_path):
    c = cfg(tmp_path)
    assert schedule_due(c, {}, datetime(2026, 10, 25, 3, 10)) == ["window"]  # a Sunday, before the daily check
    assert schedule_due(c, {"window": "2026-10-25"}, datetime(2026, 10, 25, 7, 5)) == ["check"]
    assert schedule_due(c, {}, datetime(2026, 10, 25, 6, 30)) == []  # window's 3 h are over, check not yet
    assert schedule_due(c, {}, datetime(2026, 10, 26, 3, 10)) == []  # Monday


# --- the maintenance window ---

def test_window_order_puts_everything_of_its_own_last(tmp_path):
    clock = Clock()
    j, c, n = janitor(tmp_path, clock, docker=FakeDocker(clock), docker_hosts={"docker1": "a", "docker2": "b"})
    j.check()
    steps = [(s["kind"], s["id"]) for s in j.plan_steps()]
    guests = [i for k, i in steps if k == "guest"]
    assert guests == ["102", "101", "200"]  # by node, the janitor's own VM (200) last
    assert [i for k, i in steps if k == "redeploy"] == ["docker2", "docker1"]  # its own host last
    assert [i for k, i in steps if k == "node"] == ["pve2", "pve1"]  # its own node last
    assert [k for k, _ in steps] == ["guest"] * 3 + ["redeploy"] * 2 + ["node"] * 2


def test_window_patches_restarts_rebuilds_and_reboots(tmp_path):
    clock = Clock()
    c = FakeCluster(GUESTS, clock, need_restart={"101"}, node_reboot={"pve2"})
    j, c, n = janitor(tmp_path, clock, cluster=c, self_guest="", docker=FakeDocker(clock, ["a", "b"]))
    lines = j.run_window()
    assert c.requests("101") == ["guest-check", "guest-snapshot", "guest-patch", "guest-check", "guest-reboot",
                                 "guest-status", "guest-delsnapshot", "guest-start", "guest-check"]  # pve2 rebooted
    assert "then restarted" in next(l for l in lines if "**web**" in l)
    assert "✅ **docker1**: rebuilt 2 agents fully patched (a, b)." in lines
    pve2 = next(l for l in lines if "**pve2**" in l)
    assert "rebooted (running kernel a, newest installed b)" in pve2
    assert ("pve1", "node-reboot") not in [c_[:2] for c_ in c.calls]  # pve1 didn't need one
    assert n.reports[-1][0] == "Maintenance window" and j.state["window"]["finished"]


def test_node_reboot_restarts_guests_that_dont_start_on_boot(tmp_path):
    clock = Clock()
    c = FakeCluster(GUESTS, clock, node_reboot={"pve1"})
    j, c, n = janitor(tmp_path, clock, cluster=c, self_guest="", redeploy=False)
    lines = j.run_window()
    assert ("pve1", "guest-start", "102") in c.calls and "Started 102 again" in next(l for l in lines if "**pve1**" in l)


def test_janitor_restarting_its_own_guest_resumes_the_window(tmp_path):
    clock = Clock()
    c = FakeCluster(GUESTS, clock, need_restart={"200"})
    j, c, n = janitor(tmp_path, clock, cluster=c, redeploy=False)

    def die(seconds):
        if seconds >= 600:
            raise Killed  # its own guest restarting takes the janitor down
        clock.sleep(seconds)
    j.sleep = die
    with pytest.raises(Killed):
        j.run_window()
    step = next(s for s in j.state["window"]["steps"] if s["id"] == "200")
    assert step["status"] == "rebooting" and "then restarted" in step["result"]
    assert c.requests("200")[-2:] == ["guest-delsnapshot", "guest-reboot"]  # snapshot gone before going down

    j2, _, n2 = janitor(tmp_path, clock, cluster=c, redeploy=False)  # the restarted janitor, same state file
    lines = j2.run_window(resume=True)
    assert any("**docker1**" in l and "then restarted" in l for l in lines)
    assert c.requests("200").count("guest-patch") == 1  # not patched twice
    assert n2.reports[-1][0] == "Maintenance window"


def test_janitor_rebooting_its_own_node_announces_and_resumes(tmp_path):
    clock = Clock()
    c = FakeCluster(GUESTS, clock, node_reboot={"pve1"})
    j, c, n = janitor(tmp_path, clock, cluster=c, redeploy=False, reboot_guests=False)

    def die(seconds):
        if seconds >= 1800:
            raise Killed
        clock.sleep(seconds)
    j.sleep = die
    with pytest.raises(Killed):
        j.run_window()
    assert n.reports[-1][0] == "Maintenance window: rebooting pve1"
    j2, _, n2 = janitor(tmp_path, clock, cluster=c, redeploy=False, reboot_guests=False)
    lines = j2.run_window(resume=True)
    assert "rebooted" in next(l for l in lines if "**pve1**" in l)
    assert c.calls.count(("pve1", "node-reboot")) == 1  # not rebooted again after resuming


def test_failed_patch_keeps_the_snapshot_and_skips_the_restart(tmp_path):
    clock = Clock()
    c = FakeCluster(GUESTS, clock, need_restart={"101"}, fail={("guest-patch", "101"): "dpkg error"})
    j, c, n = janitor(tmp_path, clock, cluster=c, self_guest="", redeploy=False, reboot_nodes=False)
    lines = j.run_window()
    web = next(l for l in lines if "**web**" in l)
    assert web.startswith("❌") and "kept for rollback" in web
    assert "guest-reboot" not in c.requests("101") and "guest-delsnapshot" not in c.requests("101")


def test_requests_patch_now_but_leave_its_own_guest_to_the_window(tmp_path):
    clock = Clock()
    j, c, n = janitor(tmp_path, clock)
    j.check()
    j.request_guests([102, 200])
    j.run_job(j.queue.get())
    results = j.jobs[-1]["results"]
    assert results[0].startswith("✅ **dns**") and "only patched in the maintenance window" in results[1]
    with pytest.raises(ValueError):
        j.request_redeploy("nope")


def test_bus_marks_changes_destructive(tmp_path):
    from proxmox_janitor.__main__ import bus_tools
    from proxmox_janitor.bus import Runtime
    clock = Clock()
    j, c, n = janitor(tmp_path, clock)
    tools = {t.name: t for t in bus_tools(j, Monitor(c, j.cfg, n, j.state), Runtime("janitor"))}
    assert not any(tools[t].read_only for t in ("patch_guests", "patch_node", "redeploy_containers"))
    assert all(tools[t].read_only for t in ("janitor_status", "health", "list_updates", "job_status"))


# --- health ---

def test_cpu_and_memory_alert_only_when_sustained(tmp_path):
    clock = Clock()
    c = FakeCluster(GUESTS, clock)
    m = Monitor(c, cfg(tmp_path), FakeNotifier(), State(str(tmp_path / "s.json")), clock=clock)
    inv = c.inventory()
    inv["guests"][0].update(cpu=0.95, mem=1, maxmem=10)
    inv["guests"][1].update(cpu=0.1, mem=9, maxmem=10)
    assert m.sample(inv) == []  # just started
    clock.sleep(14 * 60)
    assert m.sample(inv) == []
    clock.sleep(60)
    fs = {f.key: f for f in m.sample(inv)}
    assert set(fs) == {"cpu:guest:101", "mem:guest:102"} and fs["cpu:guest:101"].section == CPU
    assert "CPU at 95% for 15 min" in fs["cpu:guest:101"].summary
    inv["guests"][0]["cpu"] = 0.2  # back to normal: the timer resets
    assert set(f.key for f in m.sample(inv)) == {"mem:guest:102"} and "cpu:guest:101" not in m.state["over"]


def test_hosts_are_watched_too(tmp_path):
    clock = Clock()
    c = FakeCluster(GUESTS, clock)
    m = Monitor(c, cfg(tmp_path), FakeNotifier(), State(str(tmp_path / "s.json")), clock=clock)
    inv = c.inventory()
    inv["nodes"][0].update(cpu=0.9)
    m.sample(inv)
    clock.sleep(15 * 60)
    assert [f.key for f in m.sample(inv)] == ["cpu:node:pve1"]


def disks(used_gb, total_gb, growable=True, storage_used=100, storage_total=1000):
    return {"volumes": [{"disk": "scsi0", "storage": "local-lvm", "storage_used": storage_used * GIB,
                         "storage_total": storage_total * GIB,
                         "filesystems": [{"mount": "/", "type": "ext4", "used": used_gb * GIB, "total": total_gb * GIB,
                                          "growable": growable}]}]}


def test_grow_amount():
    assert grow_gb(int(36 * GIB), int(40 * GIB), 70, 5, 50) == 12  # 36/0.7 = 51.4 -> +12
    assert grow_gb(int(9 * GIB), int(10 * GIB), 70, 5, 50) == 5  # at least GROW_MIN_GB
    assert grow_gb(int(900 * GIB), int(1000 * GIB), 70, 5, 50) == 50  # at most GROW_MAX_GB


def test_full_disk_is_grown_and_reported(tmp_path):
    clock = Clock()
    c = FakeCluster(GUESTS, clock)
    c.disks["200"] = disks(36, 40)
    n = FakeNotifier()
    m = Monitor(c, cfg(tmp_path), n, State(str(tmp_path / "s.json")), clock=clock)
    assert m.check_disks(c.inventory()) == []
    assert ("pve1", "guest-grow", "200", "scsi0", "12", "90") in c.calls
    assert n.reports[-1][0] == "Disk grown" and "was 90% full; added 12 GB" in n.reports[-1][1][0]
    assert "Now 69% used" in n.reports[-1][1][0]


def test_disks_that_cant_grow_are_reported_not_grown(tmp_path):
    clock = Clock()
    c = FakeCluster(GUESTS, clock)
    c.disks["200"] = disks(36, 40, storage_used=890)  # +12 GB would pass the storage's 90%
    c.disks["102"] = disks(9, 10, growable=False)
    c.disks["101"] = disks(5, 10)  # 50%: fine
    m = Monitor(c, cfg(tmp_path), FakeNotifier(), State(str(tmp_path / "s.json")), clock=clock)
    fs = {f.key: f for f in m.check_disks(c.inventory())}
    assert set(fs) == {"disk:guest:200:scsi0:/", "disk:guest:102:scsi0:/"} and all(f.section == DISK for f in fs.values())
    assert "would be over 90% used" in fs["disk:guest:200:scsi0:/"].summary
    assert "can't be grown automatically" in fs["disk:guest:102:scsi0:/"].summary
    assert not any(x[1] == "guest-grow" for x in c.calls)


def test_disk_grow_waits_for_a_busy_window(tmp_path):
    import threading
    clock = Clock()
    c = FakeCluster(GUESTS, clock)
    c.disks["200"] = disks(36, 40)
    ops = threading.Lock()
    m = Monitor(c, cfg(tmp_path), FakeNotifier(), State(str(tmp_path / "s.json")), ops=ops, clock=clock)
    with ops:
        assert m.check_disks(c.inventory()) == []
    assert not any(x[1] == "guest-grow" for x in c.calls)


def test_health_and_patch_digests_dont_clear_each_other(tmp_path):
    n = Notifier([], 24, State(str(tmp_path / "s.json")))
    sent = []
    n._deliver = lambda msg, due: sent.append(msg) or True
    n.send([Finding("updates:node:pve1", "pve1: 3 updates")], owns=lambda k: not is_health(k))
    n.send([Finding("cpu:guest:101", "web: CPU at 95%")], owns=is_health)
    n.send([], owns=is_health)  # CPU back to normal
    assert "updates:node:pve1" in n.state["notified"] and len(sent) == 3
    assert sent[-1].sections[0].lines == ["web: CPU at 95%"]  # only the CPU item cleared


# --- notifications ---

def test_long_digests_are_paged_at_line_breaks():
    from proxmox_janitor.notice import PAGE, Message, Section
    lines = [f"**guest{i}** · CT {i} on pve1 — 44 updates (21 security)" for i in range(150)]
    msg = Message("t", "warning", [Section("⚠️ Waiting", lines), Section("ℹ️ Later", ["one", "two"])])
    pages = msg.pages()
    assert len(pages) > 1 and all(len(p) <= PAGE for p in pages)
    assert "\n".join(pages).replace("\n\n", "\n") == msg.markdown().replace("\n\n", "\n")  # nothing lost


def test_discord_gets_an_embed_and_other_urls_get_markdown(monkeypatch):
    import proxmox_janitor.notice as notice
    posted, apprised = [], []

    class Resp:
        status_code, ok, text = 200, True, ""

    monkeypatch.setattr(notice.requests, "post", lambda url, json, params, timeout: posted.append((url, json)) or Resp())
    hook = "https://discord.com/api/webhooks/" + "123/fake-TOKEN"  # split so the public-sync secret scan passes
    out = notice.Outbox([hook, "ntfy://ntfy.sh/topic"])
    out.apobj.notify = lambda title, body, body_format: apprised.append((title, body)) or True
    msg = notice.Message("⚠️ 2 need attention", "warning", [notice.Section("🔥 CPU", ["**a** — 95%"])],
                         "Proxmox janitor", "footer")
    assert out.send(msg)
    embed = posted[0][1]["embeds"][0]
    assert embed["color"] == notice.COLOR["warning"] and embed["author"] == {"name": "Proxmox janitor"}
    assert apprised == [("Proxmox janitor: ⚠️ 2 need attention", embed["description"])]


def test_undelivered_digest_is_retried(tmp_path):
    n = Notifier([], 24, State(str(tmp_path / "s.json")))
    sent = []
    n._deliver = lambda msg, due: sent.append(msg) and False  # target failed
    f = [Finding("updates:node:pve1", "pve1: 3 updates")]
    n.send(f)
    n.send(f)
    assert len(sent) == 2 and n.state["notified"] == {}
    n._deliver = lambda msg, due: sent.append(msg) or True
    n.send(f)
    n.send(f)
    assert len(sent) == 3 and "updates:node:pve1" in n.state["notified"]


# --- clients and config ---

def test_remote_client_parses_and_raises():
    def runner(cmd, **kw):
        if cmd[-1] == "inventory":
            return subprocess.CompletedProcess(cmd, 0, json.dumps({"guests": []}) + "\n", "")
        return subprocess.CompletedProcess(cmd, 1, json.dumps({"error": "not quorate"}) + "\n", "")
    c = Cluster({"pve1": "192.0.2.11"}, "/k", "/kh", runner=runner)
    assert c.inventory() == {"guests": []}
    with pytest.raises(RemoteError, match="not quorate"):
        c.call("pve1", "node-patch")
    d = Remote({"docker1": "192.0.2.21"}, "/k", "/kh", user="deploy", runner=lambda cmd, **kw: (
        subprocess.CompletedProcess(cmd, 0, '{"started": true}\n', "")))
    assert d.call("docker1", "redeploy-start") == {"started": True}


def test_config(monkeypatch):
    monkeypatch.setenv("PVE_NODES", "pve1=192.0.2.11, pve2=192.0.2.12")
    monkeypatch.setenv("DOCKER_HOSTS", "docker1=192.0.2.21")
    c = Config.from_env()
    assert c.nodes == {"pve1": "192.0.2.11", "pve2": "192.0.2.12"} and c.docker_hosts == {"docker1": "192.0.2.21"}
    assert (c.cpu_percent, c.mem_percent, c.sustain_minutes, c.disk_percent, c.disk_target_percent) == (80, 80, 15, 85, 70)
    assert (c.window_day, c.window_time, c.reboot_guests, c.reboot_nodes, c.redeploy) == ("sun", "03:00", True, True, True)
    monkeypatch.setenv("DISK_TARGET_PERCENT", "90")
    with pytest.raises(SystemExit):
        Config.from_env()


# --- node/janitor-cmd (the forced command on the Proxmox nodes) ---

def node_cmd():
    path = str(ROOT / "node" / "janitor-cmd")
    loader = importlib.machinery.SourceFileLoader("janitor_cmd", path)
    spec = importlib.util.spec_from_loader("janitor_cmd", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_node_cmd_parses_apt_simulation():
    m = node_cmd()
    out = "\n".join([
        "@@UPDATE_RC 0",
        "Inst libc6 [2.41-12] (2.41-12+deb13u1 Debian:13.2/stable, Debian-Security:13/stable-security [amd64])",
        "Remv oldpkg [0.9]",
        "@@STALE nginx",
        "@@KERNEL 6.1.0-25-amd64 6.1.0-26-amd64",
    ])
    lxc, vm = m.parse_check(out, is_vm=False), m.parse_check(out, is_vm=True)
    assert [u["pkg"] for u in lxc["updates"]] == ["libc6"] and lxc["updates"][0]["security"]
    assert lxc["removals"] == ["oldpkg"] and len(lxc["reasons"]) == 1 and len(vm["reasons"]) == 2
    assert m.size_bytes("10G") == 10 * GIB and m.size_bytes("512M") == 512 * 1024 ** 2 and m.size_bytes("x") == 0


def test_node_cmd_refuses_anything_unexpected():
    m = node_cmd()
    for bad in ["", "reboot", "node-reboot now", "guest-check 102; rm -rf /", "guest-check abc", "guest-snapshot 102 0",
                "guest-delsnapshot 102 important-snap", "guest-grow 102 rootfs 0 90", "guest-grow 102 rootfs 1000 90",
                "guest-grow 102 rootfs 5 100", "guest-grow 102 rootfs 5 40", "guest-grow 102 efidisk0 5 90",
                "guest-grow 102 rootfs 5", "inventory now"]:
        with pytest.raises(m.Refused):
            m.dispatch(bad)
    called = []
    m.COMMANDS["guest-grow"] = (lambda *a: called.append(a) or {}, m.COMMANDS["guest-grow"][1])
    m.dispatch("guest-grow 102 mp0 12 90")
    assert called == [("102", "mp0", "12", "90")]


def test_node_cmd_wont_reboot_a_node_without_full_quorum(monkeypatch):
    m = node_cmd()
    monkeypatch.setattr(m, "quorum", lambda: (True, ["pve2"]))
    ran = []
    monkeypatch.setattr(m, "run", lambda cmd, timeout=600: ran.append(cmd) or (0, ""))
    with pytest.raises(m.Refused, match="every node online"):
        m.node_reboot()
    assert not ran


def test_node_cmd_kernel_sort():
    m = node_cmd()
    assert sorted(["6.17.2-1-pve", "7.0.14-24-pve", "6.17.13-2-pve"], key=m.version_key)[-1] == "7.0.14-24-pve"


@pytest.mark.parametrize("workflow", [".github/workflows/deploy.yml", ".public/overlay/.github/workflows/deploy.yml"])
def test_deploy_renders_every_setting_it_is_given(workflow):
    path = ROOT / workflow
    if not path.exists():
        pytest.skip("the public copy has no .public/")
    wf = path.read_text(encoding="utf-8")
    step = wf.split("- name: Render agent.env", 1)[1].split("- name:", 1)[0]
    env_block, run_block = step.split("run: |", 1)
    given = set(re.findall(r"^\s+([A-Z_]+): \$\{\{ (?:vars|secrets)\.", env_block, re.M))
    written = set(re.findall(r"[A-Z_]+", re.search(r"for v in (.*?); do", run_block, re.S).group(1)))
    assert given - written == set(), f"passed to the step but never written to agent.env: {sorted(given - written)}"
