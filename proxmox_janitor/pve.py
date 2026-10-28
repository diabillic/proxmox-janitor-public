"""SSH to the forced-command scripts: node/janitor-cmd on the Proxmox nodes, agent-redeploy-ssh on
the Docker hosts. Every reply is one JSON object; {"error": ...} becomes a RemoteError."""

from __future__ import annotations

import json
import subprocess
from typing import Callable


class RemoteError(Exception):
    pass


class Remote:
    def __init__(self, hosts: dict[str, str], ssh_key: str, known_hosts: str, user: str = "root",
                 runner: Callable = subprocess.run):
        self.hosts, self.ssh_key, self.known_hosts, self.user, self.runner = hosts, ssh_key, known_hosts, user, runner

    def call(self, host: str, *args: str, timeout: int = 900) -> dict:
        if host not in self.hosts:
            raise RemoteError(f"{host} isn't configured")
        cmd = ["ssh", "-i", self.ssh_key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
               "-o", f"UserKnownHostsFile={self.known_hosts}", "-o", "StrictHostKeyChecking=yes",
               "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=30", f"{self.user}@{self.hosts[host]}", " ".join(args)]
        try:
            p = self.runner(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RemoteError(f"{host}: {args[0]} timed out after {timeout}s")
        lines = (p.stdout or "").strip().splitlines()
        try:
            data = json.loads(lines[-1]) if lines else None
        except ValueError:
            data = None
        if isinstance(data, dict) and data.get("error"):
            raise RemoteError(f"{host}: {data['error']}")
        if p.returncode != 0 or not isinstance(data, dict):
            raise RemoteError(f"{host}: {args[0]} failed ({(p.stderr or p.stdout or '').strip()[-300:] or p.returncode})")
        return data


class Cluster(Remote):
    def inventory(self, prefer: list[str] = ()) -> dict:
        """Cluster-wide guests and nodes from the first node that answers (`prefer` first)."""
        errors = []
        for node in list(prefer) + [n for n in self.hosts if n not in prefer]:
            try:
                return self.call(node, "inventory", timeout=120)
            except RemoteError as exc:
                errors.append(str(exc))
        raise RemoteError("no node answered: " + "; ".join(errors))
