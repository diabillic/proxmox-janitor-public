"""Agent bus: expose this agent to the Discord bot, and hand alerts to it.

- Runtime: what the last cycle found and diagnosed, plus a wake-up event so the bot can
  ask for an immediate check.
- serve_mcp(): a minimal MCP server (Streamable HTTP, JSON responses, stateless) on the LAN,
  authenticated with a bearer token. Each tool is annotated readOnlyHint or destructiveHint.
- Approvals for destructive tools, in one of two modes (APPROVAL_MODE):
  * "code" (default): the agent enforces it. A destructive call only creates a pending action
    and sends a one-time code to APPROVAL_NOTIFY_URLS (a channel the client can't read);
    confirm_action(action_id, code) then runs exactly the stored call.
  * "client": the MCP client (e.g. a Hermes plugin with Allow/Deny buttons) asks the operator
    before calling, and the agent trusts that. Every action is announced to
    APPROVAL_NOTIFY_URLS before it runs (no announcement, no action) and its result after.
  No approval channel means no actions in either mode.
- push_alert(): POST a notification digest to a bot; the caller falls back to Apprise if
  the bot can't be reached.

Standard library plus requests (alert push) and notice.py (approval messages).
"""

from __future__ import annotations

import hmac
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

import requests

from .notice import Message, Outbox, Section

log = logging.getLogger(__name__)

PROTOCOL_VERSION = "2025-06-18"
MAX_BODY = 1_000_000


@dataclass
class BusTool:
    name: str
    description: str
    input_schema: dict
    fn: Callable[..., Any]
    read_only: bool = True

    def listing(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {"readOnlyHint": self.read_only, "destructiveHint": not self.read_only},
        }


def schema(props: dict | None = None, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props or {}, "required": required or [], "additionalProperties": False}


@dataclass
class Runtime:
    """Shared between the check loop (writer) and the MCP server threads (readers)."""

    agent: str
    revision: str = ""
    started_at: float = field(default_factory=time.time)
    last_cycle_at: float | None = None
    findings: list[dict] = field(default_factory=list)
    last_diagnosis: str | None = None
    last_diagnosis_at: float | None = None
    wake: threading.Event = field(default_factory=threading.Event)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, findings: list, diagnosis: str | None) -> None:
        with self._lock:
            self.last_cycle_at = time.time()
            self.findings = [
                {"key": f.key, "severity": f.severity, "summary": f.summary,
                 "resolved": getattr(f, "resolved", False), "escalate": f.escalate}
                for f in findings
            ]
            if diagnosis:
                self.last_diagnosis, self.last_diagnosis_at = diagnosis, time.time()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "agent": self.agent,
                "revision": self.revision[:12],
                "uptimeSeconds": int(time.time() - self.started_at),
                "lastCycleSecondsAgo": None if self.last_cycle_at is None else int(time.time() - self.last_cycle_at),
                "openFindings": list(self.findings),
            }

    def diagnosis(self) -> dict:
        with self._lock:
            return {"diagnosis": self.last_diagnosis,
                    "secondsAgo": None if self.last_diagnosis_at is None else int(time.time() - self.last_diagnosis_at)}

    def request_check(self) -> str:
        self.wake.set()
        return "A check cycle was requested and will start within seconds; ask for agent_status afterwards."

    def common_tools(self, check_is_destructive: bool) -> list[BusTool]:
        return [
            BusTool("agent_status", f"{self.agent} agent: revision, uptime, when it last checked, and its current "
                                    "open findings.", schema(), self.snapshot),
            BusTool("agent_last_diagnosis", f"{self.agent} agent: the most recent LLM diagnosis it sent, if any.",
                    schema(), self.diagnosis),
            BusTool("agent_run_check", f"Ask the {self.agent} agent to run a full check cycle now"
                    + (" (this can apply its automatic fixes)." if check_is_destructive else " (read-only)."),
                    schema(), self.request_check, read_only=not check_is_destructive),
        ]


@dataclass
class PendingAction:
    id: str
    tool: BusTool
    args: dict
    code: str
    expires: float
    attempts: int = 0

    def describe(self) -> str:
        args = ", ".join(f"{k}={json.dumps(v)}" for k, v in self.args.items()) or "no arguments"
        return f"{self.tool.name}({args})"


class Approvals:
    """Human approval for destructive tools, enforced here rather than trusted to the MCP client."""

    def __init__(self, agent: str, notify_urls: list[str], ttl_minutes: int = 15, max_attempts: int = 3,
                 mode: str = "code"):
        if mode not in ("code", "client"):
            raise ValueError(f"APPROVAL_MODE must be 'code' or 'client', not {mode!r}")
        self.agent, self.ttl, self.max_attempts, self.mode = agent, ttl_minutes * 60, max_attempts, mode
        self.outbox = Outbox(notify_urls, "approval notification")
        self._pending: dict[str, PendingAction] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return len(self.outbox) > 0

    def _notify(self, title: str, level: str, action: PendingAction, *lines: str) -> bool:
        """An embed with the exact call in a code block, then the given lines."""
        call = action.describe().replace("`", "'")
        sections = [Section("", [f"```\n{call}\n```"], bullets=False)]
        sections += [Section("", [line], bullets=False) for line in lines]
        try:
            return self.outbox.send(Message(title, level, sections, f"{self.agent.title()} agent",
                                            f"Action {action.id}"))
        except Exception as exc:  # a broken webhook must never let an action through
            log.warning("Approval notification failed: %s", exc)
            return False

    def handle(self, tool: BusTool, args: dict) -> Any:
        """Entry point for every destructive call."""
        return self.run_audited(tool, args) if self.mode == "client" else self.request(tool, args)

    def run_audited(self, tool: BusTool, args: dict) -> Any:
        """Client mode: the client got the operator's approval; run it, announced before and after."""
        if not self.enabled:
            return {"status": "refused", "reason": "Actions need an audit channel (APPROVAL_NOTIFY_URLS) and none is "
                                                   "configured on this agent."}
        action = PendingAction(secrets.token_hex(3), tool, dict(args), "", 0)
        if not self._notify("▶️ Running an approved action", "info", action, "*Approved in your assistant.*"):
            return {"status": "refused", "reason": "The action couldn't be announced to the audit channel, so it was not run."}
        log.info("Client-approved action %s: running %s", action.id, tool.name)
        try:
            result = tool.fn(**action.args)
        except Exception as exc:
            self._notify("❌ Action failed", "error", action, f"**Error:** {exc}")
            raise
        self._notify("✅ Action done", "ok", action, "**Result**\n" + _code_block(result))
        return {"status": "done", "action": action.describe(), "result": result}

    def request(self, tool: BusTool, args: dict) -> dict:
        if not self.enabled:
            return {"status": "refused", "reason": "Actions need an approval channel (APPROVAL_NOTIFY_URLS) and none "
                                                   "is configured on this agent. Tell the operator what you'd do instead."}
        now = time.time()
        action = PendingAction(secrets.token_hex(3), tool, dict(args), f"{secrets.randbelow(10**6):06d}", now + self.ttl)
        with self._lock:
            for k in [k for k, p in self._pending.items() if p.expires < now]:
                del self._pending[k]
            self._pending[action.id] = action
        sent = self._notify(
            f"🔐 Approval code {action.code}", "warning", action,
            f"Code **{action.code}** approves this action.",
            f"*Expires in {self.ttl // 60} minutes. Only give it to your assistant if you want this to run.*",
        )
        if not sent:
            with self._lock:
                self._pending.pop(action.id, None)
            return {"status": "refused", "reason": "The approval code couldn't be delivered, so the action was not queued."}
        log.info("Approval requested: action %s %s", action.id, tool.name)  # never log the code
        return {
            "status": "approval_required", "action_id": action.id, "action": action.describe(),
            "expires_in_minutes": self.ttl // 60,
            "instructions": "Nothing has run. The operator was sent a 6-digit code in a channel you cannot read. "
                            "Tell them what this action will do and ask for the code, then call confirm_action with "
                            "action_id and code. Never guess a code: wrong codes cancel the action.",
        }

    def confirm(self, action_id: str, code: str) -> Any:
        with self._lock:
            action = self._pending.get(str(action_id))
            if action is None or action.expires < time.time():
                self._pending.pop(str(action_id), None)
                return {"status": "refused", "reason": "No such pending action (expired, used or cancelled). "
                                                       "Call the action again to get a new code."}
            if not hmac.compare_digest(str(code).strip().encode(), action.code.encode()):
                action.attempts += 1
                left = self.max_attempts - action.attempts
                if left <= 0:
                    del self._pending[action.id]
                    log.warning("Approval for action %s cancelled after %d wrong codes", action.id, action.attempts)
                    self._notify("🚫 Action cancelled", "warning", action,
                                 f"Cancelled after {action.attempts} wrong codes.")
                    return {"status": "refused", "reason": "Wrong code; the action has been cancelled."}
                return {"status": "refused", "reason": f"Wrong code; {left} attempt(s) left. Ask the operator again."}
            del self._pending[action.id]
        log.info("Approved action %s: running %s", action.id, action.tool.name)
        return {"status": "approved", "action": action.describe(), "result": action.tool.fn(**action.args)}

    def cancel(self, action_id: str) -> dict:
        with self._lock:
            action = self._pending.pop(str(action_id), None)
        return {"status": "cancelled" if action else "not_found", "action_id": action_id}

    def tools(self) -> list[BusTool]:
        if self.mode == "client":
            return []  # no codes to confirm
        return [
            BusTool("confirm_action", f"Run a {self.agent} action the operator approved, using the 6-digit code "
                                      "they give you. Runs exactly the action that was requested.",
                    schema({"action_id": {"type": "string"}, "code": {"type": "string", "description": "6-digit code"}},
                           ["action_id", "code"]), self.confirm, read_only=False),
            BusTool("cancel_action", "Discard a pending action without running it.",
                    schema({"action_id": {"type": "string"}}, ["action_id"]), self.cancel),
        ]


APPROVAL_TOOLS = {"confirm_action", "cancel_action"}


def _rpc_result(id_: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _rpc_error(id_: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def make_handler(token: str, tools: dict[str, BusTool], server_name: str, version: str, approvals: Approvals):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # route through logging, quietly
            log.debug("bus %s - " + fmt, self.address_string(), *args)

        def _send(self, status: int, body: dict | None = None) -> None:
            data = json.dumps(body).encode() if body is not None else b""
            self.send_response(status)
            if body is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            supplied = self.headers.get("x-api-key") or self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            return bool(token) and hmac.compare_digest(supplied.encode(), token.encode())

        def do_GET(self):
            if self.path == "/health":
                return self._send(200, {"ok": True, "agent": server_name})
            return self._send(405, {"error": "use POST /mcp"})

        def do_POST(self):
            if self.path.rstrip("/") != "/mcp":
                return self._send(404, {"error": "not found"})
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._send(413, {"error": "body too large"})
            try:
                msg = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._send(400, _rpc_error(None, -32700, "parse error"))
            method, id_ = msg.get("method"), msg.get("id")
            if id_ is None:  # notification
                return self._send(202)
            if method == "initialize":
                client_version = (msg.get("params") or {}).get("protocolVersion") or PROTOCOL_VERSION
                return self._send(200, _rpc_result(id_, {
                    "protocolVersion": client_version, "capabilities": {"tools": {}},
                    "serverInfo": {"name": server_name, "version": version}}))
            if method == "ping":
                return self._send(200, _rpc_result(id_, {}))
            if method == "tools/list":
                return self._send(200, _rpc_result(id_, {"tools": [t.listing() for t in tools.values()]}))
            if method == "tools/call":
                params = msg.get("params") or {}
                tool = tools.get(params.get("name"))
                if tool is None:
                    return self._send(200, _rpc_error(id_, -32602, f"unknown tool {params.get('name')}"))
                args = params.get("arguments") or {}
                log.info("bus call %s(%s)", tool.name, ", ".join(sorted(args)))
                try:
                    # Destructive tools go through the approval policy (code or audited client approval).
                    gated = not tool.read_only and tool.name not in APPROVAL_TOOLS
                    data = approvals.handle(tool, args) if gated else tool.fn(**args)
                    text, is_error = (data if isinstance(data, str) else json.dumps(data, default=str)), False
                except TypeError as exc:
                    text, is_error = f"Error: invalid arguments ({exc})", True
                except Exception as exc:  # report tool failures to the caller, keep serving
                    log.warning("bus tool %s failed: %s", tool.name, exc)
                    text, is_error = f"Error: {exc}", True
                return self._send(200, _rpc_result(id_, {"content": [{"type": "text", "text": text}], "isError": is_error}))
            return self._send(200, _rpc_error(id_, -32601, f"method not found: {method}"))

    return Handler


def serve_mcp(host: str, port: int, token: str, tools: list[BusTool], server_name: str, approvals: Approvals,
              version: str = "1.0"):
    """Start the MCP server on a daemon thread; returns the server (call .shutdown() to stop)."""
    tools = tools + approvals.tools()
    server = ThreadingHTTPServer((host, port),
                                 make_handler(token, {t.name: t for t in tools}, server_name, version, approvals))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="agent-bus", daemon=True).start()
    log.info("Agent bus: MCP on %s:%s/mcp with %d tools", host, server.server_address[1], len(tools))
    return server


def _code_block(value: Any, limit: int = 900) -> str:
    text = value if isinstance(value, str) else json.dumps(value, indent=1, default=str)
    text = text.replace("`", "'")
    return f"```\n{text[:limit]}{'…' if len(text) > limit else ''}\n```"


def push_alert(url: str, token: str, agent: str, title: str, body: str, findings: list, diagnosis: str | None) -> bool:
    """Hand a notification digest to the Discord bot. Returns False if it wasn't accepted."""
    payload = {
        "agent": agent, "title": title, "body": body, "diagnosis": diagnosis,
        "findings": [{"key": f.key, "severity": f.severity, "summary": f.summary} for f in findings],
    }
    try:
        resp = requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"}, timeout=15)
        if resp.status_code < 300:
            return True
        log.warning("Bot rejected alert: HTTP %s", resp.status_code)
    except requests.RequestException as exc:
        log.warning("Bot unreachable for alert: %s", exc)
    return False
