"""Core analysis engine for mcp-log-analyzer (zero dependencies).

Parses MCP (Model Context Protocol) JSON-RPC session logs in JSON Lines
format, pairs requests with responses, and produces findings such as
unanswered requests, tool errors, slow calls, secrets in traffic, repeated
(looping) calls and context-bloating payloads.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

# Conservative, well-known secret shapes. Matches are never printed in reports.
SECRET_PATTERNS: dict[str, str] = {
    "aws_access_key_id": r"AKIA[0-9A-Z]{16}",
    "github_token": r"gh[pousr]_[A-Za-z0-9]{30,}",
    "slack_token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
    "openai_style_key": r"sk-[A-Za-z0-9_\-]{24,}",
    "bearer_token": r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}",
    "private_key_block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "credential_assignment": (
        r"(?i)(?:api[_-]?key|secret|token|password|passwd)[\"']?\s*[:=]\s*[\"']?"
        r"[A-Za-z0-9._\-/+]{8,}"
    ),
}
_COMPILED = {k: re.compile(v) for k, v in SECRET_PATTERNS.items()}


@dataclass
class Message:
    """One JSON-RPC message plus log metadata."""

    line: int
    ts: float | None
    direction: str | None
    body: dict[str, Any]


@dataclass
class Call:
    """A request paired (or not) with its response."""

    line: int
    method: str
    req_id: Any
    ts: float | None = None
    tool: str | None = None
    args: Any = None
    outcome: str = "no_response"  # ok | rpc_error | tool_error | no_response
    error: str = ""
    latency: float | None = None
    resp_chars: int = 0


@dataclass
class Finding:
    """A single issue discovered in the log."""

    severity: str
    code: str
    message: str
    line: int | None = None


@dataclass
class Analysis:
    """Full analysis result."""

    summary: dict[str, Any] = field(default_factory=dict)
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "tools": self.tools,
            "findings": [f.__dict__ for f in self.findings],
        }


def to_ts(value: Any) -> float | None:
    """Convert epoch seconds / numeric string / ISO-8601 to epoch seconds."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            pass
        try:
            return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def parse_log(lines: Iterable[str]) -> tuple[list[Message], list[tuple[int, str]]]:
    """Parse JSONL lines into messages.

    Accepts raw JSON-RPC objects (optionally with a ``ts`` key) or wrappers of
    the form ``{"ts":..., "dir":"c2s", "msg": {...jsonrpc...}}``.
    Returns (messages, parse_errors) where parse_errors is [(line, reason)].
    """
    messages: list[Message] = []
    errors: list[tuple[int, str]] = []
    for n, raw in enumerate(lines, start=1):
        text = raw.strip()
        if not text:
            continue
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            errors.append((n, f"invalid JSON ({exc.msg})"))
            continue
        if not isinstance(obj, dict):
            errors.append((n, "line is not a JSON object"))
            continue
        ts = to_ts(obj.get("ts") or obj.get("timestamp"))
        direction = obj.get("dir") or obj.get("direction")
        body = obj.get("msg") or obj.get("message")
        if not isinstance(body, dict):
            body = obj
        if "jsonrpc" not in body and "method" not in body and "id" not in body:
            errors.append((n, "not a JSON-RPC message"))
            continue
        messages.append(Message(n, ts, direction, body))
    return messages, errors


def scan_secrets(text: str) -> list[str]:
    """Return the names of secret patterns found in text (never the values)."""
    return [name for name, rx in _COMPILED.items() if rx.search(text)]


def _first_text(result: Any) -> str:
    if isinstance(result, dict):
        for item in result.get("content") or []:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                return item["text"][:120]
    return ""


def _p95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, int(round(0.95 * len(ordered) + 0.5)) - 1))
    return ordered[idx]


def analyze(
    messages: list[Message],
    parse_errors: Iterable[tuple[int, str]] = (),
    slow: float = 2.0,
    large_chars: int = 20000,
    repeat: int = 3,
) -> Analysis:
    """Analyze parsed messages and return an :class:`Analysis`."""
    parse_errors = list(parse_errors)
    pending: dict[str, Call] = {}
    calls: list[Call] = []
    findings: list[Finding] = []
    known_tools: set[str] | None = None
    saw_init = False
    notifications = responses = 0
    seen_secret: set[tuple[str, int]] = set()

    for line, reason in parse_errors:
        findings.append(Finding("low", "PARSE_ERROR", f"Skipped line: {reason}", line))

    for m in messages:
        b = m.body
        method, mid = b.get("method"), b.get("id")
        if method is not None and mid is not None:
            call = Call(m.line, str(method), mid, m.ts)
            if method == "initialize":
                saw_init = True
            if method == "tools/call":
                params = b.get("params") or {}
                call.tool = str(params.get("name"))
                call.args = params.get("arguments")
            pending[json.dumps(mid)] = call
            calls.append(call)
        elif method is not None:
            notifications += 1
        elif mid is not None and ("result" in b or "error" in b):
            responses += 1
            call = pending.pop(json.dumps(mid), None)
            if call is None:
                findings.append(Finding("low", "ORPHAN_RESPONSE",
                                        f"Response id={mid!r} has no matching request.", m.line))
            else:
                payload = b["error"] if "error" in b else b.get("result")
                call.resp_chars = len(json.dumps(payload))
                if m.ts is not None and call.ts is not None:
                    call.latency = max(0.0, m.ts - call.ts)
                if "error" in b:
                    call.outcome = "rpc_error"
                    err = b["error"] if isinstance(b["error"], dict) else {}
                    call.error = str(err.get("message", ""))[:120]
                elif isinstance(payload, dict) and payload.get("isError") is True:
                    call.outcome = "tool_error"
                    call.error = _first_text(payload)
                else:
                    call.outcome = "ok"
                if call.method == "tools/list" and isinstance(payload, dict):
                    known_tools = {
                        str(t.get("name")) for t in payload.get("tools", []) if isinstance(t, dict)
                    }
        for name in scan_secrets(json.dumps(b)):
            if (name, m.line) not in seen_secret:
                seen_secret.add((name, m.line))
                findings.append(Finding(
                    "high", "SECRET_IN_TRAFFIC",
                    f"Possible secret ({name}) in message payload. Redact before sharing.", m.line))

    repeats: dict[tuple[str, str], list[Call]] = {}
    for c in calls:
        if c.outcome == "no_response":
            findings.append(Finding("high", "UNANSWERED_REQUEST",
                                    f"{c.tool or c.method} (id={c.req_id!r}) never got a response "
                                    "(hung or dropped).", c.line))
        elif c.outcome == "rpc_error":
            findings.append(Finding("medium", "RPC_ERROR",
                                    f"{c.tool or c.method}: JSON-RPC error: {c.error}", c.line))
        elif c.outcome == "tool_error":
            findings.append(Finding("medium", "TOOL_ERROR",
                                    f"{c.tool}: call returned normally but result.isError=true: {c.error}", c.line))
        if c.latency is not None and c.latency >= slow:
            findings.append(Finding("low", "SLOW_CALL",
                                    f"{c.tool or c.method} took {c.latency:.2f}s (threshold {slow:g}s).", c.line))
        if c.resp_chars >= large_chars:
            findings.append(Finding("low", "LARGE_PAYLOAD",
                                    f"{c.tool or c.method} returned ~{c.resp_chars // 4} tokens "
                                    "of context; consider paging or trimming.", c.line))
        if c.method == "tools/call":
            if known_tools is not None and c.tool not in known_tools:
                findings.append(Finding("medium", "UNKNOWN_TOOL",
                                        f"Tool {c.tool!r} was called but is not in tools/list.", c.line))
            key = (c.tool or "", json.dumps(c.args, sort_keys=True, default=str))
            repeats.setdefault(key, []).append(c)

    for (tool, _), group in repeats.items():
        if len(group) >= repeat:
            findings.append(Finding("medium", "REPEATED_CALL",
                                    f"{tool} was called {len(group)}x with identical arguments "
                                    "(possible agent loop).", group[0].line))
    if messages and not saw_init:
        findings.append(Finding("low", "NO_INITIALIZE",
                                "No initialize request found; log may be truncated.", None))

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.line or 0))

    tools: dict[str, dict[str, Any]] = {}
    for c in calls:
        if c.method != "tools/call":
            continue
        t = tools.setdefault(c.tool or "?", {"calls": 0, "errors": 0, "no_response": 0,
                                             "_lat": [], "_chars": 0})
        t["calls"] += 1
        t["errors"] += c.outcome in ("rpc_error", "tool_error")
        t["no_response"] += c.outcome == "no_response"
        t["_chars"] += c.resp_chars
        if c.latency is not None:
            t["_lat"].append(c.latency)
    for t in tools.values():
        lat = t.pop("_lat")
        chars = t.pop("_chars")
        t["avg_latency_s"] = round(sum(lat) / len(lat), 3) if lat else None
        t["p95_latency_s"] = round(_p95(lat), 3) if lat else None
        t["est_response_tokens"] = chars // 4

    stamps = [m.ts for m in messages if m.ts is not None]
    tool_calls = [c for c in calls if c.method == "tools/call"]
    bad = [c for c in tool_calls if c.outcome != "ok"]
    summary = {
        "messages": len(messages),
        "requests": len(calls),
        "responses": responses,
        "notifications": notifications,
        "tool_calls": len(tool_calls),
        "tool_call_failure_rate": round(len(bad) / len(tool_calls), 3) if tool_calls else 0.0,
        "duration_s": round(max(stamps) - min(stamps), 3) if len(stamps) > 1 else None,
        "est_response_tokens": sum(c.resp_chars for c in calls) // 4,
        "parse_errors": len(parse_errors),
        "findings_high": sum(f.severity == "high" for f in findings),
        "findings_medium": sum(f.severity == "medium" for f in findings),
        "findings_low": sum(f.severity == "low" for f in findings),
    }
    return Analysis(summary, tools, findings, calls)


def redact_text(text: str) -> str:
    """Replace secret-looking substrings with ``[REDACTED:<pattern>]``."""
    for name, rx in _COMPILED.items():
        text = rx.sub(f"[REDACTED:{name}]", text)
    return text


def redact_value(value: Any) -> Any:
    """Recursively redact every string inside a JSON value."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    return value
