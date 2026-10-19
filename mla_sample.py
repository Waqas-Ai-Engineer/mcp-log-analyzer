"""Synthetic sample MCP session used by the demo and example file.

Everything here is made up (SAMPLE DATA). The AWS key is the public example key
from AWS documentation, not a real credential.
"""
from __future__ import annotations

import json

T0 = 1_700_000_000.0  # fixed synthetic start time


def _w(ts: float, direction: str, msg: dict) -> str:
    return json.dumps({"ts": round(ts, 3), "dir": direction, "msg": msg})


def sample_lines() -> list[str]:
    """Return a deterministic list of JSONL lines (SAMPLE DATA)."""
    L: list[str] = []
    rpc = {"jsonrpc": "2.0"}
    L.append(_w(T0, "c2s", {**rpc, "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}))
    L.append(_w(T0 + 0.1, "s2c", {**rpc, "id": 1, "result": {"serverInfo": {"name": "demo-server"}}}))
    L.append(_w(T0 + 0.11, "c2s", {**rpc, "method": "notifications/initialized"}))
    L.append(_w(T0 + 0.2, "c2s", {**rpc, "id": 2, "method": "tools/list"}))
    tools = [{"name": n} for n in ("search_docs", "read_file", "run_query", "send_email")]
    L.append(_w(T0 + 0.3, "s2c", {**rpc, "id": 2, "result": {"tools": tools}}))

    def call(i: int, t: float, name: str, args: dict, dur: float | None, result: dict | None = None,
             error: dict | None = None) -> None:
        L.append(_w(t, "c2s", {**rpc, "id": i, "method": "tools/call",
                               "params": {"name": name, "arguments": args}}))
        if dur is None:
            return
        body = {**rpc, "id": i}
        body.update({"error": error} if error else {"result": result})
        L.append(_w(t + dur, "s2c", body))

    ok = lambda text: {"content": [{"type": "text", "text": text}]}  # noqa: E731
    call(3, T0 + 1.0, "search_docs", {"q": "refund policy"}, 0.4, ok("3 matches"))
    call(4, T0 + 2.0, "read_file", {"path": "config.env"}, 0.2,
         ok("DB_HOST=localhost\nAWS_KEY=AKIAIOSFODNN7EXAMPLE"))
    call(5, T0 + 3.0, "run_query", {"sql": "SELEC * FROM t"}, 1.1,
         {"isError": True, "content": [{"type": "text", "text": "syntax error near SELEC"}]})
    for i, t in ((6, 4.0), (7, 4.5), (8, 5.0)):
        call(i, T0 + t, "read_file", {"path": "notes.txt"}, 0.1, ok("file not found, retrying"))
    call(9, T0 + 6.0, "run_query", {"sql": "SELECT count(*) FROM orders"}, 6.5, ok("42"))
    call(10, T0 + 13.0, "delete_records", {"table": "orders"}, 0.05,
         error={"code": -32602, "message": "Unknown tool: delete_records"})
    call(11, T0 + 14.0, "search_docs", {"q": "shipping times"}, None)
    call(12, T0 + 15.0, "search_docs", {"q": "everything"}, 0.9, ok("Lorem ipsum " * 2500))
    L.append("this line is not JSON (sample parse error)")
    return L
