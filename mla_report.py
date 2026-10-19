"""Report renderers (text, markdown, json) for mcp-log-analyzer."""
from __future__ import annotations

import json

from mla_core import Analysis


def _fmt(v: object) -> str:
    return "-" if v is None else str(v)


def render_text(a: Analysis) -> str:
    """Plain-text report for terminals."""
    s = a.summary
    out = ["MCP LOG ANALYZER REPORT", "=" * 23,
           f"messages={s['messages']} requests={s['requests']} responses={s['responses']} "
           f"notifications={s['notifications']} parse_errors={s['parse_errors']}",
           f"tool_calls={s['tool_calls']} failure_rate={s['tool_call_failure_rate']:.0%} "
           f"duration_s={_fmt(s['duration_s'])} est_response_tokens={s['est_response_tokens']}",
           f"findings: high={s['findings_high']} medium={s['findings_medium']} low={s['findings_low']}",
           "", "PER-TOOL STATS",
           f"{'tool':<18}{'calls':>6}{'err':>5}{'hung':>5}{'avg_s':>8}{'p95_s':>8}{'~tokens':>9}"]
    for name, t in sorted(a.tools.items()):
        out.append(f"{name:<18}{t['calls']:>6}{t['errors']:>5}{t['no_response']:>5}"
                   f"{_fmt(t['avg_latency_s']):>8}{_fmt(t['p95_latency_s']):>8}{t['est_response_tokens']:>9}")
    out += ["", "FINDINGS"]
    if not a.findings:
        out.append("  none - session looks healthy")
    for f in a.findings:
        where = f"line {f.line}" if f.line else "log"
        out.append(f"  [{f.severity.upper():<6}] {f.code:<18} {where:<9} {f.message}")
    return "\n".join(out) + "\n"


def render_markdown(a: Analysis) -> str:
    """Markdown report (paste into issues / PRs)."""
    s = a.summary
    out = ["# MCP session report", "",
           f"- Messages: **{s['messages']}** ({s['requests']} requests, {s['responses']} responses, "
           f"{s['notifications']} notifications)",
           f"- Tool calls: **{s['tool_calls']}**, failure rate **{s['tool_call_failure_rate']:.0%}**",
           f"- Estimated response tokens: **{s['est_response_tokens']}**",
           f"- Findings: {s['findings_high']} high / {s['findings_medium']} medium / {s['findings_low']} low",
           "", "## Per-tool stats", "",
           "| Tool | Calls | Errors | Hung | Avg s | p95 s | ~Tokens |", "|---|---|---|---|---|---|---|"]
    for name, t in sorted(a.tools.items()):
        out.append(f"| `{name}` | {t['calls']} | {t['errors']} | {t['no_response']} | "
                   f"{_fmt(t['avg_latency_s'])} | {_fmt(t['p95_latency_s'])} | {t['est_response_tokens']} |")
    out += ["", "## Findings", ""]
    if not a.findings:
        out.append("None - session looks healthy.")
    for f in a.findings:
        where = f"line {f.line}" if f.line else "log"
        out.append(f"- **{f.severity.upper()}** `{f.code}` ({where}): {f.message}")
    return "\n".join(out) + "\n"


def render_json(a: Analysis) -> str:
    """Machine-readable JSON report."""
    return json.dumps(a.to_dict(), indent=2) + "\n"


RENDERERS = {"text": render_text, "markdown": render_markdown, "json": render_json}
