# Launch posts

## X / LinkedIn (3 sentences)
My MCP server "sometimes does nothing" and the logs were unreadable, so I built MCP Log Analyzer. It reads a JSONL session log and flags hung calls, isError results, agent loops, slow tools, context bloat and leaked secrets, with zero dependencies. Free and MIT: https://github.com/Waqas-Ai-Engineer/mcp-log-analyzer

## Reddit (r/ClaudeAI, r/mcp, r/Python: check each sub's self-promo rules first)
Title: I built a small tool to find hung/looping MCP tool calls in session logs
Body: Debugging MCP is painful when a tool call never returns or an agent calls the same tool 5 times. I wrote a stdlib-only Python CLI that pairs requests/responses from a JSONL capture and reports hung calls, isError results, loops, p95 latency per tool, token-heavy payloads and secret-looking strings, plus a redact command for sharing logs. Demo runs offline on synthetic data. Feedback welcome on the log format and missing checks. Repo: https://github.com/Waqas-Ai-Engineer/mcp-log-analyzer

## Show HN title
Show HN: MCP Log Analyzer - find hung and looping tool calls in MCP session logs
