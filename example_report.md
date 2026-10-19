# MCP session report

- Messages: **24** (12 requests, 11 responses, 1 notifications)
- Tool calls: **10**, failure rate **30%**
- Estimated response tokens: **7679**
- Findings: 2 high / 4 medium / 3 low

## Per-tool stats

| Tool | Calls | Errors | Hung | Avg s | p95 s | ~Tokens |
|---|---|---|---|---|---|---|
| `delete_records` | 1 | 1 | 0 | 0.05 | 0.05 | 14 |
| `read_file` | 4 | 0 | 0 | 0.125 | 0.2 | 72 |
| `run_query` | 2 | 1 | 0 | 3.8 | 6.5 | 32 |
| `search_docs` | 3 | 0 | 1 | 0.65 | 0.9 | 7523 |

## Findings

- **HIGH** `SECRET_IN_TRAFFIC` (line 9): Possible secret (aws_access_key_id) in message payload. Redact before sharing.
- **HIGH** `UNANSWERED_REQUEST` (line 22): search_docs (id=11) never got a response (hung or dropped).
- **MEDIUM** `TOOL_ERROR` (line 10): run_query: call returned normally but result.isError=true: syntax error near SELEC
- **MEDIUM** `REPEATED_CALL` (line 12): read_file was called 3x with identical arguments (possible agent loop).
- **MEDIUM** `RPC_ERROR` (line 20): delete_records: JSON-RPC error: Unknown tool: delete_records
- **MEDIUM** `UNKNOWN_TOOL` (line 20): Tool 'delete_records' was called but is not in tools/list.
- **LOW** `SLOW_CALL` (line 18): run_query took 6.50s (threshold 2s).
- **LOW** `LARGE_PAYLOAD` (line 23): search_docs returned ~7510 tokens of context; consider paging or trimming.
- **LOW** `PARSE_ERROR` (line 25): Skipped line: invalid JSON (Expecting value)

