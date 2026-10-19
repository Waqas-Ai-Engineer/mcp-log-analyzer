# Authorized use only

- Analyze only MCP session logs you own or have explicit permission to inspect.
- Logs can contain personal data, prompts and credentials: store them securely and run `redact` before sharing.
- This tool performs no network access, interception or capture; it only reads files you give it.
- Sample data is synthetic. The AWS key in the sample is the public AWS documentation example.
- Redaction is best-effort pattern matching, not a guarantee. Rotate any real secret that appeared in a log.
