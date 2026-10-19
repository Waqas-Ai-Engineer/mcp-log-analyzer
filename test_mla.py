import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from mla_cli import main
from mla_core import analyze, parse_log, redact_text, scan_secrets, to_ts
from mla_report import RENDERERS
from mla_sample import sample_lines


def run(lines, **kw):
    msgs, errs = parse_log(lines)
    return analyze(msgs, errs, **kw)


def codes(a):
    return [f.code for f in a.findings]


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.a = run(sample_lines())

    def test_to_ts_variants(self):
        self.assertEqual(to_ts(5), 5.0)
        self.assertEqual(to_ts("2.5"), 2.5)
        self.assertEqual(to_ts("1970-01-01T00:00:10Z"), 10.0)
        self.assertIsNone(to_ts("junk"))
        self.assertIsNone(to_ts(True))

    def test_raw_and_wrapped_formats(self):
        raw = ['{"jsonrpc":"2.0","id":1,"method":"ping","ts":1}', '{"jsonrpc":"2.0","id":1,"result":{},"ts":2}']
        a = run(raw)
        self.assertEqual(a.calls[0].latency, 1.0)
        self.assertEqual(a.calls[0].outcome, "ok")

    def test_parse_errors(self):
        self.assertIn("PARSE_ERROR", codes(self.a))
        _, errs = parse_log(["[1]", "{}", "x"])
        self.assertEqual(len(errs), 3)

    def test_unanswered(self):
        self.assertIn("UNANSWERED_REQUEST", codes(self.a))

    def test_tool_error_and_rpc_error(self):
        c = codes(self.a)
        self.assertIn("TOOL_ERROR", c)
        self.assertIn("RPC_ERROR", c)

    def test_unknown_tool(self):
        self.assertIn("UNKNOWN_TOOL", codes(self.a))

    def test_repeated_and_threshold(self):
        self.assertIn("REPEATED_CALL", codes(self.a))
        self.assertNotIn("REPEATED_CALL", codes(run(sample_lines(), repeat=4)))

    def test_slow_and_large(self):
        c = codes(self.a)
        self.assertIn("SLOW_CALL", c)
        self.assertIn("LARGE_PAYLOAD", c)
        self.assertNotIn("SLOW_CALL", codes(run(sample_lines(), slow=100)))

    def test_secret_detected_not_leaked(self):
        f = [x for x in self.a.findings if x.code == "SECRET_IN_TRAFFIC"]
        self.assertTrue(f)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", RENDERERS["text"](self.a))

    def test_tool_stats(self):
        t = self.a.tools["read_file"]
        self.assertEqual(t["calls"], 4)
        self.assertIsNotNone(t["p95_latency_s"])

    def test_sorted_by_severity(self):
        sev = [f.severity for f in self.a.findings]
        self.assertEqual(sev[0], "high")

    def test_clean_session(self):
        lines = [json.dumps(m) for m in (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            {"jsonrpc": "2.0", "id": 1, "result": {}})]
        self.assertEqual(run(lines).findings, [])

    def test_missing_initialize(self):
        a = run(['{"jsonrpc":"2.0","id":1,"method":"ping"}', '{"jsonrpc":"2.0","id":1,"result":{}}'])
        self.assertIn("NO_INITIALIZE", codes(a))

    def test_orphan_response(self):
        self.assertIn("ORPHAN_RESPONSE", codes(run(['{"jsonrpc":"2.0","id":9,"result":{}}'])))


class RedactTests(unittest.TestCase):
    def test_redact(self):
        s = "key AKIAIOSFODNN7EXAMPLE and password=hunter2example"
        out = redact_text(s)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertNotIn("hunter2example", out)
        self.assertEqual(scan_secrets(out), [])


class CliTests(unittest.TestCase):
    def call(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_demo_all_formats(self):
        for fmt in ("text", "markdown", "json"):
            code, out = self.call(["demo", "--format", fmt])
            self.assertEqual(code, 0)
            self.assertIn("SAMPLE DATA", out)
        self.assertIn("findings", json.loads(self.call(["demo", "--format", "json"])[1].split("\n\n", 1)[1]))

    def test_analyze_fail_on_and_redact(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "s.jsonl")
            with open(log, "w") as fh:
                fh.write(self.call(["sample"])[1])
            self.assertEqual(self.call(["analyze", log, "--fail-on", "high"])[0], 1)
            out = os.path.join(d, "r.jsonl")
            self.assertEqual(self.call(["redact", log, "-o", out])[0], 0)
            self.assertNotIn("SECRET_IN_TRAFFIC", self.call(["analyze", out, "--format", "json"])[1])
            self.assertIn("SECRET_IN_TRAFFIC", self.call(["analyze", log, "--format", "json"])[1])

    def test_missing_file(self):
        self.assertEqual(self.call(["analyze", "/no/such/file.jsonl"])[0], 2)


if __name__ == "__main__":
    unittest.main()
