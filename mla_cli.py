"""Command line interface for mcp-log-analyzer."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from mla_core import SEVERITY_ORDER, analyze, parse_log, redact_value
from mla_report import RENDERERS
from mla_sample import sample_lines


def _read(path: str) -> list[str]:
    if path == "-":
        return sys.stdin.read().splitlines()
    with open(path, encoding="utf-8") as fh:
        return fh.read().splitlines()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mla.py",
        description="Analyze MCP (Model Context Protocol) JSON-RPC session logs. "
                    "Use only on logs you own or are authorized to inspect.")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze a JSONL session log")
    a.add_argument("log", help="path to JSONL log, or - for stdin")
    a.add_argument("--format", choices=sorted(RENDERERS), default="text")
    a.add_argument("--slow", type=float, default=2.0, help="slow-call threshold in seconds (default 2)")
    a.add_argument("--large-chars", type=int, default=20000, help="large payload threshold in chars")
    a.add_argument("--repeat", type=int, default=3, help="identical-call count that flags a loop")
    a.add_argument("--fail-on", choices=sorted(SEVERITY_ORDER), help="exit 1 if a finding at/above this severity exists")
    r = sub.add_parser("redact", help="write a copy of the log with secrets redacted")
    r.add_argument("log")
    r.add_argument("-o", "--output", required=True)
    d = sub.add_parser("demo", help="analyze built-in synthetic SAMPLE DATA (offline)")
    d.add_argument("--format", choices=sorted(RENDERERS), default="text")
    s = sub.add_parser("sample", help="print the synthetic sample log as JSONL")
    s.set_defaults(format="text")
    return p


def _run_analysis(lines: list[str], fmt: str, slow: float = 2.0, large: int = 20000,
                  repeat: int = 3) -> tuple[str, int]:
    messages, errors = parse_log(lines)
    result = analyze(messages, errors, slow=slow, large_chars=large, repeat=repeat)
    return RENDERERS[fmt](result), max((SEVERITY_ORDER[f.severity] for f in result.findings), default=0)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns a process exit code."""
    args = build_parser().parse_args(argv)
    if args.cmd == "sample":
        print("\n".join(sample_lines()))
        return 0
    if args.cmd == "demo":
        print("SAMPLE DATA - synthetic session, nothing here is real.\n")
        text, _ = _run_analysis(sample_lines(), args.format)
        print(text)
        return 0
    try:
        lines = _read(args.log)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "redact":
        messages, errors = parse_log(lines)
        with open(args.output, "w", encoding="utf-8") as fh:
            for m in messages:
                rec = {"ts": m.ts, "dir": m.direction, "msg": redact_value(m.body)}
                fh.write(json.dumps({k: v for k, v in rec.items() if v is not None}) + "\n")
        print(f"wrote {len(messages)} messages to {args.output} ({len(errors)} unparseable lines dropped)")
        return 0
    text, worst = _run_analysis(lines, args.format, args.slow, args.large_chars, args.repeat)
    print(text)
    if args.fail_on and worst >= SEVERITY_ORDER[args.fail_on]:
        return 1
    return 0
