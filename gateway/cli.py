"""Command line: cost report and audit-log verification.

  python -m gateway.cli report [--month YYYY-MM] [--log audit/audit.jsonl] [--policy policy.yaml] [--csv]
  python -m gateway.cli verify [--log audit/audit.jsonl]
"""
from __future__ import annotations

import argparse
import csv
import sys

from .audit import AuditLog
from .budgets import cost_report
from .policy import load_policy


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gateway")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("report"); r.add_argument("--month"); r.add_argument("--csv", action="store_true")
    v = sub.add_parser("verify")
    for p in (r, v):
        p.add_argument("--log", default="audit/audit.jsonl")
        p.add_argument("--policy", default="policy.yaml")
    a = ap.parse_args(argv)
    log = AuditLog(a.log)
    if a.cmd == "verify":
        ok, msg = log.verify()
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    rows = cost_report(log.records(), load_policy(a.policy), a.month)
    if a.csv:
        w = csv.DictWriter(sys.stdout, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
        return 0
    print(f"{'department':<18}{'month':<9}{'reqs':>6}{'tok_in':>9}{'tok_out':>9}{'spent $':>11}{'budget $':>10}{'used':>8}  state")
    for x in rows:
        b = "-" if x["budget_usd"] is None else f"{x['budget_usd']:.2f}"
        pct = "-" if x["pct"] is None else f"{x['pct']:.1f}%"
        print(f"{x['dept']:<18}{x['month']:<9}{x['requests']:>6}{x['tokens_in']:>9}{x['tokens_out']:>9}{x['spent_usd']:>11.4f}{b:>10}{pct:>8}  {x['state']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
