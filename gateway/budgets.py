"""Monthly department budgets, computed from the audit log itself.

Spend is the sum of cost_usd on 'decision' records for the department in the
current calendar month (UTC). Because the ledger is rebuilt from the log, the
budget and the audit trail cannot disagree.
"""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass


def month_key(ts: float) -> str:
    return time.strftime("%Y-%m", time.gmtime(ts))


@dataclass
class BudgetStatus:
    dept: str
    month: str
    spent_usd: float
    limit_usd: float | None
    pct: float | None
    state: str  # ok | warn | over | unlimited


class Ledger:
    def __init__(self):
        self.spend = defaultdict(float)     # (month, dept) -> usd
        self.tokens = defaultdict(lambda: [0, 0, 0])  # (month, dept) -> [in, out, requests]

    def add(self, rec: dict):
        # Any decision that reached a model costs money, even if the answer was withheld afterwards.
        if rec.get("step") != "decision" or not (rec.get("cost_usd") or rec.get("outcome") in ("allowed", "warned")):
            return
        k = (month_key(rec["ts"]), rec["dept"])
        self.spend[k] += rec.get("cost_usd", 0.0) or 0.0
        t = self.tokens[k]
        t[0] += rec.get("tokens_in", 0) or 0; t[1] += rec.get("tokens_out", 0) or 0; t[2] += 1

    @classmethod
    def from_records(cls, records) -> "Ledger":
        led = cls()
        for r in records:
            led.add(r)
        return led

    def status(self, dept: str, dept_cfg: dict, warn_pct: float, month: str | None = None) -> BudgetStatus:
        month = month or month_key(time.time())
        spent = round(self.spend[(month, dept)], 6)
        limit = dept_cfg.get("monthly_budget_usd")
        if limit is None:
            return BudgetStatus(dept, month, spent, None, None, "unlimited")
        pct = 100.0 * spent / limit if limit else 100.0
        state = "over" if spent >= limit else "warn" if pct >= warn_pct else "ok"
        return BudgetStatus(dept, month, spent, limit, round(pct, 2), state)


def cost_report(records, policy, month: str | None = None) -> list[dict]:
    led = Ledger.from_records(records)
    month = month or month_key(time.time())
    warn = policy.budgets.get("warn_at_pct", 80)
    rows = []
    for dept, cfg in policy.departments.items():
        s = led.status(dept, cfg, warn, month)
        tin, tout, n = led.tokens[(month, dept)]
        rows.append(dict(dept=dept, month=month, requests=n, tokens_in=tin, tokens_out=tout,
                         spent_usd=s.spent_usd, budget_usd=s.limit_usd, pct=s.pct, state=s.state))
    return rows
