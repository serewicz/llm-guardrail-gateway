import time

from gateway.budgets import Ledger, cost_report, month_key
from gateway.cli import main
from gateway.identity import Identity


def spend(gw, dept, usd):
    """Simulate past usage by writing decision records straight into the audit log."""
    rec = gw.audit.append(request_id="sim", user="sim", dept=dept, step="decision", outcome="allowed",
                          model="onprem-llama", tokens_in=1000, tokens_out=500, cost_usd=usd)
    gw.ledger.add(rec)


def test_under_budget_is_allowed(gw):
    spend(gw, "legal", 10)
    assert gw.handle(Identity("lee", "legal"), "q").outcome == "allowed"


def test_warn_at_80_pct(gw):
    spend(gw, "legal", 80)  # 80 of 100
    r = gw.handle(Identity("lee", "legal"), "q")
    assert r.outcome == "warned" and "80%" in r.reasons[0]


def test_just_below_warn(gw):
    spend(gw, "legal", 79.99)
    assert gw.handle(Identity("lee", "legal"), "q").outcome == "allowed"


def test_block_at_limit(gw):
    spend(gw, "legal", 100)
    r = gw.handle(Identity("lee", "legal"), "q")
    assert r.outcome == "blocked" and "budget" in r.reasons[0]
    assert list(gw.audit.records())[-1]["policy"] == "budgets.at_limit"


def test_route_cheaper_at_limit(gw):
    spend(gw, "it", 500)
    r = gw.handle(Identity("dev", "it"), "q", model="hosted-large")
    assert r.outcome == "warned" and r.model == "hosted-small"


def test_budgets_are_per_department(gw):
    spend(gw, "legal", 100)
    assert gw.handle(Identity("maria", "water-operations"), "q").outcome == "allowed"


def test_last_month_does_not_count(gw):
    old = time.time() - 40 * 86400
    gw.ledger.add({"ts": old, "step": "decision", "outcome": "allowed", "dept": "legal", "cost_usd": 1000})
    assert gw.handle(Identity("lee", "legal"), "q").outcome == "allowed"


def test_blocked_requests_cost_nothing(gw):
    spend(gw, "legal", 100)
    for _ in range(3):
        gw.handle(Identity("lee", "legal"), "q")
    led = Ledger.from_records(gw.audit.records())
    assert round(led.spend[(month_key(time.time()), "legal")], 2) == 100


def test_simulated_month(gw):
    """1,000 simulated water-operations requests at ~$0.25 each against a $200 budget."""
    outcomes = []
    for i in range(1000):
        if gw.ledger.status("water-operations", gw.policy.departments["water-operations"], 80).state == "over":
            outcomes.append(gw.handle(Identity("maria", "water-operations"), "q").outcome)
            continue
        spend(gw, "water-operations", 0.25)
        outcomes.append("sim")
    # 800 requests reach the $200 limit; everything after is blocked.
    assert outcomes.count("sim") == 800 and outcomes.count("blocked") == 200


def test_ledger_rebuilds_from_log(gw, policy):
    spend(gw, "legal", 42)
    gw2 = type(gw)(policy, type(gw.audit)(gw.audit.path), gw.providers)
    assert gw2.ledger.status("legal", policy.departments["legal"], 80).spent_usd == 42


def test_restricted_label_reroutes_to_onprem(gw):
    r = gw.handle(Identity("maria", "water-operations"), "q", model="hosted-small", labels=["cip-restricted"])
    assert r.model == "onprem-llama" and r.outcome == "warned"


def test_restricted_label_blocks_if_no_onprem(gw):
    gw.policy.departments["it"]["models"] = ["hosted-large", "hosted-small"]
    r = gw.handle(Identity("dev", "it"), "q", labels=["cip-restricted"])
    assert r.outcome == "blocked"


def test_budget_fallback_cannot_bypass_label(gw):
    gw.policy.departments["it"]["fallback_model"] = "hosted-small"
    spend(gw, "it", 500)
    r = gw.handle(Identity("dev", "it"), "q", model="hosted-large", labels=["cip-restricted"])
    assert r.model == "onprem-llama"


def test_cost_report(gw, policy, capsys, tmp_path):
    spend(gw, "legal", 85)
    rows = {r["dept"]: r for r in cost_report(gw.audit.records(), policy)}
    assert rows["legal"]["state"] == "warn" and rows["legal"]["pct"] == 85.0
    assert rows["it"]["state"] == "ok"
    assert main(["report", "--log", str(gw.audit.path), "--policy", "policy.yaml"]) == 0
    assert "legal" in capsys.readouterr().out
    assert main(["verify", "--log", str(gw.audit.path)]) == 0
