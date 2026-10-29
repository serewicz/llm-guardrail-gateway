import copy

import pytest
import yaml

from gateway.policy import PolicyError, validate
from tests.conftest import ROOT

RAW = yaml.safe_load((ROOT / "policy.yaml").read_text())


def bad(mutate):
    raw = copy.deepcopy(RAW); mutate(raw)
    with pytest.raises(PolicyError):
        validate(raw)


def test_shipped_policy_is_valid():
    p = validate(copy.deepcopy(RAW))
    assert p.dept("nope") is p.departments["unassigned"]


def test_legal_has_no_hosted_models(policy):
    assert all(not policy.models[m].get("hosted") for m in policy.departments["legal"]["models"])


def test_cip_restricted_label_blocks_hosted(policy):
    assert policy.labels["cip-restricted"]["allow_hosted_model"] is False


def test_rejects_unknown_model():       bad(lambda r: r["departments"]["legal"]["models"].append("gpt-x"))
def test_rejects_unknown_user_dept():   bad(lambda r: r["users"].__setitem__("bob", "marketing"))
def test_rejects_bad_prompt_mode():     bad(lambda r: r["audit"].__setitem__("log_prompt_text", "sometimes"))
def test_rejects_bad_warn_pct():        bad(lambda r: r["budgets"].__setitem__("warn_at_pct", 150))
def test_rejects_negative_budget():     bad(lambda r: r["departments"]["legal"].__setitem__("monthly_budget_usd", -1))
def test_rejects_missing_section():     bad(lambda r: r.pop("departments"))
def test_rejects_fallback_not_allowed(): bad(lambda r: r["departments"]["legal"].__setitem__("fallback_model", "hosted-small"))
