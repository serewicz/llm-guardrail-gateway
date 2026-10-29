from pathlib import Path

import pytest

from gateway.audit import AuditLog
from gateway.core import Gateway
from gateway.policy import load_policy
from gateway.providers import MockProvider

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def policy():
    return load_policy(ROOT / "policy.yaml")


@pytest.fixture
def gw(policy, tmp_path):
    provs = {}
    for name, m in policy.models.items():
        p = MockProvider(name, reply="Lake Travis is a reservoir on the Colorado River.")
        p.hosted = bool(m.get("hosted", False))
        provs[name] = p
    return Gateway(policy, AuditLog(tmp_path / "audit.jsonl"), provs)
