"""Load and validate the policy-as-code YAML file."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

PROMPT_MODES = {"full", "hash", "omit"}


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    version: str
    models: dict
    departments: dict
    users: dict
    labels: dict = field(default_factory=dict)
    audit: dict = field(default_factory=dict)
    budgets: dict = field(default_factory=dict)
    pii: dict = field(default_factory=dict)
    injection: dict = field(default_factory=dict)
    default_dept: str = "unassigned"

    def dept(self, name: str) -> dict:
        return self.departments.get(name) or self.departments[self.default_dept]

    def prompt_mode(self) -> str:
        return self.audit.get("log_prompt_text", "hash")


def load_policy(path: str | Path) -> Policy:
    raw = yaml.safe_load(Path(path).read_text())
    return validate(raw)


def validate(raw: dict) -> Policy:
    for key in ("version", "models", "departments", "users"):
        if key not in raw:
            raise PolicyError(f"missing required section: {key}")
    p = Policy(**{k: raw[k] for k in raw if k in Policy.__dataclass_fields__})
    if p.default_dept not in p.departments:
        raise PolicyError(f"default_dept '{p.default_dept}' is not a department")
    for d, cfg in p.departments.items():
        for m in cfg.get("models", []):
            if m not in p.models:
                raise PolicyError(f"department {d} allows unknown model {m}")
        cheap = cfg.get("fallback_model")
        if cheap and cheap not in cfg.get("models", []):
            raise PolicyError(f"department {d}: fallback_model {cheap} must be in its allowed models")
        if cfg.get("monthly_budget_usd", 0) < 0:
            raise PolicyError(f"department {d}: negative budget")
    for u, d in p.users.items():
        if d not in p.departments:
            raise PolicyError(f"user {u} maps to unknown department {d}")
    if p.prompt_mode() not in PROMPT_MODES:
        raise PolicyError(f"audit.log_prompt_text must be one of {sorted(PROMPT_MODES)}")
    pct = p.budgets.get("warn_at_pct", 80)
    if not 0 < pct <= 100:
        raise PolicyError("budgets.warn_at_pct must be in (0, 100]")
    return p
