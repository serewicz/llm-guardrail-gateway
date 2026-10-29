"""The gateway pipeline: identify -> checks -> model -> checks -> answer.

Every step writes to the audit log. Nothing reaches a provider unless the
policy allows it.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .audit import AuditLog, hash_text
from .identity import Identity
from .policy import Policy
from .providers import build_providers


@dataclass
class Result:
    outcome: str  # allowed | blocked | warned
    answer: str = ""
    model: str | None = None
    reasons: list[str] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    request_id: str = ""


class Gateway:
    def __init__(self, policy: Policy, audit: AuditLog, providers: dict | None = None):
        self.policy = policy
        self.audit = audit
        self.providers = providers if providers is not None else build_providers(policy.models)
        self._n = 0

    # -- helpers ---------------------------------------------------------
    def _prompt_field(self, prompt: str):
        mode = self.policy.prompt_mode()
        return {"full": prompt, "hash": hash_text(prompt), "omit": None}[mode]

    def cost(self, model: str, tin: int, tout: int) -> float:
        m = self.policy.models[model]
        return round(tin / 1000 * m.get("usd_per_1k_in", 0) + tout / 1000 * m.get("usd_per_1k_out", 0), 6)

    def _log(self, rid, who: Identity, step, outcome, policy=None, **kw):
        return self.audit.append(request_id=rid, user=who.user, dept=who.dept, step=step,
                                 policy=policy, outcome=outcome, **kw)

    # -- main entry ------------------------------------------------------
    def handle(self, who: Identity, prompt: str, model: str | None = None, labels: list[str] | None = None) -> Result:
        self._n += 1
        rid = f"{int(time.time()*1000)}-{self._n}"
        t0 = time.perf_counter()
        dept = self.policy.dept(who.dept)
        allowed = dept.get("models", [])
        model = model or (allowed[0] if allowed else None)
        self._log(rid, who, "request", "received", model=model, prompt=self._prompt_field(prompt),
                  prompt_chars=len(prompt), labels=labels or [])

        def block(policy_name, reason):
            self._log(rid, who, "decision", "blocked", policy=policy_name, model=model, reason=reason,
                      latency_ms=round((time.perf_counter() - t0) * 1000, 2))
            return Result("blocked", reasons=[reason], model=model, request_id=rid)

        if model not in allowed:
            return block("models.allowlist", f"department '{who.dept}' may not use model '{model}'")
        if model not in self.providers:
            return block("models.available", f"model '{model}' is not configured or has no credentials")

        prov = self.providers[model]
        try:
            c = prov.complete(prompt, who.user)
        except Exception as e:  # provider down: fail closed, log it
            return block("provider.error", f"provider error: {type(e).__name__}")
        cost = self.cost(model, c.tokens_in, c.tokens_out)
        latency = round((time.perf_counter() - t0) * 1000, 2)
        self._log(rid, who, "decision", "allowed", model=model, tokens_in=c.tokens_in, tokens_out=c.tokens_out,
                  cost_usd=cost, latency_ms=latency)
        return Result("allowed", c.text, model, [], c.tokens_in, c.tokens_out, cost, rid)
