"""The gateway pipeline: identify -> checks -> model -> checks -> answer.

Every step writes to the audit log. Nothing reaches a provider unless the
policy allows it.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .audit import AuditLog, hash_text
from .budgets import Ledger
from .filters import find_pii, injection_score, redact
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
        self.ledger = Ledger.from_records(audit.records())

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

    def pii_action(self, kind: str) -> str:
        return self.policy.pii.get("types", {}).get(kind, self.policy.pii.get("action", "redact"))

    # -- main entry ------------------------------------------------------
    def handle(self, who: Identity, prompt: str, model: str | None = None, labels: list[str] | None = None) -> Result:
        self._n += 1
        rid = f"{int(time.time()*1000)}-{self._n}"
        t0 = time.perf_counter()
        dept = self.policy.dept(who.dept)
        allowed = dept.get("models", [])
        model = model or (allowed[0] if allowed else None)
        labels = list(labels or [])
        self._log(rid, who, "request", "received", model=model, prompt=self._prompt_field(redact(prompt, find_pii(prompt))),
                  prompt_chars=len(prompt), labels=labels)

        reasons: list[str] = []
        fired: list[str] = []

        def block(policy_name, reason, review=False, **kw):
            rec = self._log(rid, who, "decision", "blocked", policy=policy_name, model=model, reason=reason,
                            review=review, latency_ms=round((time.perf_counter() - t0) * 1000, 2), **kw)
            self.ledger.add(rec)
            return Result("blocked", reasons=[reason], model=model, request_id=rid,
                          tokens_in=kw.get("tokens_in", 0), tokens_out=kw.get("tokens_out", 0), cost_usd=kw.get("cost_usd", 0.0))

        if model not in allowed:
            return block("models.allowlist", f"department '{who.dept}' may not use model '{model}'")

        # Input checks: PII, then prompt injection.
        pii_cfg, inj_cfg = self.policy.pii, self.policy.injection
        if pii_cfg.get("enabled", True):
            found = find_pii(prompt)
            if found:
                acts = {f.kind: self.pii_action(f.kind) for f in found}
                self._log(rid, who, "input_check", "pii_found", policy="pii", findings=sorted(acts.items()))
                blocked = sorted(k for k, a in acts.items() if a == "block")
                if blocked:
                    return block("pii.block", f"prompt contains {', '.join(blocked)}")
                red = [f for f in found if acts[f.kind] == "redact"]
                if red:
                    prompt = redact(prompt, red)
                    fired.append("pii.redact"); reasons.append(f"redacted {', '.join(sorted({f.kind for f in red}))}")
                warn = sorted(k for k, a in acts.items() if a == "warn")
                if warn:
                    fired.append("pii.warn"); reasons.append(f"prompt may contain {', '.join(warn)}; kept on-prem")
                    labels.append("pii")
        if inj_cfg.get("enabled", True):
            inj = injection_score(prompt)
            if inj.score >= inj_cfg.get("warn_at", 0.3):
                self._log(rid, who, "input_check", "injection_suspect", policy="injection", score=inj.score, hits=inj.hits)
            if inj.score >= inj_cfg.get("block_at", 0.5) and inj_cfg.get("action", "block_and_review") == "block_and_review":
                return block("injection.block", f"possible prompt injection (score {inj.score}: {', '.join(inj.hits)})", review=True)
            if inj.score >= inj_cfg.get("warn_at", 0.3):
                fired.append("injection.warn"); reasons.append(f"possible prompt injection (score {inj.score})")

        # Budgets.
        warn_pct = self.policy.budgets.get("warn_at_pct", 80)
        bs = self.ledger.status(who.dept, dept, warn_pct)
        if bs.state == "over":
            action = dept.get("at_limit", self.policy.budgets.get("at_limit", "block"))
            fb = dept.get("fallback_model")
            over = f"monthly budget reached for {who.dept}: ${bs.spent_usd:.2f} of ${bs.limit_usd:.2f}"
            if action == "route_cheaper" and fb:
                # Spend continues past the limit, but only on the cheaper model.
                fired.append("budgets.route_cheaper")
                reasons.append(over + (f"; routed {model} -> {fb}" if fb != model else f"; using {fb}"))
                model = fb
            else:
                return block("budgets.at_limit", over)
        elif bs.state == "warn":
            fired.append("budgets.warn"); reasons.append(f"{bs.pct:.0f}% of monthly budget used (${bs.spent_usd:.2f}/${bs.limit_usd:.2f})")

        # Labels: restricted data never goes to a hosted model. Checked last so no
        # earlier reroute (e.g. budget fallback) can send it to a hosted model.
        no_hosted = [l for l in (labels or []) if not self.policy.labels.get(l, {}).get("allow_hosted_model", True)]
        if no_hosted and self.policy.models[model].get("hosted", False):
            local = [m for m in allowed if not self.policy.models[m].get("hosted", False)]
            if not local:
                return block("labels.no_hosted", f"labels {no_hosted} may not go to a hosted model and dept has no on-prem model")
            fired.append("labels.no_hosted"); reasons.append(f"rerouted {model} -> {local[0]} for labels {no_hosted}")
            model = local[0]

        if model not in self.providers:
            return block("models.available", f"model '{model}' is not configured or has no credentials")

        prov = self.providers[model]
        try:
            c = prov.complete(prompt, who.user)
        except Exception as e:  # provider down: fail closed, log it
            return block("provider.error", f"provider error: {type(e).__name__}")
        cost = self.cost(model, c.tokens_in, c.tokens_out)
        spent = dict(tokens_in=c.tokens_in, tokens_out=c.tokens_out, cost_usd=cost)

        # Retrieved text can carry instructions planted in a document.
        if c.context and inj_cfg.get("enabled", True) and inj_cfg.get("scan_retrieved", True):
            worst = max((injection_score(t) for t in c.context), key=lambda x: x.score)
            if worst.score >= inj_cfg.get("retrieved_block_at", inj_cfg.get("block_at", 0.5)):
                return block("injection.retrieved", f"retrieved text looks like an injection (score {worst.score}: {', '.join(worst.hits)}); answer withheld",
                             review=True, **spent)
            if worst.score >= inj_cfg.get("warn_at", 0.3):
                fired.append("injection.retrieved_warn"); reasons.append(f"retrieved text may contain instructions (score {worst.score})")

        # Output PII.
        text = c.text
        if pii_cfg.get("enabled", True) and pii_cfg.get("scan_output", True):
            out = [f for f in find_pii(text) if self.pii_action(f.kind) != "warn"]
            if out:
                text = redact(text, out)
                fired.append("pii.output_redact"); reasons.append(f"redacted {', '.join(sorted({f.kind for f in out}))} in answer")
        latency = round((time.perf_counter() - t0) * 1000, 2)
        outcome = "warned" if reasons else "allowed"
        rec = self._log(rid, who, "decision", outcome, policy=",".join(fired) or None, reasons=reasons, model=model,
                        tokens_in=c.tokens_in, tokens_out=c.tokens_out, cost_usd=cost, latency_ms=latency)
        self.ledger.add(rec)
        return Result(outcome, text, model, reasons, c.tokens_in, c.tokens_out, cost, rid)
