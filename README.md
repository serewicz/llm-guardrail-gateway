# llm-guardrail-gateway

**Status: early build, not production.** Built and tested with mock models and fictional data only. No real users. Not security reviewed.

One policy layer between people (or apps) and any LLM, hosted or on-prem. Every request passes the same checks, set in one YAML file a governance owner can review, and every step lands in an append-only audit log.

It extends [utility-rag-assistant](https://github.com/serewicz/utility-rag-assistant), which already does role-based retrieval, a per-query cost log, CI leak tests and a NIST AI RMF starter policy. The gateway takes those ideas out of one app and puts them in front of every model.

## The problem

When a utility puts LLMs in front of staff, someone has to answer:

- Did restricted data or personal information go to a hosted model?
- Did someone talk the model into ignoring its rules, or did a document carry hidden instructions?
- Which department spent what on tokens this month, and who stops it at the limit?
- Can we show an auditor what happened?

Usually each app answers these its own way, or not at all.

## Architecture

```mermaid
flowchart LR
    U[user / app<br/>X-User header<br/>SSO later] --> ID[identify<br/>user + dept]
    ID --> IN[input checks<br/>PII, injection]
    IN --> AL[model allowlist]
    AL --> BU[budget check<br/>warn / block / route cheaper]
    BU --> LB[label check<br/>cip-restricted stays on-prem]
    LB --> P{provider}
    P --> M1[mock / offline]
    P --> M2[utility-rag-assistant]
    P --> M3[OpenAI-compatible<br/>hosted or Ollama]
    P --> OUT[output + retrieved-text checks]
    OUT --> A[answer]
    ID -.-> LOG[(append-only audit log<br/>hash-chained JSONL)]
    IN -.-> LOG
    BU -.-> LOG
    OUT -.-> LOG
```

| Piece | File |
|---|---|
| Pipeline | `gateway/core.py` |
| Policy loader and validation | `gateway/policy.py`, `policy.yaml` |
| Budgets and cost report | `gateway/budgets.py`, `gateway/cli.py` |
| Audit log (SHA-256 chain, `verify`) | `gateway/audit.py` |
| Providers (mock, utility-rag, OpenAI-compatible) | `gateway/providers.py` |
| Demo identity (header) | `gateway/identity.py` |
| HTTP API | `gateway/app.py` |

Each audit record has: timestamp, request id, user, department, step, policy that fired, model, tokens in and out, estimated cost, latency, outcome, and the prompt as full text, a SHA-256 hash, or nothing, per `audit.log_prompt_text`.

## Policy as code

`policy.yaml` (all values fictional):

```yaml
departments:
  water-operations: { monthly_budget_usd: 200, models: [onprem-llama, hosted-small, utility-rag] }
  legal:            { monthly_budget_usd: 100, models: [onprem-llama] }      # no hosted models
  it:               { monthly_budget_usd: 500, models: [hosted-large, hosted-small, onprem-llama],
                      at_limit: route_cheaper, fallback_model: hosted-small }
labels:
  cip-restricted:   { allow_hosted_model: false }
budgets:
  warn_at_pct: 80
  at_limit: block
audit:
  log_prompt_text: hash   # full | hash | omit
```

The loader rejects unknown models, users mapped to unknown departments, bad prompt modes, negative budgets, and fallback models a department is not allowed to use. Budgets are computed from the audit log itself, so spend and audit trail cannot disagree.

## Quickstart

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -q                      # all tests, offline
python scripts/demo.py         # walk-through with fictional users
uvicorn gateway.app:app        # HTTP API on :8000 (mock models)
curl -s localhost:8000/v1/ask -H 'X-User: maria' -H 'content-type: application/json' \
     -d '{"prompt":"How is Lake Travis water released during a flood?"}'
python -m gateway.cli report   # per-department cost report from audit/audit.jsonl
python -m gateway.cli verify   # check the audit log hash chain
```

To put it in front of utility-rag-assistant, run that app on port 8000, start the gateway on another port (`uvicorn gateway.app:app --port 8080`), and ask with `"model": "utility-rag"` as a `water-operations` user. The gateway forwards the user in `X-User`, so the RAG app still applies its own role-based retrieval.

## Demo

`python scripts/demo.py` seeds fictional month-to-date spend (legal at $85 of $100, IT at its $500 limit) and runs six requests. Actual output from this commit:

```
lee (legal) asks model=hosted-small      -> BLOCKED  department 'legal' may not use model 'hosted-small'
lee (legal) asks model=default           -> WARNED   85% of monthly budget used ($85.00/$100.00)
dev (it) asks model=hosted-large         -> WARNED   budget reached; routed hosted-large -> hosted-small
maria asks hosted-small, cip-restricted  -> WARNED   rerouted hosted-small -> onprem-llama
stranger (unassigned) asks hosted-large  -> BLOCKED  not on the allowlist
```

## Test results

<!-- results -->
35 tests pass (`pytest -q`, offline): audit chain and tamper detection, model allowlists, prompt logging modes, fail-closed on provider errors, policy validation, budgets (warn at 80%, block at limit, route cheaper, per-department, month rollover, a simulated 1,000-request month), label routing and the cost report.
<!-- /results -->

## Limitations (read these)

- **Identity is a demo header.** Anyone can send `X-User: dev`. SSO/OIDC is roadmap work. Do not expose this to a network.
- **Costs are estimates.** Token counts from the mock and the RAG app use ~4 characters per token. Prices in `policy.yaml` are placeholders.
- **The budget check runs before the call**, so a department can overshoot its limit by one request.
- **Labels come from the caller** (or the RAG app). The gateway does not classify documents itself.
- **The hosted and Ollama providers are written but not tested end to end.** Everything above ran against mock models.
- **The audit log is tamper-evident, not tamper-proof.** Someone with write access can rewrite the whole file. Ship it to WORM storage or a SIEM.
- It is **not NERC CIP certified**, and it **does not replace a security review**.

## Roadmap

1. ~~Gateway, audit log, per-user and per-department cost tracking~~ (built)
2. ~~Budgets with warn and stop, policy YAML and its tests~~ (built)
3. PII filtering and prompt-injection test sets in CI
4. SSO identity in place of the demo header; end-to-end tests with a hosted model and Ollama
5. Export the audit log to a SIEM; a usage and cost dashboard; policy changes gated on owner approval (CODEOWNERS)

## License

MIT. Author: Tim Serewicz.
