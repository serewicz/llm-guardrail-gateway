"""FastAPI front door. Run: uvicorn gateway.app:app"""
from __future__ import annotations

import os
from dataclasses import asdict

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .audit import AuditLog
from .core import Gateway
from .identity import identify
from .policy import load_policy


class Ask(BaseModel):
    prompt: str
    model: str | None = None
    labels: list[str] = []


def create_app(gw: Gateway | None = None) -> FastAPI:
    if gw is None:
        policy = load_policy(os.environ.get("POLICY_FILE", "policy.yaml"))
        gw = Gateway(policy, AuditLog(os.environ.get("AUDIT_LOG", "audit/audit.jsonl")))
    app = FastAPI(title="LLM Guardrail Gateway (early build)")
    app.state.gw = gw

    @app.post("/v1/ask")
    def ask(body: Ask, x_user: str | None = Header(default=None)):
        # DEMO identity: X-User header. Replace with SSO/OIDC before any real use.
        who = identify(x_user, gw.policy.users, gw.policy.default_dept)
        r = gw.handle(who, body.prompt, body.model, body.labels)
        return JSONResponse(asdict(r), status_code=403 if r.outcome == "blocked" else 200)

    @app.get("/healthz")
    def health():
        ok, msg = gw.audit.verify()
        return {"ok": ok, "audit": msg, "policy_version": gw.policy.version}

    return app


app = create_app() if os.environ.get("GATEWAY_AUTOSTART", "1") == "1" and os.path.exists(os.environ.get("POLICY_FILE", "policy.yaml")) else None
