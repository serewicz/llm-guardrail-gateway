import httpx
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.audit import hash_text
from gateway.core import Gateway
from gateway.identity import Identity, identify
from gateway.providers import UtilityRAGProvider


def test_identify_unknown_user_gets_default(policy):
    assert identify("stranger", policy.users, policy.default_dept).dept == "unassigned"
    assert identify(None, policy.users).user == "anonymous"
    assert identify("maria", policy.users).dept == "water-operations"


def test_allowed_request_is_logged(gw):
    r = gw.handle(Identity("maria", "water-operations"), "How full is Lake Travis?")
    assert r.outcome == "allowed" and r.model == "onprem-llama"
    recs = list(gw.audit.records())
    assert [x["step"] for x in recs] == ["request", "decision"]
    d = recs[-1]
    for k in ("user", "dept", "model", "tokens_in", "tokens_out", "cost_usd", "latency_ms", "outcome"):
        assert k in d
    assert recs[0]["prompt"] == hash_text("How full is Lake Travis?")


def test_model_allowlist_blocks(gw):
    r = gw.handle(Identity("lee", "legal"), "summarize this", model="hosted-small")
    assert r.outcome == "blocked"
    assert list(gw.audit.records())[-1]["policy"] == "models.allowlist"


def test_prompt_modes(gw):
    gw.policy.audit["log_prompt_text"] = "omit"
    gw.handle(Identity("dev", "it"), "secret plan")
    assert list(gw.audit.records())[0]["prompt"] is None
    gw.policy.audit["log_prompt_text"] = "full"
    gw.handle(Identity("dev", "it"), "secret plan")
    assert list(gw.audit.records())[2]["prompt"] == "secret plan"


def test_provider_error_fails_closed(gw):
    class Boom:
        hosted = False
        def complete(self, *a, **k):
            raise ConnectionError("down")
    gw.providers["onprem-llama"] = Boom()
    r = gw.handle(Identity("maria", "water-operations"), "hi")
    assert r.outcome == "blocked" and "provider error" in r.reasons[0]


def test_utility_rag_provider_forwards_user():
    seen = {}
    def handler(req):
        seen["user"] = req.headers["X-User"]
        return httpx.Response(200, json={"answer": "Mansfield Dam [1]", "tokens_in": 120, "tokens_out": 8,
                                         "sources": [{"doc": "lcra-dams", "text": "Mansfield Dam forms Lake Travis."}]})
    p = UtilityRAGProvider(client=httpx.Client(base_url="http://rag", transport=httpx.MockTransport(handler)))
    c = p.complete("Which dam forms Lake Travis?", "maria")
    assert seen["user"] == "maria" and c.tokens_in == 120 and c.context == ["Mansfield Dam forms Lake Travis."]


def test_http_api(gw):
    client = TestClient(create_app(gw))
    assert client.post("/v1/ask", json={"prompt": "hello"}, headers={"X-User": "maria"}).status_code == 200
    assert client.post("/v1/ask", json={"prompt": "x", "model": "hosted-large"}, headers={"X-User": "lee"}).status_code == 403
    assert client.get("/healthz").json()["ok"] is True
