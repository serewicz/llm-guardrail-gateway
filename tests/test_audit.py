import json

from gateway.audit import AuditLog


def test_chain_verifies(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.append(step="x", n=i)
    assert log.verify() == (True, "ok")


def test_edit_is_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(3):
        log.append(step="x", cost_usd=0.01)
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1]); rec["cost_usd"] = 0.0
    lines[1] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    ok, msg = AuditLog(p).verify()
    assert not ok and "line 2" in msg


def test_deletion_is_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(3):
        log.append(step="x", n=i)
    lines = p.read_text().splitlines()
    p.write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, msg = AuditLog(p).verify()
    assert not ok and "chain broken" in msg


def test_reopen_continues_chain(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).append(step="a")
    AuditLog(p).append(step="b")
    assert AuditLog(p).verify()[0]
