"""Append-only audit log.

One JSON object per line. Each record carries the SHA-256 of the previous
record, so editing or deleting a line in the middle breaks the chain and
`verify()` reports where. This is tamper-evident, not tamper-proof: anyone
with write access can rewrite the whole file. Ship it to WORM storage or a
SIEM for real integrity.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


def _digest(rec: dict) -> str:
    return hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()


def hash_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last = GENESIS
        for rec in self.records():
            self._last = rec["hash"]

    def append(self, **fields) -> dict:
        with self._lock:
            rec = {"ts": round(time.time(), 3), **fields, "prev": self._last}
            rec["hash"] = _digest(rec)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
            self._last = rec["hash"]
            return rec

    def records(self):
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        for i, rec in enumerate(self.records(), 1):
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec.get("prev") != prev:
                return False, f"line {i}: chain broken (prev hash mismatch)"
            if _digest(body) != rec.get("hash"):
                return False, f"line {i}: record was modified"
            prev = rec["hash"]
        return True, "ok"
