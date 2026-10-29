"""Run the seeded PII set and the red-team set; print honest rates.

  python -m gateway.evals
"""
from __future__ import annotations

from pathlib import Path

import yaml

from .filters import find_pii, injection_score

DATA = Path(__file__).resolve().parent.parent / "data"


def pii_eval():
    d = yaml.safe_load((DATA / "pii_cases.yaml").read_text())
    misses, fps = [], []
    for c in d["positives"]:
        got = {f.kind for f in find_pii(c["text"])}
        if not set(c["expect"]) <= got:
            misses.append((c["text"], sorted(set(c["expect"]) - got)))
    for t in d["negatives"]:
        if find_pii(t):
            fps.append((t, [f.kind for f in find_pii(t)]))
    return dict(positives=len(d["positives"]), misses=misses, negatives=len(d["negatives"]), false_positives=fps)


def redteam_eval(block_at=0.5, retrieved_block_at=0.3):
    d = yaml.safe_load((DATA / "redteam.yaml").read_text())
    res = {}
    for group in ("user", "retrieved"):
        items = d["attacks"][group]
        thr = retrieved_block_at if group == "retrieved" else block_at
        missed = [t for t in items if injection_score(t).score < thr]
        res[group] = dict(total=len(items), blocked=len(items) - len(missed), missed=missed)
    fp = [t for t in d["benign"] if injection_score(t).score >= block_at]
    res["benign"] = dict(total=len(d["benign"]), wrongly_blocked=fp)
    fpr = [t for t in d["benign_retrieved"] if injection_score(t).score >= retrieved_block_at]
    res["benign_retrieved"] = dict(total=len(d["benign_retrieved"]), wrongly_blocked=fpr)
    return res


def main():
    p = pii_eval()
    print(f"PII: {p['positives'] - len(p['misses'])}/{p['positives']} seeded cases fully detected; "
          f"{len(p['false_positives'])}/{p['negatives']} clean texts wrongly flagged")
    for t, k in p["misses"]:
        print(f"  MISS {k}: {t}")
    for t, k in p["false_positives"]:
        print(f"  FALSE POSITIVE {k}: {t}")
    r = redteam_eval()
    for g in ("user", "retrieved"):
        x = r[g]
        print(f"Injection ({g}): {x['blocked']}/{x['total']} blocked ({100*x['blocked']/x['total']:.0f}%)")
        for t in x["missed"]:
            print(f"  MISSED: {t}")
    b = r["benign"]
    print(f"Benign prompts wrongly blocked: {len(b['wrongly_blocked'])}/{b['total']}")
    for t in b["wrongly_blocked"]:
        print(f"  FALSE POSITIVE: {t}")
    b = r["benign_retrieved"]
    print(f"Benign retrieved passages wrongly blocked: {len(b['wrongly_blocked'])}/{b['total']}")
    for t in b["wrongly_blocked"]:
        print(f"  FALSE POSITIVE: {t}")


if __name__ == "__main__":
    main()
