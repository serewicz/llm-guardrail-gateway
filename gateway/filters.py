"""PII detection and prompt-injection checks.

Pattern-based and deliberately simple. They catch common, well-formed cases
and miss plenty: obfuscated numbers, PII spelled out in words, injections in
other languages or paraphrased. See the red-team results in the README.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------- PII


def _luhn(digits: str) -> bool:
    s, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        s += d; alt = not alt
    return s % 10 == 0


_STREET = r"(?:st|street|ave|avenue|rd|road|dr|drive|blvd|boulevard|ln|lane|way|ct|court|cir|circle|pkwy|parkway|hwy|highway|trl|trail|pl|place|loop|cv|cove)"

PII_PATTERNS = {
    "ssn": [re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"),
            re.compile(r"(?i)\b(?:ssn|social security(?: number| no\.?)?)\s*[:#]?\s*(\d{9})\b")],
    "account_number": [re.compile(r"(?i)\b(?:account|acct|a/c|routing|member|customer)\s*(?:number|no\.?|#)?\s*[:#]?\s*(\d[\d -]{5,18}\d)\b")],
    "card_number": [re.compile(r"\b(?:\d[ -]?){12,18}\d\b")],
    "phone": [re.compile(r"(?<!\d)(?:\+?1[ .-]?)?\(?\b\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b")],
    "email": [re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")],
    "address": [re.compile(rf"(?i)\b\d{{1,6}}\s+(?:[NSEW]\.?\s+)?(?:[A-Za-z0-9']+\s+){{1,4}}{_STREET}\b\.?")],
}


@dataclass
class Finding:
    kind: str
    start: int
    end: int


def find_pii(text: str) -> list[Finding]:
    out: list[Finding] = []
    for kind, pats in PII_PATTERNS.items():
        for pat in pats:
            for m in pat.finditer(text):
                s, e = (m.start(1), m.end(1)) if m.lastindex else (m.start(), m.end())
                if kind == "card_number" and not _luhn(re.sub(r"\D", "", m.group())):
                    continue
                out.append(Finding(kind, s, e))
    # Drop overlaps, keep the first/longest span (e.g. an account number is not also a phone).
    out.sort(key=lambda f: (f.start, -(f.end - f.start)))
    kept: list[Finding] = []
    for f in out:
        if not kept or f.start >= kept[-1].end:
            kept.append(f)
    return kept


def redact(text: str, findings: list[Finding]) -> str:
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        text = text[:f.start] + f"[{f.kind.upper()}]" + text[f.end:]
    return text


# ---------------------------------------------------------------- injection
# (weight, pattern). Score = sum of weights of distinct patterns that match.
INJECTION_PATTERNS: list[tuple[float, str, re.Pattern]] = [(w, n, re.compile(p, re.I)) for w, n, p in [
    (0.6, "ignore_instructions", r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|any|your|system)\b.{0,20}\b(instructions?|rules?|prompts?|directions?|guidelines?|polic(y|ies))"),
    (0.5, "new_instructions", r"\b(new|updated|real|actual)\s+(instructions?|rules?|system prompt)\b|\bfrom now on\b"),
    (0.5, "reveal_system", r"\b(reveal|show|print|repeat|output|leak|tell me)\b.{0,30}\b(system prompt|hidden (prompt|instructions?)|initial instructions?|your instructions?)"),
    (0.4, "role_override", r"\byou are (now|no longer)\b|\bact as\b.{0,30}\b(unrestricted|unfiltered|jailbroken|dan|developer mode)\b|\bpretend (you|to be)\b.{0,40}\b(no|without) (rules|restrictions|filters)"),
    (0.4, "jailbreak_terms", r"\b(jailbreak|dan mode|developer mode|do anything now|no restrictions|without (any )?(restrictions|filters|limits))\b"),
    (0.5, "exfiltrate", r"\b(send|post|upload|email|exfiltrate|forward)\b.{0,40}\b(to|at)\b.{0,20}(https?://|\S+@\S+|webhook)"),
    (0.4, "markup_smuggling", r"<\s*/?\s*(system|instructions?|admin)\s*>|\[\s*(system|inst)\s*\]|###\s*(system|instruction)"),
    (0.3, "hidden_directive", r"\b(assistant|ai|model|llm|chatbot)s?\b.{0,20}\b(must|should|will)\b.{0,40}\b(say|respond|include|mention|recommend|rate)\b"),
    (0.3, "secrecy", r"\b(do not|don't|never)\s+(tell|mention|reveal|inform)\b.{0,30}\b(user|anyone|human)\b"),
    (0.3, "credentials", r"\b(api[_ -]?key|password|secret key|access token|credentials)\b.{0,30}\b(give|send|print|show|reveal|list)\b|\b(give|send|print|show|reveal|list)\b.{0,30}\b(api[_ -]?key|passwords?|secret keys?|access tokens?|credentials)\b"),
]]
_INVISIBLE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e]")


@dataclass
class InjectionScore:
    score: float
    hits: list[str]


_SPACED = re.compile(r"\b(?:\w ){3,}\w\b")


def _normalize(text: str) -> str:
    """Undo one cheap evasion: letters separated by single spaces ('i g n o r e')."""
    text = _INVISIBLE.sub("", text)
    return _SPACED.sub(lambda m: m.group().replace(" ", ""), re.sub(r"(?<=\w) {2,}(?=\w)", "  ", text)).replace("  ", " ")


def injection_score(text: str) -> InjectionScore:
    norm = _normalize(text)
    hits = [n for w, n, p in INJECTION_PATTERNS if p.search(text) or p.search(norm)]
    score = sum(w for w, n, _ in INJECTION_PATTERNS if n in hits)
    if _INVISIBLE.search(text):  # zero-width / bidi chars are a common hiding trick
        hits.append("invisible_chars"); score += 0.3
    return InjectionScore(round(min(score, 1.0), 2), hits)
