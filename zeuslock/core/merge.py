"""Merge step: turns the findings of both layers into one clean list.

Both layers can report the same part of the text:
- two regex rules on the same value (OpenAI rule + Bearer rule on 'sk-...')
- a short match inside a longer one (an email regex inside 'mysql://user:pass@host',
  13 digits that pass Luhn inside a Slack token)
- the LLM on a value regex already found, with a worse category (an IBAN called CREDENTIAL)

Rules:
1. Regex findings first (exact shapes + validators), then LLM findings.
2. Inside each layer, longer findings first.
3. A finding that overlaps one already kept is dropped, except when it sits fully inside it and:
   - it is a NETWORK finding: the private IP inside 'postgresql://app:pw@10.20.0.15' still tells
     where the internal server is, so it is reported too;
   - the longer one is SOURCE_CODE: a key inside a code block is a credential on its own.
"""


def length(finding: dict) -> int:
    return finding["end"] - finding["start"]


def conflicts(a: dict, b: dict) -> bool:
    """True if a and b cannot both be reported."""
    if a["end"] <= b["start"] or b["end"] <= a["start"]:
        return False                                    # no overlap
    outer, inner = (a, b) if length(a) >= length(b) else (b, a)
    nested = outer["start"] <= inner["start"] and inner["end"] <= outer["end"]
    same_span = length(outer) == length(inner)
    if nested and not same_span:
        if inner["category"] == "NETWORK" or outer["category"] == "SOURCE_CODE":
            return False
    return True


def merge(regex_findings: list[dict], llm_findings: list[dict]) -> list[dict]:
    """One list of findings without duplicates, sorted by position in the text."""
    kept = []
    for layer in (regex_findings, llm_findings):
        for finding in sorted(layer, key=length, reverse=True):
            if not any(conflicts(finding, other) for other in kept):
                kept.append(finding)
    return sorted(kept, key=lambda f: (f["start"], f["end"]))
