"""detect(): the whole detector in one call.

    level1: prompt -> regex layer + LLM layer -> merge -> "alert" / "allow"
    level2: same, hardened against tricks (see zeuslock/level2/hardening.py)
"""

from zeuslock.core.llm import find_with_llm
from zeuslock.core.merge import merge
from zeuslock.core.patterns import find_all
from zeuslock.level2.hardening import detect_level2

MODES = ("level1", "level2")


def detect(text: str, mode: str = "level1", use_llm: bool = True) -> dict:
    """Find sensitive data in a prompt.

    Returns {"decision": "alert" | "allow",
             "findings": [{"category", "start", "end", "value"}, ...]}
    with text[start:end] == value for every finding.
    use_llm=False runs the regex side only (instant, for quick comparisons).
    """
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}, expected one of {MODES}")

    if mode == "level2":
        findings = detect_level2(text, use_llm)
    else:
        findings = merge(find_all(text), find_with_llm(text) if use_llm else [])
    return {"decision": "alert" if findings else "allow", "findings": findings}
