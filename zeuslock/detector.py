"""detect(): the whole detector in one call.

    prompt -> regex layer + LLM layer -> merge -> "alert" / "allow"
"""

from zeuslock.core.llm import find_with_llm
from zeuslock.core.merge import merge
from zeuslock.core.patterns import find_all

MODES = ("level1",)


def detect(text: str, mode: str = "level1") -> dict:
    """Find sensitive data in a prompt.

    Returns {"decision": "alert" | "allow",
             "findings": [{"category", "start", "end", "value"}, ...]}
    with text[start:end] == value for every finding.
    """
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}, expected one of {MODES}")

    findings = merge(find_all(text), find_with_llm(text))
    return {"decision": "alert" if findings else "allow", "findings": findings}
