"""Reversible anonymisation for a whole conversation.

    session = Session()
    safe = session.anonymize("Mail sarah@corp.com, card 4838 5608 9441 5465")
    # "Mail [EMAIL_1], card [CARD_1]"          <- this is what goes to the AI
    session.restore("I wrote to [EMAIL_1].")
    # "I wrote to sarah@corp.com."            <- this is what the user sees

- Placeholders are readable ([EMAIL_1], [CARD_2], [IP_1]...) so the AI keeps using them.
- The same value always gets the same placeholder, in every message of the session.
- restore() is tolerant: AIs drop brackets, change case, add spaces or markdown.
"""

import re

from zeuslock.core.validators import iban_valid, luhn_valid
from zeuslock.detector import detect


def label_for(finding: dict) -> str:
    """Readable placeholder name for a finding: EMAIL, PHONE, CARD, IBAN..."""
    category, value = finding["category"], finding["value"]
    if category == "CONTACT":
        if "@" in value:
            return "EMAIL"
        if not any(ch.isalpha() for ch in value):
            return "PHONE"
        return "ADDRESS"
    if category == "PAYMENT":
        if iban_valid(value):
            return "IBAN"
        if luhn_valid(value):
            return "CARD"
        return "WALLET"
    return {"CREDENTIAL": "SECRET", "GOV_ID": "ID", "NETWORK": "IP", "SOURCE_CODE": "CODE"}[category]


LABELS = ["EMAIL", "PHONE", "ADDRESS", "IBAN", "CARD", "WALLET", "SECRET", "ID", "IP", "CODE"]

# A placeholder as an AI might write it back:
#   [EMAIL_1]  EMAIL_1  [email_1]  [ EMAIL_1 ]  [EMAIL 1]  {EMAIL_1}  <EMAIL_1>  (EMAIL_1)
# - not glued to a letter/digit before it (so 'XEMAIL_1' is not a placeholder)
# - nothing glued after the number, so EMAIL_10 is never read as EMAIL_1 (nor EMAIL_1x)
PLACEHOLDER = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?P<open>[\[{<(]?)\s*"
    r"(?P<label>" + "|".join(LABELS) + r")(?P<sep>[ _-]*)(?P<number>\d+)(?![A-Za-z0-9_])"
    r"\s*(?P<close>[\]}>)]?)",
    re.IGNORECASE,
)
BRACKET_PAIRS = {"[": "]", "{": "}", "<": ">", "(": ")"}


def outer_findings(findings: list[dict]) -> list[dict]:
    """Drop findings inside a longer one (an IP inside a connection string):
    replacing the longer one already hides them."""
    kept = []
    for finding in sorted(findings, key=lambda f: f["end"] - f["start"], reverse=True):
        if not any(finding["start"] < k["end"] and k["start"] < finding["end"] for k in kept):
            kept.append(finding)
    return kept


class Session:
    """One conversation: remembers which placeholder stands for which value."""

    def __init__(self, detect_fn=detect):
        self.detect_fn = detect_fn
        self.mapping: dict[str, str] = {}        # "[EMAIL_1]" -> "sarah@corp.com"
        self.reverse: dict[str, str] = {}        # "sarah@corp.com" -> "[EMAIL_1]"
        self.counters: dict[str, int] = {}       # "EMAIL" -> 1

    def placeholder_for(self, finding: dict) -> str:
        value = finding["value"]
        if value not in self.reverse:
            label = label_for(finding)
            self.counters[label] = self.counters.get(label, 0) + 1
            placeholder = f"[{label}_{self.counters[label]}]"
            self.reverse[value] = placeholder
            self.mapping[placeholder] = value
        return self.reverse[value]

    def anonymize(self, text: str) -> str:
        """Replace every sensitive value with its placeholder."""
        findings = outer_findings(self.detect_fn(text)["findings"])
        # Numbers follow reading order: the first email in the text is EMAIL_1.
        placeholders = {id(f): self.placeholder_for(f) for f in sorted(findings, key=lambda f: f["start"])}
        # Replace right to left, so the offsets of earlier findings stay valid.
        for finding in sorted(findings, key=lambda f: f["start"], reverse=True):
            text = text[:finding["start"]] + placeholders[id(finding)] + text[finding["end"]:]
        return text

    def restore(self, text: str) -> str:
        """Put the original values back, even if the AI changed the placeholders a bit."""
        def replace(match: re.Match) -> str:
            key = f"[{match['label'].upper()}_{int(match['number'])}]"
            if key not in self.mapping:
                return match.group(0)                    # unknown placeholder: leave it
            value = self.mapping[key]
            if match["open"] and BRACKET_PAIRS[match["open"]] == match["close"]:
                return value                             # [EMAIL_1] {EMAIL_1} [EMAIL 1] (EMAIL_1) ...
            if " " in match["sep"]:
                return match.group(0)                    # "send email 1 more time" is plain English
            # Brackets that don't belong to the placeholder, e.g. "(see EMAIL_1)": keep them.
            start, end = match.start("label") - match.start(), match.end("number") - match.start()
            whole = match.group(0)
            return whole[:start] + value + whole[end:]

        return PLACEHOLDER.sub(replace, text)
