"""Regex layer: finds sensitive values that have a fixed shape.

Every rule is one line in the RULES table:
    (category, regex, group, validator)

- group:     which regex group is the sensitive value (0 = the whole match).
             Example: in "password=Hunter2" only "Hunter2" is sensitive.
- validator: optional function from validators.py; the candidate is kept
             only if it returns True (e.g. Luhn for card numbers).

Phone numbers are handled separately with the `phonenumbers` library,
because phone formats differ too much between countries for one regex.
"""

import re

import phonenumbers

from zeuslock.core.validators import (
    iban_valid,
    is_private_ip,
    luhn_valid,
    nir_valid,
    ssn_valid,
)

# Words that introduce a password, in the languages of the dev set.
PASSWORD_WORDS = r"(?:password|passwd|pwd|passcode|mot de passe|mdp|contraseña|passwort|kennwort)"

RULES = [
    # ---------------- PAYMENT ----------------
    # 13-19 digits, optionally separated by single spaces or dashes.
    ("PAYMENT", r"\b\d(?:[ -]?\d){12,18}\b", 0, luhn_valid),
    # IBAN: 2 letters, 2 check digits, then groups of up to 4 letters/digits.
    ("PAYMENT", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", 0, iban_valid),
    # Ethereum wallet.
    ("PAYMENT", r"\b0x[a-fA-F0-9]{40}\b", 0, None),
    # Bitcoin wallet: bech32 (bc1...) or legacy base58 (starts with 1 or 3).
    ("PAYMENT", r"\bbc1[a-z0-9]{25,59}\b", 0, None),
    ("PAYMENT", r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", 0, None),

    # ---------------- CREDENTIAL ----------------
    ("CREDENTIAL", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 0, None),             # GitHub
    ("CREDENTIAL", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}", 0, None),          # OpenAI
    ("CREDENTIAL", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", 0, None),              # AWS key id
    ("CREDENTIAL", r"\bxox[abposr]-[A-Za-z0-9-]{10,}", 0, None),            # Slack
    ("CREDENTIAL", r"\bhf_[A-Za-z0-9]{30,}\b", 0, None),                    # Hugging Face
    ("CREDENTIAL", r"\beyJ[\w-]+\.eyJ[\w-]+\.[\w-]+", 0, None),             # JWT
    # Whole private key block, from BEGIN to END.
    ("CREDENTIAL", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----", 0, None),
    # Connection string with a password: scheme://user:password@host...
    ("CREDENTIAL", r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]+@[^\s\"'<>]+", 0, None),
    # "Authorization: Bearer <token>"
    ("CREDENTIAL", r"(?i)\bbearer\s+([\w.~+/-]{20,}=*)", 1, None),
    # Assignments like SECRET_KEY=..., HF_TOKEN: ..., api_key = "..."
    ("CREDENTIAL", r"(?i)\b\w*(?:secret|token|api_?key|apikey)\w*\s*[:=]\s*[\"']?([\w/+.=-]{16,})", 1, None),
    # "password=...", "mot de passe du wifi : ...", "contraseña: ..."
    # Up to 3 words may sit between the keyword and the ':' / '='.
    ("CREDENTIAL", r"(?i)\b" + PASSWORD_WORDS + r"(?:\s+[\w'-]+){0,3}?\s*[:=]\s*([^\s,;\"']+)", 1, None),

    # ---------------- CONTACT ----------------
    ("CONTACT", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b", 0, None),

    # ---------------- GOV_ID ----------------
    # US SSN, only the dashed form (plain 9 digits is too ambiguous).
    ("GOV_ID", r"\b\d{3}-\d{2}-\d{4}\b", 0, ssn_valid),
    # French NIR: sex, year, month, department (or 2A/2B), commune, order, key.
    ("GOV_ID", r"\b[12] ?\d{2} ?\d{2} ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b", 0, nir_valid),
    # Passport number: only when the word "passport" appears just before it.
    ("GOV_ID", r"(?i)\b(?:passport|passeport|pasaporte|reisepass)\b[^\n]{0,40}?\b((?=[A-Z0-9]*\d)[A-Z0-9]{6,9})\b", 1, None),

    # ---------------- NETWORK ----------------
    # IPv4 address; only private ones are kept (validator).
    ("NETWORK", r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", 0, is_private_ip),
]

# Characters we never want at the end of a value (sentence punctuation).
TRAILING_PUNCTUATION = ".,;:!?)]}'\""

# Values that are obviously examples, not real secrets.
PLACEHOLDER_WORDS = ["your_", "your-", "example", "xxxx", "changeme", "placeholder", "<", ">"]


def make_finding(category: str, text: str, start: int, end: int) -> dict:
    """Build one finding, trimming trailing punctuation so text[start:end] == value."""
    while end > start and text[end - 1] in TRAILING_PUNCTUATION:
        end -= 1
    return {"category": category, "start": start, "end": end, "value": text[start:end]}


def is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(word in lowered for word in PLACEHOLDER_WORDS)


def find_with_rules(text: str, rules: list = RULES) -> list[dict]:
    """Run every rule (default: RULES) over the text."""
    findings = []
    for category, pattern, group, validator in rules:
        for match in re.finditer(pattern, text):
            start, end = match.span(group)
            value = text[start:end]
            if validator is not None and not validator(value):
                continue
            if is_placeholder(value):
                continue
            findings.append(make_finding(category, text, start, end))
    return findings


def find_phone_numbers(text: str) -> list[dict]:
    """Find phone numbers with Google's phonenumbers library.

    Numbers written with '+' work in any country. For local numbers without
    '+' we assume France ("FR"), the main market of the dev set.

    - '+' numbers: kept if they are *possible* (right length for the country).
      The writer clearly meant a phone number, even if it's not a real one.
    - local numbers: must start with 0 (French trunk prefix, e.g. 06 ...) and
      be fully *valid*, to avoid flagging IDs like '512-38-4417'.
    """
    findings = []
    for match in phonenumbers.PhoneNumberMatcher(text, "FR", leniency=phonenumbers.Leniency.POSSIBLE):
        raw = match.raw_string
        is_international = raw.startswith("+")
        is_local = raw.startswith("0") and phonenumbers.is_valid_number(match.number)
        if is_international or is_local:
            findings.append(make_finding("CONTACT", text, match.start, match.end))
    return findings


def find_all(text: str) -> list[dict]:
    """Everything the regex layer finds. Overlaps are cleaned up later (merge step)."""
    return find_with_rules(text) + find_phone_numbers(text)
