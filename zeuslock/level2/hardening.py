"""Level 2 detection: the Level 1 layers, hardened against tricks.

    prompt -> normalise (normalize.py) -> regex + extra rules + hidden tokens + LLM (fenced, chunked)
           -> map positions back to the original text -> merge

What each piece is for (attack ideas from attacks/attacks.jsonl):
- normalise: full-width digits, invisible characters, Cyrillic look-alikes, digits written as
  words, "[at]" / "[dot]", ip-10-0-3-17 hostnames
- EXTRA_RULES: cards with odd separators or split over lines, IBANs in lower case / odd
  spacing, SSN without dashes next to the word SSN, secrets as JSON values
- find_hidden_tokens: base64-encoded and reversed secrets
- LLM: injection sentences blanked out, prompt fenced as data, long prompts cut into chunks
"""

import base64
import binascii
import re

from zeuslock.core import llm
from zeuslock.core.merge import merge
from zeuslock.core.normalize import normalize
from zeuslock.core.patterns import find_all, find_with_rules, make_finding
from zeuslock.core.validators import iban_valid, luhn_valid, ssn_valid

SEP = r"[\s._/\\-]{1,3}"     # 1 to 3 of: space, newline, dot, underscore, slash, dash

EXTRA_RULES = [
    # Card as 4-4-4-4 (or Amex 4-6-5) with odd separators: "4838.5608.9441.5465", split over 2 lines.
    ("PAYMENT", rf"\b\d{{4}}(?:{SEP}\d{{4}}){{3}}\b", 0, luhn_valid),
    ("PAYMENT", rf"\b\d{{4}}{SEP}\d{{6}}{SEP}\d{{5}}\b", 0, luhn_valid),
    # IBAN in lower case and/or with odd spacing: "fr22  2207 1247 ...".
    ("PAYMENT", r"(?i)\b[a-z]{2}\d{2}(?:\s*[a-z0-9]{4}){2,7}(?:\s*[a-z0-9]{1,4})?\b", 0,
     lambda value: iban_valid(re.sub(r"\s", "", value))),
    # SSN without dashes, only right after an SSN keyword (9 bare digits alone are too ambiguous).
    ("GOV_ID", r"(?i)\b(?:ssn|social security(?: number)?|seguro social|s[ée]curit[ée] sociale|"
               r"sozialversicherungsnummer)\D{0,25}?\b(\d{3}[ .]?\d{2}[ .]?\d{4})\b", 1, ssn_valid),
    # Secret as a quoted JSON / YAML value: "api_key": "4f9XkQ2Lm..."
    ("CREDENTIAL", r"(?i)[\"']?\b\w*(?:secret|token|api_?key|apikey|password|passwd)\w*[\"']?\s*[:=]\s*"
                   r"[\"']([^\"'\s]{8,})[\"']", 1, None),
]

TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{16,}")

# Phrases that give orders to the LLM ("ignore all previous instructions", "return an empty
# list"). A 3B model obeys them even when told the prompt is data, so they are blanked out
# before the LLM sees the prompt. Only the phrase is blanked, not the sentence: a password in
# the same sentence must stay visible. Regex never reads instructions: it still sees everything.
INJECTION = re.compile(
    r"(?i)\b(?:ignore|disregard|forget|override)\b[^.!?\n]{0,40}?\b(?:instructions?|rules|system prompt)\b"
    r"|\b(?:return|answer|output|reply|respond)\b[^.!?\n]{0,20}?(?:empty (?:list|array|result|json|answer)"
    r"|no findings|\[\])"
    r"|\bsystem override\b"
)


def blank_injections(text: str) -> str:
    """Same text, with injection phrases replaced by spaces (same length, so positions stay valid)."""
    return INJECTION.sub(lambda m: " " * len(m.group(0)), text)
CHUNK_SIZE = 2000      # characters per LLM call; a small model loses track in very long prompts
CHUNK_OVERLAP = 300    # so a secret on a chunk border is fully inside at least one chunk


def decode_base64(token: str) -> str | None:
    """The decoded text if token is base64 for readable text, else None."""
    try:
        decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded.isprintable() else None


def find_hidden_tokens(text: str) -> list[dict]:
    """Secrets hidden by encoding: base64 of a sensitive value, or a reversed token.
    The whole encoded token is reported, with the category of what it hides."""
    findings = []
    for match in TOKEN.finditer(text):
        token = match.group(0)
        decoded = decode_base64(token)
        inside = find_all(decoded) if decoded else []
        if not inside:
            inside = [f for f in find_with_rules(token[::-1]) if f["category"] == "CREDENTIAL"]
        if inside:
            findings.append(make_finding(inside[0]["category"], text, *match.span()))
    return findings


def find_with_llm_chunked(text: str) -> list[dict]:
    """LLM layer (injections blanked, prompt fenced), one call per chunk for long prompts."""
    text = blank_injections(text)
    if len(text) <= CHUNK_SIZE:
        return llm.find_with_llm(text, guarded=True)
    findings = []
    for offset in range(0, len(text), CHUNK_SIZE - CHUNK_OVERLAP):
        chunk = text[offset:offset + CHUNK_SIZE]
        for f in llm.find_with_llm(chunk, guarded=True):
            findings.append({**f, "start": f["start"] + offset, "end": f["end"] + offset})
        if offset + CHUNK_SIZE >= len(text):
            break
    return findings


def detect_level2(text: str, use_llm: bool = True) -> list[dict]:
    """All Level 2 findings, with offsets in the ORIGINAL text."""
    norm = normalize(text)

    regex_findings = find_all(norm.text) + find_with_rules(norm.text, EXTRA_RULES) + find_hidden_tokens(norm.text)
    llm_findings = find_with_llm_chunked(norm.text) if use_llm else []

    def to_original(findings: list[dict]) -> list[dict]:
        mapped = []
        for f in findings:
            if f["end"] <= f["start"]:
                continue
            start, end = norm.to_original(f["start"], f["end"])
            mapped.append({"category": f["category"], "start": start, "end": end, "value": text[start:end]})
        return mapped

    return merge(to_original(regex_findings), to_original(llm_findings))
