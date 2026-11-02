"""LLM layer: finds sensitive data that has no fixed shape.

The regex layer (patterns.py) is good at values with a fixed format, but it
cannot understand meaning. This layer uses a small local model (served by
Ollama) for:

- passwords written in normal sentences ("...the dog's name plus the year, so Biscuit2019")
- postal addresses
- proprietary source code (business logic, internal names)

Two questions are asked:
1. "Which passwords / addresses are in this text?"  The model returns values;
   we find their position ourselves, so text[start:end] == value always holds,
   and anything the model invents (not in the text) is thrown away.
2. For code, Python finds the code blocks (by the shape of the lines) and the
   model only answers "is this block proprietary, yes or no?". Small models are
   bad at copying a whole code block, but good at this yes/no question.
"""

import json
import os
import re

import requests

from zeuslock.core.patterns import is_placeholder, make_finding

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("ZEUSLOCK_MODEL", "qwen2.5:3b")
TIMEOUT_SECONDS = 60

# ---------------- 1. passwords in prose + postal addresses ----------------

# The only categories we take from question 1. The others are handled by regex + validators.
TEXT_CATEGORIES = {"CREDENTIAL", "CONTACT"}

FIND_PROMPT = """You find sensitive data in a user's prompt before it is sent to an AI assistant.
The prompt can be in any language (English, French, Spanish, German...).

Report ONLY these two kinds of data:
- CREDENTIAL: a password chosen by a person, written inside a sentence.
  "I set the password to the dog's name plus the year, so Biscuit2019" -> "Biscuit2019"
- CONTACT: a full postal address: street number + street name + city or postcode.
  "send it to 14 avenue Jean Jaurès, 69007 Lyon" -> "14 avenue Jean Jaurès, 69007 Lyon"
  "our tenant at 2217 Maple Grove Drive, Apt 4B, Austin, TX 78704" -> "2217 Maple Grove Drive, Apt 4B, Austin, TX 78704"

Never report: card numbers, IBANs, wallet addresses, API keys or tokens, ID numbers,
IP addresses, emails, phone numbers, code, names of people or companies, a city alone,
questions about passwords ("how do I reset my password?"), placeholders (YOUR_API_KEY).

"value" must be copied EXACTLY from the prompt. If nothing matches, return {"findings": []}.
Answer with JSON only: {"findings": [{"category": "...", "value": "..."}]}"""

FIND_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "category": {"type": "string", "enum": sorted(TEXT_CATEGORIES)},
                    "value": {"type": "string"},
                },
                "required": ["category", "value"],
            },
        }
    },
    "required": ["findings"],
}

# ---------------- 2. proprietary code ----------------

CODE_PROMPT = """You decide if a piece of code is proprietary to a company.

Proprietary (true): business logic or internal names, e.g. pricing or commission rules,
fraud or risk scoring, internal tables, configs, secret rates or weights.
Not proprietary (false): generic or textbook code, error messages, stack traces,
terminal output, log lines, a standard library example.

Answer with JSON only: {"proprietary": true} or {"proprietary": false}"""

CODE_SCHEMA = {
    "type": "object",
    "properties": {"proprietary": {"type": "boolean"}},
    "required": ["proprietary"],
}

# A line "looks like code" if it has a keyword at the start or typical code punctuation.
CODE_LINE = re.compile(
    r"^\s*(?:def|class|return|if|elif|else|for|while|import|from|export|const|let|var|function|"
    r"public|private|protected|async|await|SELECT|FROM|WHERE|JOIN|GROUP BY|ORDER BY|INSERT|UPDATE)\b"
    r"|[{};]\s*$"                 # ends with { } or ;
    r"|^\s*[}\])]"                # starts with a closing bracket
    r"|\w\s*(?:[+\-*/]?=)\s*\S"   # assignment: x = ..., x *= ...
)

# KEY=value lines (.env files). That is config, not code; its secrets are found by regex.
ENV_LINE = re.compile(r"^\s*\w+\s*=")


def ask_model(system: str, text: str, schema: dict) -> str:
    """Send one question to Ollama and return the model's raw JSON answer."""
    response = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": text},
            ],
            "format": schema,
            "stream": False,
            "options": {"temperature": 0},
        },
        timeout=TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()["message"]["content"]


def is_available() -> bool:
    """True if the Ollama server is running and answers."""
    try:
        requests.get(f"{OLLAMA_URL}/api/tags", timeout=2).raise_for_status()
        return True
    except requests.RequestException:
        return False


def locate(text: str, value: str) -> list[tuple[int, int]]:
    """Every (start, end) where the model's value appears in the text."""
    value = value.strip()
    if not value:
        return []
    spans = []
    start = text.find(value)
    while start != -1:
        spans.append((start, start + len(value)))
        start = text.find(value, start + 1)
    return spans


def looks_right(category: str, value: str) -> bool:
    """Cheap sanity checks on what the model returned.

    - a password has at least one letter (drops '4021', card numbers...)
    - an address has 4+ words with letters and a number (drops phones, ID numbers)
    """
    has_letter = any(ch.isalpha() for ch in value)
    if category == "CREDENTIAL":
        return has_letter and len(value) >= 6
    if category == "CONTACT":
        has_digit = any(ch.isdigit() for ch in value)
        return has_letter and has_digit and len(value.split()) >= 4
    return False


def parse_answer(text: str, answer: str) -> list[dict]:
    """Turn the model's answer to question 1 into findings with exact offsets."""
    try:
        items = json.loads(answer).get("findings", [])
    except (json.JSONDecodeError, AttributeError):
        return []

    findings = []
    for item in items:
        if not isinstance(item, dict):
            continue
        category = item.get("category")
        value = item.get("value")
        if category not in TEXT_CATEGORIES or not isinstance(value, str):
            continue
        if is_placeholder(value) or not looks_right(category, value.strip()):
            continue
        for start, end in locate(text, value):   # value not in text -> invented -> dropped
            findings.append(make_finding(category, text, start, end))
    return findings


def find_code_blocks(text: str) -> list[tuple[int, int]]:
    """(start, end) of every block of consecutive lines that looks like code.

    A block is a run of non-empty lines, each one either code-like or indented,
    with at least 2 code-like lines. Prose lines and empty lines end a block.
    Blocks made only of KEY=value lines are skipped.
    """
    blocks = []
    block_start = block_end = None
    code_lines = 0
    position = 0

    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        line_start, line_end = position, position + len(content)
        position += len(line)

        is_code = bool(CODE_LINE.search(content))
        is_indented = content[:1] in (" ", "\t") and content.strip() != ""
        if is_code or is_indented:
            if block_start is None:
                block_start, code_lines = line_start, 0
            block_end = line_end
            code_lines += is_code
            continue

        if block_start is not None and code_lines >= 2:
            blocks.append((block_start, block_end))
        block_start = None

    if block_start is not None and code_lines >= 2:
        blocks.append((block_start, block_end))
    return [(start, end) for start, end in blocks
            if not all(ENV_LINE.match(line) for line in text[start:end].splitlines())]


def is_proprietary(code: str) -> bool:
    try:
        return json.loads(ask_model(CODE_PROMPT, code, CODE_SCHEMA)).get("proprietary") is True
    except (json.JSONDecodeError, AttributeError):
        return False


def find_with_llm(text: str) -> list[dict]:
    """Everything the LLM layer finds. Returns [] if Ollama is not reachable,
    so the regex layer still works on its own."""
    try:
        findings = parse_answer(text, ask_model(FIND_PROMPT, text, FIND_SCHEMA))
        for start, end in find_code_blocks(text):
            if is_proprietary(text[start:end]):
                # No punctuation trimming: a final ')' or ';' is part of the code.
                findings.append({"category": "SOURCE_CODE", "start": start, "end": end, "value": text[start:end]})
    except (requests.RequestException, KeyError, ValueError):
        return []
    return findings
