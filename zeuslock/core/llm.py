"""LLM layer: finds sensitive data that has no fixed shape.

The regex layer (patterns.py) is good at values with a fixed format, but it
cannot understand meaning. This layer asks a small local model (served by
Ollama) to find:

- passwords written in normal sentences ("...the dog's name plus the year, so Biscuit2019")
- postal addresses
- proprietary source code (business logic, internal names)

The model only returns *values*. We find their position in the text ourselves,
so text[start:end] == value always holds, and anything the model invents
(a value that is not in the text) is thrown away.
"""

import json
import os

import requests

from zeuslock.core.patterns import is_placeholder, make_finding

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("ZEUSLOCK_MODEL", "qwen2.5:3b")
TIMEOUT_SECONDS = 60

# The only categories we trust the model with. The others are handled by regex + validators.
LLM_CATEGORIES = {"CREDENTIAL", "CONTACT", "SOURCE_CODE"}

SYSTEM_PROMPT = """You find sensitive data in a user's prompt before it is sent to an AI assistant.
The prompt can be in any language (English, French, Spanish, German...).

Report ONLY these three kinds of data:
- CREDENTIAL: a real password or secret written in a sentence, e.g. "the password is the dog's name, so Biscuit2019" -> "Biscuit2019".
- CONTACT: a full postal address (street number + street, city or postcode), e.g. "12 rue des Lilas, 69003 Lyon".
- SOURCE_CODE: proprietary code with business logic or internal names (pricing rules, scoring, internal configs).
  Generic textbook code (hello world, a plain sorting function) is NOT proprietary.

Rules:
- "value" must be copied EXACTLY from the prompt, character for character.
- For SOURCE_CODE, the value is the whole code block.
- Do not report questions about passwords ("how do I reset my password?"), placeholders
  (YOUR_API_KEY, changeme), company names, people's names, cities alone, or emails/phones/card numbers.
- If nothing matches, return {"findings": []}.

Answer with JSON only: {"findings": [{"category": "...", "value": "..."}]}"""

# Ask Ollama to answer with exactly this JSON shape.
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "category": {"type": "string", "enum": sorted(LLM_CATEGORIES)},
                    "value": {"type": "string"},
                },
                "required": ["category", "value"],
            },
        }
    },
    "required": ["findings"],
}


def ask_model(text: str) -> str:
    """Send the prompt to Ollama and return the model's raw JSON answer."""
    response = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": text},
            ],
            "format": RESPONSE_SCHEMA,
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
    """Every (start, end) where the model's value appears in the text.

    Models sometimes change the whitespace of a code block. If the exact value
    is not found, we look for its first and last lines instead and take
    everything between them.
    """
    value = value.strip()
    if not value:
        return []

    spans = []
    start = text.find(value)
    while start != -1:
        spans.append((start, start + len(value)))
        start = text.find(value, start + 1)
    if spans:
        return spans

    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if len(lines) < 2:
        return []
    first = text.find(lines[0])
    if first == -1:
        return []
    last = text.find(lines[-1], first + len(lines[0]))
    if last == -1:
        return []
    return [(first, last + len(lines[-1]))]


def parse_answer(text: str, answer: str) -> list[dict]:
    """Turn the model's JSON answer into findings with exact offsets."""
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
        if category not in LLM_CATEGORIES or not isinstance(value, str):
            continue
        if is_placeholder(value):
            continue
        for start, end in locate(text, value):   # value not in text -> invented -> dropped
            if category == "SOURCE_CODE":
                # Keep code as is: a final ')' or ';' is part of the code, not punctuation.
                findings.append({"category": category, "start": start, "end": end, "value": text[start:end]})
            else:
                findings.append(make_finding(category, text, start, end))
    return findings


def find_with_llm(text: str) -> list[dict]:
    """Everything the LLM layer finds. Returns [] if Ollama is not reachable,
    so the regex layer still works on its own."""
    try:
        answer = ask_model(text)
    except (requests.RequestException, KeyError, ValueError):
        return []
    return parse_answer(text, answer)
