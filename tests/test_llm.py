"""Tests for zeuslock/core/llm.py (the LLM layer).

Most tests replace the model with fixed answers, so they run without Ollama.
The last tests talk to the real model and are skipped when Ollama is not running.
"""

import json

import pytest
import requests

from zeuslock.core import llm

PRICING_CODE = (
    "Can you speed this up? It's our pricing engine:\n\n"
    "def quote_premium(client):\n"
    "    base = client.fleet_size * RATE_TABLE[client.region]\n"
    "    if client.claims_last_3y > 2:\n"
    "        base *= LOYALTY_PENALTY\n"
    "    return round(base * (1 - client.negotiated_discount), 2)"
)


def fake_model(monkeypatch, findings=(), proprietary=False):
    """Make ask_model answer without calling Ollama."""
    def answer(system, text, schema):
        if system == llm.CODE_PROMPT:
            return json.dumps({"proprietary": proprietary})
        return json.dumps({"findings": list(findings)})
    monkeypatch.setattr(llm, "ask_model", answer)


def test_password_in_prose(monkeypatch):
    text = "I set the password to the CFO's dog's name plus the year, so Biscuit2019. Can you help?"
    fake_model(monkeypatch, [{"category": "CREDENTIAL", "value": "Biscuit2019"}])
    findings = llm.find_with_llm(text)
    assert findings == [{"category": "CREDENTIAL", "start": 61, "end": 72, "value": "Biscuit2019"}]
    assert text[61:72] == "Biscuit2019"


def test_postal_address(monkeypatch):
    text = "Envoie le colis au 12 rue des Lilas, 69003 Lyon avant vendredi."
    fake_model(monkeypatch, [{"category": "CONTACT", "value": "12 rue des Lilas, 69003 Lyon"}])
    [finding] = llm.find_with_llm(text)
    assert finding["value"] == "12 rue des Lilas, 69003 Lyon"
    assert text[finding["start"]:finding["end"]] == finding["value"]


def test_proprietary_code_block(monkeypatch):
    fake_model(monkeypatch, proprietary=True)
    [finding] = llm.find_with_llm(PRICING_CODE)
    assert finding["category"] == "SOURCE_CODE"
    assert finding["value"].startswith("def quote_premium")
    assert finding["value"].endswith("negotiated_discount), 2)")   # final ')' is kept
    assert PRICING_CODE[finding["start"]:finding["end"]] == finding["value"]


def test_generic_code_is_not_reported(monkeypatch):
    fake_model(monkeypatch, proprietary=False)
    assert llm.find_with_llm(PRICING_CODE) == []


def test_code_blocks_found_by_shape():
    sql = "Optimise ce calcul :\nSELECT agent_id, SUM(montant)\nFROM ventes\nGROUP BY agent_id;"
    assert [sql[s:e] for s, e in llm.find_code_blocks(sql)] == [
        "SELECT agent_id, SUM(montant)\nFROM ventes\nGROUP BY agent_id;"
    ]
    assert llm.find_code_blocks("How do I reset my password?") == []
    assert llm.find_code_blocks("AWS_REGION=eu-west-3\nAWS_KEY=abc") == []    # .env, not code


def test_invented_values_are_dropped(monkeypatch):
    fake_model(monkeypatch, [{"category": "CREDENTIAL", "value": "NotInTheText123"}])
    assert llm.find_with_llm("How do I reset my password?") == []


def test_implausible_values_are_dropped(monkeypatch):
    text = "IT extension 4021, call +33 6 45 12 98 03, key YOUR_API_KEY, card 4838 5608 9441 5465"
    fake_model(monkeypatch, [
        {"category": "CREDENTIAL", "value": "4021"},                  # no letters
        {"category": "CONTACT", "value": "+33 6 45 12 98 03"},        # a phone, not an address
        {"category": "CREDENTIAL", "value": "YOUR_API_KEY"},          # placeholder
        {"category": "PAYMENT", "value": "4838 5608 9441 5465"},      # regex layer's job
    ])
    assert llm.find_with_llm(text) == []


def test_every_occurrence_is_reported(monkeypatch):
    text = "password Biscuit2019, again: Biscuit2019"
    fake_model(monkeypatch, [{"category": "CREDENTIAL", "value": "Biscuit2019"}])
    assert [f["start"] for f in llm.find_with_llm(text)] == [9, 29]


def test_bad_json_gives_no_findings(monkeypatch):
    monkeypatch.setattr(llm, "ask_model", lambda system, text, schema: "sorry, I can't help")
    assert llm.find_with_llm("anything") == []


def test_ollama_down_gives_no_findings(monkeypatch):
    def down(system, text, schema):
        raise requests.ConnectionError("Ollama is not running")
    monkeypatch.setattr(llm, "ask_model", down)
    assert llm.find_with_llm("anything") == []


needs_ollama = pytest.mark.skipif(not llm.is_available(), reason="Ollama is not running")


@needs_ollama
def test_real_model_finds_password_in_prose():
    text = ("For the shared finance mailbox I set the password to the CFO's dog's name "
            "plus the year, so Biscuit2019. Can you write the onboarding note?")
    assert "Biscuit2019" in {f["value"] for f in llm.find_with_llm(text)}


@needs_ollama
def test_real_model_finds_proprietary_code():
    assert "SOURCE_CODE" in {f["category"] for f in llm.find_with_llm(PRICING_CODE)}
