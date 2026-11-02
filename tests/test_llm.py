"""Tests for zeuslock/core/llm.py (the LLM layer).

Most tests replace the model with a fixed answer, so they run without Ollama.
The last test talks to the real model and is skipped when Ollama is not running.
"""

import json

import pytest
import requests

from zeuslock.core import llm


def fake_model(monkeypatch, findings):
    """Make ask_model return the given findings instead of calling Ollama."""
    answer = json.dumps({"findings": findings})
    monkeypatch.setattr(llm, "ask_model", lambda text: answer)


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


def test_source_code_with_changed_whitespace(monkeypatch):
    """The model often re-indents code; we still find the whole block."""
    text = (
        "Can you speed this up?\n\n"
        "def quote_premium(client):\n"
        "    base = client.fleet_size * RATE_TABLE[client.region]\n"
        "    return round(base * (1 - client.negotiated_discount), 2)"
    )
    model_value = (
        "def quote_premium(client):\n"
        "  base = client.fleet_size * RATE_TABLE[client.region]\n"
        "  return round(base * (1 - client.negotiated_discount), 2)"
    )
    fake_model(monkeypatch, [{"category": "SOURCE_CODE", "value": model_value}])
    [finding] = llm.find_with_llm(text)
    assert finding["category"] == "SOURCE_CODE"
    assert finding["value"].startswith("def quote_premium")
    assert finding["value"].endswith("negotiated_discount), 2)")


def test_invented_values_are_dropped(monkeypatch):
    fake_model(monkeypatch, [{"category": "CREDENTIAL", "value": "NotInTheText123"}])
    assert llm.find_with_llm("How do I reset my password?") == []


def test_other_categories_and_placeholders_are_dropped(monkeypatch):
    text = "card 4838 5608 9441 5465, key YOUR_API_KEY"
    fake_model(monkeypatch, [
        {"category": "PAYMENT", "value": "4838 5608 9441 5465"},   # regex layer's job
        {"category": "CREDENTIAL", "value": "YOUR_API_KEY"},       # placeholder
    ])
    assert llm.find_with_llm(text) == []


def test_every_occurrence_is_reported(monkeypatch):
    text = "password Biscuit2019, again: Biscuit2019"
    fake_model(monkeypatch, [{"category": "CREDENTIAL", "value": "Biscuit2019"}])
    assert [f["start"] for f in llm.find_with_llm(text)] == [9, 29]


def test_bad_json_gives_no_findings(monkeypatch):
    monkeypatch.setattr(llm, "ask_model", lambda text: "sorry, I can't help")
    assert llm.find_with_llm("anything") == []


def test_ollama_down_gives_no_findings(monkeypatch):
    def down(text):
        raise requests.ConnectionError("Ollama is not running")
    monkeypatch.setattr(llm, "ask_model", down)
    assert llm.find_with_llm("anything") == []


@pytest.mark.skipif(not llm.is_available(), reason="Ollama is not running")
def test_real_model_finds_password_in_prose():
    text = ("For the shared finance mailbox I set the password to the CFO's dog's name "
            "plus the year, so Biscuit2019. Can you write the onboarding note?")
    assert "Biscuit2019" in {f["value"] for f in llm.find_with_llm(text)}
