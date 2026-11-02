"""Tests for the merge step (zeuslock/core/merge.py) and detect() (zeuslock/detector.py).

The LLM layer is switched off (returns []) unless a test needs it, so these run
without Ollama. The last test uses the real model and is skipped when Ollama is not running.
"""

import json
from pathlib import Path

import pytest

from submission import detect
from zeuslock import detector
from zeuslock.core import llm
from zeuslock.core.merge import merge

DEV_SET = Path(__file__).parent.parent / "data" / "dev_set.jsonl"


def finding(category, start, end, text="x" * 200):
    return {"category": category, "start": start, "end": end, "value": text[start:end]}


@pytest.fixture
def no_llm(monkeypatch):
    monkeypatch.setattr(detector, "find_with_llm", lambda text: [])


def fake_llm(monkeypatch, findings):
    monkeypatch.setattr(detector, "find_with_llm", lambda text: findings)


# ---------------- merge ----------------

def test_same_value_twice_is_reported_once():
    a = finding("CREDENTIAL", 10, 40)
    assert merge([a, dict(a)], []) == [a]


def test_shorter_match_inside_longer_is_dropped():
    token = finding("CREDENTIAL", 10, 60)
    digits = finding("PAYMENT", 25, 38)           # Luhn digits inside a Slack token
    assert merge([digits, token], []) == [token]


def test_private_ip_inside_connection_string_is_kept():
    url = finding("CREDENTIAL", 10, 70)
    ip = finding("NETWORK", 40, 50)
    assert merge([url, ip], []) == [url, ip]


def test_regex_wins_over_llm():
    iban = finding("PAYMENT", 10, 32)
    llm_guess = finding("CREDENTIAL", 10, 32)     # same IBAN, wrong category
    assert merge([iban], [llm_guess]) == [iban]


def test_secret_inside_code_block_is_kept():
    key = finding("CREDENTIAL", 30, 70)
    code = finding("SOURCE_CODE", 0, 150)
    assert merge([key], [code]) == [code, key]


def test_result_is_sorted_by_position():
    late, early = finding("CONTACT", 100, 120), finding("PAYMENT", 5, 20)
    assert merge([late], [early]) == [early, late]


# ---------------- detect ----------------

def test_card_gives_alert(no_llm):
    text = "Can you check why my Visa 4838 5608 9441 5465 keeps getting declined?"
    assert detect(text) == {
        "decision": "alert",
        "findings": [{"category": "PAYMENT", "start": 26, "end": 45, "value": "4838 5608 9441 5465"}],
    }


def test_clean_prompt_gives_allow(no_llm):
    assert detect("How do I reset my password if I lost my email?") == {"decision": "allow", "findings": []}


def test_dev_set_overlaps_are_cleaned(no_llm):
    dev = {json.loads(line)["id"]: json.loads(line)["text"]
           for line in DEV_SET.read_text(encoding="utf-8").splitlines()}

    # dev-017: no email inside the connection string
    assert [f["category"] for f in detect(dev["dev-017"])["findings"]] == ["CREDENTIAL"]
    # dev-018: token + connection string + the private IP inside it
    assert [f["category"] for f in detect(dev["dev-018"])["findings"]] == ["CREDENTIAL", "CREDENTIAL", "NETWORK"]
    # dev-036: no PAYMENT inside the Slack token
    assert "PAYMENT" not in {f["category"] for f in detect(dev["dev-036"])["findings"]}


def test_llm_findings_are_added(monkeypatch):
    text = "I set the password to the dog's name plus the year, so Biscuit2019."
    fake_llm(monkeypatch, [finding("CREDENTIAL", 55, 66, text)])
    result = detect(text)
    assert result["decision"] == "alert"
    assert [f["value"] for f in result["findings"]] == ["Biscuit2019"]


def test_offsets_always_match_value(no_llm):
    for line in DEV_SET.read_text(encoding="utf-8").splitlines():
        text = json.loads(line)["text"]
        for f in detect(text)["findings"]:
            assert text[f["start"]:f["end"]] == f["value"]


def test_unknown_mode_is_refused(no_llm):
    with pytest.raises(ValueError):
        detect("hello", mode="level9")


@pytest.mark.skipif(not llm.is_available(), reason="Ollama is not running")
def test_real_detect_combines_both_layers():
    text = ("Card 4838 5608 9441 5465 declined. Also, the mailbox password is the dog's "
            "name plus the year, so Biscuit2019.")
    values = {f["value"] for f in detect(text)["findings"]}
    assert {"4838 5608 9441 5465", "Biscuit2019"} <= values
