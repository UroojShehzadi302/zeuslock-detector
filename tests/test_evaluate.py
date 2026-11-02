"""Tests for zeuslock/level1/evaluate.py, with a fake detector (no Ollama needed)."""

from zeuslock.level1.evaluate import evaluate, format_report, percentile, value_match

EXAMPLES = [
    {"id": "a", "text": "card 4838 5608 9441 5465",
     "expected": {"clean": False, "categories": ["PAYMENT"], "values": ["4838 5608 9441 5465"]}},
    {"id": "b", "text": "password=Hunter22",
     "expected": {"clean": False, "categories": ["CREDENTIAL"], "values": ["password=Hunter22"]}},
    {"id": "c", "text": "my ip is 10.0.0.1",
     "expected": {"clean": False, "categories": ["NETWORK"], "values": ["10.0.0.1"]}},
    {"id": "d", "text": "hello there",
     "expected": {"clean": True, "categories": [], "values": []}},
]

ANSWERS = {
    "card 4838 5608 9441 5465": [("PAYMENT", "4838 5608 9441 5465")],
    "password=Hunter22": [("CREDENTIAL", "Hunter22")],       # overlap, not exact
    "my ip is 10.0.0.1": [],                                  # miss
    "hello there": [("CONTACT", "there")],                    # false alarm
}


def fake_detect(text):
    findings = [{"category": c, "start": text.find(v), "end": text.find(v) + len(v), "value": v}
                for c, v in ANSWERS[text]]
    return {"decision": "alert" if findings else "allow", "findings": findings}


def test_prompt_level():
    report = evaluate(EXAMPLES, fake_detect)
    assert report["accuracy"] == 0.5
    assert [r["id"] for r in report["misses"]] == ["c"]
    assert [r["id"] for r in report["false_alarms"]] == ["d"]


def test_category_level():
    per = evaluate(EXAMPLES, fake_detect)["per_category"]
    assert per["PAYMENT"]["precision"] == 1.0 and per["PAYMENT"]["recall"] == 1.0
    assert per["NETWORK"]["recall"] == 0.0
    assert per["CONTACT"]["fp"] == 1 and per["CONTACT"]["precision"] == 0.0


def test_value_level():
    assert evaluate(EXAMPLES, fake_detect)["values"] == {"exact": 1, "overlap": 1, "missed": 1}
    assert value_match("password=X1", ["X1"]) == "overlap"
    assert value_match("abc", ["xyz"]) == "missed"


def test_wrong_prompts_listed_and_report_prints():
    report = evaluate(EXAMPLES, fake_detect)
    assert [r["id"] for r in report["wrong"]] == ["c", "d"]
    text = format_report(report, "test")
    assert "misses        1   c" in text
    assert "false alarms  1   d" in text


def test_percentile():
    assert percentile([1, 2, 3, 4, 5], 50) == 3
    assert percentile([1, 2, 3, 4, 5], 95) == 5
