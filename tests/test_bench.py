"""Tests for the step 10 speedups (answer cache, setups) and zeuslock/level2/bench.py. No Ollama needed."""

import json

from zeuslock.core import llm
from zeuslock.level2 import bench


class FakeResponse:
    def __init__(self, content):
        self.content = content

    def raise_for_status(self):
        pass

    def json(self):
        return {"message": {"content": self.content}}


class FakeHTTP:
    """Counts the calls that would go to Ollama."""

    def __init__(self):
        self.calls = 0

    def post(self, url, json, timeout):
        self.calls += 1
        return FakeResponse('{"findings": []}')


def test_same_question_is_asked_only_once(monkeypatch):
    http = FakeHTTP()
    monkeypatch.setattr(llm, "HTTP", http)
    monkeypatch.setattr(llm, "USE_CACHE", True)
    llm.clear_cache()
    for _ in range(3):
        assert llm.ask_model("system", "same text", llm.FIND_SCHEMA) == '{"findings": []}'
    assert http.calls == 1
    llm.ask_model("system", "other text", llm.FIND_SCHEMA)
    assert http.calls == 2


def test_cache_can_be_switched_off(monkeypatch):
    http = FakeHTTP()
    monkeypatch.setattr(llm, "HTTP", http)
    monkeypatch.setattr(llm, "USE_CACHE", False)
    llm.ask_model("system", "same text", llm.FIND_SCHEMA)
    llm.ask_model("system", "same text", llm.FIND_SCHEMA)
    assert http.calls == 2


def test_cache_forgets_the_oldest_answers(monkeypatch):
    monkeypatch.setattr(llm, "HTTP", FakeHTTP())
    monkeypatch.setattr(llm, "USE_CACHE", True)
    monkeypatch.setattr(llm, "CACHE_SIZE", 2)
    llm.clear_cache()
    for text in ("a", "b", "c"):
        llm.ask_model("system", text, llm.FIND_SCHEMA)
    assert [key[2] for key in llm._answers] == ["b", "c"]
    llm.clear_cache()


def test_default_url_avoids_slow_localhost():
    assert "127.0.0.1" in llm.OLLAMA_URL or "localhost" not in llm.OLLAMA_URL


def test_bench_reports_speed_and_identical_findings(monkeypatch):
    calls = []
    def fake_detect(text, mode="level2"):
        calls.append(llm.USE_CACHE)
        return {"decision": "allow", "findings": []}
    monkeypatch.setattr(bench, "detect", fake_detect)
    monkeypatch.setattr(bench, "load_dev_set", lambda: [{"text": "a"}, {"text": "b"}])
    monkeypatch.setattr(bench, "load_attacks", lambda: [{"text": "c"}])

    report = bench.run(quick=False)
    assert "identical findings: 3/3 prompts" in report
    assert calls == [False] * 3 + [True] * 6         # before: no cache; after + again: cache
    assert llm.USE_CACHE is True                     # the real setup is put back afterwards
