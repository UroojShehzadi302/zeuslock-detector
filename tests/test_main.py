"""Tests for main.py (the command line). Detector and evaluation are faked, no Ollama needed."""

import json

import pytest

import main


@pytest.fixture(autouse=True)
def fake_backend(monkeypatch):
    monkeypatch.setattr(main.llm, "is_available", lambda: True)
    monkeypatch.setattr(main, "detect", lambda text: {"decision": "allow", "findings": [], "text": text})
    monkeypatch.setattr(main.evaluate, "run", lambda regex_only=False: f"REPORT regex_only={regex_only}")
    monkeypatch.setattr(main.chat, "run", lambda messages=None: print(f"CHAT {messages}"))


def test_level1_detect_prints_json(capsys):
    assert main.main(["level1", "detect", "café 4838"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["decision"] == "allow"
    assert printed["text"] == "café 4838"


def test_level1_eval(capsys):
    assert main.main(["level1", "eval"]) == 0
    assert "REPORT regex_only=False" in capsys.readouterr().out


def test_level1_eval_regex_only(capsys):
    assert main.main(["level1", "eval", "--regex-only"]) == 0
    assert "REPORT regex_only=True" in capsys.readouterr().out


def test_level2_chat(capsys):
    assert main.main(["level2", "chat", "hello", "again"]) == 0
    assert "CHAT ['hello', 'again']" in capsys.readouterr().out


def test_level2_not_built_yet(capsys):
    assert main.main(["level2", "bench"]) == 1
    assert "not built yet" in capsys.readouterr().err


def test_all_runs_both_evaluations(capsys):
    assert main.main(["all"]) == 0
    out = capsys.readouterr().out
    assert "REPORT regex_only=True" in out and "REPORT regex_only=False" in out
    assert "CHAT [" in out


def test_warns_when_ollama_is_down(monkeypatch, capsys):
    monkeypatch.setattr(main.llm, "is_available", lambda: False)
    main.main(["level1", "detect", "hello"])
    assert "Ollama is not running" in capsys.readouterr().err


def test_missing_command_shows_usage():
    with pytest.raises(SystemExit):
        main.main([])
