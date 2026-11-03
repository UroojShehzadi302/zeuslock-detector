"""Tests for main.py (the command line). Detector, evaluation, attacks and chat are faked, no Ollama needed."""

import json

import pytest

import main


@pytest.fixture(autouse=True)
def fake_backend(monkeypatch):
    monkeypatch.setattr(main.llm, "is_available", lambda: True)
    monkeypatch.setattr(main, "detect", lambda text, mode="level1": {"decision": "allow", "findings": [],
                                                                    "text": text, "mode": mode})
    monkeypatch.setattr(main.evaluate, "run",
                        lambda regex_only=False, mode="level1": f"REPORT regex_only={regex_only} mode={mode}")
    monkeypatch.setattr(main.attacks, "run", lambda use_llm=True: f"ATTACKS use_llm={use_llm}")
    monkeypatch.setattr(main.chat, "run", lambda messages=None: print(f"CHAT {messages}"))
    monkeypatch.setattr(main.bench, "run", lambda quick=False: f"BENCH quick={quick}")
    monkeypatch.setattr(main.pytest, "main", lambda args: print(f"PYTEST {args}") or 0)


def test_level1_detect_prints_json(capsys):
    assert main.main(["level1", "detect", "café 4838"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["decision"] == "allow"
    assert printed["text"] == "café 4838"
    assert printed["mode"] == "level1"


def test_level2_detect_uses_level2_mode(capsys):
    assert main.main(["level2", "detect", "four eight three eight"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "level2"


def test_level1_eval(capsys):
    assert main.main(["level1", "eval"]) == 0
    assert "REPORT regex_only=False mode=level1" in capsys.readouterr().out


def test_level1_eval_regex_only(capsys):
    assert main.main(["level1", "eval", "--regex-only"]) == 0
    assert "REPORT regex_only=True mode=level1" in capsys.readouterr().out


def test_level2_eval(capsys):
    assert main.main(["level2", "eval", "--regex-only"]) == 0
    assert "REPORT regex_only=True mode=level2" in capsys.readouterr().out


def test_level2_attacks(capsys):
    assert main.main(["level2", "attacks", "--no-llm"]) == 0
    assert "ATTACKS use_llm=False" in capsys.readouterr().out


def test_level2_chat(capsys):
    assert main.main(["level2", "chat", "hello", "again"]) == 0
    assert "CHAT ['hello', 'again']" in capsys.readouterr().out


def test_level2_bench(capsys):
    assert main.main(["level2", "bench", "--quick"]) == 0
    assert "BENCH quick=True" in capsys.readouterr().out


def test_each_level_runs_only_its_own_tests(capsys):
    assert main.main(["level1", "test"]) == 0
    level1 = capsys.readouterr().out
    assert "test_patterns.py" in level1 and "test_hardening.py" not in level1
    assert main.main(["level2", "test"]) == 0
    level2 = capsys.readouterr().out
    assert "test_hardening.py" in level2 and "test_patterns.py" not in level2


def test_every_test_file_belongs_to_a_level():
    files = {p.name for p in main.TESTS.glob("test_*.py")}
    assert files == set(main.LEVEL_TESTS["level1"]) | set(main.LEVEL_TESTS["level2"])


def test_all_runs_everything(capsys):
    assert main.main(["all"]) == 0
    out = capsys.readouterr().out
    assert "REPORT regex_only=True" in out and "REPORT regex_only=False" in out
    assert "ATTACKS use_llm=True" in out
    assert "CHAT [" in out
    assert "BENCH quick=True" in out


def test_warns_when_ollama_is_down(monkeypatch, capsys):
    monkeypatch.setattr(main.llm, "is_available", lambda: False)
    main.main(["level1", "detect", "hello"])
    assert "Ollama is not running" in capsys.readouterr().err


def test_missing_command_shows_usage():
    with pytest.raises(SystemExit):
        main.main([])
