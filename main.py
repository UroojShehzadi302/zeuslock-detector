"""Command line for the ZeusLock detector.

    python main.py level1 detect "My card is 4838 5608 9441 5465"
    python main.py level1 eval                 # dev-set report (regex + LLM)
    python main.py level1 eval --regex-only    # regex layer alone

    python main.py level2 detect "card four eight three eight ..."   # hardened detection
    python main.py level2 eval [--regex-only]  # dev-set report with the Level 2 detector
    python main.py level2 attacks [--no-llm]   # adversarial prompts: Level 1 vs Level 2
    python main.py level2 chat                 # anonymize -> AI reply -> restore (interactive)
    python main.py level2 chat "msg 1" "msg 2" # same, with scripted messages
    python main.py level2 bench [--quick]      # speed before / after, findings must be identical

    python main.py level1 test                 # only the Level 1 tests
    python main.py level2 test                 # only the Level 2 tests

    python main.py all                         # everything
"""

import argparse
import json
import sys
from pathlib import Path

import pytest

from zeuslock.core import llm
from zeuslock.detector import detect
from zeuslock.level1 import evaluate
from zeuslock.level2 import attacks, bench, chat

TESTS = Path(__file__).parent / "tests"
LEVEL_TESTS = {
    "level1": ["test_validators.py", "test_patterns.py", "test_llm.py", "test_detector.py",
               "test_evaluate.py", "test_main.py"],
    "level2": ["test_session.py", "test_hardening.py", "test_bench.py"],
}

CHAT_DEMO = [
    "Please email sarah.okonkwo@brightwell-partners.co.uk: her card 4838 5608 9441 5465 was charged twice.",
    "Also tell sarah.okonkwo@brightwell-partners.co.uk the refund takes 5 days.",
]


def warn_if_ollama_down() -> None:
    if not llm.is_available():
        print(f"warning: Ollama is not running at {llm.OLLAMA_URL}, only the regex layer will be used.\n"
              f"Start it with: ollama serve", file=sys.stderr)


def run_detect(text: str, mode: str) -> int:
    warn_if_ollama_down()
    print(json.dumps(detect(text, mode=mode), indent=2, ensure_ascii=False))
    return 0


def run_eval(regex_only: bool, mode: str) -> int:
    if not regex_only:
        warn_if_ollama_down()
        print("Running the dev set through regex + LLM (~5 min)...\n", file=sys.stderr)
    print(evaluate.run(regex_only, mode=mode))
    return 0


def run_attacks(no_llm: bool) -> int:
    if not no_llm:
        warn_if_ollama_down()
        print("Running every attack through Level 1 and Level 2 (~5 min)...\n", file=sys.stderr)
    print(attacks.run(use_llm=not no_llm))
    return 0


def run_chat(messages: list[str]) -> int:
    warn_if_ollama_down()
    chat.run(messages)
    return 0


def run_bench(quick: bool) -> int:
    warn_if_ollama_down()
    minutes = "~3" if quick else "~15"
    print(f"Timing every prompt before / after the speedup ({minutes} min)...\n", file=sys.stderr)
    print(bench.run(quick))
    return 0


def run_tests(level: str) -> int:
    return pytest.main(["-q", *(str(TESTS / name) for name in LEVEL_TESTS[level])])


def run_all() -> int:
    print(evaluate.run(regex_only=True))
    print()
    run_eval(regex_only=False, mode="level1")
    print()
    run_attacks(no_llm=False)
    print("\n=== Level 2, chat demo ===\n")
    run_chat(CHAT_DEMO)
    print()
    run_bench(quick=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="main.py", description="ZeusLock: local detector for sensitive data in AI prompts.")
    levels = parser.add_subparsers(dest="level", required=True)

    for level, help_text in [("level1", "Level 1: detect() + dev-set evaluation"),
                             ("level2", "Level 2: hardened detect, attacks, chat (anonymize / restore)")]:
        level_parser = levels.add_parser(level, help=help_text)
        commands = level_parser.add_subparsers(dest="command", required=True)
        detect_parser = commands.add_parser("detect", help="check one prompt")
        detect_parser.add_argument("text", help="the prompt to check (in quotes)")
        eval_parser = commands.add_parser("eval", help="evaluate on data/dev_set.jsonl")
        eval_parser.add_argument("--regex-only", action="store_true", help="skip the LLM layer (instant)")
        commands.add_parser("test", help=f"run only the {level} tests")
        if level == "level2":
            attacks_parser = commands.add_parser("attacks", help="run attacks/attacks.jsonl, Level 1 vs Level 2")
            attacks_parser.add_argument("--no-llm", action="store_true", help="regex side only (instant)")
            chat_parser = commands.add_parser("chat", help="anonymize -> AI reply -> restore")
            chat_parser.add_argument("messages", nargs="*", help="messages to send instead of typing them")
            bench_parser = commands.add_parser("bench", help="speed before / after, findings must be identical")
            bench_parser.add_argument("--quick", action="store_true", help="10 dev prompts + 5 attacks (~3 min)")

    levels.add_parser("all", help="run everything: evaluations, attacks, chat demo, quick bench")
    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to cp1252: print accents and symbols safely.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    args = build_parser().parse_args(argv)
    if args.level == "all":
        return run_all()
    if args.command == "detect":
        return run_detect(args.text, args.level)
    if args.command == "eval":
        return run_eval(args.regex_only, args.level)
    if args.command == "attacks":
        return run_attacks(args.no_llm)
    if args.command == "chat":
        return run_chat(args.messages)
    if args.command == "test":
        return run_tests(args.level)
    return run_bench(args.quick)


if __name__ == "__main__":
    sys.exit(main())
