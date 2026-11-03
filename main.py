"""Command line for the ZeusLock detector.

    python main.py level1 detect "My card is 4838 5608 9441 5465"
    python main.py level1 eval                 # dev-set report (regex + LLM)
    python main.py level1 eval --regex-only    # regex layer alone
    python main.py level2 chat                 # anonymize -> AI reply -> restore (interactive)
    python main.py level2 chat "msg 1" "msg 2" # same, with scripted messages
    python main.py level2 detect|attacks|bench # not built yet (steps 9-10)
    python main.py all                         # everything that exists
"""

import argparse
import json
import sys

from zeuslock.core import llm
from zeuslock.detector import detect
from zeuslock.level1 import evaluate
from zeuslock.level2 import chat

LEVEL2_COMMANDS = {
    "detect": "detection with anti-obfuscation",
    "chat": "anonymize -> AI reply -> restore",
    "attacks": "adversarial prompts: Level 1 vs Level 2 caught",
    "bench": "speed before / after",
}


def warn_if_ollama_down() -> None:
    if not llm.is_available():
        print(f"warning: Ollama is not running at {llm.OLLAMA_URL}, only the regex layer will be used.\n"
              f"Start it with: ollama serve", file=sys.stderr)


def level1_detect(text: str) -> int:
    warn_if_ollama_down()
    print(json.dumps(detect(text), indent=2, ensure_ascii=False))
    return 0


def level1_eval(regex_only: bool) -> int:
    if not regex_only:
        warn_if_ollama_down()
        print("Running the dev set through regex + LLM (~5 min)...\n", file=sys.stderr)
    print(evaluate.run(regex_only))
    return 0


def level2(command: str, messages: list[str]) -> int:
    if command == "chat":
        warn_if_ollama_down()
        chat.run(messages)
        return 0
    print(f"level2 {command} ({LEVEL2_COMMANDS[command]}) is not built yet: coming in steps 9-10.",
          file=sys.stderr)
    return 1


def run_all() -> int:
    print(evaluate.run(regex_only=True))
    print()
    level1_eval(regex_only=False)
    print("\n=== Level 2, chat demo ===\n")
    chat.run(["Please email sarah.okonkwo@brightwell-partners.co.uk: her card 4838 5608 9441 5465 was charged twice.",
              "Also tell sarah.okonkwo@brightwell-partners.co.uk the refund takes 5 days."])
    print("\nLevel 2 attacks / bench: not built yet (steps 9-10), skipped.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="main.py", description="ZeusLock: local detector for sensitive data in AI prompts.")
    levels = parser.add_subparsers(dest="level", required=True)

    level1 = levels.add_parser("level1", help="Level 1: detect() + dev-set evaluation")
    commands1 = level1.add_subparsers(dest="command", required=True)
    detect_parser = commands1.add_parser("detect", help="check one prompt")
    detect_parser.add_argument("text", help="the prompt to check (in quotes)")
    eval_parser = commands1.add_parser("eval", help="evaluate on data/dev_set.jsonl")
    eval_parser.add_argument("--regex-only", action="store_true", help="skip the LLM layer (instant)")

    level2_parser = levels.add_parser("level2", help="Level 2: chat (anonymize / restore); detect, attacks, bench coming")
    level2_parser.add_argument("command", choices=sorted(LEVEL2_COMMANDS))
    level2_parser.add_argument("messages", nargs="*", help="chat only: messages to send instead of typing them")

    levels.add_parser("all", help="run everything: Level 1 evaluations + Level 2 chat demo")
    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to cp1252: print accents and symbols safely.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    args = build_parser().parse_args(argv)
    if args.level == "level1" and args.command == "detect":
        return level1_detect(args.text)
    if args.level == "level1" and args.command == "eval":
        return level1_eval(args.regex_only)
    if args.level == "level2":
        return level2(args.command, args.messages)
    return run_all()


if __name__ == "__main__":
    sys.exit(main())
