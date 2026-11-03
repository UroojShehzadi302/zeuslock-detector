"""Run the adversarial prompts (attacks/attacks.jsonl) against Level 1 and Level 2.

    python -m zeuslock.level2.attacks            # with the LLM (~5 min)
    python -m zeuslock.level2.attacks --no-llm   # regex side only (instant)

An attack is CAUGHT when the decision is "alert" and every expected category is found.
"""

import argparse
import json
from pathlib import Path

from zeuslock.detector import detect

ATTACKS = Path(__file__).parent.parent.parent / "attacks" / "attacks.jsonl"


def load_attacks(path: Path = ATTACKS) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def caught(attack: dict, result: dict) -> bool:
    found = {f["category"] for f in result["findings"]}
    return result["decision"] == "alert" and set(attack["expected"]["categories"]) <= found


def run_attacks(attacks: list[dict], use_llm: bool = True, detect_fn=detect) -> list[dict]:
    rows = []
    for attack in attacks:
        level1 = detect_fn(attack["text"], mode="level1", use_llm=use_llm)
        level2 = detect_fn(attack["text"], mode="level2", use_llm=use_llm)
        rows.append({
            "id": attack["id"],
            "attack": attack["attack"],
            "categories": attack["expected"]["categories"],
            "level1": caught(attack, level1),
            "level2": caught(attack, level2),
            "level2_found": [(f["category"], f["value"]) for f in level2["findings"]],
        })
    return rows


def format_report(rows: list[dict], use_llm: bool) -> str:
    title = "Level 2 attacks, regex + LLM" if use_llm else "Level 2 attacks, regex side only (--no-llm)"
    mark = {True: "caught", False: "MISSED"}
    lines = [f"=== {title} ===", "", f"  {'id':<7} {'attack':<48} {'category':<12} {'level1':<7} level2"]
    for r in rows:
        lines.append(f"  {r['id']:<7} {r['attack'][:48]:<48} {'+'.join(r['categories']):<12} "
                     f"{mark[r['level1']]:<7} {mark[r['level2']]}")
    total = len(rows)
    l1, l2 = sum(r["level1"] for r in rows), sum(r["level2"] for r in rows)
    lines += ["", f"Caught: level1 {l1}/{total}   level2 {l2}/{total}"]

    still_missed = [r for r in rows if not r["level2"]]
    if still_missed:
        lines += ["", "Still getting through Level 2:"]
        for r in still_missed:
            lines.append(f"  {r['id']}  {r['attack']}  (found: {r['level2_found'] or 'nothing'})")
    return "\n".join(lines)


def run(use_llm: bool = True) -> str:
    return format_report(run_attacks(load_attacks(), use_llm), use_llm)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the attack prompts against Level 1 and Level 2.")
    parser.add_argument("--no-llm", action="store_true", help="regex side only (instant)")
    print(run(use_llm=not parser.parse_args().no_llm))


if __name__ == "__main__":
    main()
