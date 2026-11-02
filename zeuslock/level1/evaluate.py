"""Level 1 evaluation: run the detector on the dev set and measure it.

    python -m zeuslock.level1.evaluate              # full detector (regex + LLM)
    python -m zeuslock.level1.evaluate --regex-only # regex layer alone, for comparison

What is measured:
- prompt level: misses (should alert, did not), false alarms (should allow, did not), accuracy
- category level: precision / recall per category
- value level: expected values found exactly, or overlapping (e.g. "password=X" vs "X")
- speed: mean, p50, p95, max milliseconds per prompt
- a table of every prompt that differs from its label, with our note when we think
  the label is wrong (see LABEL_NOTES)
"""

import argparse
import json
import statistics
import time
from pathlib import Path

from zeuslock.core.merge import merge
from zeuslock.core.patterns import find_all
from zeuslock.detector import detect

DEV_SET = Path(__file__).parent.parent.parent / "data" / "dev_set.jsonl"
CATEGORIES = ["PAYMENT", "CREDENTIAL", "CONTACT", "GOV_ID", "NETWORK", "SOURCE_CODE"]

# Prompts where we disagree with the label on purpose. Shown next to the error.
LABEL_NOTES = {
    "dev-011": "label value includes 'password=', we report only the password",
    "dev-016": "label value is only the BEGIN line, we report the whole key block",
    "dev-026": "label mistake: an SSN is GOV_ID, not CONTACT",
    "dev-031": "label mistake: 1.1.1.1 is a public resolver, not sensitive",
    "dev-037": "debatable: the number fails Luhn, so it is not a real card",
    "dev-048": "debatable: a real email address is personal data",
}


def detect_regex_only(text: str) -> dict:
    """Same output as detect(), without the LLM layer."""
    findings = merge(find_all(text), [])
    return {"decision": "alert" if findings else "allow", "findings": findings}


def load_dev_set(path: Path = DEV_SET) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def value_match(expected: str, found: list[str]) -> str:
    """'exact', 'overlap' (one contains the other) or 'missed'."""
    if expected in found:
        return "exact"
    if any(expected in value or value in expected for value in found):
        return "overlap"
    return "missed"


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, round(p / 100 * (len(ordered) - 1)))
    return ordered[index]


def evaluate(examples: list[dict], detect_fn=detect) -> dict:
    """Run detect_fn on every example and compute all the numbers."""
    rows = []
    for example in examples:
        start = time.perf_counter()
        result = detect_fn(example["text"])
        seconds = time.perf_counter() - start

        expected = example["expected"]
        rows.append({
            "id": example["id"],
            "seconds": seconds,
            "want_alert": not expected["clean"],
            "got_alert": result["decision"] == "alert",
            "want_categories": set(expected["categories"]),
            "got_categories": {f["category"] for f in result["findings"]},
            "value_matches": [value_match(v, [f["value"] for f in result["findings"]])
                              for v in expected["values"]],
            "found_values": [f["value"] for f in result["findings"]],
        })

    misses = [r for r in rows if r["want_alert"] and not r["got_alert"]]
    false_alarms = [r for r in rows if not r["want_alert"] and r["got_alert"]]
    correct = [r for r in rows if r["want_alert"] == r["got_alert"]]

    per_category = {}
    for category in CATEGORIES:
        tp = sum(category in r["want_categories"] and category in r["got_categories"] for r in rows)
        fp = sum(category not in r["want_categories"] and category in r["got_categories"] for r in rows)
        fn = sum(category in r["want_categories"] and category not in r["got_categories"] for r in rows)
        per_category[category] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else 1.0,
            "recall": tp / (tp + fn) if tp + fn else 1.0,
        }

    all_matches = [m for r in rows for m in r["value_matches"]]
    seconds = [r["seconds"] for r in rows]
    return {
        "rows": rows,
        "total": len(rows),
        "accuracy": len(correct) / len(rows),
        "misses": misses,
        "false_alarms": false_alarms,
        "per_category": per_category,
        "values": {kind: all_matches.count(kind) for kind in ("exact", "overlap", "missed")},
        "latency": {
            "mean": statistics.mean(seconds),
            "p50": percentile(seconds, 50),
            "p95": percentile(seconds, 95),
            "max": max(seconds),
        },
        "wrong": [r for r in rows
                  if r["want_alert"] != r["got_alert"] or r["want_categories"] != r["got_categories"]],
    }


def format_report(report: dict, title: str) -> str:
    """The report as plain text."""
    lines = [f"=== {title} ===", ""]

    total = report["total"]
    lines += [
        "Prompt level (alert / allow)",
        f"  accuracy      {report['accuracy']:.0%}  ({total - len(report['misses']) - len(report['false_alarms'])}/{total})",
        f"  misses        {len(report['misses'])}   {', '.join(r['id'] for r in report['misses'])}",
        f"  false alarms  {len(report['false_alarms'])}   {', '.join(r['id'] for r in report['false_alarms'])}",
        "",
        "Category level",
        f"  {'category':<12} {'precision':>9} {'recall':>7}   tp  fp  fn",
    ]
    for category, c in report["per_category"].items():
        lines.append(f"  {category:<12} {c['precision']:>9.0%} {c['recall']:>7.0%}  {c['tp']:>3} {c['fp']:>3} {c['fn']:>3}")

    v = report["values"]
    lines += [
        "",
        f"Value level ({sum(v.values())} expected values)",
        f"  exact {v['exact']}   overlap {v['overlap']}   missed {v['missed']}",
        "",
        "Speed (milliseconds per prompt)",
        "  mean {mean:.1f}   p50 {p50:.1f}   p95 {p95:.1f}   max {max:.1f}".format(
            **{k: s * 1000 for k, s in report["latency"].items()}),
        "",
        f"Prompts that differ from the label ({len(report['wrong'])})",
    ]
    for r in report["wrong"]:
        want = "alert" if r["want_alert"] else "allow"
        got = "alert" if r["got_alert"] else "allow"
        lines.append(f"  {r['id']}  want {want} {sorted(r['want_categories'])}  got {got} {sorted(r['got_categories'])}")
        if r["id"] in LABEL_NOTES:
            lines.append(f"           note: {LABEL_NOTES[r['id']]}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the detector on the dev set.")
    parser.add_argument("--regex-only", action="store_true", help="skip the LLM layer")
    parser.add_argument("--dev-set", type=Path, default=DEV_SET)
    args = parser.parse_args()

    detect_fn = detect_regex_only if args.regex_only else detect
    title = "Level 1, regex only" if args.regex_only else "Level 1, regex + LLM"
    print(format_report(evaluate(load_dev_set(args.dev_set), detect_fn), title))


if __name__ == "__main__":
    main()
