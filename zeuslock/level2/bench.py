"""Speed benchmark: before vs after, and proof that detection did not change.

    python -m zeuslock.level2.bench            # dev set + attacks (~15 min)
    python -m zeuslock.level2.bench --quick    # 10 dev prompts + 5 attacks (~3 min)

Every prompt is run twice through detect():
- BEFORE: the old setup ("localhost" URL, a new HTTP connection per call, no answer cache)
- AFTER:  the current setup (127.0.0.1, one reused connection, answer cache)
The findings must be IDENTICAL for every prompt: a speedup that changes detection is rejected.
Then every prompt is run a third time (AFTER), to show the cache on a repeated prompt.
"""

import argparse
import json
import statistics
import time
from pathlib import Path

import requests

from zeuslock.core import llm
from zeuslock.detector import detect
from zeuslock.level1.evaluate import load_dev_set, percentile
from zeuslock.level2.attacks import load_attacks

DATA = Path(__file__).parent.parent.parent

SETUPS = {
    "before": {"url": "http://localhost:11434", "http": requests, "cache": False},
    "after": {"url": "http://127.0.0.1:11434", "http": requests.Session(), "cache": True},
}


def use_setup(name: str) -> None:
    setup = SETUPS[name]
    llm.OLLAMA_URL, llm.HTTP, llm.USE_CACHE = setup["url"], setup["http"], setup["cache"]


def timed_run(texts: list[str], mode: str) -> tuple[list[float], list[list]]:
    seconds, findings = [], []
    for text in texts:
        start = time.perf_counter()
        result = detect(text, mode=mode)
        seconds.append(time.perf_counter() - start)
        findings.append([(f["category"], f["start"], f["end"]) for f in result["findings"]])
    return seconds, findings


def stats(seconds: list[float]) -> str:
    return (f"mean {statistics.mean(seconds):6.2f} s   p50 {percentile(seconds, 50):6.2f} s   "
            f"p95 {percentile(seconds, 95):6.2f} s   total {sum(seconds):7.1f} s")


def run(quick: bool = False, mode: str = "level2") -> str:
    dev = [e["text"] for e in load_dev_set()]
    attacks = [a["text"] for a in load_attacks()]
    if quick:
        dev, attacks = dev[:10], attacks[:5]
    texts = dev + attacks

    try:
        use_setup("before")
        before_s, before_f = timed_run(texts, mode)
        use_setup("after")
        llm.clear_cache()
        after_s, after_f = timed_run(texts, mode)
        again_s, again_f = timed_run(texts, mode)          # same prompts again: answers cached
    finally:
        use_setup("after")

    same = sum(b == a == g for b, a, g in zip(before_f, after_f, again_f))
    changed = [i for i, (b, a, g) in enumerate(zip(before_f, after_f, again_f)) if not b == a == g]
    lines = [
        f"=== Speed benchmark, {mode}, {len(dev)} dev prompts + {len(attacks)} attacks ===",
        "",
        f"  before (localhost, new connection, no cache)  {stats(before_s)}",
        f"  after  (127.0.0.1, reused connection, cache)  {stats(after_s)}",
        f"  after, same prompts again (cache hits)        {stats(again_s)}",
        "",
        f"  speedup: {statistics.mean(before_s) / statistics.mean(after_s):.1f}x faster on new prompts",
        f"  identical findings: {same}/{len(texts)} prompts",
    ]
    if changed:
        lines.append(f"  CHANGED (speedup rejected): prompts {changed}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Speed before / after, with identical findings.")
    parser.add_argument("--quick", action="store_true", help="10 dev prompts + 5 attacks")
    parser.add_argument("--mode", choices=["level1", "level2"], default="level2")
    args = parser.parse_args()
    print(run(args.quick, args.mode))


if __name__ == "__main__":
    main()
