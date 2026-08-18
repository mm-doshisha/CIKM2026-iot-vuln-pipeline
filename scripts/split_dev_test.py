#!/usr/bin/env python3
"""Stratified dev/test split of CVE benchmark traces.

Produces two JSON files listing CVE IDs:
  - dev_cves.json  (30 CVEs, stratified by vuln_class, seed=0)
  - test_cves.json (251 CVEs, remaining)

Usage:
    python scripts/split_dev_test.py
"""

import json
import random
from pathlib import Path

TRACES_DIR = Path("benchmarks/traces")
OUTPUT_DIR = Path("benchmarks")
DEV_SIZE = 30
SEED = 0


def main():
    traces = sorted(TRACES_DIR.glob("CVE-*.json"))
    by_class: dict[str, list[str]] = {}
    for t in traces:
        data = json.load(open(t))
        vc = data.get("vuln_class", "Unknown")
        by_class.setdefault(vc, []).append(t.stem)

    total = sum(len(v) for v in by_class.values())
    rng = random.Random(SEED)

    dev_cves = []
    for cls, cves in sorted(by_class.items()):
        n_sample = max(1, round(len(cves) / total * DEV_SIZE))
        sampled = rng.sample(cves, min(n_sample, len(cves)))
        dev_cves.extend(sampled)

    if len(dev_cves) > DEV_SIZE:
        rng.shuffle(dev_cves)
        dev_cves = dev_cves[:DEV_SIZE]
    elif len(dev_cves) < DEV_SIZE:
        remaining = [c for cls_cves in by_class.values()
                     for c in cls_cves if c not in dev_cves]
        rng.shuffle(remaining)
        dev_cves.extend(remaining[:DEV_SIZE - len(dev_cves)])

    dev_set = set(dev_cves)
    test_cves = [c for cls_cves in by_class.values()
                 for c in cls_cves if c not in dev_set]

    dev_cves.sort()
    test_cves.sort()

    dev_path = OUTPUT_DIR / "dev_cves.json"
    test_path = OUTPUT_DIR / "test_cves.json"

    json.dump(dev_cves, open(dev_path, "w"), indent=2)
    json.dump(test_cves, open(test_path, "w"), indent=2)

    print(f"Dev:  {len(dev_cves)} CVEs -> {dev_path}")
    print(f"Test: {len(test_cves)} CVEs -> {test_path}")

    print("\nDev class distribution:")
    for cls in sorted(by_class):
        n = sum(1 for c in dev_cves if c in by_class[cls])
        print(f"  {cls}: {n}/{len(by_class[cls])} "
              f"({n/len(dev_cves)*100:.0f}% dev, "
              f"{len(by_class[cls])/total*100:.0f}% full)")


if __name__ == "__main__":
    main()
