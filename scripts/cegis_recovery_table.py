#!/usr/bin/env python3
"""Per-iteration CEGIS recovery table. For each case in the deployed corpus (3 seeds),
read success_iteration = the CEGIS iteration at which its detection condition first
passed verification (attack True AND benign False). Aggregate into a histogram so the
marginal 'save' of each iteration beyond the first is explicit. Numbers auto-read.
Usage: cegis_recovery_table.py [corpus_dir]  (default output/nollm_pathx)"""
import json, glob, sys
from collections import Counter

CORPUS = sys.argv[1] if len(sys.argv) > 1 else "output/nollm_pathx"
SEEDS = (42, 123, 456)

hist = Counter()
exhausted = 0
total = 0
for s in SEEDS:
    for f in sorted(glob.glob(f"{CORPUS}/seed_{s}/CVE-*.json")):
        d = json.load(open(f))
        total += 1
        if d.get("status") == "success":
            si = d.get("success_iteration")
            hist[si if si is not None else "none"] += 1
        else:
            exhausted += 1

succ = sum(hist.values())
print(f"corpus={CORPUS}  3-seed total={total}")
print(f"{'CEGIS iter':<12}{'success':>8}{'cumulative':>12}{'cum DR':>9}{'saved here':>12}")
cum = 0
keys = sorted(hist, key=lambda x: (not isinstance(x, int), x))
for k in keys:
    cum += hist[k]
    saved = hist[k] if (isinstance(k, int) and k > 0) else 0
    label = f"iter {k}" if isinstance(k, int) else str(k)
    print(f"{label:<12}{hist[k]:>8}{cum:>12}{100*cum/total:>8.1f}%{('+'+str(saved)) if saved else '-':>12}")
print(f"{'exhausted':<12}{exhausted:>8}{'':>12}{'':>9}{'(lost)':>12}")
print(f"\ntotal success = {succ}/{total} = {100*succ/total:.1f}%   exhausted = {exhausted} = {100*exhausted/total:.1f}%")

iter0 = hist.get(0, 0)
saved = succ - iter0
print(f"first-try (iter 0)              : {iter0}/{total} = {100*iter0/total:.1f}%")
print(f"saved by CEGIS iteration (>=1)  : {saved}/{total} = +{100*saved/total:.1f}pp")
denom = total - iter0
print(f"recovery rate = saved / not-first-try = {saved}/{denom} = {100*saved/denom:.1f}%")

# markdown horizontal bars. iter 0-9 = main CEGIS loop (--max-iterations 10). Cases
# with success_iteration >= 10 are NOT extra main-loop rounds: they are the alt-
# hypothesis phase (phase=alt) that runs after the main loop exhausts, so they are
# grouped and labelled "alt-phase" (the §5 -alt-phase mechanism). 'none' = success
# with no recorded iteration; folded into alt-phase.
print("\n--- markdown cumulative bars (paste into doc) ---")
def barp(pct):
    return "█" * round(pct / 2)  # 1 block = 2pp; bar grows with cumulative synthesis success
altphase = sum(v for k, v in hist.items() if isinstance(k, int) and k >= 10) + hist.get("none", 0)
cum = 0
rows = []
for k in range(10):
    c = hist.get(k, 0)
    if not c:
        continue
    cum += c
    rows.append((f"iter {k}", c, 100 * cum / total, k == 0))
cum += altphase
rows.append(("alt-phase", altphase, 100 * cum / total, False))
for lbl, c, pct, first in rows:
    note = f"first {c}" if first else f"+{c}"
    line = f"{lbl:<10} {barp(pct)} {pct:.1f}%"
    print(f"{line:<54} ({note})")
print(f"exhausted  {exhausted} ({100*exhausted/total:.1f}%) never reach a passing condition")
