#!/usr/bin/env python3
"""Pooled variant-DR per method, read from existing eval reports' per_cve.variants.
Lets the §3e robustness table gain baseline columns (same metric, fair comparison).
Variant-DR must be read WITH cross-fire FPR (broad rules trade FPR for robustness)."""
import json, glob, os
from collections import defaultdict

# (label, eval-dir under output/suricata_eval/) — proposed + the §3d baselines
METHODS = [
    ("proposed", "enctest_pathx"),
    ("RuleXploit", "rulexploit"),
    ("GRIDAI", "b1_gridai"),
    ("GRIDAI", "g1_gridai"),
    ("CMIRGen", "cmirgen"),
    ("AutoCombo", "autocombo"),
    ("Moreno", "moreno"),
    ("Moreno", "m1_moreno"),
    # Syrius is excluded from the numeric comparison set (§3b/§11, qualitative only).
]
VARIANTS = ("reordered", "deeper_traversal", "urlencoded", "encoded_traversal")


def pooled(tag):
    det = defaultdict(int); tot = defaultdict(int); seeds = 0
    fpr_fp = fpr_tot = 0
    for f in sorted(glob.glob(f"output/suricata_eval/{tag}/seed_*/suricata_eval_report.json")):
        r = json.load(open(f)); seeds += 1
        a = r.get("aggregate", {})
        fpr_fp += a.get("real_benign_fp", 0) or 0
        fpr_tot += a.get("real_benign_total", 0) or 0
        for _cve, d in (r.get("per_cve") or {}).items():
            for vt, hit in (d.get("variants") or {}).items():
                tot[vt] += 1; det[vt] += 1 if hit else 0
    return det, tot, seeds, fpr_fp, fpr_tot


seen = set()
print(f"{'method':<11} | " + " | ".join(f"{v[:13]:<13}" for v in VARIANTS) + " | cross-fire FPR | seeds")
print("-" * 100)
for label, tag in METHODS:
    if not os.path.isdir(f"output/suricata_eval/{tag}"):
        continue
    if label in seen:
        continue
    det, tot, seeds, fp, ft = pooled(tag)
    if seeds == 0:
        continue
    seen.add(label)
    cells = []
    for vt in VARIANTS:
        if tot[vt]:
            cells.append(f"{det[vt]}/{tot[vt]}={100*det[vt]/tot[vt]:.0f}%".ljust(13))
        else:
            cells.append("-".ljust(13))
    fpr = f"{fp}/{ft}={100*fp/ft:.1f}%" if ft else "-"
    print(f"{label:<11} | " + " | ".join(cells) + f" | {fpr:<13} | {seeds} ({tag})")
