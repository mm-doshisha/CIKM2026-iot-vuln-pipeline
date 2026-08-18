#!/usr/bin/env python3
"""Build the variant-DR table (non-circular detection robustness): each variant is a
mutation the rule was NOT built from, so firing on it measures generalization rather
than the circular self-pcap yield. before=enctest_pathx (deployed literal ruleset,
nollm_pathx), after=enctest_trav (mechanism-pcre; only encoded_traversal changes).
Numbers are read from the eval reports' per_cve.variants — never hand-typed."""
import json
from collections import defaultdict

SEEDS = (42, 123, 456)
VARIANTS = ("deeper_traversal", "reordered", "urlencoded", "encoded_traversal")
LABEL = {
    "deeper_traversal": "deeper_traversal (deeper ../)",
    "reordered":        "reordered (param order)",
    "urlencoded":       "urlencoded (param VALUE %-enc)",
    "encoded_traversal":"encoded_traversal (PATH %-enc)",
}


def counts(tag, seed):
    p = f"output/suricata_eval/{tag}/seed_{seed}/suricata_eval_report.json"
    r = json.load(open(p))
    det = defaultdict(int); tot = defaultdict(int)
    for _cve, d in (r.get("per_cve") or {}).items():
        for vt, hit in (d.get("variants") or {}).items():
            tot[vt] += 1
            det[vt] += 1 if hit else 0
    return det, tot


def table(tag, title):
    print(f"\n### {title}  ({tag})")
    rows = {s: counts(tag, s) for s in SEEDS}
    pdet = defaultdict(int); ptot = defaultdict(int)
    hdr = "| variant | " + " | ".join(f"s{s}" for s in SEEDS) + " | pooled |"
    print(hdr)
    print("|" + "---|" * (len(SEEDS) + 2))
    for vt in VARIANTS:
        cells = []
        for s in SEEDS:
            det, tot = rows[s]
            cells.append(f"{det[vt]}/{tot[vt]}")
            pdet[vt] += det[vt]; ptot[vt] += tot[vt]
        pooled = (f"{pdet[vt]}/{ptot[vt]} = {100*pdet[vt]/ptot[vt]:.1f}%"
                  if ptot[vt] else "n/a")
        print(f"| {LABEL[vt]} | " + " | ".join(cells) + f" | {pooled} |")


table("enctest_pathx", "BEFORE — deployed literal ruleset")
table("enctest_trav", "AFTER — mechanism pcre (A, only encoded_traversal changes)")
