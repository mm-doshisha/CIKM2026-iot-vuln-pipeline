#!/usr/bin/env python3
"""Compare before/after traversal-variant DR + cross-fire FPR across 3 seeds.

Usage: extract_trav_eval.py <before_tag> <after_tag>
  e.g. extract_trav_eval.py enctest_pathx enctest_trav
Reads output/suricata_eval/<tag>/seed_{42,123,456}/suricata_eval_report.json.
Reports encoded_traversal (the new metric) with explicit detected/total counted
from per_cve, plus the guard variants and cross-fire FPR.
"""
import json, sys

SEEDS = (42, 123, 456)
GUARDS = ("urlencoded", "deeper_traversal", "reordered")


def load(tag, s):
    p = "output/suricata_eval/{}/seed_{}/suricata_eval_report.json".format(tag, s)
    try:
        return json.load(open(p))
    except Exception:
        return None


def rate(agg, key):
    vdr = agg.get("variant_detection_rates", {})
    v = vdr.get(key)
    return None if v is None else float(v)


def encoded_counts(report):
    """Count encoded_traversal detected/total from per_cve (rate alone hides N)."""
    det = tot = 0
    for cve, d in (report.get("per_cve") or {}).items():
        v = (d.get("variants") or {})
        if "encoded_traversal" in v:
            tot += 1
            if v["encoded_traversal"]:
                det += 1
    return det, tot


def show(tag):
    print("--- {} ---".format(tag))
    for s in SEEDS:
        r = load(tag, s)
        if not r:
            print("  seed_{}: MISSING".format(s)); continue
        agg = r.get("aggregate", {})
        det, tot = encoded_counts(r)
        enc_r = rate(agg, "encoded_traversal")
        enc_str = "{}/{} ({:.1%})".format(det, tot, enc_r) if enc_r is not None else "ABSENT"
        guards = " ".join(
            "{}={}".format(g, ("{:.1%}".format(rate(agg, g)) if rate(agg, g) is not None else "-"))
            for g in GUARDS)
        print("  seed_{}: encoded_traversal={}  {}  crossfire={}/{}  tpr={:.3f} total={}".format(
            s, enc_str, guards,
            agg.get("real_benign_fp", "?"), agg.get("real_benign_total", "?"),
            agg.get("tpr", 0), agg.get("total", "?")))


if __name__ == "__main__":
    before = sys.argv[1] if len(sys.argv) > 1 else "enctest_pathx"
    after = sys.argv[2] if len(sys.argv) > 2 else "enctest_trav"
    print("=== BEFORE (literal-path rules) ===")
    show(before)
    print("=== AFTER (mechanism-pcre rules) ===")
    show(after)
