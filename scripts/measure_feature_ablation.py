#!/usr/bin/env python3
"""Firing-layer feature ablation on the complete 281x3 corpus (no GPU).

For one atk seed dir, measure attack DR (rule fires on its own attack / 281)
under feature removals that can be reconstructed deterministically post-synthesis:

  full          : the corpus rule as stored (all features on)
  -fallback     : drop rules emitted only by the fallback path
                  (artifact_status == 'fallback'); they would not exist without it
  -traversal-fix: re-add the OLD phantom '../' marker on http.uri.raw for
                  path_traversal cases (the pre-fix behavior). On body traversal
                  the URI has no '../', so the marker re-breaks the rule.

multipart is NOT reconstructable post-synthesis (it changes buffer assignment
during synthesis); this script only COUNTS multipart-bodied attack cases so the
cost of a -multipart re-synthesis can be judged.

Usage: measure_feature_ablation.py <atk_seed_dir>
Run inside cegis-ids container, PYTHONPATH=/workspace.
"""
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, "/workspace")
from src.evaluation.pcap_generator import generate_attack_pcap
from src.evaluation.suricata_runner import run_suricata
from src.hypothesis.rmin_translator import _pattern_label

D = sys.argv[1]


def fire(rule, req):
    if not rule or rule.startswith("#"):
        return False
    if not re.search(r"sid:\s*\d+", rule):
        rule = rule.rstrip(")") + " sid:9900002; rev:1;)"
    with tempfile.TemporaryDirectory() as t:
        rp = os.path.join(t, "r.rules")
        open(rp, "w").write(rule + "\n")
        pc = os.path.join(t, "b.pcap")
        generate_attack_pcap(req, pc)
        sr = run_suricata(pc, rp, os.path.join(t, "log"))
    return (not sr.get("error")) and bool(sr.get("triggered"))


def add_phantom_traversal(rule):
    """Replicate the pre-fix behavior: append a http.uri.raw content:"../" guard."""
    i = rule.rfind(")")
    if i < 0:
        return rule
    return rule[:i] + ' http.uri.raw; content:"../";' + rule[i:]


def attack_value_of(r):
    an = r.get("final_analysis") or r.get("interpreted_analysis") or {}
    hyp = (an.get("attack_hypothesis") or {}) if isinstance(an, dict) else {}
    return r.get("attack_value") or hyp.get("payload") or ""


N = 281
full = nofb = notrav = 0
mp_cases = []
total = 0
for f in sorted(os.listdir(D)):
    if not f.startswith("CVE") or not f.endswith(".json"):
        continue
    total += 1
    r = json.load(open(os.path.join(D, f)))
    cid = r.get("case_id") or f[:-5]
    rule = (r.get("suricata_rule") or "").strip()
    req = r.get("http_request") or {}
    # multipart accounting
    ct = ((req.get("headers") or {}).get("Content-Type")
          or (req.get("headers") or {}).get("content-type") or "")
    if "multipart" in str(ct).lower():
        mp_cases.append(cid)
    fired = fire(rule, req)
    if fired:
        full += 1
    # -fallback: this rule would not exist without fallback
    is_fb = (r.get("artifact_status") == "fallback"
             or r.get("verification_status") == "fallback_param_none")
    if fired and not is_fb:
        nofb += 1
    # -traversal-fix: re-add phantom marker for path_traversal labelled cases
    if fired:
        try:
            label = _pattern_label(attack_value_of(r), r.get("final_analysis") or {})
        except Exception:
            label = None
        if label == "path_traversal":
            if fire(add_phantom_traversal(rule), req):
                notrav += 1  # still fires (URI traversal) → fix not responsible
            # else: re-breaks → traversal-fix WAS responsible, drop from notrav
        else:
            notrav += 1  # not a traversal case, unaffected

print(f"DIR {D}  total={total}")
print(f"  full            DR = {full}/{N} = {full/N*100:.1f}%")
print(f"  -fallback       DR = {nofb}/{N} = {nofb/N*100:.1f}%  (dropped {full-nofb} fallback fires)")
print(f"  -traversal-fix  DR = {notrav}/{N} = {notrav/N*100:.1f}%  (lost {full-notrav} traversal recoveries)")
print(f"  multipart attack cases = {len(mp_cases)}: {mp_cases}")
