#!/usr/bin/env python3
"""Build a DEV-only benign trace dir for fair baseline filtering: copy traces from
benchmarks/traces_benign_full whose request signature is NOT in the evaluation set
(benchmarks/traces_benign). This is the same dev/eval signature split that
extract_benign_values.py uses for the proposed method's filter, so baselines
(CMIRGen/AutoCombo) can filter against a held-out benign set disjoint from the
FPR-evaluation set — removing the train/test leakage of --benign-dir=traces_benign.

Usage: make_dev_benign.py  (writes benchmarks/traces_benign_dev/)
"""
import json, os, shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / "benchmarks" / "traces_benign_full"
EVAL = ROOT / "benchmarks" / "traces_benign"
OUT = ROOT / "benchmarks" / "traces_benign_dev"


def sig(trace):
    r = (trace.get("trace") or {}).get("request") or {}
    params = r.get("params") or {}
    if isinstance(params, dict):
        pj = ";".join(sorted(f"{k}={v}" for k, v in params.items()))
    else:
        pj = str(params)
    return (r.get("method"), r.get("path"), pj)


eval_sigs = set()
for f in EVAL.glob("*.json"):
    try:
        eval_sigs.add(sig(json.loads(f.read_text(encoding="utf-8"))))
    except Exception:
        pass
print(f"eval signatures: {len(eval_sigs)} (from {len(list(EVAL.glob('*.json')))} eval traces)")

OUT.mkdir(parents=True, exist_ok=True)
kept = dropped = 0
for f in sorted(FULL.glob("BENIGN-*.json")):
    try:
        t = json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        continue
    if sig(t) in eval_sigs:
        dropped += 1
        continue
    shutil.copy2(f, OUT / f.name)
    kept += 1
print(f"dev-only benign written: {kept} kept, {dropped} dropped (overlap with eval) -> {OUT}")
