#!/usr/bin/env python3
"""Deployed DR / FPR with the fixed template (isolating the fix): re-render each
rule from the SAME stored analysis (status==success only), apply is_degenerate, and
measure firing. Conservative (coverage from the old run). PARALLEL over all
cohort x seed x spec via threads (run_suricata is --runmode single, so safe)."""
import json, glob, os, re, tempfile, sys
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
sys.path.insert(0, "/workspace")
from src.evaluation.pcap_generator import generate_attack_pcap
from src.evaluation.suricata_runner import run_suricata
from src.hypothesis.agents.rule_agent import RuleGenAgent
from src.hypothesis.rule_template import assemble_rule
from src.hypothesis.rule_postprocess import is_degenerate
try:
    from src.hypothesis.rmin_translator import _pattern_label, PATTERN_PCRE
except Exception:
    _pattern_label = lambda *a, **k: None
    PATTERN_PCRE = {}

WORKERS = int(os.environ.get("WORKERS", "32"))


def fires(req, rule):
    """Return (fired, err). Detects silent TmThreadSpawn deflation (Suricata rc=1
    with missing eve.json) via stderr and retries, so ulimit pressure cannot be
    miscounted as a non-firing rule."""
    if not rule:
        return False, 0
    if not re.search(r"sid:\s*\d+", rule):
        rule = rule.rstrip(")") + " sid:9900007; rev:1;)"
    for _attempt in range(4):
        try:
            with tempfile.TemporaryDirectory() as t:
                rp = os.path.join(t, "r.rules"); open(rp, "w").write(rule + "\n")
                pc = os.path.join(t, "a.pcap"); generate_attack_pcap(req, pc)
                ld = os.path.join(t, "log")
                sr = run_suricata(pc, rp, ld)
                if sr.get("error"):
                    continue  # timeout/not-found: retry
                serr = os.path.join(ld, "suricata_stderr.txt")
                if os.path.exists(serr):
                    txt = open(serr, encoding="utf-8", errors="replace").read()
                    if "thread spawn failed" in txt or "TmThreadSpawn" in txt:
                        continue  # spawn failure deflates silently: retry
                return bool(sr.get("triggered")), 0
        except Exception:
            continue
    return False, 1  # all retries exhausted: genuine error (flagged)


def build_rule(req, analysis, cve):
    av = RuleGenAgent._extract_attack_value(req, analysis)
    label = _pattern_label(av, analysis) if av else None
    pcre = PATTERN_PCRE.get(label, "") if label else ""
    spec = RuleGenAgent._build_spec_from_analysis(analysis, req, pcre)
    return assemble_rule(spec, cve, req.get("method", "GET"), "", sid_range=(9000001, 9999999))


def process(task):
    cohort, seed, f = task
    r = json.load(open(f))
    old = (r.get("suricata_rule") or "").strip()
    req = r.get("http_request") or {}
    res = dict(old_fired=0, success=0, nondegen=0, new_fired=0, err=0)
    if old and not old.startswith("#") and req:
        of, e = fires(req, old); res["old_fired"] = int(of); res["err"] += e
    if r.get("status") == "success" and req:
        res["success"] = 1
        hyp = (r.get("verified_hypothesis") or r.get("interpreted_hypothesis") or {})
        if not hyp.get("dangerous_param") and r.get("identified_param"):
            hyp = dict(hyp); hyp["dangerous_param"] = r["identified_param"]
        try:
            rule = build_rule(req, {"attack_hypothesis": hyp}, os.path.basename(f)[:-5])
        except Exception:
            rule = None
        if rule and not is_degenerate(rule):
            res["nondegen"] = 1
            nf, e = fires(req, rule); res["new_fired"] = int(nf); res["err"] += e
    return (cohort, seed), res


COHORTS = [
    ("attackDR", "output/ablation/bh4b_atk", "CVE-"),
    ("FPR-CVE", "output/ablation/bh4b_cve", "BENIGN-"),
    ("FPR-UNSW", "output/ablation/bh4b_unsw", "BENIGN-"),
]
tasks = []
totals = {}
for label, base, prefix in COHORTS:
    for s in ("42", "123", "456"):
        d = os.path.join(base, "seed_" + s)
        if not os.path.isdir(d):
            d = base
        files = sorted(glob.glob(os.path.join(d, prefix + "*.json"))) if os.path.isdir(d) else []
        totals[(label, s)] = len(files)
        for f in files:
            tasks.append((label, s, f))

print(f"=== Deployed re-measure (FIXED template) | {len(tasks)} specs, {WORKERS} workers ===", flush=True)
agg = defaultdict(lambda: defaultdict(int))
with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    for key, res in ex.map(process, tasks):
        for k, v in res.items():
            agg[key][k] += v

for (label, s), tot in totals.items():
    if not tot:
        continue
    a = agg[(label, s)]
    print(f"{label} seed_{s}: NEW {a['new_fired']}/{tot} = {a['new_fired']/tot*100:.1f}%   "
          f"OLD {a['old_fired']}/{tot} = {a['old_fired']/tot*100:.1f}%   "
          f"(success={a['success']} nondegen={a['nondegen']} err={a['err']})", flush=True)
print("DONE remeasure", flush=True)
