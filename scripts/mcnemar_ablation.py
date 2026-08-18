#!/usr/bin/env python3
"""McNemar test for the §5 feature ablation (ablation_v2), per-CVE attack_detected.

Pairs each of the 281x3 = 843 (seed, CVE) cells between the completed-form base
(ablv2_base) and each ablation condition. A CVE absent from a report's per_cve
means no rule was deployed = not detected (False), so the test captures the
COVERAGE effect (the real ablation effect), not merely firing-given-a-rule.
Intersecting only rule-bearing CVEs would hide exactly the cells where base made
a rule and the ablation did not -- which is where the DR difference lives.

Statistics: two-sided exact binomial McNemar (gold standard) plus a
continuity-corrected chi-square (df=1) for reference. Reports the raw p and
whether it survives Bonferroni correction for the number of conditions tested.

Run from the repository root (where output/suricata_eval/ablv2_* live):
  python3 scripts/mcnemar_ablation.py
"""
import json, glob
from math import comb, erfc, sqrt

GT = "benchmarks/ground_truth.json"
SEEDS = ("42", "123", "456")
BASE = "ablv2_base"
# (label, eval-dir under output/suricata_eval/, seeds). 全条件 3 seed。テンプレート(tmpl)
# の s456 は 2026-06-03 に再合成して 279/281 まで完走した(残2=CVE-2024-55591・
# CVE-2020-3161 が ABLATE_TEMPLATE 経路で rule 検証後にハングする難 AuthBypass=原 stall の
# 原因)。残2は合成不能=非検出として扱う(2/843 で影響は無視できる)。
CONDS = [
    ("反復(iter)", "ablv2_iter", SEEDS),
    ("エージェント(agent)", "ablv2_agent", SEEDS),
    ("方針決定(direct)", "ablv2_direct", SEEDS),
    ("テンプレート(tmpl)", "ablv2_tmpl", SEEDS),
    ("メモリ(mem)", "ablv2_mem", SEEDS),
    ("検証SV(sv)", "ablv2_sv", SEEDS),
    ("fallback(nofb)", "ablv2_nofb", SEEDS),
    ("alt-phase(aphase)", "ablv2_aphase", SEEDS),
]


def cve_universe():
    gt = json.load(open(GT))
    if isinstance(gt, dict):
        return list(gt.keys())
    return [(x.get("cve_id") or x.get("cve") or x.get("id")) for x in gt]


def fires_full(cond, cves, seeds=SEEDS):
    """(seed, cve) -> attack_detected over the given seeds; absent (no rule) -> False."""
    d = {(s, c): False for s in seeds for c in cves}
    for s in seeds:
        f = f"output/suricata_eval/{cond}/seed_{s}/suricata_eval_report.json"
        try:
            r = json.load(open(f))
        except FileNotFoundError:
            continue
        for cve, e in (r.get("per_cve") or {}).items():
            if (s, cve) in d:
                d[(s, cve)] = bool(e.get("attack_detected"))
    return d


def mcnemar(A, B):
    keys = [k for k in A if k in B]
    b = sum(1 for k in keys if A[k] and not B[k])
    c = sum(1 for k in keys if B[k] and not A[k])
    n = b + c
    nA = sum(A[k] for k in keys)
    nB = sum(B[k] for k in keys)
    if n == 0:
        return len(keys), nA, nB, 0, 0, 0.0, 1.0, 1.0
    tail = sum(comb(n, k) for k in range(min(b, c) + 1)) * (0.5 ** n)
    chi2 = ((abs(b - c) - 1) ** 2) / n
    return len(keys), nA, nB, b, c, chi2, erfc(sqrt(chi2 / 2)), min(1.0, 2 * tail)


def main():
    cves = cve_universe()
    m = len(CONDS)
    alpha = 0.05 / m
    print(f"# McNemar vs {BASE}, Bonferroni m={m}, alpha'={alpha:.4f}  "
          f"(no-rule=not-detected; tmpl の s456 は 279/281, 残2 AuthBypass は非検出扱い)")
    print(f"{'condition':<22} {'N':>5} {'base+':>6} {'X+':>6} {'b':>5} {'c':>5} "
          f"{'chi2cc':>8} {'p_exact':>11}  sig(raw/Bonf)")
    for label, tag, seeds in CONDS:
        base = fires_full(BASE, cves, seeds)
        n, nA, nB, b, c, chi2, _pchi, pe = mcnemar(base, fires_full(tag, cves, seeds))
        sig = ("yes" if pe < 0.05 else "no") + "/" + ("yes" if pe < alpha else "no")
        print(f"{label:<22} {n:>5} {nA:>6} {nB:>6} {b:>5} {c:>5} {chi2:>8.1f} {pe:>11.2e}  {sig}")


if __name__ == "__main__":
    main()
