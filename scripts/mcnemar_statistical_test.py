#!/usr/bin/env python3
"""
McNemar's test for pairwise statistical significance of CEGIS-IDS conditions.

Computes:
  1. Pipeline DR (Detection Rate): per-CVE success/fail from CVE-*.json status field
  2. Suricata TPR: per-CVE attack_detected from suricata_eval_report.json
  3. McNemar's exact test (binomial) for small discordant counts, chi-squared otherwise
  4. 2x2 contingency tables (both success, A4 only, other only, both fail)
  5. Cohen's kappa and odds ratio as effect size measures
  6. Bonferroni correction for multiple comparisons
  7. Per-seed results + aggregated across seeds

Usage:
    python3 scripts/mcnemar_statistical_test.py --base-dir .

Usage (local, if data is copied):
    python3 scripts/mcnemar_statistical_test.py --base-dir .
"""

import argparse
import json
import math
import sys
from pathlib import Path
from collections import defaultdict

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SEEDS = [42, 123, 456]

# Condition directory names in output/
CONDITIONS = {
    "A4": "a4_proposed",
    "A2": "a2_stateless",
    "A3": "a3_reflexion",
    "A1": "a1_oneshot",
    "B1": "b1_direct_llm",
    "E2a": "e2a_no_agent",
}

# Pairs to compare (A4 vs each)
PAIRS = [
    ("A4", "A2", "構造化メモリの効果"),
    ("A4", "A3", "構造化 vs 自然言語リフレクション"),
    ("A4", "A1", "CEGIS反復の効果"),
    ("A4", "E2a", "エージェントの効果"),
    ("A4", "B1", "CEGIS検証の効果"),
]

N_COMPARISONS = len(PAIRS)  # For Bonferroni correction


# ---------------------------------------------------------------------------
# Helper: load individual CVE results
# ---------------------------------------------------------------------------

def load_dr_results(base_dir: Path, condition: str, seed: int) -> dict:
    """Load DR (pipeline success/fail) per CVE.
    Returns {cve_id: bool} where True = success.
    """
    seed_dir = base_dir / "output" / condition / f"seed_{seed}"
    if not seed_dir.exists():
        print(f"  [WARN] Missing DR dir: {seed_dir}", file=sys.stderr)
        return {}

    results = {}
    for jf in sorted(seed_dir.glob("CVE-*.json")):
        try:
            with open(jf) as f:
                data = json.load(f)
            cve_id = data.get("case_id", jf.stem)
            status = data.get("status", "failed")
            results[cve_id] = (status == "success")
        except Exception as e:
            print(f"  [WARN] Could not parse {jf}: {e}", file=sys.stderr)
    return results


def load_suricata_results(base_dir: Path, condition: str, seed: int) -> dict:
    """Load Suricata TPR (attack_detected) per CVE.
    Returns {cve_id: bool} where True = detected.
    """
    # Try suricata_eval/ first (post-fix re-evaluation output)
    eval_dir = base_dir / "output" / "suricata_eval" / condition / f"seed_{seed}"
    report_path = eval_dir / "suricata_eval_report.json"

    if not report_path.exists():
        # Fallback: eval/ subdirectory (older eval runs)
        eval_dir = base_dir / "output" / "eval" / condition / f"seed_{seed}"
        report_path = eval_dir / "suricata_eval_report.json"

    if not report_path.exists():
        eval_dir = base_dir / "result_data" / "hpc_eval" / condition / f"seed_{seed}"
        report_path = eval_dir / "suricata_eval_report.json"

    if not report_path.exists():
        eval_dir = base_dir / "result_data" / "eval_suricata" / condition / f"seed_{seed}"
        report_path = eval_dir / "suricata_eval_report.json"

    if not report_path.exists():
        print(f"  [WARN] Missing Suricata report: tried multiple paths for {condition}/seed_{seed}", file=sys.stderr)
        return {}

    try:
        with open(report_path) as f:
            data = json.load(f)
        per_cve = data.get("per_cve", {})
        return {cve: info["attack_detected"] for cve, info in per_cve.items()}
    except Exception as e:
        print(f"  [WARN] Could not parse {report_path}: {e}", file=sys.stderr)
        return {}


def load_suricata_fpr_results(base_dir: Path, condition: str, seed: int) -> dict:
    """Load Suricata FPR (benign_clean) per CVE.
    Returns {cve_id: bool} where True = false positive (benign NOT clean).
    """
    eval_dir = base_dir / "output" / "suricata_eval" / condition / f"seed_{seed}"
    report_path = eval_dir / "suricata_eval_report.json"

    if not report_path.exists():
        eval_dir = base_dir / "output" / "eval" / condition / f"seed_{seed}"
        report_path = eval_dir / "suricata_eval_report.json"

    if not report_path.exists():
        eval_dir = base_dir / "result_data" / "hpc_eval" / condition / f"seed_{seed}"
        report_path = eval_dir / "suricata_eval_report.json"

    if not report_path.exists():
        eval_dir = base_dir / "result_data" / "eval_suricata" / condition / f"seed_{seed}"
        report_path = eval_dir / "suricata_eval_report.json"

    if not report_path.exists():
        return {}

    try:
        with open(report_path) as f:
            data = json.load(f)
        per_cve = data.get("per_cve", {})
        return {cve: not info.get("benign_clean", True) for cve, info in per_cve.items()}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# McNemar's test (exact binomial for small n, chi-squared otherwise)
# ---------------------------------------------------------------------------

def _binom_cdf(k, n, p=0.5):
    """Cumulative binomial probability P(X <= k) for X ~ Binom(n, p)."""
    total = 0.0
    for i in range(k + 1):
        total += math.comb(n, i) * (p ** i) * ((1 - p) ** (n - i))
    return total


def mcnemar_exact(b, c):
    """Exact McNemar's test (two-sided) using binomial distribution.
    b = discordant pair count (A4 success, other fail)
    c = discordant pair count (A4 fail, other success)
    Returns p-value.
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    # Two-sided p-value: 2 * P(X <= k) where X ~ Binom(n, 0.5)
    p = 2.0 * _binom_cdf(k, n, 0.5)
    return min(p, 1.0)


def mcnemar_chi2(b, c):
    """McNemar's chi-squared test (with continuity correction).
    Returns (chi2, p_value).
    """
    n = b + c
    if n == 0:
        return 0.0, 1.0
    # With continuity correction
    chi2 = (abs(b - c) - 1) ** 2 / n if n > 0 else 0.0

    # p-value from chi-squared distribution with 1 df
    # Using survival function approximation
    p = chi2_sf(chi2, 1)
    return chi2, p


def chi2_sf(x, df=1):
    """Survival function (1 - CDF) of chi-squared distribution.
    Simple numerical approximation for df=1.
    """
    if x <= 0:
        return 1.0
    # For df=1: chi2 CDF = 2*Phi(sqrt(x)) - 1, so SF = 2*(1-Phi(sqrt(x)))
    z = math.sqrt(x)
    # Standard normal survival function approximation (Abramowitz & Stegun)
    return 2.0 * _norm_sf(z)


def _norm_sf(z):
    """Standard normal survival function approximation."""
    if z < 0:
        return 1.0 - _norm_sf(-z)
    # Abramowitz & Stegun formula 26.2.17
    p = 0.2316419
    b1 = 0.319381530
    b2 = -0.356563782
    b3 = 1.781477937
    b4 = -1.882496680
    b5 = 1.330274429
    t = 1.0 / (1.0 + p * z)
    phi = math.exp(-z * z / 2.0) / math.sqrt(2.0 * math.pi)
    return phi * (b1 * t + b2 * t**2 + b3 * t**3 + b4 * t**4 + b5 * t**5)


def mcnemar_test(b, c, threshold=25):
    """Run McNemar's test: exact if discordant pairs < threshold, chi2 otherwise.
    Returns (stat, p_value, method).
    """
    n = b + c
    if n < threshold:
        p = mcnemar_exact(b, c)
        return n, p, "exact_binomial"
    else:
        chi2, p = mcnemar_chi2(b, c)
        return chi2, p, "chi2_corrected"


# ---------------------------------------------------------------------------
# Cohen's kappa
# ---------------------------------------------------------------------------

def cohens_kappa(a, b, c, d):
    """Cohen's kappa from 2x2 table.
    a = both success, b = A4 only, c = other only, d = both fail.
    """
    n = a + b + c + d
    if n == 0:
        return 0.0
    po = (a + d) / n  # observed agreement
    pe = ((a + b) * (a + c) + (c + d) * (b + d)) / (n * n)  # expected agreement
    if pe == 1.0:
        return 1.0
    return (po - pe) / (1.0 - pe)


def odds_ratio(b, c):
    """Odds ratio for discordant pairs."""
    if c == 0:
        return float('inf') if b > 0 else 1.0
    return b / c


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def build_contingency(results_a4: dict, results_other: dict):
    """Build 2x2 contingency table from paired results.
    Only considers CVEs present in both conditions.
    Returns (a, b, c, d, common_cves):
      a = both success
      b = A4 success, other fail
      c = A4 fail, other success
      d = both fail
    """
    common = sorted(set(results_a4.keys()) & set(results_other.keys()))
    a = b = c = d = 0
    for cve in common:
        s_a4 = results_a4[cve]
        s_other = results_other[cve]
        if s_a4 and s_other:
            a += 1
        elif s_a4 and not s_other:
            b += 1
        elif not s_a4 and s_other:
            c += 1
        else:
            d += 1
    return a, b, c, d, common


def analyze_pair(name_a4, name_other, desc, dr_a4, dr_other,
                 sur_a4, sur_other, fpr_a4, fpr_other, seed):
    """Analyze one pair for one seed. Returns dict with results."""
    result = {
        "pair": f"{name_a4} vs {name_other}",
        "description": desc,
        "seed": seed,
    }

    # DR analysis
    if dr_a4 and dr_other:
        a, b, c, d, common = build_contingency(dr_a4, dr_other)
        n = len(common)
        stat, p, method = mcnemar_test(b, c)
        result["DR"] = {
            "n": n,
            "both_success": a,
            "a4_only": b,
            "other_only": c,
            "both_fail": d,
            "a4_rate": (a + b) / n if n > 0 else 0,
            "other_rate": (a + c) / n if n > 0 else 0,
            "mcnemar_stat": stat,
            "p_value": p,
            "method": method,
            "kappa": cohens_kappa(a, b, c, d),
            "odds_ratio": odds_ratio(b, c),
        }
    else:
        result["DR"] = None

    # Suricata TPR analysis
    if sur_a4 and sur_other:
        a, b, c, d, common = build_contingency(sur_a4, sur_other)
        n = len(common)
        stat, p, method = mcnemar_test(b, c)
        result["Suricata_TPR"] = {
            "n": n,
            "both_success": a,
            "a4_only": b,
            "other_only": c,
            "both_fail": d,
            "a4_rate": (a + b) / n if n > 0 else 0,
            "other_rate": (a + c) / n if n > 0 else 0,
            "mcnemar_stat": stat,
            "p_value": p,
            "method": method,
            "kappa": cohens_kappa(a, b, c, d),
            "odds_ratio": odds_ratio(b, c),
        }
    else:
        result["Suricata_TPR"] = None

    # Suricata FPR analysis (benign false positive per CVE)
    if fpr_a4 and fpr_other:
        a, b, c, d, common = build_contingency(fpr_a4, fpr_other)
        n = len(common)
        stat, p, method = mcnemar_test(b, c)
        result["Suricata_FPR"] = {
            "n": n,
            "both_fp": a,      # both have FP
            "a4_only_fp": b,   # only A4 has FP
            "other_only_fp": c, # only other has FP
            "both_clean": d,   # both clean
            "a4_fpr": (a + b) / n if n > 0 else 0,
            "other_fpr": (a + c) / n if n > 0 else 0,
            "mcnemar_stat": stat,
            "p_value": p,
            "method": method,
            "kappa": cohens_kappa(a, b, c, d),
            "odds_ratio": odds_ratio(b, c),
        }
    else:
        result["Suricata_FPR"] = None

    return result


def format_p(p, bonferroni_p=None):
    """Format p-value with significance stars."""
    stars = ""
    if p < 0.001:
        stars = "***"
    elif p < 0.01:
        stars = "**"
    elif p < 0.05:
        stars = "*"
    bonf = ""
    if bonferroni_p is not None:
        bonf = f" (Bonf: {bonferroni_p:.4f}{'*' if bonferroni_p < 0.05 else ''})"
    return f"{p:.4f}{stars}{bonf}"


def print_results(all_results):
    """Print formatted results."""

    print("=" * 90)
    print("McNemar検定: CEGIS-IDSパイプライン ペアワイズ統計的有意差検定")
    print("=" * 90)
    print()

    # Group by pair
    by_pair = defaultdict(list)
    for r in all_results:
        by_pair[r["pair"]].append(r)

    for pair_name, pair_results in by_pair.items():
        desc = pair_results[0]["description"]
        print(f"\n{'─' * 90}")
        print(f"■ {pair_name} ({desc})")
        print(f"{'─' * 90}")

        # ----- DR -----
        print(f"\n  ▶ パイプライン検出率 (DR)")
        has_dr = any(r["DR"] is not None for r in pair_results)
        if not has_dr:
            print(f"    データなし")
        else:
            print(f"    {'Seed':>6}  {'N':>4}  {'両方成功':>8}  {'A4のみ':>6}  {'他のみ':>6}  {'両方失敗':>8}  "
                  f"{'A4 DR':>7}  {'他 DR':>7}  {'p値':>12}  {'方法':>16}  {'κ':>6}  {'OR':>6}")
            print(f"    {'─' * 110}")

            p_values_dr = []
            for r in sorted(pair_results, key=lambda x: x["seed"]):
                dr = r["DR"]
                if dr is None:
                    print(f"    {r['seed']:>6}  データなし")
                    continue
                bonf_p = min(dr["p_value"] * N_COMPARISONS, 1.0)
                p_values_dr.append(dr["p_value"])
                or_str = f"{dr['odds_ratio']:.2f}" if dr['odds_ratio'] != float('inf') else "inf"
                print(f"    {r['seed']:>6}  {dr['n']:>4}  {dr['both_success']:>8}  {dr['a4_only']:>6}  "
                      f"{dr['other_only']:>6}  {dr['both_fail']:>8}  "
                      f"{dr['a4_rate']:>6.1%}  {dr['other_rate']:>6.1%}  "
                      f"{format_p(dr['p_value'], bonf_p):>20}  {dr['method']:>16}  "
                      f"{dr['kappa']:>6.3f}  {or_str:>6}")

            if len(p_values_dr) == 3:
                # Fisher's method to combine p-values across seeds
                combined = combine_pvalues_fisher(p_values_dr)
                print(f"\n    3 seed統合 (Fisher法): p = {format_p(combined, min(combined * N_COMPARISONS, 1.0))}")

        # ----- Suricata TPR -----
        print(f"\n  ▶ Suricata TPR")
        has_sur = any(r["Suricata_TPR"] is not None for r in pair_results)
        if not has_sur:
            print(f"    データなし")
        else:
            print(f"    {'Seed':>6}  {'N':>4}  {'両方検知':>8}  {'A4のみ':>6}  {'他のみ':>6}  {'両方未検知':>8}  "
                  f"{'A4 TPR':>7}  {'他 TPR':>7}  {'p値':>12}  {'方法':>16}  {'κ':>6}  {'OR':>6}")
            print(f"    {'─' * 110}")

            p_values_sur = []
            for r in sorted(pair_results, key=lambda x: x["seed"]):
                sur = r["Suricata_TPR"]
                if sur is None:
                    print(f"    {r['seed']:>6}  データなし")
                    continue
                bonf_p = min(sur["p_value"] * N_COMPARISONS, 1.0)
                p_values_sur.append(sur["p_value"])
                or_str = f"{sur['odds_ratio']:.2f}" if sur['odds_ratio'] != float('inf') else "inf"
                print(f"    {r['seed']:>6}  {sur['n']:>4}  {sur['both_success']:>8}  {sur['a4_only']:>6}  "
                      f"{sur['other_only']:>6}  {sur['both_fail']:>8}  "
                      f"{sur['a4_rate']:>6.1%}  {sur['other_rate']:>6.1%}  "
                      f"{format_p(sur['p_value'], bonf_p):>20}  {sur['method']:>16}  "
                      f"{sur['kappa']:>6.3f}  {or_str:>6}")

            if len(p_values_sur) >= 2:
                combined = combine_pvalues_fisher(p_values_sur)
                print(f"\n    {len(p_values_sur)} seed統合 (Fisher法): p = {format_p(combined, min(combined * N_COMPARISONS, 1.0))}")

        # ----- Suricata FPR -----
        print(f"\n  ▶ Suricata FPR (誤検知)")
        has_fpr = any(r.get("Suricata_FPR") is not None for r in pair_results)
        if not has_fpr:
            print(f"    データなし")
        else:
            print(f"    {'Seed':>6}  {'N':>4}  {'両方FP':>6}  {'A4のみFP':>8}  {'他のみFP':>8}  {'両方clean':>8}  "
                  f"{'A4 FPR':>7}  {'他 FPR':>7}  {'p値':>12}  {'方法':>16}")
            print(f"    {'─' * 110}")

            p_values_fpr = []
            for r in sorted(pair_results, key=lambda x: x["seed"]):
                fpr = r.get("Suricata_FPR")
                if fpr is None:
                    print(f"    {r['seed']:>6}  データなし")
                    continue
                bonf_p = min(fpr["p_value"] * N_COMPARISONS, 1.0)
                p_values_fpr.append(fpr["p_value"])
                print(f"    {r['seed']:>6}  {fpr['n']:>4}  {fpr['both_fp']:>6}  {fpr['a4_only_fp']:>8}  "
                      f"{fpr['other_only_fp']:>8}  {fpr['both_clean']:>8}  "
                      f"{fpr['a4_fpr']:>6.1%}  {fpr['other_fpr']:>6.1%}  "
                      f"{format_p(fpr['p_value'], bonf_p):>20}  {fpr['method']:>16}")

            if len(p_values_fpr) >= 2:
                combined = combine_pvalues_fisher(p_values_fpr)
                print(f"\n    {len(p_values_fpr)} seed統合 (Fisher法): p = {format_p(combined, min(combined * N_COMPARISONS, 1.0))}")

    # ----- Summary table -----
    print(f"\n\n{'=' * 90}")
    print("サマリーテーブル (Bonferroni補正後)")
    print(f"{'=' * 90}")
    print(f"\n{'比較ペア':<25}  {'指標':<12}  {'平均p値':>10}  {'Bonf.p値':>10}  {'有意?':>6}  "
          f"{'A4のみ平均':>10}  {'他のみ平均':>10}")
    print(f"{'─' * 100}")

    for pair_name, pair_results in by_pair.items():
        for metric_key, metric_label in [("DR", "DR"), ("Suricata_TPR", "Suricata TPR"), ("Suricata_FPR", "Suricata FPR")]:
            p_vals = []
            b_vals = []
            c_vals = []
            for r in pair_results:
                m = r.get(metric_key)
                if m is not None:
                    p_vals.append(m["p_value"])
                    b_key = "a4_only_fp" if metric_key == "Suricata_FPR" else "a4_only"
                    c_key = "other_only_fp" if metric_key == "Suricata_FPR" else "other_only"
                    b_vals.append(m[b_key])
                    c_vals.append(m[c_key])

            if not p_vals:
                continue

            avg_p = sum(p_vals) / len(p_vals)
            combined_p = combine_pvalues_fisher(p_vals) if len(p_vals) > 1 else p_vals[0]
            bonf_p = min(combined_p * N_COMPARISONS, 1.0)
            sig = "Yes" if bonf_p < 0.05 else "No"
            avg_b = sum(b_vals) / len(b_vals)
            avg_c = sum(c_vals) / len(c_vals)

            print(f"{pair_name:<25}  {metric_label:<12}  {combined_p:>10.4f}  {bonf_p:>10.4f}  {sig:>6}  "
                  f"{avg_b:>10.1f}  {avg_c:>10.1f}")


def combine_pvalues_fisher(p_values):
    """Fisher's method to combine independent p-values.
    Test statistic: -2 * sum(ln(p_i)) ~ chi2(2k).
    """
    if not p_values:
        return 1.0
    # Replace exact zeros to avoid log(0)
    p_values = [max(p, 1e-300) for p in p_values]
    k = len(p_values)
    stat = -2.0 * sum(math.log(p) for p in p_values)
    # chi2 survival function with df = 2*k
    return chi2_sf_general(stat, 2 * k)


def chi2_sf_general(x, df):
    """Chi-squared survival function for general df.
    Uses regularized incomplete gamma function approximation.
    """
    if x <= 0:
        return 1.0
    # For even df, exact formula
    if df % 2 == 0:
        return _chi2_sf_even(x, df)
    # For odd df, use Wilson-Hilferty approximation
    z = ((x / df) ** (1/3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    return _norm_sf(z)


def _chi2_sf_even(x, df):
    """Exact chi2 SF for even df using Poisson tail."""
    lam = x / 2.0
    k = df // 2
    # P(Poisson(lam) < k) = sum_{i=0}^{k-1} e^{-lam} * lam^i / i!
    total = 0.0
    term = math.exp(-lam)
    for i in range(k):
        total += term
        term *= lam / (i + 1)
    return total


def main():
    parser = argparse.ArgumentParser(description="McNemar統計検定 for CEGIS-IDS")
    parser.add_argument("--base-dir",
                        default=".",
                        help="Root of the repo")
    parser.add_argument("--json-output", default=None,
                        help="Optional: save raw results as JSON")
    args = parser.parse_args()

    base = Path(args.base_dir)
    print(f"Base directory: {base}", file=sys.stderr)

    all_results = []

    for seed in SEEDS:
        print(f"\n--- Loading seed {seed} ---", file=sys.stderr)

        # Load A4 data (always needed)
        dr_a4 = load_dr_results(base, CONDITIONS["A4"], seed)
        sur_a4 = load_suricata_results(base, CONDITIONS["A4"], seed)
        fpr_a4 = load_suricata_fpr_results(base, CONDITIONS["A4"], seed)
        print(f"  A4: DR={len(dr_a4)} CVEs, Suricata TPR={len(sur_a4)} CVEs, FPR={len(fpr_a4)} CVEs", file=sys.stderr)

        for name_a4, name_other, desc in PAIRS:
            cond_other = CONDITIONS[name_other]
            dr_other = load_dr_results(base, cond_other, seed)
            sur_other = load_suricata_results(base, cond_other, seed)
            fpr_other = load_suricata_fpr_results(base, cond_other, seed)
            print(f"  {name_other}: DR={len(dr_other)} CVEs, Suricata TPR={len(sur_other)} CVEs, FPR={len(fpr_other)} CVEs", file=sys.stderr)

            result = analyze_pair(name_a4, name_other, desc, dr_a4, dr_other,
                                  sur_a4, sur_other, fpr_a4, fpr_other, seed)
            all_results.append(result)

    print_results(all_results)

    if args.json_output:
        # Serialize, handling inf
        def sanitize(obj):
            if isinstance(obj, float):
                if math.isinf(obj):
                    return "inf"
                if math.isnan(obj):
                    return "NaN"
            if isinstance(obj, dict):
                return {k: sanitize(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [sanitize(v) for v in obj]
            return obj

        with open(args.json_output, "w") as f:
            json.dump(sanitize(all_results), f, indent=2, ensure_ascii=False)
        print(f"\nJSON results saved to: {args.json_output}", file=sys.stderr)


if __name__ == "__main__":
    main()
