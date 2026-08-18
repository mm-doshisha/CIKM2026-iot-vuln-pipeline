"""Aggregate evaluation results across seeds (mean +/- std).

Reads suricata_eval_report.json from each seed directory and computes
cross-seed statistics for each condition.

Usage:
    python scripts/aggregate_seeds.py \
        --eval-dir output/eval \
        --output output/eval/summary.json
"""

import argparse
import json
import math
import sys
from pathlib import Path


def mean_std(values):
    if not values:
        return 0.0, 0.0
    n = len(values)
    mu = sum(values) / n
    if n < 2:
        return mu, 0.0
    var = sum((x - mu) ** 2 for x in values) / (n - 1)
    return mu, math.sqrt(var)


def fmt(mu, std):
    return f"{mu * 100:.1f} +/- {std * 100:.1f}"


def load_suricata_report(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_hypothesis_summary(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def aggregate_condition(eval_dir, condition, seeds):
    tpr_vals = []
    fpr_vals = []
    real_fpr_vals = []
    total_rules = []
    tp_vals = []
    fp_vals = []

    param_match_vals = []
    success_vals = []

    for seed in seeds:
        report_path = eval_dir / condition / f"seed_{seed}" / "suricata_eval_report.json"
        if report_path.exists():
            report = load_suricata_report(report_path)
            agg = report.get("aggregate", {})
            tpr_vals.append(agg.get("tpr", 0))
            fpr_vals.append(agg.get("fpr", 0))
            real_fpr_vals.append(agg.get("real_benign_fpr", 0))
            total_rules.append(agg.get("total", 0))
            tp_vals.append(agg.get("true_positives", 0))
            fp_vals.append(agg.get("false_positives", 0))

        summary_path = eval_dir.parent / condition / f"seed_{seed}" / "e2e_summary.json"
        if summary_path.exists():
            summary = load_hypothesis_summary(summary_path)
            n = summary.get("total", 0)
            if n > 0:
                success_vals.append(summary.get("success", 0) / n)
                param_match_vals.append(summary.get("param_match", 0) / n)

    if not tpr_vals:
        return None

    tpr_mu, tpr_std = mean_std(tpr_vals)
    fpr_mu, fpr_std = mean_std(fpr_vals)
    real_fpr_mu, real_fpr_std = mean_std(real_fpr_vals)
    rules_mu, rules_std = mean_std(total_rules)
    success_mu, success_std = mean_std(success_vals)
    param_mu, param_std = mean_std(param_match_vals)

    return {
        "condition": condition,
        "n_seeds": len(tpr_vals),
        "tpr": {"mean": tpr_mu, "std": tpr_std, "values": tpr_vals},
        "fpr": {"mean": fpr_mu, "std": fpr_std, "values": fpr_vals},
        "real_benign_fpr": {"mean": real_fpr_mu, "std": real_fpr_std, "values": real_fpr_vals},
        "n_rules": {"mean": rules_mu, "std": rules_std, "values": total_rules},
        "pipeline_success": {"mean": success_mu, "std": success_std, "values": success_vals},
        "param_match": {"mean": param_mu, "std": param_std, "values": param_match_vals},
    }


def aggregate_no_seed(eval_dir, condition):
    report_path = eval_dir / condition / "suricata_eval_report.json"
    if not report_path.exists():
        return None
    report = load_suricata_report(report_path)
    agg = report.get("aggregate", {})
    return {
        "condition": condition,
        "n_seeds": 1,
        "tpr": {"mean": agg.get("tpr", 0), "std": 0, "values": [agg.get("tpr", 0)]},
        "fpr": {"mean": agg.get("fpr", 0), "std": 0, "values": [agg.get("fpr", 0)]},
        "real_benign_fpr": {"mean": agg.get("real_benign_fpr", 0), "std": 0},
        "n_rules": {"mean": agg.get("total", 0), "std": 0},
    }


def main():
    parser = argparse.ArgumentParser(description="Aggregate seeds")
    parser.add_argument("--eval-dir", default="output/eval")
    parser.add_argument("--output", default="output/eval/summary.json")
    parser.add_argument("--seeds", default="42,123,456")
    args = parser.parse_args()

    eval_dir = Path(args.eval_dir)
    seeds = [int(s) for s in args.seeds.split(",")]

    conditions_with_seeds = [
        "f1_falcon", "b1_direct_llm", "a1_oneshot", "a2_stateless",
        "a3_reflexion", "a4_proposed", "r3_hardened",
    ]
    conditions_no_seeds = ["v1_vedas", "s1_syrius", "t1_template"]

    results = {}

    for cond in conditions_no_seeds:
        r = aggregate_no_seed(eval_dir, cond)
        if r:
            results[cond] = r

    for cond in conditions_with_seeds:
        r = aggregate_condition(eval_dir, cond, seeds)
        if r:
            results[cond] = r

    print("=" * 70)
    print("CROSS-SEED AGGREGATION SUMMARY (dev split)")
    print("=" * 70)
    print(f"{'Condition':<16} {'TPR':>16} {'FPR':>16} {'Rules':>10} {'Seeds':>6}")
    print("-" * 70)

    for cond in conditions_no_seeds + conditions_with_seeds:
        if cond not in results:
            continue
        r = results[cond]
        tpr = r["tpr"]
        fpr = r["fpr"]
        n_rules = r["n_rules"]
        n_seeds = r["n_seeds"]

        if n_seeds > 1:
            tpr_str = f"{tpr['mean']*100:.1f} +/- {tpr['std']*100:.1f}%"
            fpr_str = f"{fpr['mean']*100:.1f} +/- {fpr['std']*100:.1f}%"
            rules_str = f"{n_rules['mean']:.0f}"
        else:
            tpr_str = f"{tpr['mean']*100:.1f}%"
            fpr_str = f"{fpr['mean']*100:.1f}%"
            rules_str = f"{n_rules['mean']:.0f}"

        print(f"{cond:<16} {tpr_str:>16} {fpr_str:>16} {rules_str:>10} {n_seeds:>6}")

    print("=" * 70)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nFull results saved to {out_path}")


if __name__ == "__main__":
    main()
