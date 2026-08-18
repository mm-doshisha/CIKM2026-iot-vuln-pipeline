"""Compare intermediate analysis accuracy: GRIDAI vs Proposed method.

Evaluates dangerous parameter identification (sink_param) accuracy.
This is the metric that directly impacts downstream Suricata rule generation.

Usage:
    python scripts/eval_analysis_accuracy.py \
        --ground-truth benchmarks/ground_truth.json \
        --gridai-dir output/gridai_analysis/seed_42 \
        --proposed-dir output/a4_proposed/seed_42 \
        --output-dir output/analysis_comparison
"""

import argparse
import json
import logging
from collections import Counter
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("eval_analysis")


def normalize_param(raw: str) -> str:
    if not raw:
        return ""
    return raw.strip().lower().replace("-", "_")


def load_ground_truth(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        gt_list = json.load(f)
    return {entry["cve_id"]: entry for entry in gt_list}


def load_gridai_analysis(gridai_dir: str) -> dict:
    results = {}
    for f in sorted(Path(gridai_dir).glob("CVE-*.json")):
        with open(f, encoding="utf-8") as fh:
            data = json.load(fh)
        cve_id = data.get("case_id", f.stem)
        parsed = data.get("analysis_parsed", {})
        if parsed.get("_parse_failed"):
            results[cve_id] = {"status": "parse_failed", "raw": data.get("analysis_raw", "")}
        else:
            results[cve_id] = {
                "status": data.get("status", "unknown"),
                "attack_type": parsed.get("attack_type", ""),
                "malicious_params": parsed.get("malicious_params", []),
                "target_endpoint": parsed.get("target_endpoint", ""),
                "payload_location": parsed.get("payload_location", ""),
                "key_content_matches": parsed.get("key_content_matches", []),
            }
    return results


def load_proposed_analysis(proposed_dir: str) -> dict:
    results = {}
    for f in sorted(Path(proposed_dir).glob("CVE-*.json")):
        with open(f, encoding="utf-8") as fh:
            data = json.load(fh)
        cve_id = data.get("case_id", f.stem)
        hyp = (data.get("verified_hypothesis")
               or data.get("interpreted_hypothesis")
               or data.get("attack_hypothesis")
               or {})
        if not hyp and "interpreted_analysis" in data:
            hyp = data["interpreted_analysis"].get("attack_hypothesis", {})
        results[cve_id] = {
            "status": data.get("status", "unknown"),
            "dangerous_param": hyp.get("dangerous_param", ""),
        }
    return results


def _normalize_gt_params(ground_truth_param) -> list[str]:
    if isinstance(ground_truth_param, list):
        return [g for g in ground_truth_param if g and str(g).lower() not in ("none", "null", "")]
    if not ground_truth_param or str(ground_truth_param).lower() in ("none", "null", ""):
        return []
    return [str(ground_truth_param)]


def param_match(predicted: str, ground_truth_param) -> str:
    gt_params = _normalize_gt_params(ground_truth_param)
    if not gt_params:
        return "gt_none"
    if not predicted:
        return "miss"
    pred = normalize_param(predicted)
    for gp in gt_params:
        gt = normalize_param(gp)
        if pred == gt or pred in gt or gt in pred:
            return "exact"
    return "wrong"


def param_in_list(param_list: list, ground_truth_param) -> str:
    gt_params = _normalize_gt_params(ground_truth_param)
    if not gt_params:
        return "gt_none"
    if not param_list:
        return "miss"
    for gp in gt_params:
        gt = normalize_param(gp)
        for p in param_list:
            pred = normalize_param(str(p))
            if pred == gt or pred in gt or gt in pred:
                return "exact"
    return "wrong"


def main():
    parser = argparse.ArgumentParser(
        description="Compare intermediate analysis accuracy")
    parser.add_argument("--ground-truth", default="benchmarks/ground_truth.json")
    parser.add_argument("--gridai-dir", required=True)
    parser.add_argument("--proposed-dir", required=True)
    parser.add_argument("--output-dir", default="output/analysis_comparison")
    args = parser.parse_args()

    gt = load_ground_truth(args.ground_truth)
    gridai = load_gridai_analysis(args.gridai_dir)
    proposed = load_proposed_analysis(args.proposed_dir)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_cves = sorted(gt.keys())
    logger.info("Ground truth: %d CVEs", len(all_cves))
    logger.info("GRIDAI analysis: %d CVEs", len(gridai))
    logger.info("Proposed analysis: %d CVEs", len(proposed))

    gridai_param_results = Counter()
    proposed_param_results = Counter()

    per_cve = []

    for cve_id in all_cves:
        gt_entry = gt[cve_id]
        gt_param = gt_entry.get("sink_param", "")

        g = gridai.get(cve_id, {})
        p = proposed.get(cve_id, {})

        g_param = param_in_list(g.get("malicious_params", []), gt_param)
        p_param = param_match(p.get("dangerous_param", ""), gt_param)

        gridai_param_results[g_param] += 1
        proposed_param_results[p_param] += 1

        per_cve.append({
            "cve_id": cve_id,
            "gt_param": gt_param,
            "gridai_params": g.get("malicious_params", []),
            "gridai_param_match": g_param,
            "proposed_param": p.get("dangerous_param", ""),
            "proposed_param_match": p_param,
        })

    total = len(all_cves)
    gt_has_param = total - gridai_param_results.get("gt_none", 0)

    g_correct = gridai_param_results.get("exact", 0) + gridai_param_results.get("partial", 0)
    p_correct = proposed_param_results.get("exact", 0) + proposed_param_results.get("partial", 0)
    g_miss = gridai_param_results.get("miss", 0)
    p_miss = proposed_param_results.get("miss", 0)
    g_wrong = gridai_param_results.get("wrong", 0)
    p_wrong = proposed_param_results.get("wrong", 0)

    # Head-to-head
    both_have = [c for c in per_cve
                 if c["gridai_param_match"] != "gt_none"
                 and c["proposed_param_match"] != "gt_none"]
    both_correct = sum(1 for c in both_have
                       if c["gridai_param_match"] in ("exact", "partial")
                       and c["proposed_param_match"] in ("exact", "partial"))
    gridai_wins = sum(1 for c in both_have
                      if c["gridai_param_match"] in ("exact", "partial")
                      and c["proposed_param_match"] in ("wrong", "miss"))
    proposed_wins = sum(1 for c in both_have
                        if c["proposed_param_match"] in ("exact", "partial")
                        and c["gridai_param_match"] in ("wrong", "miss"))
    both_wrong = sum(1 for c in both_have
                     if c["gridai_param_match"] in ("wrong", "miss")
                     and c["proposed_param_match"] in ("wrong", "miss"))

    g_acc = g_correct / gt_has_param * 100 if gt_has_param else 0
    p_acc = p_correct / gt_has_param * 100 if gt_has_param else 0
    g_miss_r = g_miss / gt_has_param * 100 if gt_has_param else 0
    p_miss_r = p_miss / gt_has_param * 100 if gt_has_param else 0
    g_wrong_r = g_wrong / gt_has_param * 100 if gt_has_param else 0
    p_wrong_r = p_wrong / gt_has_param * 100 if gt_has_param else 0

    W = 72
    print("\n" + "=" * W)
    print("PARAMETER IDENTIFICATION ACCURACY: GRIDAI vs Proposed")
    print("=" * W)
    print(f"Total CVEs: {total}  |  With ground-truth sink_param: {gt_has_param}")

    print("\n" + "-" * W)
    print(f"{'Metric':<22s} {'GRIDAI':>8s} {'Proposed':>8s}  Description")
    print("-" * W)
    print(f"{'PM Accuracy (%)':<22s} {g_acc:>7.1f}% {p_acc:>7.1f}%  "
          f"Correct param / N={gt_has_param} CVEs with known")
    print(f"{'':22s} {'':>8s} {'':>8s}  "
          f"sink_param. Higher = better identification.")
    print(f"{'Miss Rate (%)':<22s} {g_miss_r:>7.1f}% {p_miss_r:>7.1f}%  "
          f"System produced no param at all.")
    print(f"{'':22s} {'':>8s} {'':>8s}  "
          f"Miss -> downstream rule generation impossible.")
    print(f"{'Wrong Rate (%)':<22s} {g_wrong_r:>7.1f}% {p_wrong_r:>7.1f}%  "
          f"System output a param, but it does not")
    print(f"{'':22s} {'':>8s} {'':>8s}  "
          f"match ground truth. Rule targets wrong param.")
    print("-" * W)

    print(f"\n{'Head-to-Head (N=' + str(len(both_have)) + ')':<22s} "
          f"{'Count':>8s} {'(%)':>8s}  Description")
    print("-" * W)
    n = len(both_have) or 1
    print(f"{'Both correct':<22s} {both_correct:>8d} {both_correct/n*100:>7.1f}%  "
          f"Shared baseline: both methods succeed.")
    print(f"{'Proposed only':<22s} {proposed_wins:>8d} {proposed_wins/n*100:>7.1f}%  "
          f"Proposed correct, GRIDAI wrong/miss.")
    print(f"{'':22s} {'':>8s} {'':>8s}  "
          f"= net advantage of Proposed over GRIDAI.")
    print(f"{'GRIDAI only':<22s} {gridai_wins:>8d} {gridai_wins/n*100:>7.1f}%  "
          f"GRIDAI correct, Proposed wrong/miss.")
    print(f"{'':22s} {'':>8s} {'':>8s}  "
          f"= cases where GRIDAI outperforms.")
    print(f"{'Both wrong':<22s} {both_wrong:>8d} {both_wrong/n*100:>7.1f}%  "
          f"Neither method identified the param.")
    print(f"{'':22s} {'':>8s} {'':>8s}  "
          f"= hard cases for both approaches.")
    print("-" * W)

    # Save detailed results
    report = {
        "summary": {
            "total_cves": total,
            "cves_with_param": gt_has_param,
            "gridai_param_accuracy": g_acc,
            "proposed_param_accuracy": p_acc,
            "gridai_miss_rate": g_miss_r,
            "proposed_miss_rate": p_miss_r,
            "gridai_wrong_rate": g_wrong_r,
            "proposed_wrong_rate": p_wrong_r,
            "gridai_param_counts": dict(gridai_param_results),
            "proposed_param_counts": dict(proposed_param_results),
            "head_to_head": {
                "n": len(both_have),
                "both_correct": both_correct,
                "gridai_only": gridai_wins,
                "proposed_only": proposed_wins,
                "both_wrong": both_wrong,
            },
        },
        "per_cve": per_cve,
    }

    report_path = out_dir / "analysis_comparison_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\nReport: {report_path}")

    disagreements = [c for c in per_cve
                     if c["gridai_param_match"] != c["proposed_param_match"]
                     and c["gridai_param_match"] != "gt_none"]
    disagree_path = out_dir / "param_disagreements.json"
    disagree_path.write_text(
        json.dumps(disagreements, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Disagreements: {disagree_path} ({len(disagreements)} CVEs)")


if __name__ == "__main__":
    main()
