"""Evaluate attack/benign classification performance.

Uses MOER pipeline output as classifier:
  verification_status="verified" + identified_param → ATTACK
  otherwise → BENIGN

Usage:
    python scripts/eval_classification.py \
        --attack-dir output/moer_8b_full \
        --benign-dir output/moer_8b_benign \
        [--baseline-dir output/bis_test/baseline-classify]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def classify_moer_result(result: dict) -> str:
    if result.get("verification_status") == "verified" and result.get("identified_param"):
        return "ATTACK"
    return "BENIGN"


def load_results(directory: Path, is_benign: bool) -> list[dict]:
    entries = []
    for path in sorted(directory.glob("*.json")):
        if path.name.startswith("e2e_") or path.name == "summary.json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        case_id = data.get("case_id") or path.stem
        entries.append({
            "case_id": case_id,
            "is_benign": is_benign,
            "ground_truth": "BENIGN" if is_benign else "ATTACK",
            "moer_verdict": classify_moer_result(data),
            "verification_status": data.get("verification_status"),
            "identified_param": data.get("identified_param"),
            "status": data.get("status"),
        })
    return entries


def compute_metrics(entries: list[dict], verdict_key: str = "moer_verdict") -> dict:
    tp = fp = tn = fn = 0
    for e in entries:
        gt = e["ground_truth"]
        pred = e[verdict_key]
        if pred == "ATTACK" and gt == "ATTACK":
            tp += 1
        elif pred == "ATTACK" and gt == "BENIGN":
            fp += 1
        elif pred == "BENIGN" and gt == "BENIGN":
            tn += 1
        elif pred == "BENIGN" and gt == "ATTACK":
            fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    accuracy = (tp + tn) / len(entries) if entries else 0.0
    return {
        "total": len(entries),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "accuracy": round(accuracy, 4),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack-dir", required=True)
    parser.add_argument("--benign-dir", required=True)
    parser.add_argument("--baseline-dir", help="BIS baseline-classify results for comparison")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    attack_entries = load_results(Path(args.attack_dir), is_benign=False)
    benign_entries = load_results(Path(args.benign_dir), is_benign=True)
    all_entries = attack_entries + benign_entries

    print(f"Attack traces: {len(attack_entries)}")
    print(f"Benign traces: {len(benign_entries)}")
    print(f"Total: {len(all_entries)}")
    print()

    moer_metrics = compute_metrics(all_entries, "moer_verdict")
    print("=== MOER Pipeline (CEGIS-as-classifier) ===")
    print(f"  TP={moer_metrics['tp']} FP={moer_metrics['fp']} TN={moer_metrics['tn']} FN={moer_metrics['fn']}")
    print(f"  Precision: {moer_metrics['precision']:.4f}")
    print(f"  Recall:    {moer_metrics['recall']:.4f}")
    print(f"  F1:        {moer_metrics['f1']:.4f}")
    print(f"  FPR:       {moer_metrics['fpr']:.4f}")
    print(f"  Accuracy:  {moer_metrics['accuracy']:.4f}")

    result = {"moer": moer_metrics, "attack_count": len(attack_entries), "benign_count": len(benign_entries)}

    if args.baseline_dir:
        baseline_path = Path(args.baseline_dir)
        if baseline_path.exists():
            for e in all_entries:
                bp = baseline_path / f"{e['case_id']}.json"
                if bp.exists():
                    bd = json.loads(bp.read_text(encoding="utf-8"))
                    e["baseline_verdict"] = bd.get("verdict", "BENIGN")
                else:
                    e["baseline_verdict"] = "BENIGN"
            baseline_metrics = compute_metrics(all_entries, "baseline_verdict")
            print()
            print("=== Baseline (direct LLM classify) ===")
            print(f"  TP={baseline_metrics['tp']} FP={baseline_metrics['fp']} TN={baseline_metrics['tn']} FN={baseline_metrics['fn']}")
            print(f"  Precision: {baseline_metrics['precision']:.4f}")
            print(f"  Recall:    {baseline_metrics['recall']:.4f}")
            print(f"  F1:        {baseline_metrics['f1']:.4f}")
            print(f"  FPR:       {baseline_metrics['fpr']:.4f}")
            print(f"  Accuracy:  {baseline_metrics['accuracy']:.4f}")
            result["baseline"] = baseline_metrics

    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()
