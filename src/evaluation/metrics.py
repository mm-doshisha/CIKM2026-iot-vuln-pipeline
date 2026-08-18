"""Compute evaluation metrics for Suricata rule effectiveness (RQ2)."""

import json
import logging
from pathlib import Path

logger = logging.getLogger("metrics")


def compute_per_cve_metrics(attack_results: list, benign_results: list,
                            variant_results: list = None) -> dict:
    """Compute per-CVE detection metrics.

    Args:
        attack_results: list of (cve_id, suricata_result) for attack pcaps
        benign_results: list of (cve_id, suricata_result) for benign pcaps
        variant_results: list of (cve_id, variant_type, suricata_result)
    """
    per_cve = {}

    for cve_id, result in attack_results:
        if cve_id not in per_cve:
            per_cve[cve_id] = {"attack_detected": False, "benign_clean": True,
                               "variants": {}}
        per_cve[cve_id]["attack_detected"] = result.get(
            "expected_sid_triggered", result["triggered"])
        per_cve[cve_id]["attack_alerts"] = result["alerts"]
        per_cve[cve_id]["attack_rule_sids"] = sorted(result.get("rule_sids", []))

    for cve_id, result in benign_results:
        if cve_id not in per_cve:
            per_cve[cve_id] = {"attack_detected": False, "benign_clean": True,
                               "variants": {}}
        per_cve[cve_id]["benign_clean"] = not result.get(
            "expected_sid_triggered", result["triggered"])
        per_cve[cve_id]["benign_alerts"] = result["alerts"]
        per_cve[cve_id]["benign_rule_sids"] = sorted(result.get("rule_sids", []))

    if variant_results:
        for cve_id, variant_type, result in variant_results:
            if cve_id in per_cve:
                per_cve[cve_id]["variants"][variant_type] = result.get(
                    "expected_sid_triggered", result["triggered"])

    return per_cve


def compute_aggregate_metrics(per_cve: dict) -> dict:
    """Compute aggregate TPR, FPR, and variant detection rates."""
    total = len(per_cve)
    if total == 0:
        return {"tpr": 0, "fpr": 0, "total": 0}

    tp = sum(1 for v in per_cve.values() if v.get("attack_detected"))
    fp = sum(1 for v in per_cve.values() if not v.get("benign_clean", True))

    variant_stats = {}
    for cve_data in per_cve.values():
        for vtype, detected in cve_data.get("variants", {}).items():
            if vtype not in variant_stats:
                variant_stats[vtype] = {"detected": 0, "total": 0}
            variant_stats[vtype]["total"] += 1
            if detected:
                variant_stats[vtype]["detected"] += 1

    variant_rates = {}
    for vtype, stats in variant_stats.items():
        variant_rates[vtype] = (stats["detected"] / stats["total"]
                                if stats["total"] > 0 else 0)

    return {
        "total": total,
        "true_positives": tp,
        "false_positives": fp,
        "tpr": tp / total,
        "fpr": fp / total,
        "variant_detection_rates": variant_rates,
    }


def compute_class_metrics(per_cve: dict, ground_truth: dict) -> dict:
    """Compute metrics broken down by vulnerability class."""
    class_data = {}
    for cve_id, metrics in per_cve.items():
        gt = ground_truth.get(cve_id, {})
        vuln_class = gt.get("vuln_class", "unknown")
        if vuln_class not in class_data:
            class_data[vuln_class] = {"tp": 0, "fp": 0, "total": 0}
        class_data[vuln_class]["total"] += 1
        if metrics.get("attack_detected"):
            class_data[vuln_class]["tp"] += 1
        if not metrics.get("benign_clean", True):
            class_data[vuln_class]["fp"] += 1

    result = {}
    for cls, data in class_data.items():
        result[cls] = {
            "total": data["total"],
            "tpr": data["tp"] / data["total"] if data["total"] > 0 else 0,
            "fpr": data["fp"] / data["total"] if data["total"] > 0 else 0,
        }
    return result


def format_results_table(per_cve: dict, ground_truth: dict) -> str:
    """Format results as a readable table."""
    lines = []
    lines.append(f"{'CVE ID':25s} {'Class':10s} {'Attack':8s} {'Benign':8s} {'Variants':20s}")
    lines.append("-" * 75)

    for cve_id in sorted(per_cve.keys()):
        m = per_cve[cve_id]
        gt = ground_truth.get(cve_id, {})
        vuln_class = gt.get("vuln_class", "?")
        atk = "HIT" if m.get("attack_detected") else "MISS"
        ben = "OK" if m.get("benign_clean", True) else "FP"
        variants = ", ".join(
            f"{vt}={'Y' if det else 'N'}"
            for vt, det in m.get("variants", {}).items()
        ) or "-"
        lines.append(f"{cve_id:25s} {vuln_class:10s} {atk:8s} {ben:8s} {variants:20s}")

    return "\n".join(lines)


def save_evaluation_report(per_cve: dict, aggregate: dict,
                           class_metrics: dict, ground_truth: dict,
                           output_path: str):
    """Save full evaluation report as JSON."""
    report = {
        "aggregate": aggregate,
        "class_metrics": class_metrics,
        "per_cve": {},
    }

    for cve_id, m in per_cve.items():
        gt = ground_truth.get(cve_id, {})
        report["per_cve"][cve_id] = {
            "vuln_class": gt.get("vuln_class", "unknown"),
            "attack_detected": m.get("attack_detected", False),
            "benign_clean": m.get("benign_clean", True),
            "variants": m.get("variants", {}),
            "attack_alert_count": len(m.get("attack_alerts", [])),
            "benign_alert_count": len(m.get("benign_alerts", [])),
        }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    logger.info("Evaluation report saved to %s", output_path)
    return report
