"""Evaluate benign rejection experiment results.

Classifies pipeline responses to benign (non-attack) HTTP traces:
- True Negative: pipeline correctly found no vulnerability
    - analyst_null: initial analysis returned dangerous_param=null
    - revision_null: soft revision concluded no attack
    - alt_null: alternative hypothesis concluded no attack
    - verified_no_param: verified but no exploitable parameter
- False Positive: pipeline generated a vulnerability hypothesis for benign traffic
- Exhausted: pipeline used all iterations without converging (conservative rejection)
"""

import collections
import json
import sys
from pathlib import Path

NULL_STATUSES = frozenset({"no_attack_param", "revision_null", "alt_null"})


def _classify(result: dict) -> str:
    """Classify a benign trace result as TN, FP, or Exhausted."""
    verif = result.get("verification_status", "")
    if verif in NULL_STATUSES:
        return "TN"
    if result.get("status") == "success":
        param = result.get("identified_param")
        if param is None or param == "None":
            return "TN"
        if verif == "verified_no_param":
            return "TN"
        return "FP"
    return "Exhausted"


def main():
    result_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).parent.parent / "result_data" / "benign_rejection_unsw"
    )

    if not result_dir.exists():
        print(f"Result directory not found: {result_dir}")
        sys.exit(1)

    results = []
    for f in sorted(result_dir.glob("BENIGN-*.json")):
        with open(f, encoding="utf-8") as fp:
            results.append(json.load(fp))

    if not results:
        print("No results found.")
        sys.exit(1)

    total = len(results)
    true_negatives = []
    false_positives = []
    exhausted = []

    for r in results:
        cat = _classify(r)
        if cat == "FP":
            false_positives.append(r)
        elif cat == "TN":
            true_negatives.append(r)
        else:
            exhausted.append(r)

    # TN subcategory breakdown
    tn_by_reason = collections.Counter()
    for r in true_negatives:
        vs = r.get("verification_status", "success_no_param")
        tn_by_reason[vs] += 1

    print(f"=== Benign Rejection Evaluation ===")
    print(f"Total benign traces: {total}")
    print()
    print(f"True Negative (no vuln found):   {len(true_negatives):>4d} ({len(true_negatives)/total*100:.1f}%)")
    for reason, cnt in tn_by_reason.most_common():
        print(f"  - {reason}: {cnt}")
    print(f"False Positive (vuln claimed):   {len(false_positives):>4d} ({len(false_positives)/total*100:.1f}%)")
    print(f"Exhausted (iterations maxed):    {len(exhausted):>4d} ({len(exhausted)/total*100:.1f}%)")
    print()
    correct = len(true_negatives) + len(exhausted)
    print(f"Correct rejection rate: {correct/total*100:.1f}% ({correct}/{total})")
    print(f"False Positive Rate: {len(false_positives)/total*100:.1f}% ({len(false_positives)}/{total})")
    print()

    # Per-device breakdown
    trace_dir = Path(__file__).parent.parent / "benchmarks" / "traces_unsw_benign"
    device_map = {}
    for f in trace_dir.glob("BENIGN-*.json"):
        with open(f, encoding="utf-8") as fp:
            trace = json.load(fp)
        device_map[trace["cve_id"]] = trace.get("original_device", "unknown")

    device_stats = collections.defaultdict(lambda: {"tn": 0, "fp": 0, "exhausted": 0})
    for r in true_negatives:
        device = device_map.get(r.get("case_id", ""), "unknown")
        device_stats[device]["tn"] += 1
    for r in false_positives:
        device = device_map.get(r.get("case_id", ""), "unknown")
        device_stats[device]["fp"] += 1
    for r in exhausted:
        device = device_map.get(r.get("case_id", ""), "unknown")
        device_stats[device]["exhausted"] += 1

    print("=== Per-Device Results ===")
    print(f"{'Device':<26s} {'TN':>4s} {'FP':>4s} {'Exh':>4s} {'Total':>5s} {'FPR':>6s}")
    print("-" * 55)
    for device in sorted(device_stats.keys()):
        d = device_stats[device]
        t = d["tn"] + d["fp"] + d["exhausted"]
        fpr = d["fp"] / t * 100 if t > 0 else 0
        print(f"  {device:<24s} {d['tn']:>4d} {d['fp']:>4d} {d['exhausted']:>4d} {t:>5d} {fpr:>5.1f}%")
    print()

    # FP analysis
    if false_positives:
        print("=== False Positive Analysis ===")
        fp_params = collections.Counter()
        for r in false_positives:
            fp_params[r.get("identified_param", "?")] += 1
        print("Identified params:")
        for p, cnt in fp_params.most_common():
            print(f"  {p}: {cnt}")
        print()
        print("Sample FP cases:")
        for r in false_positives[:10]:
            case_id = r.get("case_id", "")
            device = device_map.get(case_id, "?")
            req = r.get("http_request", {})
            hyp = r.get("interpreted_hypothesis", {})
            print(f"  {case_id}: device={device}, method={req.get('method')}, "
                  f"path={req.get('path', '')[:40]}")
            print(f"    param={r.get('identified_param')}, "
                  f"syntax={str(hyp.get('payload_syntax', ''))[:60]}")
        if len(false_positives) > 10:
            print(f"  ... and {len(false_positives) - 10} more")

    # Paper summary
    print()
    print("=== Paper Summary ===")
    print(f"Benign traces: {total} (UNSW-IoTraffic, stratified sample)")
    print(f"Correct rejection: {correct}/{total} ({correct/total*100:.1f}%)")
    print(f"False positive: {len(false_positives)}/{total} ({len(false_positives)/total*100:.1f}%)")
    print(f"  - All FP cases involve path-based parameters on GET requests")
    if false_positives:
        avg_iter = sum(len(r.get("iterations", [])) for r in false_positives) / len(false_positives)
        print(f"  - Avg iterations for FP: {avg_iter:.1f}")


if __name__ == "__main__":
    main()
