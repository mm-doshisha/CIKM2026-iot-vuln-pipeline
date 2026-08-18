"""Generate Suricata rules for existing pipeline results that lack them.

Reads CVE-*.json from a pipeline output directory, generates rules via
RuleGenAgent for each verified result, and writes the rule back into the JSON.

Usage:
    python scripts/generate_suricata_rules.py --input-dir output/8b_full --workers 2
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.hypothesis.agents.rule_agent import RuleGenAgent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("gen_suricata")

print_lock = Lock()


def process_one(result_path: Path, agent: RuleGenAgent) -> dict:
    with open(result_path, encoding="utf-8") as f:
        data = json.load(f)

    cve_id = data.get("case_id", result_path.stem)

    if data.get("suricata_rule"):
        return {"cve_id": cve_id, "status": "already_has_rule"}

    if data.get("status") != "success":
        return {"cve_id": cve_id, "status": "skipped_not_success"}

    http_request = dict(data.get("http_request", {}))
    http_request.setdefault("case_id", cve_id)
    raw_analysis = data.get("final_analysis") or data.get("verified_analysis")
    if not raw_analysis:
        for key in ["interpreted_analysis", "initial_analysis"]:
            if data.get(key):
                raw_analysis = data[key]
                break

    if not raw_analysis:
        return {"cve_id": cve_id, "status": "skipped_no_analysis"}
    analysis = dict(raw_analysis)
    analysis.setdefault("case_id", cve_id)

    try:
        rule = agent.generate(http_request, analysis)
        data["suricata_rule"] = rule
        if rule is None:
            data["rule_status"] = "degenerate"
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        is_valid = bool(rule) and not str(rule).startswith("#")
        status = "degenerate" if rule is None else "generated"
        return {"cve_id": cve_id, "status": status, "valid": is_valid,
                "rule_len": len(rule or "")}
    except Exception as e:
        logger.error("Failed %s: %s", cve_id, e)
        return {"cve_id": cve_id, "status": "error", "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Generate Suricata rules for pipeline results")
    parser.add_argument("--input-dir", required=True, help="Pipeline output directory")
    parser.add_argument("--max-repair", type=int, default=3, help="Max validation repair rounds")
    parser.add_argument("--max-semantic", type=int, default=3, help="Max PCAP semantic repair rounds")
    parser.add_argument("--no-template", action="store_true", help="Disable JSON template rule generation")
    parser.add_argument("--no-semantic-verify", action="store_true", help="Disable PCAP-driven semantic verification")
    parser.add_argument("--workers", type=int, default=2, help="Parallel workers")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    result_files = sorted(input_dir.glob("CVE-*.json"))
    logger.info("Found %d result files in %s (workers=%d)", len(result_files), input_dir, args.workers)

    agent = RuleGenAgent(
        max_validation_rounds=args.max_repair,
        max_semantic_rounds=args.max_semantic,
        use_template=not args.no_template,
        enable_semantic_verify=not args.no_semantic_verify,
    )

    stats = {"total": 0, "generated": 0, "valid": 0, "skipped": 0, "error": 0, "already": 0}
    t0 = time.time()
    done_count = 0

    def on_result(result, idx):
        nonlocal done_count
        done_count += 1
        status = result["status"]
        if status == "generated":
            stats["generated"] += 1
            if result.get("valid"):
                stats["valid"] += 1
            tag = "OK" if result.get("valid") else "UNVALIDATED"
        elif status == "already_has_rule":
            stats["already"] += 1
            tag = "EXISTING"
        elif status == "error":
            stats["error"] += 1
            tag = "ERROR"
        else:
            stats["skipped"] += 1
            tag = "SKIP"

        elapsed = time.time() - t0
        active = done_count - stats["already"] - stats["skipped"]
        rate = elapsed / max(active, 1)
        pending = len(result_files) - done_count
        remaining = rate * pending / max(args.workers, 1)
        with print_lock:
            print(f"[{done_count}/{len(result_files)}] {result['cve_id']:30s} {tag:12s} "
                  f"(gen={stats['generated']}, valid={stats['valid']}, skip={stats['skipped']}, "
                  f"err={stats['error']}, ETA={remaining/60:.0f}min)", flush=True)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(process_one, path, agent): i for i, path in enumerate(result_files)}
        for future in as_completed(futures):
            idx = futures[future]
            try:
                result = future.result()
                on_result(result, idx)
            except Exception as e:
                done_count += 1
                stats["error"] += 1
                with print_lock:
                    print(f"[{done_count}/{len(result_files)}] EXCEPTION: {e}", flush=True)

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.0f}s ({elapsed/60:.1f}min)")
    print(f"  Total: {len(result_files)}")
    print(f"  Generated: {stats['generated']} (valid: {stats['valid']})")
    print(f"  Already had rule: {stats['already']}")
    print(f"  Skipped: {stats['skipped']}")
    print(f"  Errors: {stats['error']}")


if __name__ == "__main__":
    main()
