"""Run the hypothesis pipeline on all traces and evaluate against ground truth.

Usage:
    python scripts/run_hypothesis_e2e.py [--traces-dir benchmarks/traces] [--output-dir output/hypothesis]
"""

import argparse
import json
import logging
import os
import queue
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.hypothesis.agents import Runner
from src.hypothesis.agents import runner as _runner_module
from src.hypothesis.param_match import normalise_param, match_param

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("e2e_runner")


def load_ground_truth(gt_path: str) -> dict:
    with open(gt_path, encoding="utf-8") as f:
        gt_list = json.load(f)
    return {item["cve_id"]: item for item in gt_list}


def evaluate_analysis(result: dict, gt: dict) -> dict:
    """Compare pipeline analysis against ground truth."""
    NULL_STATUSES = frozenset({"no_attack_param", "revision_null", "alt_null"})
    verif = result.get("verification_status", "")

    if verif in NULL_STATUSES:
        none_values = ("", "none", "null", "n/a")
        exp_sink = gt.get("sink_param")
        is_gt_null = (exp_sink is None
                      or str(exp_sink).lower().strip() in none_values)
        return {
            "match": is_gt_null,
            "reason": "analyst_null_correct" if is_gt_null else "analyst_null_wrong",
            "dangerous_param": {
                "predicted": None,
                "expected": exp_sink,
                "match": is_gt_null,
            },
        }

    if result["status"] != "success":
        return {"match": False, "reason": "pipeline_failed"}

    analysis = result.get("final_analysis", {})
    hyp = analysis.get("attack_hypothesis", {})

    eval_result = {
        "dangerous_param": {
            "predicted": hyp.get("dangerous_param", ""),
            "expected": gt.get("sink_param", ""),
            "match": False,
        },
        "payload_syntax": {
            "predicted": hyp.get("payload_syntax", ""),
            "expected_encoding": gt.get("payload_encoding", ""),
        },
        "endpoint": {
            "predicted_from_request": result["http_request"]["path"],
            "expected": gt.get("endpoint", ""),
            "match": False,
        },
    }

    pred_param = hyp.get("dangerous_param")
    exp_sink = gt.get("sink_param")
    eval_result["dangerous_param"]["match"] = match_param(pred_param, exp_sink)

    pred_path = result["http_request"]["path"].split("?")[0].rstrip("/")
    exp_path = (gt.get("endpoint") or "").split("?")[0].rstrip("/")
    eval_result["endpoint"]["match"] = (pred_path == exp_path)

    eval_result["match"] = eval_result["dangerous_param"]["match"]

    return eval_result


_port_pool = None
_suricata_fp_check_enabled = False


def _suricata_fp_check(result: dict, trace_file: Path) -> dict:
    """Post-check: reject rules that fire on benign traffic for the same endpoint."""
    rule = result.get("suricata_rule")
    if not rule or result.get("status") != "success":
        return result

    import re
    import tempfile
    from src.evaluation.pcap_generator import generate_benign_pcap
    from src.evaluation.suricata_runner import run_suricata, validate_rules
    from src.hypothesis.analyst import _extract_request_only

    try:
        with open(trace_file, encoding="utf-8") as f:
            trace = json.load(f)
        http_request = _extract_request_only(trace)
    except Exception as e:
        logger.warning("FP check: could not load trace %s: %s", trace_file, e)
        return result

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_path = os.path.join(tmpdir, "test.rules")
            rule_fixed = rule
            if not re.search(r"sid:\s*\d+", rule_fixed):
                rule_fixed = rule_fixed.rstrip(")") + " sid:9999999; rev:1;)"
            with open(rules_path, "w") as f:
                f.write(rule_fixed + "\n")

            if not validate_rules(rules_path):
                result["fp_check"] = "skip_invalid_rule"
                return result

            benign_pcap = os.path.join(tmpdir, "benign.pcap")
            generate_benign_pcap(http_request, benign_pcap)

            log_dir = os.path.join(tmpdir, "suricata_log")
            sr = run_suricata(benign_pcap, rules_path, log_dir)

            if sr.get("triggered"):
                result["status"] = "failed"
                result["fp_check"] = "rejected_benign_fp"
                logger.info("FP check REJECT: rule fires on benign traffic")
            else:
                result["fp_check"] = "passed"

            out_path = Path(result.get("_output_path", ""))
            if out_path.exists():
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.warning("FP check error: %s", e)
        result["fp_check"] = "error"

    return result


def _run_one(trace_file: Path, output_dir: str, port: int,
             max_iterations: int, gt: dict,
             skip_suricata: bool = False,
             use_blackboard: bool = True,
             use_deliberation: bool = True,
             use_manifest: bool = False,
             use_agentic_policy: bool = True,
             stateless_loop: bool = False,
             reflexion_mode: bool = False,
             suppress_condition_memory: bool = False) -> dict:
    """Run pipeline on a single trace. Thread-safe (each call gets its own Runner)."""
    cve_id = trace_file.stem

    existing_result = Path(output_dir) / f"{cve_id}.json"
    if existing_result.exists():
        try:
            with open(existing_result, encoding="utf-8") as ef:
                result = json.load(ef)
            if result.get("status") in ("success", "failed"):
                gt_entry = gt.get(cve_id, {})
                evaluation = evaluate_analysis(result, gt_entry) if gt_entry else {"match": False, "reason": "no_ground_truth"}
                return {"cve_id": cve_id, "result": result, "evaluation": evaluation, "skipped": True}
        except Exception:
            pass

    actual_port = port
    if _port_pool is not None:
        actual_port = _port_pool.get()

    try:
        orch = Runner(port=actual_port, max_iterations=max_iterations,
                           skip_suricata=skip_suricata,
                           use_blackboard=use_blackboard,
                           use_deliberation=use_deliberation,
                           use_manifest=use_manifest,
                           use_agentic_policy=use_agentic_policy,
                           stateless_loop=stateless_loop,
                           reflexion_mode=reflexion_mode,
                           suppress_condition_memory=suppress_condition_memory)
        result = orch.run(str(trace_file), output_dir)
    except Exception as e:
        logger.error("Pipeline crashed for %s: %s", cve_id, e)
        result = {"case_id": cve_id, "status": "crashed", "error": str(e)}
    finally:
        if _port_pool is not None:
            _port_pool.put(actual_port)

    if _suricata_fp_check_enabled:
        result["_output_path"] = str(Path(output_dir) / f"{cve_id}.json")
        result = _suricata_fp_check(result, trace_file)

    gt_entry = gt.get(cve_id, {})
    evaluation = evaluate_analysis(result, gt_entry) if gt_entry else {"match": False, "reason": "no_ground_truth"}

    return {
        "cve_id": cve_id,
        "result": result,
        "evaluation": evaluation,
        "skipped": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--traces-dir", default="benchmarks/traces")
    parser.add_argument("--output-dir", default="output/hypothesis")
    parser.add_argument("--ground-truth", default="benchmarks/ground_truth.json")
    parser.add_argument("--pattern", default="CVE-*.json",
                        help="Glob pattern for trace files (default: CVE-*.json)")
    parser.add_argument("--port", type=int, default=9090)
    parser.add_argument("--max-iterations", type=int, default=7)
    parser.add_argument("--alt-iterations", type=int, default=None,
                        help="ALT_ITERATIONS override (default: use runner constant)")
    parser.add_argument("--same-failure-stop", type=int, default=None,
                        help="SAME_FAILURE_STOP override (default: use runner constant)")
    parser.add_argument("--workers", "-w", type=int, default=1,
                        help="Number of parallel workers (each gets its own port)")
    parser.add_argument("--single", help="Run only this CVE ID")
    parser.add_argument("--skip-existing", action="store_true",
                        help="Skip CVEs that already have results")
    parser.add_argument("--skip-suricata", action="store_true",
                        help="Skip Suricata rule generation (faster, generate rules later)")
    parser.add_argument("--no-blackboard", action="store_true",
                        help="Disable failed-condition blackboard hints")
    parser.add_argument("--no-deliberation", action="store_true",
                        help="Disable Analyst deliberation (soft revision on repeated failure)")
    parser.add_argument("--with-manifest", action="store_true",
                        help="Enable parsed request manifest for agents")
    parser.add_argument("--no-agentic-policy", action="store_true",
                        help="Disable stateful verification-recovery policy")
    parser.add_argument("--stateless-loop", action="store_true",
                        help="A2: Loop without memory injection (blackboard not passed to LLM)")
    parser.add_argument("--reflexion-mode", action="store_true",
                        help="A3: Use NL reflections instead of structured blackboard")
    parser.add_argument("--suppress-condition-memory", action="store_true",
                        help="A4-lite: Keep hypothesis memory, suppress condition-level tried_conditions")
    parser.add_argument("--seed", type=int, default=None,
                        help="LLM seed for reproducibility (e.g. 42, 123, 456)")
    parser.add_argument("--no-classify", action="store_true",
                        help="Experiment 1 (filter-OFF / Option C): analyst never rejects benign; always names a best-guess param. Ablates the 2-class filter while pg2 gate stays fixed. Records analyst_benign_judgment for analyst-vs-downstream decomposition. Run with MECH_GATE=hard MECH_EXACT=1 --max-iterations 10 to hold pg2 fixed.")
    parser.add_argument("--suricata-fp-check", action="store_true",
                        help="Reject rules that fire on benign traffic (post-generation FP check)")
    parser.add_argument("--skip-extra-benign", action="store_true",
                        help="Skip CVE-paired benign paths in verify_condition (Layer A only)")
    parser.add_argument("--benign-values", default=None,
                        help="Path to benign_values.json (default: data/benign_values.json)")
    parser.add_argument("--cve-list", default=None,
                        help="JSON file with list of CVE IDs to process (e.g. benchmarks/dev_cves.json)")
    args = parser.parse_args()

    if args.stateless_loop and args.reflexion_mode:
        parser.error("--stateless-loop and --reflexion-mode are mutually exclusive")

    if args.no_classify:
        from src.hypothesis.analyst_assume_attack import patch_prompts_no_classify
        patch_prompts_no_classify()
        logger.info("NO-CLASSIFY mode (filter-OFF): analyst never rejects benign; "
                    "2-class filter ablated, mechanism gate held fixed. MECH_GATE=%s",
                    os.environ.get("MECH_GATE", "off"))

    if args.suricata_fp_check:
        global _suricata_fp_check_enabled
        _suricata_fp_check_enabled = True
        logger.info("SURICATA-FP-CHECK enabled: rules tested against benign traffic")

    if args.seed is not None:
        from src.hypothesis.analyst import set_llm_seed
        set_llm_seed(args.seed)
        logger.info("LLM seed set to %d", args.seed)

    import src.hypothesis.skeleton as _skel
    if args.skip_extra_benign:
        _skel.EXTRA_BENIGN_DIR = None
        logger.info("EXTRA_BENIGN_DIR disabled (Layer A only)")
    if args.benign_values:
        _skel.BENIGN_VALUES_PATH = Path(args.benign_values).resolve()
        logger.info("BENIGN_VALUES_PATH overridden to %s", _skel.BENIGN_VALUES_PATH)

    if args.alt_iterations is not None:
        _runner_module.ALT_ITERATIONS = args.alt_iterations
        logger.info("ALT_ITERATIONS overridden to %d", args.alt_iterations)
    if args.same_failure_stop is not None:
        _runner_module.SAME_FAILURE_STOP = args.same_failure_stop
        logger.info("SAME_FAILURE_STOP overridden to %d", args.same_failure_stop)

    traces_dir = Path(args.traces_dir)
    pattern = getattr(args, "pattern", None) or "CVE-*.json"
    trace_files = sorted(traces_dir.glob(pattern))

    if args.cve_list:
        with open(args.cve_list, encoding="utf-8") as f:
            cve_ids = set(json.load(f))
        trace_files = [f for f in trace_files if f.stem in cve_ids]
        logger.info("Filtered to %d CVEs from %s", len(trace_files), args.cve_list)

    if args.single:
        trace_files = [f for f in trace_files if args.single in f.stem]

    gt = load_ground_truth(args.ground_truth)

    logger.info("Found %d traces, %d ground truth entries, %d workers",
                len(trace_files), len(gt), args.workers)

    start_time = time.time()
    results = []

    if args.workers <= 1:
        runner = Runner(port=args.port, max_iterations=args.max_iterations,
                                     skip_suricata=args.skip_suricata,
                                     use_blackboard=not args.no_blackboard,
                                     use_deliberation=not args.no_deliberation,
                                     use_manifest=args.with_manifest,
                                     use_agentic_policy=not args.no_agentic_policy,
                                     stateless_loop=args.stateless_loop,
                                     reflexion_mode=args.reflexion_mode,
                                     suppress_condition_memory=args.suppress_condition_memory)
        for i, trace_file in enumerate(trace_files):
            cve_id = trace_file.stem
            logger.info("\n========== [%d/%d] %s ==========", i + 1, len(trace_files), cve_id)

            existing_result = Path(args.output_dir) / f"{cve_id}.json"
            skip = False
            if args.skip_existing and existing_result.exists():
                try:
                    with open(existing_result, encoding="utf-8") as ef:
                        result = json.load(ef)
                    if result.get("status") in ("success", "failed"):
                        logger.info("Skipping %s (already exists, status=%s)", cve_id, result.get("status"))
                        skip = True
                except Exception:
                    pass
            if not skip:
                try:
                    result = runner.run(str(trace_file), args.output_dir)
                except Exception as e:
                    logger.error("Pipeline crashed for %s: %s", cve_id, e)
                    result = {"case_id": cve_id, "status": "crashed", "error": str(e)}

            gt_entry = gt.get(cve_id, {})
            evaluation = evaluate_analysis(result, gt_entry) if gt_entry else {"match": False, "reason": "no_ground_truth"}
            results.append({
                "cve_id": cve_id, "result": result, "evaluation": evaluation,
            })
            status_icon = "OK" if result["status"] == "success" else "FAIL"
            param_icon = "OK" if evaluation.get("match") else "MISS"
            logger.info("[%s] status=%s param=%s", cve_id, status_icon, param_icon)
    else:
        global _port_pool
        _port_pool = queue.Queue()
        for i in range(args.workers):
            _port_pool.put(args.port + i)
        futures = {}
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            for i, trace_file in enumerate(trace_files):
                future = executor.submit(
                    _run_one, trace_file, args.output_dir, args.port,
                    args.max_iterations, gt,
                    args.skip_suricata,
                    not args.no_blackboard,
                    not args.no_deliberation,
                    args.with_manifest,
                    not args.no_agentic_policy,
                    args.stateless_loop,
                    args.reflexion_mode,
                    args.suppress_condition_memory)
                futures[future] = trace_file

            for future in as_completed(futures):
                trace_file = futures[future]
                try:
                    r = future.result()
                    results.append(r)
                    cve_id = r["cve_id"]
                    status = r["result"]["status"]
                    match = r.get("evaluation", {}).get("match", False)
                    done = len(results)
                    logger.info("[%d/%d] %s status=%s param=%s",
                               done, len(trace_files), cve_id,
                               "OK" if status == "success" else "FAIL",
                               "OK" if match else "MISS")
                except Exception as e:
                    cve_id = trace_file.stem
                    logger.error("[%s] worker exception: %s", cve_id, e)
                    results.append({
                        "cve_id": cve_id,
                        "result": {"case_id": cve_id, "status": "crashed", "error": str(e)},
                        "evaluation": {"match": False, "reason": "worker_exception"},
                    })

    results.sort(key=lambda r: r["cve_id"])
    elapsed = time.time() - start_time

    success_count = sum(1 for r in results if r["result"]["status"] == "success")
    param_match_count = sum(1 for r in results if r.get("evaluation", {}).get("match"))

    print("\n" + "=" * 60)
    print(f"HYPOTHESIS PIPELINE E2E RESULTS")
    print(f"=" * 60)
    print(f"Total:           {len(trace_files)}")
    print(f"Workers:         {args.workers}")
    if len(trace_files) > 0:
        print(f"Success:         {success_count}/{len(trace_files)} ({100*success_count/len(trace_files):.1f}%)")
        print(f"Param match:     {param_match_count}/{len(trace_files)} ({100*param_match_count/len(trace_files):.1f}%)")
        print(f"Elapsed:         {elapsed:.1f}s")
        print(f"Avg per trace:   {elapsed/len(trace_files):.1f}s")
    else:
        print("No trace files found — check --traces-dir and --pattern")
        print(f"Elapsed:         {elapsed:.1f}s")
    print()

    for r in results:
        status = "OK" if r["result"]["status"] == "success" else "FAIL"
        param = "OK" if r.get("evaluation", {}).get("match") else "MISS"
        si = r["result"].get("success_iteration")
        iter_info = f"iter={si}" if si is not None else "---"
        print(f"  {r['cve_id']:25s} {status:4s}  {param:4s}  {iter_info}")

    summary_path = Path(args.output_dir) / "e2e_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total": len(trace_files),
            "workers": args.workers,
            "success": success_count,
            "param_match": param_match_count,
            "elapsed_seconds": elapsed,
            "results": [{
                "cve_id": r["cve_id"],
                "status": r["result"]["status"],
                "iterations": len(r["result"].get("iterations", [])),
                "success_iteration": r["result"].get("success_iteration"),
                "evaluation": r.get("evaluation", {}),
            } for r in results],
        }, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print(f"\nSummary saved to {summary_path}")


if __name__ == "__main__":
    main()
