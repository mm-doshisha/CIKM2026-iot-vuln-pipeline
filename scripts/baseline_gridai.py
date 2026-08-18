"""Baseline G1-GRIDAI: Reimplementation of the GRIDAI multi-agent approach
for Suricata rule generation (Li et al., arXiv:2510.13257, 2025).

GRIDAI uses a multi-agent pipeline with separate agents for:
  1. Payload analysis (extract attack attributes)
  2. Rule generation (multiple candidates)
  3. Validation (syntax + detection)
  4. Rule repair (fix failing rules with diagnostic feedback)

This is a clean-room reimplementation using prompts faithful to the paper's
Appendix C. We skip the variant-detection (Aass) and memory-update (Amem)
agents since our benchmark evaluates per-CVE independently.

Same model (Qwen3-8B), same benchmark (281 CVEs), same evaluation harness.

Usage (inside Docker):
    python scripts/baseline_gridai.py \
        --traces-dir benchmarks/traces \
        --output-dir output/gridai_baseline/seed_42 \
        --llm-endpoint http://127.0.0.1:8080/v1/chat/completions \
        --benign-dir benchmarks/traces_benign \
        --seed 42 --workers 4
"""

import argparse
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.evaluation.pcap_generator import generate_attack_pcap
from src.evaluation.suricata_runner import run_suricata, validate_rules

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("baseline_gridai")

LLM_MODEL = "qwen3-8b"
SID_BASE = 6000001
_LLM_SEED: int | None = None


def _call_llm(endpoint: str, messages: list, temperature: float = 0.3,
              max_tokens: int = 4096) -> str:
    payload = json.dumps({
        "model": LLM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        **({"seed": _LLM_SEED} if _LLM_SEED is not None else {}),
    }).encode("utf-8")

    req = Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=300) as resp:
        body = json.loads(resp.read().decode("utf-8"))

    return body["choices"][0]["message"]["content"]


def _truncate(text: str, max_len: int = 512) -> str:
    if len(text) > max_len:
        return text[:max_len] + f"... [truncated, {len(text)} chars]"
    return text


def strip_think_blocks(text: str) -> str:
    cleaned = re.sub(
        r"<\s*think\s*>.*?<\s*/\s*think\s*>",
        "", text, flags=re.DOTALL | re.IGNORECASE,
    )
    cleaned = re.sub(
        r"<\s*think\s*>.*",
        "", cleaned, flags=re.DOTALL | re.IGNORECASE,
    )
    return cleaned.strip()


# ---------------------------------------------------------------------------
# Prompt templates faithful to GRIDAI Appendix C methodology
# ---------------------------------------------------------------------------

ANALYSIS_SYSTEM = """You are a network security analyst specializing in HTTP-based attack analysis. Your task is to analyze an HTTP request payload and identify the attack characteristics.

Analyze the payload and output a structured analysis in JSON format:
{
  "attack_type": "type of attack (e.g., command injection, path traversal, auth bypass)",
  "attack_indicators": ["list of specific strings/patterns that indicate the attack"],
  "target_endpoint": "the targeted URL path",
  "http_method": "GET/POST/PUT",
  "malicious_params": ["parameter names carrying attack payloads"],
  "payload_location": "uri/body/header",
  "key_content_matches": ["specific content strings for Suricata content matching"]
}

Be precise about the attack indicators. Focus on strings that are unique to this attack and would not appear in benign traffic. /no_think"""

GENERATION_SYSTEM = """You are a Suricata IDS rule expert. Given an attack analysis, generate Suricata detection rules.

Guidelines for rule generation (from GRIDAI methodology):
- Generate exactly 3 candidate rules, each on its own line
- Use this exact format: alert http any any -> any any (options;)
- Place sticky buffer keyword BEFORE its content: http.method; content:"POST"; http.uri; content:"/path";
- Use the correct sticky buffer keywords: http.method, http.uri, http.request_body, http.header
- Include flow:established,to_server; msg; sid; rev in all rules
- Each rule needs a unique sid (use sid:PLACEHOLDER1; sid:PLACEHOLDER2; sid:PLACEHOLDER3;)
- Vary specificity: Rule 1 = most specific, Rule 2 = balanced, Rule 3 = most general
- Inside content:"...", encode special chars as hex: ; → |3b| and " → |22|
- Do NOT use deprecated keywords: http_method, http_uri, http_header, http_client_body

Example rule:
alert http any any -> any any (msg:"Example Attack"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/cgi-bin/admin.cgi"; nocase; http.request_body; content:"cmd="; nocase; sid:1000001; rev:1;)

Output exactly 3 rules, one per line. No explanations. /no_think"""

REPAIR_SYSTEM = """You are a Suricata IDS rule repair specialist. A generated rule has failed validation. Your task is to fix the rule based on the diagnostic feedback.

Repair guidelines:
- If the rule has syntax errors: fix the Suricata syntax (correct sticky buffer placement, proper escaping, valid keywords)
- If the rule did not trigger on attack traffic: adjust content matches to align with the actual payload. Verify that content strings are literal substrings of the traffic
- If the rule triggered on benign traffic: make content matches more specific to reduce false positives
- Use this exact format: alert http any any -> any any (options;)
- Do NOT use deprecated keywords
- Place sticky buffer keyword BEFORE its content
- Include flow:established,to_server; msg; sid; rev

Example rule:
alert http any any -> any any (msg:"Example Attack"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/cgi-bin/admin.cgi"; nocase; sid:1000001; rev:1;)

Output ONLY the corrected rule, no explanations. /no_think"""

SELECTION_SYSTEM = """You are evaluating multiple valid Suricata rules for the same attack. Select the single best rule based on these criteria (from GRIDAI methodology):
1. Generalization: covers attack variants without being too broad
2. Conciseness: minimal content keywords while maintaining accuracy
3. Robustness: unlikely to be evaded by minor payload changes
4. Deployment value: practical for production IDS deployment

Output ONLY the number of the best rule (1, 2, or 3). No explanation. /no_think"""


# ---------------------------------------------------------------------------
# Stage 1: Payload analysis
# ---------------------------------------------------------------------------

def _format_body(body) -> str:
    """Format body as URL-encoded form to match PCAP wire format."""
    if isinstance(body, dict):
        from urllib.parse import urlencode
        return urlencode(body, doseq=True)
    return str(body)


def format_payload(trace: dict) -> str:
    req = trace.get("trace", {}).get("request", {})
    resp = trace.get("trace", {}).get("response", {})
    method = req.get("method", "GET")
    path = req.get("path", "/")
    params = req.get("params", {})
    headers = req.get("headers", {})
    body = req.get("body")

    lines = [f"HTTP {method} {path}"]

    if params:
        lines.append("Query Parameters:")
        for k, v in params.items():
            lines.append(f"  {k} = {_truncate(str(v), 256)}")

    notable_headers = {k: v for k, v in headers.items()
                       if k.lower() not in ("host", "connection", "accept",
                                            "user-agent", "accept-encoding",
                                            "content-length")}
    if notable_headers:
        lines.append("Headers:")
        for k, v in notable_headers.items():
            lines.append(f"  {k}: {_truncate(str(v), 256)}")

    if body:
        lines.append(f"Body: {_truncate(_format_body(body), 512)}")

    if resp.get("status_code"):
        lines.append(f"Response: HTTP {resp['status_code']}")

    return "\n".join(lines)


def analyze_payload(endpoint: str, payload_text: str) -> str:
    messages = [
        {"role": "system", "content": ANALYSIS_SYSTEM},
        {"role": "user", "content": f"Analyze this HTTP attack payload:\n\n{payload_text}"},
    ]
    return _call_llm(endpoint, messages)


# ---------------------------------------------------------------------------
# Stage 2: Multi-candidate rule generation
# ---------------------------------------------------------------------------

def generate_candidates(endpoint: str, payload_text: str,
                        analysis: str) -> list[str]:
    messages = [
        {"role": "system", "content": GENERATION_SYSTEM},
        {"role": "user", "content": (
            f"Attack payload:\n{payload_text}\n\n"
            f"Attack analysis:\n{analysis}\n\n"
            "Generate 3 candidate Suricata rules."
        )},
    ]
    raw = _call_llm(endpoint, messages)
    return _extract_rules(raw)


def _normalize_rule(rule: str) -> str:
    """Fix common LLM formatting errors: missing header, missing parens."""
    rule = rule.strip()
    if not rule.startswith("alert "):
        return rule
    m = re.match(r"alert\s+(\w+)\s+(.+)", rule)
    if not m:
        return rule
    proto = m.group(1)
    rest = m.group(2)
    has_header = re.match(r"(\$?\w+\s+\S+\s+->)", rest)
    if "(" not in rest and ";" in rest:
        if has_header:
            header_m = re.match(r"(.+?->.*?\S+\s+\S+)\s+(.*)", rest)
            if header_m:
                return f"alert {proto} {header_m.group(1)} ({header_m.group(2)})"
        return f"alert {proto} any any -> any any ({rest})"
    if "(" in rest and ")" not in rest:
        return rule + ")"
    return rule


def _extract_rules(raw: str) -> list[str]:
    text = strip_think_blocks(raw)
    candidates = []

    for m in re.finditer(r"```(?:\w*)\s*\n(.*?)\n```", text, re.DOTALL):
        for line in m.group(1).splitlines():
            line = line.strip()
            if line.startswith("alert "):
                candidates.append(_normalize_rule(line))

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("alert "):
            normed = _normalize_rule(line)
            if normed not in candidates:
                candidates.append(normed)

    return candidates


# ---------------------------------------------------------------------------
# Stage 3: Validation
# ---------------------------------------------------------------------------

def validate_syntax(rule_text: str) -> tuple:
    tmp_dir = tempfile.mkdtemp(prefix="gridai_syntax_")
    try:
        rules_path = os.path.join(tmp_dir, "test.rules")
        Path(rules_path).write_text(rule_text + "\n", encoding="utf-8")
        result = validate_rules(rules_path, log_dir=tmp_dir)
        if result["valid"]:
            return True, ""
        err_msg = "; ".join(result["errors"][:5]) if result["errors"] else "unknown error"
        return False, err_msg
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def validate_detection(rule_text: str, trace: dict, tmp_dir: str) -> tuple:
    http_req = trace.get("trace", {}).get("request", {})
    pcap_path = os.path.join(tmp_dir, "attack.pcap")
    rules_path = os.path.join(tmp_dir, "detect.rules")

    generate_attack_pcap(http_req, pcap_path)
    Path(rules_path).write_text(rule_text + "\n", encoding="utf-8")

    log_dir = os.path.join(tmp_dir, "suricata_detect")
    result = run_suricata(pcap_path, rules_path, log_dir=log_dir)

    if result.get("error"):
        return False, f"Suricata error: {result['error']}"

    if result["triggered"]:
        return True, ""

    req = trace.get("trace", {}).get("request", {})
    feedback_lines = ["Rule did not trigger on attack traffic."]
    feedback_lines.append(f"  Method: {req.get('method', 'GET')}")
    feedback_lines.append(f"  URI: {_truncate(req.get('path', '/'), 200)}")
    body = req.get("body")
    if body:
        feedback_lines.append(f"  Body: {_truncate(str(body), 200)}")

    content_matches = re.findall(r'content:"([^"]*)"', rule_text)
    full_request = f"{req.get('method', '')} {req.get('path', '')}"
    if body:
        full_request += f" {body}"
    for kw in content_matches:
        present = kw in full_request or kw.lower() in full_request.lower()
        feedback_lines.append(f'  content:"{kw}" -> {"FOUND" if present else "NOT FOUND"}')

    return False, "\n".join(feedback_lines)


def validate_benign(rule_text: str, benign_dir: str, tmp_dir: str) -> tuple:
    rules_path = os.path.join(tmp_dir, "benign.rules")
    Path(rules_path).write_text(rule_text + "\n", encoding="utf-8")

    benign_files = sorted(Path(benign_dir).glob("BENIGN-*.json"))
    if not benign_files:
        return True, ""

    fp_cases = []
    for bf in benign_files:
        try:
            benign_trace = json.loads(bf.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        benign_req = benign_trace.get("trace", {}).get("request", {})
        pcap_path = os.path.join(tmp_dir, f"benign_{bf.stem}.pcap")
        generate_attack_pcap(benign_req, pcap_path, sport=30000)

        log_dir = os.path.join(tmp_dir, f"benign_log_{bf.stem}")
        result = run_suricata(pcap_path, rules_path, log_dir=log_dir)
        if result["triggered"]:
            fp_cases.append(bf.stem)

    if not fp_cases:
        return True, ""
    return False, f"False positives on: {', '.join(fp_cases[:5])}"


# ---------------------------------------------------------------------------
# Stage 4: Rule repair
# ---------------------------------------------------------------------------

def repair_rule(endpoint: str, rule_text: str, payload_text: str,
                feedback: str, feedback_type: str) -> str:
    if feedback_type == "syntax":
        context = f"Syntax error: {feedback}"
    elif feedback_type == "detection":
        context = f"Detection failure: {feedback}"
    elif feedback_type == "fp":
        context = f"False positive: {feedback}"
    else:
        context = feedback

    messages = [
        {"role": "system", "content": REPAIR_SYSTEM},
        {"role": "user", "content": (
            f"Original attack payload:\n{payload_text}\n\n"
            f"Failed rule:\n{rule_text}\n\n"
            f"Failure diagnosis:\n{context}\n\n"
            "Output the corrected rule."
        )},
    ]
    raw = _call_llm(endpoint, messages)
    rules = _extract_rules(raw)
    if rules:
        return rules[-1]
    raise ValueError("No rule in repair output")


# ---------------------------------------------------------------------------
# Stage 5: Rule selection (from valid candidates)
# ---------------------------------------------------------------------------

def select_best_rule(endpoint: str, candidates: list[str],
                     payload_text: str) -> str:
    if len(candidates) == 1:
        return candidates[0]

    rule_list = "\n".join(
        f"Rule {i+1}: {r}" for i, r in enumerate(candidates)
    )
    messages = [
        {"role": "system", "content": SELECTION_SYSTEM},
        {"role": "user", "content": (
            f"Attack payload:\n{payload_text}\n\n"
            f"Valid candidate rules:\n{rule_list}\n\n"
            "Which rule number is best?"
        )},
    ]
    raw = _call_llm(endpoint, messages)
    text = strip_think_blocks(raw)

    for ch in text:
        if ch.isdigit():
            idx = int(ch) - 1
            if 0 <= idx < len(candidates):
                return candidates[idx]

    return candidates[0]


# ---------------------------------------------------------------------------
# Main GRIDAI pipeline for one CVE
# ---------------------------------------------------------------------------

def _set_sid(rule: str, sid: int) -> str:
    """Set SID in rule, only matching sid: outside content quotes."""
    if re.search(r'\bsid:\s*\w+', rule):
        rule = re.sub(r'\bsid:\s*\w+', f"sid:{sid}", rule, count=1)
    else:
        if rule.rstrip().endswith(")"):
            rule = rule.rstrip()[:-1] + f" sid:{sid}; rev:1;)"
    return rule


def run_gridai_one(cve_id: str, trace: dict, endpoint: str,
                   max_repair_rounds: int = 5,
                   benign_dir: str = None,
                   sid: int = SID_BASE) -> dict:
    start = time.time()
    payload_text = format_payload(trace)

    # Stage 1: Payload analysis
    logger.info("[%s] Stage 1: Analyzing payload", cve_id)
    try:
        analysis = analyze_payload(endpoint, payload_text)
    except Exception as e:
        logger.warning("[%s] Analysis failed: %s", cve_id, e)
        analysis = "Analysis unavailable. Generate rules directly from the payload."

    # Stage 2: Multi-candidate rule generation
    logger.info("[%s] Stage 2: Generating candidates", cve_id)
    try:
        candidates = generate_candidates(endpoint, payload_text, analysis)
    except Exception as e:
        logger.warning("[%s] Generation failed: %s", cve_id, e)
        elapsed = time.time() - start
        return {
            "case_id": cve_id,
            "status": "failed",
            "error": f"generation_failed: {e}",
            "suricata_rule": "",
            "baseline": "gridai",
            "elapsed_seconds": elapsed,
        }

    if not candidates:
        elapsed = time.time() - start
        return {
            "case_id": cve_id,
            "status": "failed",
            "error": "no_candidates_generated",
            "suricata_rule": "",
            "baseline": "gridai",
            "elapsed_seconds": elapsed,
        }

    logger.info("[%s] Generated %d candidates", cve_id, len(candidates))

    # Stage 3: Validate each candidate + Stage 4: Repair failing ones
    valid_rules = []
    repair_log = []

    for i, rule in enumerate(candidates):
        rule = _set_sid(rule, sid + i)
        rule_valid = False

        for repair_round in range(max_repair_rounds + 1):
            label = f"candidate {i+1}" + (f" repair {repair_round}" if repair_round > 0 else "")

            # 3a: Syntax check
            passed, err = validate_syntax(rule)
            if not passed:
                logger.info("[%s] %s syntax FAIL: %s", cve_id, label, err[:100])
                repair_log.append({"candidate": i, "round": repair_round,
                                   "stage": "syntax", "error": err[:200]})
                if repair_round < max_repair_rounds:
                    try:
                        rule = repair_rule(endpoint, rule, payload_text, err, "syntax")
                        rule = _set_sid(rule, sid + i)
                    except Exception as e:
                        logger.warning("[%s] Repair failed: %s", cve_id, e)
                        break
                continue

            # 3b: Detection check
            tmp_dir = tempfile.mkdtemp(prefix=f"gridai_{cve_id}_")
            try:
                passed, err = validate_detection(rule, trace, tmp_dir)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)

            if not passed:
                logger.info("[%s] %s detection FAIL", cve_id, label)
                repair_log.append({"candidate": i, "round": repair_round,
                                   "stage": "detection", "error": err[:200]})
                if repair_round < max_repair_rounds:
                    try:
                        rule = repair_rule(endpoint, rule, payload_text, err, "detection")
                        rule = _set_sid(rule, sid + i)
                    except Exception as e:
                        logger.warning("[%s] Repair failed: %s", cve_id, e)
                        break
                continue

            # 3c: False positive check.
            # GRIDAI_FAITHFUL=1 disables this benign-FP gate to match the paper:
            # in GRIDAI (arXiv:2510.13257 §3) benign traffic is NOT used inside the
            # synthesis/repair loop — only attack-firing is validated there; benign
            # appears only in the final BAR evaluation. Our default added a benign
            # gate (charitable to GRIDAI's FPR). The faithful run removes it so
            # GRIDAI's true deployed FPR is measured.
            _faithful = os.environ.get("GRIDAI_FAITHFUL") == "1"
            if benign_dir and Path(benign_dir).exists() and not _faithful:
                tmp_dir = tempfile.mkdtemp(prefix=f"gridai_fp_{cve_id}_")
                try:
                    passed, err = validate_benign(rule, benign_dir, tmp_dir)
                finally:
                    shutil.rmtree(tmp_dir, ignore_errors=True)

                if not passed:
                    logger.info("[%s] %s FP FAIL: %s", cve_id, label, err[:100])
                    repair_log.append({"candidate": i, "round": repair_round,
                                       "stage": "fp", "error": err[:200]})
                    if repair_round < max_repair_rounds:
                        try:
                            rule = repair_rule(endpoint, rule, payload_text, err, "fp")
                            rule = _set_sid(rule, sid + i)
                        except Exception as e:
                            logger.warning("[%s] Repair failed: %s", cve_id, e)
                            break
                    continue

            # All checks passed
            rule_valid = True
            valid_rules.append(rule)
            logger.info("[%s] %s PASSED all checks", cve_id, label)
            break

    elapsed = time.time() - start

    if not valid_rules:
        # Return best-effort: the last candidate rule
        best_effort = candidates[-1] if candidates else ""
        best_effort = _set_sid(best_effort, sid)
        logger.warning("[%s] No valid rules after repair (%.1fs)", cve_id, elapsed)
        return {
            "case_id": cve_id,
            "status": "failed",
            "suricata_rule": best_effort,
            "baseline": "gridai",
            "analysis": analysis,
            "candidates_generated": len(candidates),
            "valid_rules": 0,
            "repair_log": repair_log,
            "elapsed_seconds": elapsed,
        }

    # Stage 5: Select best rule if multiple valid
    if len(valid_rules) > 1:
        logger.info("[%s] Selecting best from %d valid rules", cve_id, len(valid_rules))
        try:
            best_rule = select_best_rule(endpoint, valid_rules, payload_text)
        except Exception:
            best_rule = valid_rules[0]
    else:
        best_rule = valid_rules[0]

    best_rule = _set_sid(best_rule, sid)

    logger.info("[%s] SUCCESS (%.1fs)", cve_id, elapsed)
    return {
        "case_id": cve_id,
        "status": "success",
        "suricata_rule": best_rule,
        "baseline": "gridai",
        "analysis": analysis,
        "candidates_generated": len(candidates),
        "valid_rules": len(valid_rules),
        "repair_log": repair_log,
        "elapsed_seconds": elapsed,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Baseline G1-GRIDAI: multi-agent Suricata rule generation")
    parser.add_argument("--traces-dir", default="benchmarks/traces")
    parser.add_argument("--pattern", default="CVE-*.json", help="Glob pattern for trace files")
    parser.add_argument("--output-dir", default="output/g1_gridai/seed_42")
    parser.add_argument("--llm-endpoint",
                        default="http://127.0.0.1:8080/v1/chat/completions")
    parser.add_argument("--benign-dir", default="benchmarks/traces_benign")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--max-repair-rounds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=None,
                        help="LLM seed for reproducibility")
    parser.add_argument("--cve-list", default=None)
    args = parser.parse_args()

    global _LLM_SEED
    if args.seed is not None:
        _LLM_SEED = args.seed
        logger.info("LLM seed set to %d", args.seed)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    traces_dir = Path(args.traces_dir)

    cve_filter = None
    if args.cve_list:
        with open(args.cve_list, encoding="utf-8") as f:
            cve_filter = set(json.load(f))

    tasks = []
    for trace_file in sorted(traces_dir.glob(args.pattern)):
        cve_id = trace_file.stem
        if cve_filter and cve_id not in cve_filter:
            continue
        out_file = out_dir / f"{cve_id}.json"
        if args.skip_existing and out_file.exists():
            continue
        tasks.append((cve_id, trace_file))

    logger.info("Running GRIDAI baseline on %d CVEs with %d workers",
                len(tasks), args.workers)

    completed = 0
    failed = 0
    start_time = time.time()

    def _process(item):
        idx, (cve_id, trace_path) = item
        with open(trace_path, encoding="utf-8") as f:
            trace = json.load(f)

        sid = SID_BASE + idx * 10
        result = run_gridai_one(cve_id, trace, args.llm_endpoint,
                                max_repair_rounds=args.max_repair_rounds,
                                benign_dir=args.benign_dir,
                                sid=sid)
        out_file = out_dir / f"{cve_id}.json"
        out_file.write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return cve_id, result["status"]

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(_process, (i, t)): t[0]
                   for i, t in enumerate(tasks)}
        for future in as_completed(futures):
            cve_id = futures[future]
            try:
                _, status = future.result()
                completed += 1
                if status != "success":
                    failed += 1
                if completed % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = completed / elapsed * 3600
                    logger.info("Progress: %d/%d (%.0f CVE/hr), failed=%d",
                                completed, len(tasks), rate, failed)
            except Exception as e:
                failed += 1
                completed += 1
                logger.error("Error on %s: %s", cve_id, e)

    total_time = time.time() - start_time
    logger.info("Done: %d completed, %d failed, %.1f seconds total",
                completed, failed, total_time)


if __name__ == "__main__":
    main()
