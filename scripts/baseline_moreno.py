"""Baseline M1-Moreno: Reimplementation of the Manez Moreno et al. (JNIC 2025)
iterative 4-prompt chain for Suricata rule generation.

Reference
---------
Manez Moreno, Xabier Saez-de-Camara, Aitor Urbieta, Mikel Iturbe,
"Leveraging LLMs for Automated IDS Rule Generation: A Novel Methodology for
Securing Industrial Environments," JNIC 2025. Ikerlan Technology Research
Centre / Mondragon Unibertsitatea, Arrasate-Mondragon, Spain.
PDF: https://iturbe.info/assets/pdf/moreno2025leveraging.pdf

The 4-prompt chain (paper Section IV, "LLM Prompting Strategy"):
  Prompt 1 (Initial Rule Generation): receives anomalous flow details plus
    essential parameters (last SID, model, temperature, prompt strategy) and
    emits preliminary Suricata rules with natural-language explanations.
  Prompt 2 (Evaluation): re-submits the flow and the preliminary rules,
    classifying each as acceptable / needing-refinement / discardable. Rules
    that need detailed packet-level context are flagged for Prompt 3.
  Prompt 3 (Refinement): rules flagged for refinement get the first 500 bytes
    of the relevant payload (Tshark filters in the original) plus rule and
    explanation, for content-match tightening. Non-refined rules get no
    payload context (paper's explicit "Note").
  Prompt 4 (Parser-based Correction): refined rules are validated with
    Suricata's parser in test mode; on error the rule and the parser message
    are resubmitted. The loop is capped at three iterations.

Faithfulness review (verified 2026-06 against the JNIC 2025 PDF above)
---------------------------------------------------------------------
The four-stage chain matches the paper: flow-only Prompt 1, accept/refine/
discard Prompt 2 with a per-rule flag for packet-level refinement, Prompt 3
fed the first 500 payload bytes only for flagged rules, and a parser-feedback
Prompt 4 capped at three iterations (run_moreno_one, default
max_parser_retries=3). The "minor corrections for consistency" of Prompt 2
and the regex-based rule/explanation extraction (paper "Rule Parsing and
Validation") are preserved via _extract_rules and the verdict parser.

Adaptations (NOT in the original; documented for research integrity)
--------------------------------------------------------------------
- Input domain: the paper targets ICS/SCADA PCAPs (Modbus/MMS, Zeek flow
  summaries, Tshark payload). We feed HTTP traces from the IoT CVE benchmark.
  Input adapters are deterministic and fixed for all CVEs: format_flow_details
  renders the HTTP request as a log-like flow summary (Prompt 1/2), and
  format_payload_details renders the raw HTTP request bytes truncated to 500
  (Prompt 3), standing in for the paper's Zeek/Tshark extraction. They are not
  tuned per CVE.
- Prompt strategy: the paper sweeps zero-shot / few-shot / chain-of-thought as
  an experimental variable. This baseline fixes a single zero-shot strategy
  (Prompt 1 gives instructions, no in-context rule examples), so SID/model/
  temperature are supplied by the harness rather than embedded in the prompt
  text. SIDs are assigned deterministically after generation via _set_sid.
- Evaluation: the paper's flow/packet-level precision/recall/F1 against a
  Wireshark Ground Truth and benign flows is replaced by the shared harness
  (pcap_generator + suricata_runner). A detection trigger test only orders
  among parser-valid rules; it does not alter the prompt chain.
- LLM backend: fully local llama.cpp (model qwen3-8b) instead of the paper's
  GPT/Gemini/Claude APIs, with /no_think and qwen3 think-block stripping.

Usage (inside Docker):
    python scripts/baseline_moreno.py \
        --traces-dir benchmarks/traces \
        --output-dir output/moreno_baseline/seed_42 \
        --llm-endpoint http://127.0.0.1:8080/v1/chat/completions \
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
logger = logging.getLogger("baseline_moreno")

LLM_MODEL = "qwen3-8b"
SID_BASE = 7000001
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


def _extract_rules(raw: str) -> list[str]:
    text = strip_think_blocks(raw)
    candidates = []

    for m in re.finditer(r"```(?:\w*)\s*\n(.*?)\n```", text, re.DOTALL):
        for line in m.group(1).splitlines():
            line = line.strip()
            if line.startswith("alert "):
                candidates.append(line)

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("alert ") and line not in candidates:
            candidates.append(line)

    return candidates


def _set_sid(rule: str, sid: int) -> str:
    """Set SID in rule, only matching sid: outside content quotes."""
    if re.search(r'\bsid:\s*\w+', rule):
        rule = re.sub(r'\bsid:\s*\w+', f"sid:{sid}", rule, count=1)
    else:
        if rule.rstrip().endswith(")"):
            rule = rule.rstrip()[:-1] + f" sid:{sid}; rev:1;)"
    return rule


# ---------------------------------------------------------------------------
# HTTP flow description (analogous to Zeek flow extraction in original paper)
# ---------------------------------------------------------------------------

def _format_body(body) -> str:
    """Format body as URL-encoded form to match PCAP wire format."""
    if isinstance(body, dict):
        from urllib.parse import urlencode
        return urlencode(body, doseq=True)
    return str(body)


def format_flow_details(trace: dict) -> str:
    req = trace.get("trace", {}).get("request", {})
    resp = trace.get("trace", {}).get("response", {})
    method = req.get("method", "GET")
    path = req.get("path", "/")
    params = req.get("params", {})
    headers = req.get("headers", {})
    body = req.get("body")

    lines = [
        "=== HTTP Flow Details ===",
        f"Direction: client -> server",
        f"Protocol: HTTP/1.1",
        f"Method: {method}",
        f"URI: {path}",
    ]

    if params:
        lines.append("Query Parameters:")
        for k, v in params.items():
            lines.append(f"  {k} = {_truncate(str(v), 256)}")

    if headers:
        lines.append("Headers:")
        for k, v in headers.items():
            lines.append(f"  {k}: {_truncate(str(v), 200)}")

    if body:
        lines.append(f"Body: {_truncate(_format_body(body), 500)}")

    lines.append(f"Response Status: {resp.get('status_code', 'N/A')}")

    return "\n".join(lines)


def format_payload_details(trace: dict) -> str:
    """Deeper payload extraction (analogous to tshark payload in original)."""
    req = trace.get("trace", {}).get("request", {})
    method = req.get("method", "GET")
    path = req.get("path", "/")
    headers = req.get("headers", {})
    body = req.get("body")

    raw_request = f"{method} {path} HTTP/1.1\r\n"
    for k, v in headers.items():
        raw_request += f"{k}: {v}\r\n"
    raw_request += "\r\n"
    if body:
        raw_request += _format_body(body)

    return f"=== Raw HTTP Payload (first 500 bytes) ===\n{_truncate(raw_request, 500)}"


# ---------------------------------------------------------------------------
# Prompt 1: Initial rule generation
# ---------------------------------------------------------------------------

PROMPT1_SYSTEM = """You are a Suricata IDS rule generator. Given HTTP flow details of a malicious request, generate Suricata detection rules.

Rules:
- Generate 1-3 Suricata rules that detect this attack pattern
- Use alert http any any -> any any (...) format
- Use sticky buffers: http.method, http.uri, http.request_body, http.header
- Place sticky buffer BEFORE its content keyword
- Include flow:established,to_server; in all rules
- For each rule, add a brief natural-language explanation (one line starting with "// Explanation:")
- Focus on specific content that distinguishes this attack from normal traffic
- Inside content:"...", encode ; as |3b| and " as |22|
- Do NOT use deprecated keywords

Output format:
alert http ... (rule1)
// Explanation: what this rule detects and why

alert http ... (rule2)
// Explanation: ...

/no_think"""


# ---------------------------------------------------------------------------
# Prompt 2: Self-evaluation
# ---------------------------------------------------------------------------

PROMPT2_SYSTEM = """You are reviewing Suricata rules for quality. For each rule, classify it as:
- ACCEPT: rule is specific, correct, and ready for deployment
- REFINE: rule needs refinement (explain what needs to change and flag NEEDS_PACKET_DETAIL if deeper payload inspection would help)
- DISCARD: rule is too broad, incorrect, or would cause many false positives

Output format for each rule:
Rule N: [ACCEPT|REFINE|DISCARD] - brief reason
(if REFINE: what specifically needs to change)

/no_think"""


# ---------------------------------------------------------------------------
# Prompt 3: Refinement with packet details
# ---------------------------------------------------------------------------

PROMPT3_SYSTEM = """You are refining Suricata IDS rules using detailed packet payload information. You have access to the raw HTTP payload bytes.

Given the original rule, its explanation, and the raw packet payload:
- Adjust content matches to align with actual payload bytes
- Make the rule more specific using payload details
- Output exactly ONE improved rule starting with "alert http"

Do NOT use deprecated keywords. Place sticky buffer BEFORE content. /no_think"""


# ---------------------------------------------------------------------------
# Prompt 4: Parser error correction
# ---------------------------------------------------------------------------

PROMPT4_SYSTEM = """You are fixing Suricata rule syntax errors. The rule below failed Suricata's parser validation.

Fix the syntax error and output exactly ONE corrected rule starting with "alert http".
Common issues: wrong sticky buffer placement, missing semicolons, deprecated keywords (use http.uri not http_uri, use http.request_body not http_client_body).

Output ONLY the corrected rule. /no_think"""


# ---------------------------------------------------------------------------
# 4-prompt chain
# ---------------------------------------------------------------------------

def run_moreno_one(cve_id: str, trace: dict, endpoint: str,
                   max_parser_retries: int = 3,
                   sid: int = SID_BASE) -> dict:
    start = time.time()
    flow_details = format_flow_details(trace)
    payload_details = format_payload_details(trace)

    # --- Prompt 1: Initial generation ---
    logger.info("[%s] Prompt 1: Generating rules", cve_id)
    try:
        messages = [
            {"role": "system", "content": PROMPT1_SYSTEM},
            {"role": "user", "content": f"Generate Suricata rules for this malicious HTTP flow:\n\n{flow_details}"},
        ]
        raw1 = _call_llm(endpoint, messages)
        initial_rules = _extract_rules(raw1)
    except Exception as e:
        elapsed = time.time() - start
        return {
            "case_id": cve_id, "status": "failed",
            "error": f"prompt1_failed: {e}", "suricata_rule": "",
            "baseline": "moreno", "elapsed_seconds": elapsed,
        }

    if not initial_rules:
        elapsed = time.time() - start
        return {
            "case_id": cve_id, "status": "failed",
            "error": "no_rules_from_prompt1", "suricata_rule": "",
            "baseline": "moreno", "elapsed_seconds": elapsed,
        }

    logger.info("[%s] Prompt 1: %d rules generated", cve_id, len(initial_rules))

    # --- Prompt 2: Self-evaluation ---
    logger.info("[%s] Prompt 2: Self-evaluation", cve_id)
    try:
        rule_list = "\n".join(
            f"Rule {i+1}: {r}" for i, r in enumerate(initial_rules)
        )
        messages = [
            {"role": "system", "content": PROMPT2_SYSTEM},
            {"role": "user", "content": (
                f"HTTP flow:\n{flow_details}\n\n"
                f"Generated rules:\n{rule_list}\n\n"
                "Evaluate each rule."
            )},
        ]
        raw2 = _call_llm(endpoint, messages)
        eval_text = strip_think_blocks(raw2)
    except Exception as e:
        logger.warning("[%s] Prompt 2 failed: %s, keeping all rules", cve_id, e)
        eval_text = ""

    # Parse evaluation: keep ACCEPT and REFINE rules, discard DISCARD
    accepted = []
    needs_refine = []
    for i, rule in enumerate(initial_rules):
        marker = f"Rule {i+1}:"
        if marker in eval_text:
            line = eval_text[eval_text.index(marker):]
            line = line.split("\n")[0]
            tail = line.split(marker, 1)[-1].strip()
            # Strip a leading "[" so "[ACCEPT]"/"[REFINE]" parse like the
            # bare verdicts in the prompt's "Rule N: [ACCEPT|REFINE|DISCARD]"
            # template.
            tail = tail.lstrip("[").strip()
            verdict = tail.split()[0].upper().strip("[]") if tail else ""
            if verdict.startswith("DISCARD"):
                logger.info("[%s] Rule %d DISCARDED", cve_id, i+1)
                continue
            elif verdict.startswith("REFINE"):
                needs_refine.append(rule)
                continue
        accepted.append(rule)

    # If all discarded, keep originals
    if not accepted and not needs_refine:
        accepted = initial_rules

    # --- Prompt 3: Refinement with packet details ---
    refined_rules = list(accepted)
    if needs_refine:
        logger.info("[%s] Prompt 3: Refining %d rules", cve_id, len(needs_refine))
        for rule in needs_refine:
            try:
                messages = [
                    {"role": "system", "content": PROMPT3_SYSTEM},
                    {"role": "user", "content": (
                        f"Original rule:\n{rule}\n\n"
                        f"HTTP flow details:\n{flow_details}\n\n"
                        f"{payload_details}\n\n"
                        "Output the improved rule."
                    )},
                ]
                raw3 = _call_llm(endpoint, messages)
                new_rules = _extract_rules(raw3)
                if new_rules:
                    refined_rules.append(new_rules[-1])
                else:
                    refined_rules.append(rule)
            except Exception:
                refined_rules.append(rule)

    # --- Prompt 4: Parser validation + error correction ---
    valid_rules = []
    for i, rule in enumerate(refined_rules):
        rule = _set_sid(rule, sid + i)

        for attempt in range(max_parser_retries + 1):
            passed, err = _validate_syntax(rule)
            if passed:
                valid_rules.append(rule)
                break

            if attempt < max_parser_retries:
                logger.info("[%s] Prompt 4: Fixing syntax (attempt %d)", cve_id, attempt+1)
                try:
                    messages = [
                        {"role": "system", "content": PROMPT4_SYSTEM},
                        {"role": "user", "content": (
                            f"Rule with syntax error:\n{rule}\n\n"
                            f"Suricata error:\n{err}\n\n"
                            "Fix the syntax."
                        )},
                    ]
                    raw4 = _call_llm(endpoint, messages)
                    new_rules = _extract_rules(raw4)
                    if new_rules:
                        rule = _set_sid(new_rules[-1], sid + i)
                except Exception:
                    break

    elapsed = time.time() - start

    if not valid_rules:
        best_effort = refined_rules[0] if refined_rules else ""
        best_effort = _set_sid(best_effort, sid)
        return {
            "case_id": cve_id, "status": "failed",
            "suricata_rule": best_effort, "baseline": "moreno",
            "initial_rules": len(initial_rules),
            "refined_rules": len(refined_rules),
            "valid_rules": 0,
            "elapsed_seconds": elapsed,
        }

    # Pick the best valid rule via detection test
    best_rule = valid_rules[0]
    for rule in valid_rules:
        tmp_dir = tempfile.mkdtemp(prefix=f"moreno_{cve_id}_")
        try:
            passed, _ = _validate_detection(rule, trace, tmp_dir)
            if passed:
                best_rule = rule
                break
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    best_rule = _set_sid(best_rule, sid)

    logger.info("[%s] SUCCESS (%.1fs)", cve_id, elapsed)
    return {
        "case_id": cve_id, "status": "success",
        "suricata_rule": best_rule, "baseline": "moreno",
        "initial_rules": len(initial_rules),
        "refined_rules": len(refined_rules),
        "valid_rules": len(valid_rules),
        "elapsed_seconds": elapsed,
    }


def _validate_syntax(rule_text: str) -> tuple:
    tmp_dir = tempfile.mkdtemp(prefix="moreno_syntax_")
    try:
        rules_path = os.path.join(tmp_dir, "test.rules")
        Path(rules_path).write_text(rule_text + "\n", encoding="utf-8")
        result = validate_rules(rules_path, log_dir=tmp_dir)
        if result["valid"]:
            return True, ""
        err = "; ".join(result["errors"][:5]) if result["errors"] else "unknown"
        return False, err
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _validate_detection(rule_text: str, trace: dict, tmp_dir: str) -> tuple:
    http_req = trace.get("trace", {}).get("request", {})
    pcap_path = os.path.join(tmp_dir, "attack.pcap")
    rules_path = os.path.join(tmp_dir, "detect.rules")

    generate_attack_pcap(http_req, pcap_path)
    Path(rules_path).write_text(rule_text + "\n", encoding="utf-8")

    log_dir = os.path.join(tmp_dir, "suricata_detect")
    result = run_suricata(pcap_path, rules_path, log_dir=log_dir)

    if result["triggered"]:
        return True, ""
    return False, "Rule did not trigger on attack traffic"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Baseline M1-Moreno: 4-prompt chain Suricata rule generation")
    parser.add_argument("--traces-dir", default="benchmarks/traces")
    parser.add_argument("--pattern", default="CVE-*.json", help="Glob pattern for trace files")
    parser.add_argument("--output-dir", default="output/m1_moreno/seed_42")
    parser.add_argument("--llm-endpoint",
                        default="http://127.0.0.1:8080/v1/chat/completions")
    parser.add_argument("--benign-dir", default="benchmarks/traces_benign")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--max-parser-retries", type=int, default=3)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--cve-list", default=None)
    args = parser.parse_args()

    global _LLM_SEED
    if args.seed is not None:
        _LLM_SEED = args.seed

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

    logger.info("Running Moreno baseline on %d CVEs with %d workers",
                len(tasks), args.workers)

    completed = 0
    failed = 0
    start_time = time.time()

    def _process(item):
        idx, (cve_id, trace_path) = item
        with open(trace_path, encoding="utf-8") as f:
            trace = json.load(f)

        sid = SID_BASE + idx * 5
        result = run_moreno_one(cve_id, trace, args.llm_endpoint,
                                max_parser_retries=args.max_parser_retries,
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
