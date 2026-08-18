"""Runner: Per-trace CEGIS loop controller.

Flow:
  1. Analyst.analyze() -> hypothesis
  2. CEGIS loop:
     a. CodeGen.generate() -> mock server (skeleton + LLM detection condition)
     b. TestRunner.test() -> T1-T4 results + attribution
     c. If pass -> RuleGen.generate() -> Suricata rule
     d. If fail -> analyze_and_direct() -> direction for next CodeGen
  3. If all fail -> Analyst.try_alternative() -> mini CEGIS
"""
from __future__ import annotations

import json
import logging
import os
import copy
import subprocess
import time as _time
from pathlib import Path

from ..temperature import TEMP_GENERATIVE, TEMP_STRUCTURED
from ..analyst import _extract_request_only, _extract_response, decode_request_for_analysis
from ..analyst import _call_llm, _extract_json
from ..skeleton import (parse_request_params, identify_param,
                        generate_request_manifest, _has_named_fields,
                        _is_body_generic, _param_type)
from ..llm_server import ensure_healthy
from ..rule_pcre_guard import drop_phantom_pcre
from .analyst_tool import Analyst
from .codegen_tool import CodeGen
from .test_tool import TestRunner
from .rule_agent import RuleGenAgent

logger = logging.getLogger("runner")

MAX_ITERATIONS = int(os.environ.get("MAX_ITERATIONS", "7"))
ALT_ITERATIONS = int(os.environ.get("ALT_ITERATIONS", "3"))
SAME_FAILURE_STOP = int(os.environ.get("SAME_FAILURE_STOP", "3"))
_MAX_SOFT_REVISIONS = 2
TEST_FAILURES = frozenset({"T1", "T2", "T3", "T4"})


def _should_enter_alt_phase(iterations: list[dict]) -> tuple[bool, str]:
    """Decide whether failed main-loop evidence justifies alt hypothesis."""
    failed_iters = [it for it in iterations if it.get("counterexample")]
    if not failed_iters:
        return False, "no_failures"

    failure_types = [
        it["counterexample"].get("failed_test", "unknown")
        for it in failed_iters
    ]
    test_failure_iters = [
        it for it, ft in zip(failed_iters, failure_types)
        if ft in TEST_FAILURES
    ]
    if not test_failure_iters:
        cgf_count = sum(1 for ft in failure_types if ft == "CONDITION_GEN_FAILED")
        if cgf_count >= SAME_FAILURE_STOP:
            return True, f"condition_gen_failed_persistent ({cgf_count}x)"
        return False, "no_test_failures"

    latest_test_failure = test_failure_iters[-1]
    diagnosis = latest_test_failure.get("counterexample", {}).get(
        "llm_diagnosis", {}) or {}
    if diagnosis.get("is_hypothesis_wrong"):
        return True, "hypothesis_wrong_in_latest_test_failure"

    test_types = [ft for ft in failure_types if ft in TEST_FAILURES]
    consecutive = 1
    for i in range(1, len(test_types)):
        if test_types[i] == test_types[i - 1]:
            consecutive += 1
            if consecutive >= 3:
                return True, f"same_test_3x ({test_types[i]})"
        else:
            consecutive = 1

    return False, "no_signal"


def _is_null_param(dangerous_param) -> bool:
    """Check if the LLM returned a null-equivalent dangerous_param."""
    if dangerous_param is None:
        return True
    dp_str = str(dangerous_param).lower().strip()
    return dp_str in ("null", "none", "n/a", "") or dp_str.startswith("no ")


# --- Stage-3 fallback (param=none recovery) ---------------------------------
# When the analyst flags an attack but no parameter can be resolved (the
# unresolved_param give-up point), a dedicated extract-or-NONE LLM tries to pull
# the malicious substring directly and wire-renders it into a rule. This is a
# POST-HOC improvement (not pre-registered); the prompt is a generic
# extract-or-NONE form, not fitted to the eval set. Logic mirrors
# scripts/fallback_3seed.py exactly so an integrated run reproduces its measured
# recovery. Gated by env FALLBACK_PARAM_NONE=1 (default off) until validated
# end-to-end on the LLM server.
_FB_SYS_NOEX = (
    "You are an intrusion-detection analyst. You receive ONE HTTP request and "
    "must decide whether it carries an attack payload: a byte sequence that is "
    "malicious on its own, independent of application context. A normal request to "
    "a sensitive endpoint, or an ordinary parameter value, is NOT an attack "
    "payload. Be strict: name a payload only when the substring is unambiguously "
    "malicious by itself; when in doubt, answer NONE.")
_FB_USER_TMPL = (
    "HTTP request:\n%s\n\nRespond with EXACTLY one line:\n"
    "`PAYLOAD: <the exact malicious substring, copied verbatim from the request>`\n"
    "or\n`NONE`")
_FB_WIRE_BUFFERS = ("http.request_body", "http.uri", "http.uri.raw", "http.cookie",
                    "http.header", "http.user_agent", "http.host")


def _param_none_fallback_rule(http_request: dict):
    """Return a Suricata rule string that fires on this request via a directly
    extracted malicious substring, or None. See block comment above."""
    import re as _re
    from src.hypothesis.analyst import _call_llm
    from src.hypothesis.rule_template import escape_content
    from src.evaluation.pcap_generator import wire_buffers
    req = http_request or {}
    rj = json.dumps({k: req.get(k) for k in
                     ("method", "path", "params", "headers", "body")},
                    indent=2, ensure_ascii=False)
    msgs = [{"role": "system", "content": _FB_SYS_NOEX},
            {"role": "user", "content": _FB_USER_TMPL % rj}]
    try:
        out = _call_llm(msgs, temperature=0.0, max_tokens=200).strip()
    except Exception as e:
        logger.warning("param-none fallback LLM call failed: %s", e)
        return None
    m = _re.search(r"PAYLOAD:\s*(.+)", out)
    if not m:
        return None
    token = m.group(1).strip().strip('`"\' ')
    if not token:
        return None
    # The extracted substring must actually appear in the request (no hallucination).
    b = req.get("body")
    bs = json.dumps(b) if isinstance(b, (dict, list)) else (str(b) if b else "")
    blob = str(req.get("path") or "") + " " + bs + " " + str(req.get("params") or {})
    if token not in blob:
        return None
    wb = wire_buffers(req)
    for buf in _FB_WIRE_BUFFERS:
        wv = RuleGenAgent._wire_content(token, buf, wb)
        if wv:
            return ('alert http any any -> any any (flow:established,to_server; '
                    '%s; content:"%s"; sid:9900100; rev:1;)'
                    % (buf, escape_content(wv)))
    return None


class Runner:

    def __init__(self, port: int = 9090, max_iterations: int = None,
                 skip_suricata: bool = False,
                 use_blackboard: bool = True,
                 use_deliberation: bool = True,
                 use_manifest: bool = False,
                 use_agentic_policy: bool = True,
                 stateless_loop: bool = False,
                 reflexion_mode: bool = False,
                 suppress_condition_memory: bool = False):
        self.max_iterations = max_iterations or MAX_ITERATIONS
        self.skip_suricata = skip_suricata
        self.use_blackboard = use_blackboard
        self.use_deliberation = use_deliberation
        self.use_manifest = use_manifest
        self.use_agentic_policy = use_agentic_policy
        self.stateless_loop = stateless_loop
        self.reflexion_mode = reflexion_mode
        self.suppress_condition_memory = suppress_condition_memory
        self.analyst = Analyst()
        self.codegen = CodeGen()
        self.tester = TestRunner(port=port)
        # Back-half (rule-synthesis) ablations via env (default = pg2: all ON).
        #   ABLATE_TEMPLATE=1 -> BH1: drop the Fix4 rule template
        #   ABLATE_SV=1       -> BH4: drop semantic-verify (firing/benign check + repair)
        #   ABLATE_REPAIR=1   -> BH4b: keep the verify checks but skip the LLM repair loop
        _abl_tpl = os.environ.get("ABLATE_TEMPLATE", "0") == "1"
        _abl_sv = os.environ.get("ABLATE_SV", "0") == "1"
        _abl_rep = os.environ.get("ABLATE_REPAIR", "0") == "1"
        #   NO_LLM_RULE=1 -> rule string is 100% deterministic: skip syntax-repair
        #   (max_validation_rounds=0 also disables the freeform fallback) AND the
        #   degenerate semantic-repair, so the LLM never emits/edits Suricata syntax.
        _no_llm = os.environ.get("NO_LLM_RULE", "0") == "1"
        self.rule_gen = RuleGenAgent(
            max_validation_rounds=(0 if _no_llm else 3),
            max_semantic_rounds=(0 if _abl_rep else 3),
            use_template=(not _abl_tpl),
            enable_semantic_verify=(not _abl_sv),
            no_llm_rule=_no_llm,
        )
        try:
            self._git_commit = subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                stderr=subprocess.DEVNULL).decode().strip()
        except Exception:
            self._git_commit = "unknown"

    def run(self, trace_path: str, output_dir: str = None) -> dict:
        """Run the full multi-agent pipeline on a single trace."""
        with open(trace_path, encoding="utf-8") as f:
            trace = json.load(f)

        case_id = Path(trace_path).stem
        logger.info("=== Runner: starting %s ===", case_id)

        self.analyst.reset()

        http_request = _extract_request_only(trace)
        trace_response = _extract_response(trace)
        self.analyst._trace_response = trace_response
        logger.info("HTTP request: %s %s", http_request["method"], http_request["path"])

        decoded_request = decode_request_for_analysis(http_request)

        parsed = parse_request_params(decoded_request)

        # Constrained field list for analyst (Change 3a).
        _cand: list[str] = []
        for _src in ("query", "form", "json", "xml",
                     "multipart", "cookies", "headers"):
            _cand.extend(parsed.get(_src, {}).keys())
        candidate_params: list[str] | None = _cand[:20] if _cand else None

        manifest = ""
        if self.use_manifest:
            manifest = generate_request_manifest(decoded_request, parsed)
            logger.info("Request manifest generated (%d entries)",
                        manifest.count("\n  - "))

        result = {
            "case_id": case_id,
            "http_request": http_request,
            "iterations": [],
            "decision_log": [],
            "status": "failed",
            "interpreted_hypothesis": None,
            "verified_hypothesis": None,
            "artifact_status": "failed_no_hypothesis",
            "recovery_mode": None,
        }

        logger.info("Phase 1+2: Analyst.analyze()")
        if not ensure_healthy():
            logger.error("LLM server unavailable, skipping %s", case_id)
            result["artifact_failure_reason"] = "llm_unavailable"
            result["recovery_mode"] = "abandon"
            if output_dir:
                self._save_results(result, output_dir, case_id)
            return result

        try:
            analysis = self.analyst.analyze(decoded_request, manifest=manifest,
                                            candidate_params=candidate_params)
        except Exception as e:
            logger.error("Analyst.analyze() failed: %s", e, exc_info=True)
            result["artifact_failure_reason"] = "analyst_failed"
            result["recovery_mode"] = "abandon"
            if output_dir:
                self._save_results(result, output_dir, case_id)
            return result

        result["initial_analysis"] = copy.deepcopy(analysis)
        result["interpreted_analysis"] = copy.deepcopy(analysis)
        result["interpreted_hypothesis"] = self._extract_hypothesis(analysis)
        result["verification_status"] = "unverified"
        result["artifact_status"] = "unverified"
        if self.use_agentic_policy:
            self._append_decision_log(result, {
                "stage": "initial_interpretation",
                "tool_called": "Analyst.analyze",
                "candidate": self._extract_hypothesis(analysis),
                "candidate_result": "incumbent",
                "promotion_result": "interpreted_incumbent",
            })

        hyp = analysis.get("attack_hypothesis", {})
        dangerous_param = hyp.get("dangerous_param", "")
        logger.info("Hypothesis: param=%s, syntax=%s",
                    dangerous_param, hyp.get("payload_syntax"))

        analyst_said_null = _is_null_param(dangerous_param)
        # Experiment 1 (filter-OFF): record the analyst's 2-class judgment for the
        # analyst-layer vs downstream-layer decomposition, but do not act on it when
        # no-classify mode is active (the 2-class benign filter is ablated).
        result["analyst_benign_judgment"] = analyst_said_null
        from src.hypothesis import analyst_assume_attack as _aaa
        _no_classify = getattr(_aaa, "NO_CLASSIFY_ACTIVE", False)

        identified_param, attack_value = identify_param(parsed, decoded_request, analysis)
        if not identified_param:
            if analyst_said_null and not _no_classify:
                # Broadened fallback (FALLBACK_NULL=1): the analyst declared NO
                # dangerous param. For attack traces this is often a localization
                # miss; apply the same strict extract-or-NONE recovery. The strict
                # NOEX prompt + in-request guard keep benign FP low (NONE on clean
                # benign; only attack-token benign artifacts can fire).
                if os.environ.get("FALLBACK_NULL") == "1":
                    fb_rule = _param_none_fallback_rule(http_request)
                    if fb_rule:
                        logger.info("Param-null fallback recovered a payload rule")
                        result["status"] = "success"
                        result["suricata_rule"] = fb_rule
                        result["recovery_mode"] = "param_null_fallback"
                        result["fallback_recovered"] = True
                        result["verification_status"] = "fallback_extracted_null"
                        result["artifact_status"] = "fallback"
                        result["final_analysis"] = analysis
                        result["interpreted_analysis"] = copy.deepcopy(analysis)
                        result["interpreted_hypothesis"] = (
                            self._extract_hypothesis(analysis))
                        if output_dir:
                            self._save_results(result, output_dir, case_id)
                        return result
                logger.info("Analyst declared no dangerous param - rejecting")
                result["status"] = "failed"
                result["final_analysis"] = analysis
                result["interpreted_analysis"] = copy.deepcopy(analysis)
                result["interpreted_hypothesis"] = self._extract_hypothesis(analysis)
                result["verification_status"] = "no_attack_param"
                result["artifact_status"] = "rejected"
                result["failure_reason"] = "no_attack_param"
                result["artifact_failure_reason"] = "no_attack_param"
                result["recovery_mode"] = "abandon"
                if self.use_agentic_policy:
                    self._append_decision_log(result, {
                        "stage": "finalization",
                        "action": "reject_no_param",
                        "candidate": self._extract_hypothesis(analysis),
                        "verifier_result": "no_param_declared",
                        "candidate_result": "rejected",
                        "rejection_reason": "no_attack_param",
                        "promotion_result": "rejected",
                    })
                if output_dir:
                    self._save_results(result, output_dir, case_id)
                return result
            else:
                # LLM named a param but it could not be resolved.
                # If the analyst said "body" despite named fields existing, try
                # once more with explicit feedback before giving up.
                dp_lower = str(dangerous_param or "").lower().strip()
                if (dp_lower in {"body", "raw_body", "request body", "post body"}
                        and _has_named_fields(parsed)):
                    logger.info(
                        "Body rejected (named fields exist) — requesting alternative")
                    try:
                        recovery_bb = {
                            "tried_params": [str(dangerous_param)],
                            "tried_conditions": [],
                            "diagnosis_history": [{
                                "failed_test": "pre_cegis_body_rejection",
                                "root_cause": (
                                    "analyst returned generic 'body' label despite "
                                    "named fields existing in the request"),
                                "specific_fix": (
                                    "name the specific field key from this exact "
                                    "list (verbatim, case-sensitive): "
                                    + ", ".join(
                                        f"'{n}'" for n in (candidate_params or [])[:20])
                                    + ". Do NOT return 'body', 'raw_body', or any "
                                    "generic container label."),
                            }],
                            "failed_tests": ["pre_cegis_body_rejection"],
                            "rejected_candidates": [],
                            "previous_actions": [],
                            "repeated_failure_count": 0,
                            "repair_counts": {},
                        }
                        alt_analysis = self.analyst.try_alternative(
                            decoded_request, manifest=manifest,
                            blackboard=recovery_bb)
                        alt_dp = (alt_analysis.get("attack_hypothesis", {})
                                  .get("dangerous_param"))
                        if not _is_null_param(alt_dp):
                            alt_id, alt_val = identify_param(
                                parsed, decoded_request, alt_analysis)
                            if alt_id:
                                logger.info(
                                    "Body rejection recovery succeeded: param=%s",
                                    alt_dp)
                                analysis = alt_analysis
                                identified_param = alt_id
                                attack_value = alt_val
                                result["body_rejection_recovery"] = True
                                result["interpreted_analysis"] = copy.deepcopy(
                                    analysis)
                                result["interpreted_hypothesis"] = (
                                    self._extract_hypothesis(analysis))
                            else:
                                logger.info(
                                    "Body rejection recovery: param '%s' not found",
                                    alt_dp)
                        else:
                            logger.info(
                                "Body rejection recovery: analyst concluded not "
                                "an attack")
                    except Exception as e:
                        logger.warning("Body rejection recovery failed: %s", e,
                                       exc_info=True)

                # Second recovery: unresolved non-body param.
                # If the analyst named a specific field that cannot be found,
                # pass the parsed field names back and ask for a correction.
                if (not identified_param
                        and _has_named_fields(parsed)):
                    if candidate_params is not None:
                        result["constrained_call_ignored"] = True
                    parsed_field_names = []
                    for src in ("query", "form", "json", "xml",
                                "multipart", "cookies", "headers"):
                        parsed_field_names.extend(parsed.get(src, {}).keys())
                    if parsed_field_names:
                        recovery_bb2 = {
                            "tried_params": [str(dangerous_param)],
                            "tried_conditions": [],
                            "diagnosis_history": [{
                                "failed_test": "pre_cegis_unresolved_param",
                                "root_cause": (
                                    f"analyst returned param name "
                                    f"'{dangerous_param}' which does not match "
                                    f"any parsed field"),
                                "specific_fix": (
                                    "choose the dangerous_param from this exact "
                                    "list: "
                                    + ", ".join(
                                        f"'{n}'" for n in parsed_field_names[:20])
                                ),
                            }],
                            "failed_tests": ["pre_cegis_unresolved_param"],
                            "rejected_candidates": [],
                            "previous_actions": [],
                            "repeated_failure_count": 0,
                            "repair_counts": {},
                        }
                        try:
                            alt2_analysis = self.analyst.try_alternative(
                                decoded_request, manifest=manifest,
                                blackboard=recovery_bb2,
                                excluded=[])
                            alt2_dp = (alt2_analysis
                                       .get("attack_hypothesis", {})
                                       .get("dangerous_param"))
                            if not _is_null_param(alt2_dp):
                                alt2_id, alt2_val = identify_param(
                                    parsed, decoded_request, alt2_analysis)
                                if alt2_id:
                                    logger.info(
                                        "Unresolved-param recovery succeeded: "
                                        "param=%s", alt2_dp)
                                    analysis = alt2_analysis
                                    identified_param = alt2_id
                                    attack_value = alt2_val
                                    result["unresolved_param_recovery"] = True
                                    result["interpreted_analysis"] = (
                                        copy.deepcopy(analysis))
                                    result["interpreted_hypothesis"] = (
                                        self._extract_hypothesis(analysis))
                                else:
                                    logger.info(
                                        "Unresolved-param recovery: alt param "
                                        "'%s' also not found", alt2_dp)
                            else:
                                logger.info(
                                    "Unresolved-param recovery: analyst "
                                    "concluded not an attack")
                        except Exception as e:
                            logger.warning(
                                "Unresolved-param recovery failed: %s", e,
                                exc_info=True)

                # Stage-3 fallback (param=none recovery): before giving up on an
                # unresolved param, try a direct extract-or-NONE payload rule.
                # Gated by FALLBACK_PARAM_NONE=1 (default off) pending end-to-end
                # validation. See _param_none_fallback_rule above.
                if (not identified_param
                        and os.environ.get("FALLBACK_PARAM_NONE") == "1"):
                    fb_rule = _param_none_fallback_rule(http_request)
                    if fb_rule:
                        logger.info(
                            "Param-none fallback recovered a payload rule")
                        result["status"] = "success"
                        result["suricata_rule"] = fb_rule
                        result["recovery_mode"] = "param_none_fallback"
                        result["fallback_recovered"] = True
                        result["verification_status"] = "fallback_extracted"
                        result["artifact_status"] = "fallback"
                        result["final_analysis"] = analysis
                        result["interpreted_analysis"] = copy.deepcopy(analysis)
                        result["interpreted_hypothesis"] = (
                            self._extract_hypothesis(analysis))
                        if output_dir:
                            self._save_results(result, output_dir, case_id)
                        return result

                # If still unresolved after all recovery attempts, give up.
                if not identified_param:
                    logger.info(
                        "Param '%s' not resolved in request - marking failed",
                        dangerous_param)
                    result["status"] = "failed"
                    result["verification_status"] = "unresolved_param"
                    result["artifact_status"] = "artifact_failed"
                    result["failure_reason"] = "unresolved_param"
                    result["artifact_failure_reason"] = "unresolved_param"
                    if self.use_agentic_policy:
                        result["final_analysis"] = analysis
                        result["interpreted_analysis"] = copy.deepcopy(analysis)
                        result["interpreted_hypothesis"] = (
                            self._extract_hypothesis(analysis))
                        result["recovery_mode"] = "emit_unverified"
                        self._append_decision_log(result, {
                            "stage": "finalization",
                            "action": "emit_unverified",
                            "candidate": self._extract_hypothesis(analysis),
                            "candidate_result": "rejected",
                            "rejection_reason": "unresolved_param",
                            "promotion_result": "incumbent_preserved",
                        })
                    if output_dir:
                        self._save_results(result, output_dir, case_id)
                    return result

        # Misclassification sanity check for path-type bypass (E1-B6 Change 2).
        # Observational only — the pipeline proceeds unconditionally.
        # '=' excluded: appears in base64 path segments; all query-string cases
        # with meaningful '=' also contain '?' or '&'.
        _SUSPICIOUS_PATH_CHARS = frozenset("?&';<")
        if (_param_type(identified_param) == "path"
                and attack_value
                and (any(c in attack_value for c in _SUSPICIOUS_PATH_CHARS)
                     or "--" in attack_value)):
            _found_chars = sorted(c for c in _SUSPICIOUS_PATH_CHARS
                                  if c in attack_value)
            if "--" in attack_value:
                _found_chars.append("--")
            logger.warning(
                "Path-type bypass: attack_value='%.100s' contains %r — "
                "possible identify_param() misclassification; proceeding",
                attack_value, _found_chars)
            result["path_type_warning"] = True

        # Main CEGIS loop
        try:
            success = self._cegis_loop(
                decoded_request, http_request, analysis,
                self.max_iterations, result, trace_response,
                manifest=manifest,
                lock_param=self.use_agentic_policy)

            # Alternative hypothesis if main loop failed (agentic only).
            # ABLATE_ALT_PHASE=1 disables ONLY this alt-hypothesis backtracking
            # (try_alternative) while keeping the rest of the agentic policy
            # (blackboard/incumbent/recovery) on — fine-grained agent ablation.
            should_alt, alt_reason = _should_enter_alt_phase(result["iterations"])
            if (not success and self.use_agentic_policy
                    and os.environ.get("ABLATE_ALT_PHASE") != "1"
                    and self.analyst.tried_params
                    and should_alt
                    and result.get("artifact_status") != "rejected"):
                logger.info("=== Alternative Hypothesis Phase (reason: %s) ===",
                            alt_reason)
                result["alt_phase"] = {
                    "entered": True,
                    "reason": alt_reason,
                    "main_iterations": len(result["iterations"]),
                }
                try:
                    main_blackboard = result.get("_blackboard")
                    # CGF-persistent: the original param was never behaviorally tested —
                    # only condition synthesis failed. Don't exclude it from alt_phase;
                    # let the analyst retry fresh with the CGF blackboard as context.
                    if alt_reason.startswith("condition_gen_failed_persistent"):
                        alt_excluded = []
                    else:
                        alt_excluded = list(self.analyst.tried_params)
                    alt_analysis = self.analyst.try_alternative(
                        decoded_request, manifest=manifest,
                        blackboard=main_blackboard,
                        excluded=alt_excluded)

                    alt_dp = (alt_analysis.get("attack_hypothesis", {})
                              .get("dangerous_param"))
                    if _is_null_param(alt_dp):
                        logger.info("Alt phase: analyst concluded not an attack")
                        result["alt_phase"]["null_conclusion"] = True
                        result["status"] = "failed"
                        result["verification_status"] = "alt_null"
                        result["artifact_status"] = "rejected"
                        result["failure_reason"] = "alt_null"
                        result["artifact_failure_reason"] = "alt_null"
                        result["recovery_mode"] = "abandon"
                        result["final_analysis"] = alt_analysis
                    else:
                        self._cegis_loop(
                            decoded_request, http_request, alt_analysis,
                            ALT_ITERATIONS, result, trace_response,
                            phase="alt", manifest=manifest,
                            lock_param=self.use_agentic_policy)
                    result["alt_phase"]["alt_iterations"] = (
                        len(result["iterations"])
                        - result["alt_phase"]["main_iterations"])
                    result["alt_phase"]["alt_success"] = (
                        result["status"] == "success")
                except Exception as e:
                    logger.error("Alternative hypothesis failed: %s", e)
                    result["alt_phase"]["error"] = str(e)
            elif not success and self.use_agentic_policy:
                if not self.analyst.tried_params:
                    skip_reason = "no_tried_params"
                else:
                    skip_reason = alt_reason
                logger.info("=== Alt phase skipped (reason: %s) ===",
                            skip_reason)
                result["alt_phase"] = {
                    "entered": False,
                    "reason": skip_reason,
                    "main_iterations": len(result["iterations"]),
                }
        finally:
            self.tester.cleanup()

        if (result["status"] != "success" and self.use_agentic_policy
                and result.get("artifact_status") != "rejected"):
            # Artifact generation/verification failed. Keep reporting the
            # incumbent interpretation rather than the last failed candidate.
            result.setdefault("final_analysis",
                              copy.deepcopy(result.get("interpreted_analysis")
                                            or result.get("initial_analysis")
                                            or analysis))
            result.setdefault("failure_reason", "artifact_failed")
            result["verification_status"] = "artifact_failed"
            result["artifact_status"] = "artifact_failed"
            result.setdefault("artifact_failure_reason",
                              result.get("failure_reason", "artifact_failed"))
            result.setdefault("interpreted_hypothesis",
                              self._extract_hypothesis(
                                  result.get("interpreted_analysis")))
            result["recovery_mode"] = (
                "emit_unverified" if result.get("interpreted_hypothesis")
                else "abandon"
            )
            self._append_decision_log(result, {
                "stage": "finalization",
                "action": result["recovery_mode"],
                "incumbent": result.get("interpreted_hypothesis"),
                "verifier_result": result.get("artifact_status"),
                "candidate_result": "artifact_failed",
                "rejection_reason": result.get("artifact_failure_reason"),
                "promotion_result": "incumbent_preserved",
            })
        elif (result["status"] != "success"
              and result.get("artifact_status") != "rejected"):
            result.setdefault("final_analysis",
                              copy.deepcopy(result.get("interpreted_analysis")
                                            or result.get("initial_analysis")
                                            or analysis))
            result.setdefault("failure_reason", "artifact_failed")
            result["verification_status"] = "artifact_failed"
            result["artifact_status"] = "artifact_failed"
            result.setdefault("artifact_failure_reason",
                              result.get("failure_reason", "artifact_failed"))
            result.setdefault("interpreted_hypothesis",
                              self._extract_hypothesis(
                                  result.get("interpreted_analysis")))
            result["recovery_mode"] = (
                "emit_unverified" if result.get("interpreted_hypothesis")
                else "abandon"
            )

        # --- Rule-layer benign-FP gate (de-leaked; env RULE_FP_GATE, off by default) ---
        # The PROMOTED Suricata rule was replayed against held-out (dev-sourced)
        # benign values in rule_agent._final_benign_check. If it fires on any, the
        # rule would false-alarm on benign traffic, so this case is NOT a clean
        # detection -> downgrade success to a benign rejection. De-leaked: the values
        # come from data/benign_values.json (the held-out dev split, NOT the eval
        # set). TPR-safe: a mechanism-grounded attack rule fires on the attack, not
        # on benign; only the irreducible coupled core (a benign value literally
        # carrying the attack token) can cost TPR.
        if (os.environ.get("RULE_FP_GATE", "off").strip().lower() in ("1", "on", "hard", "true")
                and result.get("status") == "success"
                and getattr(self.rule_gen, "last_benign_fp", 0) > 0):
            logger.info("  [rule-fp-gate] promoted rule fires on %d held-out benign "
                        "value(s) -> reject", self.rule_gen.last_benign_fp)
            result["status"] = "failed"
            result["verification_status"] = "rule_benign_fp"
            result["artifact_status"] = "rejected"
            result["recovery_mode"] = "abandon"
            result["rule_status"] = "rejected_benign_fp"
            result["suricata_rule"] = None

        # Save results
        if output_dir:
            self._save_results(result, output_dir, case_id)

        logger.info("=== Runner: %s -> %s (iterations: %d) ===",
                    case_id, result["status"], len(result["iterations"]))
        return result

    @staticmethod
    def _extract_hypothesis(analysis: dict) -> dict | None:
        """Return a copy of the attack hypothesis for dual-output reporting."""
        if not analysis:
            return None
        hyp = analysis.get("attack_hypothesis")
        if not isinstance(hyp, dict):
            return None
        return copy.deepcopy(hyp)

    def _cegis_loop(self, decoded_request: dict, http_request: dict,
                    analysis: dict, max_iters: int, result: dict,
                    trace_response: dict = None, phase: str = "main",
                    manifest: str = "",
                    lock_param: bool = True) -> bool:
        """Run a CEGIS cycle. Returns True if tests pass.

        When lock_param=True (default), the identified parameter is locked for
        the entire loop - only the detection condition is refined. Parameter
        switching is deferred to the alternative-hypothesis phase.
        """
        prev_failed = None
        same_count = 0
        blackboard = {
            "tried_conditions": [],
            "tried_params": [],
            "failed_tests": [],
            "diagnosis_history": [],
            "rejected_candidates": [],
            "previous_actions": [],
            "repeated_failure_count": 0,
            "repair_counts": {},
            "reflections": [],
        }
        base_iteration = len(result["iterations"])
        soft_revision_used = False

        # Snapshot the locked parameter to guard against accidental mutation
        locked_dp = (analysis.get("attack_hypothesis", {})
                     .get("dangerous_param")) if lock_param else None

        for iteration in range(max_iters):
            if iteration > 0 and not ensure_healthy():
                logger.error("LLM server unhealthy, aborting CEGIS loop")
                result["artifact_failure_reason"] = "llm_unhealthy_mid_cegis"
                break
            # Restore locked param if it was mutated
            if locked_dp is not None:
                analysis.setdefault("attack_hypothesis", {})["dangerous_param"] = locked_dp
            codegen_temp = TEMP_GENERATIVE
            counterexample = None
            if iteration > 0 and result["iterations"]:
                counterexample = result["iterations"][-1].get("counterexample")
            logger.info("--- CEGIS iteration %d/%d (temp=%.2f) ---",
                       iteration, max_iters, codegen_temp)

            global_iteration = base_iteration + iteration
            iter_result = {
                "iteration": global_iteration,
                "local_iteration": iteration,
                "phase": phase,
                "analysis": analysis,
            }

            # CodeGen: generate Flask code (compile retry + Critic inside)
            logger.info("  CodeGen.generate()")
            if self.stateless_loop:
                bb_for_llm = None
            elif self.suppress_condition_memory:
                bb_for_llm = {k: ([] if k == "tried_conditions" else v)
                              for k, v in blackboard.items()} if blackboard else None
            else:
                reflections = blackboard.get("reflections", [])
                if reflections:
                    bb_for_llm = {
                        "tried_conditions": [{
                            "condition": "(reflection)",
                            "failed_test": "REFLECTION",
                            "reason": r,
                        } for r in reflections[-3:]],
                    }
                else:
                    bb_for_llm = None
            gen_result = self.codegen.generate(
                decoded_request, analysis, counterexample,
                temperature=TEMP_GENERATIVE,
                trace_response=trace_response,
                blackboard=bb_for_llm)

            if not gen_result["success"]:
                logger.error("  CodeGen failed: %s", gen_result["error"])
                iter_result["error"] = gen_result["error"]
                if gen_result.get("condition_generation_failed"):
                    failed_test = "CONDITION_GEN_FAILED"
                elif gen_result.get("compile_error"):
                    failed_test = "COMPILE"
                else:
                    failed_test = "CODE_GEN"
                ce = {
                    "failed_test": failed_test,
                    "details": gen_result["error"],
                }
                # ABLATE_DIRECT=1 disables ONLY the diagnose-and-direct step
                # (_analyze_and_direct: on CONDITION_GEN_FAILED, an LLM diagnoses
                # the failure and steers the next condition), keeping the rest of
                # the agentic policy (alt-phase/incumbent/recovery) on — the
                # fine-grained counterpart of ABLATE_ALT_PHASE for decomposing
                # the "−agent" bundle into its independent mechanisms.
                if (self.use_agentic_policy
                        and os.environ.get("ABLATE_DIRECT") != "1"):
                    if (failed_test == "CONDITION_GEN_FAILED"
                            and iteration < max_iters - 1):
                        direction_result = self._analyze_and_direct(
                            analysis, ce, blackboard, gen_result)
                        ce["direction"] = direction_result.get("direction", "")
                        ce["llm_diagnosis"] = {
                            "root_cause": direction_result.get("root_cause", ""),
                            "is_hypothesis_wrong": direction_result.get(
                                "is_hypothesis_wrong", False),
                            "specific_fix": direction_result.get("direction", ""),
                            "fix_type": "condition_direction",
                        }
                iter_result["counterexample"] = ce
                iter_result["candidate_status"] = "rejected"
                iter_result["promotion_decision"] = {
                    "promoted": False,
                    "reason": ce["failed_test"],
                    "incumbent_preserved": self.use_agentic_policy,
                }
                if self.use_agentic_policy:
                    self._record_case_memory(
                        blackboard, ce, iter_result, analysis,
                        same_count, None)
                    # Record each rejected condition so future CodeGen avoids them.
                    # rejection_reasons format: "'<cond>' failed: <reason>"
                    if (self.use_blackboard and blackboard is not None
                            and failed_test == "CONDITION_GEN_FAILED"):
                        import re as _re
                        for rej in gen_result.get("rejection_reasons", []):
                            m = _re.match(r"'(.+?)' failed: (.+)", rej)
                            if m:
                                blackboard["tried_conditions"].append({
                                    "condition": m.group(1),
                                    "failed_test": "CONDITION_GEN_FAILED",
                                    "reason": m.group(2)[:200],
                                })
                    self._append_decision_log(result, self._build_decision_log_entry(
                        iter_result, analysis, ce, None, codegen_temp,
                        "CodeGen.generate", "codegen_failed"))
                result["iterations"].append(iter_result)

                prev_failed, same_count, should_stop = self._track_failure(
                    ce, prev_failed, same_count)
                if ((should_stop and self.use_agentic_policy
                     and ce.get("failed_test") in TEST_FAILURES)
                        or iteration >= max_iters - 1):
                    break
                continue

            flask_code = gen_result["flask_code"]
            iter_result["flask_code_length"] = len(flask_code)
            identified_param = gen_result.get("identified_param")
            attack_value = gen_result.get("attack_value")
            if identified_param is not None:
                iter_result["identified_param"] = identified_param
                self._remember_unique(blackboard["tried_params"], identified_param)
            effective_analysis = self._analysis_with_identified_param(
                analysis, identified_param)
            iter_result["effective_analysis"] = effective_analysis

            # TestRunner: test code (crash retry + LLM diagnosis inside)
            logger.info("  TestRunner.test()")
            test_result = self.tester.test(
                flask_code, http_request, effective_analysis,
                codegen=self.codegen, temperature=TEMP_GENERATIVE,
                decoded_request=decoded_request,
                trace_response=trace_response,
                keep_mock_alive=False)

            iter_result["test_results"] = test_result.get("test_results")
            flask_code = test_result.get("flask_code", flask_code)

            if test_result.get("error"):
                iter_result["error"] = test_result["error"]
                iter_result["counterexample"] = test_result["counterexample"]
                iter_result["candidate_status"] = "rejected"
                iter_result["promotion_decision"] = {
                    "promoted": False,
                    "reason": test_result["error"],
                    "incumbent_preserved": self.use_agentic_policy,
                }
                ce = test_result["counterexample"]
                if self.use_agentic_policy:
                    self._record_case_memory(
                        blackboard, test_result["counterexample"], iter_result,
                        analysis, same_count, None)
                    self._append_decision_log(result, self._build_decision_log_entry(
                        iter_result, analysis, test_result["counterexample"],
                        None, codegen_temp, "TestRunner.test", "test_error"))
                result["iterations"].append(iter_result)

                if ce:
                    prev_failed, same_count, should_stop = self._track_failure(
                        ce, prev_failed, same_count)
                    if (should_stop and self.use_agentic_policy
                            and ce.get("failed_test") in TEST_FAILURES):
                        break
                continue

            if test_result["passed"]:
                logger.info("  ALL TESTS PASSED at iteration %d", iteration)

                suricata_rule = ""
                if self.skip_suricata:
                    logger.info("  Suricata rule generation skipped")
                else:
                    logger.info("  RuleGenAgent.generate()")
                    try:
                        suricata_rule = self.rule_gen.generate(
                            http_request, effective_analysis)
                    except Exception as e:
                        logger.error("  RuleGenAgent failed: %s", e)
                        suricata_rule = f"# Rule generation failed: {e}"

                    # Final render pass: drop a phantom pcre guard that cannot match
                    # its own buffer's wire bytes (e.g. a raw shell-metachar guard on
                    # a URL-encoded command-injection payload). The CEGIS validator
                    # scans the decoded request and so passes the guard, but real
                    # Suricata applies it per sticky buffer where the encoded payload
                    # has no raw metachar, suppressing the whole content-AND rule
                    # (= verified-but-no-fire). Deterministic; analogue of the
                    # path_traversal phantom-marker fix in rule_agent.
                    if suricata_rule and not suricata_rule.startswith("#"):
                        try:
                            suricata_rule = drop_phantom_pcre(suricata_rule, http_request)
                        except Exception as e:
                            logger.warning("  drop_phantom_pcre skipped: %s", e)

                result["status"] = "success"
                final_analysis = dict(effective_analysis)
                fa_hyp = final_analysis.get("attack_hypothesis", {})
                dp = fa_hyp.get("dangerous_param", "")
                if dp.startswith("header:"):
                    final_analysis["attack_hypothesis"] = dict(fa_hyp)
                    final_analysis["attack_hypothesis"]["dangerous_param"] = dp[7:]
                result["final_analysis"] = final_analysis
                result["interpreted_analysis"] = final_analysis
                result["interpreted_hypothesis"] = self._extract_hypothesis(final_analysis)
                result["verified_analysis"] = final_analysis
                result["verified_hypothesis"] = self._extract_hypothesis(final_analysis)
                result["verification_status"] = "verified"
                result["artifact_status"] = "verified"
                result["recovery_mode"] = "verified"
                result["identified_param"] = identified_param
                result["attack_value"] = attack_value
                result["flask_code"] = flask_code
                result["detection_condition"] = self._extract_condition(flask_code)
                result["suricata_rule"] = suricata_rule
                if suricata_rule is None:
                    result["rule_status"] = "degenerate"
                result["success_iteration"] = global_iteration
                iter_result["candidate_status"] = "promoted"
                iter_result["promotion_decision"] = {
                    "promoted": True,
                    "reason": "T1-T4 passed",
                    "verification_status": "verified",
                }
                if self.use_agentic_policy:
                    self._append_decision_log(result, self._build_decision_log_entry(
                        iter_result, final_analysis, None, None, codegen_temp,
                        "TestRunner.test + RuleGenAgent.generate", "promoted"))
                result["iterations"].append(iter_result)
                result["_blackboard"] = blackboard
                return True

            # Tests failed - Orchestrator reasons about failure and decides action
            ce = test_result["counterexample"]
            iter_result["counterexample"] = ce
            iter_result["candidate_status"] = "rejected"
            iter_result["promotion_decision"] = {
                "promoted": False,
                "reason": ce.get("failed_test", "unknown") if ce else "unknown",
                "incumbent_preserved": self.use_agentic_policy,
            }
            if self.use_agentic_policy:
                self._record_case_memory(
                    blackboard, ce, iter_result, analysis,
                    same_count, identified_param)
            result["iterations"].append(iter_result)

            # Blackboard: record failed detection condition
            if self.use_agentic_policy and self.use_blackboard and flask_code and ce:
                condition = self._extract_condition(flask_code)
                if condition:
                    blackboard["tried_conditions"].append({
                        "condition": condition,
                        "failed_test": ce.get("failed_test", "unknown"),
                        "reason": ce.get("llm_diagnosis", {}).get("root_cause", "")[:200],
                    })

            if not self.use_agentic_policy:
                if ce:
                    prev_failed, same_count, _ = self._track_failure(
                        ce, prev_failed, same_count)
                continue

            if iteration < max_iters - 1 and ce:
                projected_same_count = self._project_same_failure_count(
                    ce, prev_failed, same_count)
                remaining_iterations = max_iters - iteration - 1

                # Soft revision: deterministic trigger on repeated same failure
                # T3 failures (benign rejection) must NOT trigger param revision —
                # the param is likely correct; the condition is just too broad.
                if (lock_param and self.use_deliberation
                        and not soft_revision_used
                        and ce.get("failed_test") not in ("T3",)
                        and blackboard.get("repair_counts", {}).get(
                            "attack_model_revision", 0) < _MAX_SOFT_REVISIONS
                        and projected_same_count >= SAME_FAILURE_STOP
                        and remaining_iterations >= 2):
                    iter_result["runner_decision"] = {
                        "action": "soft_revision",
                        "reasoning": "same failure repeated; revising attack model",
                    }
                    iter_result["soft_revision"] = {
                        "triggered": True,
                        "incumbent_preserved": True,
                    }
                    self._append_decision_log(result, self._build_decision_log_entry(
                        iter_result, analysis, ce, None, codegen_temp,
                        "Orchestrator.soft_revision -> Analyst.revise",
                        "revision_candidate"))
                    logger.info("  Soft revision: reconsidering attack model once")
                    try:
                        prev_dp = locked_dp
                        analysis = self.analyst.revise(
                            decoded_request, analysis, ce,
                            temperature=TEMP_GENERATIVE,
                            blackboard=(blackboard if not self.stateless_loop
                                        else None))
                        locked_dp = (analysis.get("attack_hypothesis", {})
                                     .get("dangerous_param"))
                        soft_revision_used = True

                        if _is_null_param(locked_dp):
                            logger.info("  Soft revision concluded: not an attack")
                            iter_result["soft_revision"]["null_conclusion"] = True
                            result["status"] = "failed"
                            result["verification_status"] = "revision_null"
                            result["artifact_status"] = "rejected"
                            result["failure_reason"] = "revision_null"
                            result["artifact_failure_reason"] = "revision_null"
                            result["recovery_mode"] = "abandon"
                            result["final_analysis"] = analysis
                            break

                        same_count = 0
                        prev_failed = None
                        blackboard["tried_conditions"].clear()
                        if locked_dp != prev_dp:
                            blackboard["diagnosis_history"].clear()
                            blackboard["failed_tests"].clear()
                            blackboard["rejected_candidates"].clear()
                        blackboard.setdefault("repair_counts", {})[
                            "attack_model_revision"] = blackboard.get(
                                "repair_counts", {}).get("attack_model_revision", 0) + 1
                    except Exception as e:
                        logger.warning("  Soft revision failed: %s", e)
                        iter_result["soft_revision"]["error"] = str(e)
                    continue

                bb_ctx = (blackboard if self.use_blackboard
                         and not self.reflexion_mode else None)
                reflection = self._generate_reflection(
                    analysis, ce, blackboard.get("reflections", []),
                    blackboard=bb_ctx)
                blackboard["reflections"].append(reflection)
                ce["direction"] = reflection
                iter_result["runner_decision"] = {
                    "action": "reflexion",
                    "reflection": reflection,
                }
                blackboard["diagnosis_history"].append({
                    "failed_test": ce.get("failed_test", "unknown"),
                    "root_cause": reflection[:100],
                    "fix_type": "reflexion",
                    "specific_fix": reflection,
                    "is_hypothesis_wrong": False,
                })
                self._append_decision_log(result, self._build_decision_log_entry(
                    iter_result, analysis, ce, None, codegen_temp,
                    "TestRunner.test -> Reflexion",
                    "rejected"))
                blackboard["previous_actions"].append("reflexion")
            else:
                self._append_decision_log(result, self._build_decision_log_entry(
                    iter_result, analysis, ce, None, codegen_temp,
                    "TestRunner.test", "rejected_no_repair_budget"))

            if ce:
                prev_failed, same_count, should_stop = self._track_failure(
                    ce, prev_failed, same_count)
                if (should_stop and self.use_agentic_policy
                        and ce.get("failed_test") in TEST_FAILURES):
                    break

        result["_blackboard"] = blackboard
        return False

    @staticmethod
    def _analysis_with_identified_param(analysis: dict,
                                        identified_param: str) -> dict:
        """Return analysis with the actual mock-tested parameter recorded."""
        if identified_param is None:
            return analysis

        updated = dict(analysis)
        hyp = dict(updated.get("attack_hypothesis", {}))
        original = hyp.get("dangerous_param")
        if original != identified_param:
            hyp["analyst_dangerous_param"] = original
            hyp["dangerous_param"] = identified_param
        hyp["identified_param"] = identified_param
        updated["attack_hypothesis"] = hyp
        return updated

    def _generate_reflection(self, analysis: dict, ce: dict,
                             reflections: list[str],
                             blackboard: dict = None) -> str:
        """Generate a natural-language reflection on why the test failed.

        When blackboard is provided (A4), includes tried condition patterns
        for richer context. Without blackboard (A3), uses only failure info
        and previous reflections.
        """
        hyp = analysis.get("attack_hypothesis", {})
        failed_test = ce.get("failed_test", "unknown") if ce else "unknown"
        details = ce.get("details", "") if ce else ""
        diagnosis = (ce.get("llm_diagnosis", {}) or {}) if ce else {}

        past = ""
        if reflections:
            past = "## Previous Reflections\n"
            for i, r in enumerate(reflections[-3:]):
                past += f"{i+1}. {r}\n"

        tried_section = ""
        if blackboard:
            tried = blackboard.get("tried_conditions", [])
            if tried:
                tried_section = "## Detection Patterns Already Tried\n"
                for tc in tried[-3:]:
                    cond = str(tc.get("condition", ""))[:60]
                    reason = str(tc.get("reason", ""))[:80]
                    tried_section += f"- `{cond}` -> {reason}\n"
                tried_section += "Next attempt must use a fundamentally different pattern.\n"

        prompt = f"""A detection condition synthesis attempt failed.

## Failed Step: {failed_test}
Details: {str(details)[:300]}
Diagnosis: {json.dumps(diagnosis, default=str)[:200]}

## Hypothesis
param: {hyp.get("dangerous_param")}
syntax: {hyp.get("payload_syntax", "")}

{past}
{tried_section}
Write a 2-3 sentence reflection: what went wrong, why, and what structurally different approach to try next.
Return ONLY the reflection text, no JSON. /no_think"""

        messages = [
            {"role": "system",
             "content": "You are a security researcher reflecting on a failed "
                        "detection attempt. Write a concise, actionable reflection."},
            {"role": "user", "content": prompt},
        ]
        try:
            return _call_llm(messages, temperature=TEMP_STRUCTURED,
                             max_tokens=200).strip()
        except Exception as e:
            logger.warning("Reflection generation failed: %s", e)
            return f"Failed test {failed_test}: {str(details)[:100]}"

    @staticmethod
    def _track_failure(ce: dict, prev_failed: str, same_count: int) -> tuple:
        """Track consecutive same-test failures for early stopping."""
        failed_test = ce.get("failed_test")
        if failed_test == prev_failed:
            same_count += 1
        else:
            same_count = 1
            prev_failed = failed_test
        should_stop = same_count >= SAME_FAILURE_STOP
        if same_count == SAME_FAILURE_STOP:
            logger.info("  Same failure (%s) %d consecutive times",
                       failed_test, same_count)
        return prev_failed, same_count, should_stop

    @staticmethod
    def _project_same_failure_count(ce: dict, prev_failed: str,
                                    same_count: int) -> int:
        """Return the same-test streak count including the current failure."""
        failed_test = ce.get("failed_test") if ce else None
        return same_count + 1 if failed_test == prev_failed else 1

    @staticmethod
    def _remember_unique(items: list, value) -> None:
        """Append a case-local memory item once, preserving order."""
        if value is None:
            return
        if value not in items:
            items.append(value)

    def _record_case_memory(self, blackboard: dict, ce: dict | None,
                            iter_result: dict, analysis: dict,
                            same_count: int, identified_param: str | None) -> None:
        """Record per-case working memory for the policy agent."""
        if not blackboard or not ce:
            return

        failed_test = ce.get("failed_test", "unknown")
        diagnosis = ce.get("llm_diagnosis", {}) or {}
        hyp = analysis.get("attack_hypothesis", {})

        blackboard["failed_tests"].append(failed_test)
        blackboard["repeated_failure_count"] = same_count
        if identified_param:
            self._remember_unique(blackboard["tried_params"], identified_param)

        if diagnosis:
            blackboard["diagnosis_history"].append({
                "failed_test": failed_test,
                "root_cause": diagnosis.get("root_cause", "unknown"),
                "fix_type": diagnosis.get("fix_type", "unknown"),
                "specific_fix": diagnosis.get("specific_fix", ""),
                "is_hypothesis_wrong": diagnosis.get("is_hypothesis_wrong"),
            })

        blackboard["rejected_candidates"].append({
            "iteration": iter_result.get("iteration"),
            "phase": iter_result.get("phase"),
            "dangerous_param": hyp.get("dangerous_param"),
            "identified_param": identified_param,
            "failed_test": failed_test,
            "reason": (iter_result.get("promotion_decision") or {}).get("reason"),
        })

    def _analyze_and_direct(self, analysis: dict, ce: dict,
                            blackboard: dict, gen_result: dict = None) -> dict:
        """Analyze failure evidence and produce a specific direction for CodeGen.

        Replaces the 4-choice _plan_next_action with free-form analysis.
        The LLM examines what went wrong and outputs a concrete instruction
        for how to write the next detection condition differently.
        """
        hyp = analysis.get("attack_hypothesis", {})
        failed_test = ce.get("failed_test", "unknown") if ce else "unknown"
        diagnosis = (ce.get("llm_diagnosis", {}) or {}) if ce else {}

        # Build failure detail section
        if failed_test == "CONDITION_GEN_FAILED" and gen_result:
            rejection_reasons = gen_result.get("rejection_reasons", [])
            failure_detail = "Critic rejected all condition attempts:\n"
            for reason in rejection_reasons[-5:]:
                failure_detail += f"  - {reason[:120]}\n"
        elif diagnosis:
            failure_detail = (
                f"Root cause: {diagnosis.get('root_cause', 'unknown')}\n"
                f"Specific fix attempted: {diagnosis.get('specific_fix', 'none')}")
        else:
            failure_detail = ce.get("details", "unknown") if ce else "unknown"

        # Build past attempts section from blackboard
        past_section = ""
        if blackboard and not self.stateless_loop:
            if self.reflexion_mode:
                reflections = blackboard.get("reflections", [])
                if reflections:
                    past_section += "## Previous Reflections\n"
                    for i, r in enumerate(reflections[-5:]):
                        past_section += f"  {i+1}. {r}\n"
            else:
                hist = blackboard.get("diagnosis_history", [])
                if hist:
                    lines = []
                    for i, d in enumerate(hist[-5:]):
                        fix = d.get("specific_fix", "unknown")[:80]
                        ft = d.get("failed_test", "?")
                        lines.append(f"  {i+1}. \"{fix}\" -> {ft} FAIL")
                    past_section += "## Past Fix Directions (ALL FAILED - do NOT repeat)\n"
                    past_section += "\n".join(lines) + "\n"

                if not self.suppress_condition_memory:
                    tried = blackboard.get("tried_conditions", [])
                    if tried:
                        past_section += "\n## Past Conditions (ALL REJECTED)\n"
                        for tc in tried[-5:]:
                            cond = str(tc.get("condition", ""))[:60]
                            reason = str(tc.get("reason", ""))[:200]
                            past_section += f"  - `{cond}` : {reason}\n"

        attack_value = hyp.get("identified_param_value") or ""
        if not attack_value and gen_result:
            attack_value = gen_result.get("attack_value", "")

        from src.hypothesis.skeleton import _describe_attack_value
        value_desc = _describe_attack_value(str(attack_value))

        prompt = f"""A Boolean expression synthesis attempt failed in a CEGIS verification loop. Analyze and direct the next attempt.

## Failed Step: {failed_test}
{failure_detail}

## Synthesis Target
param: {hyp.get("dangerous_param")}
structural_properties: {value_desc}

{past_section}
## Your Task
1. Analyze WHY the previous attempts all failed (one sentence).
2. Propose a SPECIFIC, CONCRETE synthesis approach that is fundamentally
   different from all past attempts listed above.

The approach must be expressible as: `return bool(EXPR)` where EXPR uses
only `value` (str), `re` module, and basic builtins (len, any, all, ord, chr).

Return JSON:
{{"root_cause": "<one sentence: why past attempts failed>", "direction": "<specific instruction: what synthesis approach to use next, with example pattern if possible>", "is_hypothesis_wrong": true/false}}
/no_think"""

        messages = [
            {"role": "system",
             "content": ("You are a program synthesis assistant. "
                         "Analyze why a Boolean expression generation loop keeps failing "
                         "and produce a concrete direction for the next synthesis attempt. "
                         "Return ONLY JSON.")},
            {"role": "user", "content": prompt},
        ]

        try:
            raw = _call_llm(messages, temperature=TEMP_STRUCTURED, max_tokens=600)
            result = _extract_json(raw, "analyze_and_direct")
            logger.info("  Direction: %s", str(result.get("direction", ""))[:100])
            return result
        except Exception as e:
            logger.warning("  _analyze_and_direct failed: %s", e)
            return {
                "root_cause": "analysis failed",
                "direction": "Try a completely different detection approach.",
                "is_hypothesis_wrong": False,
            }

    @staticmethod
    def _append_decision_log(result: dict, entry: dict) -> None:
        """Append a compact, analysis-friendly decision-log record."""
        result.setdefault("decision_log", []).append(entry)

    def _build_decision_log_entry(self, iter_result: dict, analysis: dict,
                                  ce: dict | None, _repair_plan: dict | None,
                                  temperature: float, tool_called: str,
                                  candidate_result: str) -> dict:
        """Build a normalized decision log entry for one agent step."""
        diagnosis = (ce or {}).get("llm_diagnosis", {}) if ce else {}
        promotion = iter_result.get("promotion_decision", {})
        return {
            "stage": "cegis_iteration",
            "iteration": iter_result.get("iteration"),
            "local_iteration": iter_result.get("local_iteration"),
            "phase": iter_result.get("phase"),
            "observation": {
                "failed_test": (ce or {}).get("failed_test") if ce else None,
                "root_cause": diagnosis.get("root_cause"),
                "fix_type": diagnosis.get("fix_type"),
                "specific_fix": diagnosis.get("specific_fix"),
                "is_hypothesis_wrong": diagnosis.get("is_hypothesis_wrong"),
            },
            "incumbent": self._extract_hypothesis(analysis),
            "candidate": (iter_result.get("effective_analysis") or analysis)
            .get("attack_hypothesis", {}),
            "chosen_action": (iter_result.get("runner_decision") or {})
            .get("action"),
            "temperature": temperature,
            "tool_called": tool_called,
            "verifier_result": (
                "passed" if candidate_result == "promoted"
                else ((ce or {}).get("failed_test") if ce else iter_result.get("error"))
            ),
            "candidate_result": candidate_result,
            "promotion_result": (
                "promoted" if promotion.get("promoted")
                else "rejected"
            ),
            "rejection_reason": None if promotion.get("promoted") else (
                promotion.get("reason") or (ce or {}).get("failed_test")),
            "promotion_decision": promotion,
        }

    @staticmethod
    def _extract_condition(flask_code: str) -> str:
        """Extract the detection condition from generated mock code."""
        import re as _re
        m = _re.search(r'return bool\((.+)\)', flask_code)
        if m:
            return m.group(1).strip()
        return ""

    def _save_results(self, result: dict, output_dir: str, case_id: str):
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        result_path = out_path / f"{case_id}.json"

        serializable = {k: v for k, v in result.items()
                        if k not in ("flask_code", "_blackboard")}
        serializable["_meta"] = {
            "git_commit": self._git_commit,
            "saved_at": _time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        if "flask_code" in result:
            code_path = out_path / f"{case_id}_flask.py"
            code_path.write_text(result["flask_code"], encoding="utf-8")
            serializable["flask_code_path"] = str(code_path)

        result_path.write_text(
            json.dumps(serializable, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        logger.info("Results saved to %s", result_path)
