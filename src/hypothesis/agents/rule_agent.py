"""RuleGenAgent: Suricata rule generation with validation loop.

Responsibilities:
  - generate(): rule generation → Suricata validation → repair loop

Role: IDS signature engineer specializing in Suricata rule authoring.
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlencode, urlparse

from ..analyst import _call_llm, _truncate_request
from ..temperature import TEMP_STRUCTURED
from ..rule_postprocess import postprocess_rule, is_degenerate as _is_degenerate_fn
from ..mitre_mapping import get_mitre_technique_id
from ..rule_template import assemble_rule
from ..rule_pcre_guard import drop_phantom_pcre
from ...evaluation.pcap_generator import wire_buffers, _quote_for_query

logger = logging.getLogger("rule_agent")

RULE_GEN_ROLE = """\
You are an IDS signature engineer specializing in Suricata rule authoring for IoT threat detection.

## Your Expertise
- 8+ years writing production Suricata/Snort rules for enterprise and IoT networks
- Maintains rule sets covering 500+ IoT-specific attack patterns
- Expert at balancing detection coverage (true positive rate) vs. false positive rate

## Your Rule Design Principles
1. **Specificity over generality**: Match the exact attack pattern, not broad categories.
   A rule that matches "any POST to /cgi-bin" is too broad. Match the specific path + payload pattern.
2. **Layered matching**: Combine URI path match + payload content match + method match.
   Single-condition rules produce false positives.
3. **Buffer correctness**: Use Suricata 7.x sticky buffer syntax:
   - http.uri (NOT http.url, NOT http_uri)
   - http.request_body (NOT http.body)
   - http.method for method matching
   - http.query DOES NOT EXIST — match query strings inside http.uri
4. **Performance**: Place fast_pattern on the most unique content match.
   Avoid pcre when content match suffices.
5. **Metadata**: Include classtype, sid (9000001-9999999), rev, and MITRE ATT&CK technique ID.
   Do NOT reference any CVE number (the attack may be a zero-day).

## Common Suricata Syntax Errors to Avoid
- Using http.body → correct: http.request_body
- Using http.url → correct: http.uri
- Using http.query → does not exist, use http.uri for query strings
- Using http_uri (old syntax) → correct: http.uri (sticky buffer)
- Missing semicolons between rule options
- content match without its buffer keyword"""

RULE_REPAIR_ROLE = """\
You are an IDS signature engineer debugging a Suricata rule that failed validation.

## Your Task
Fix the syntactic and semantic errors reported by Suricata's rule parser (-T mode).
Preserve the detection intent while correcting the syntax.

## Common Fixes
- http.body → http.request_body
- http.url → http.uri
- http.query → match inside http.uri instead
- http_uri (legacy) → http.uri (sticky buffer)
- Missing buffer keyword after content/pcre
- Missing sid: or rev: in rule metadata
- Mismatched parentheses or semicolons

## PCRE Syntax Rules (Suricata 7.x)
- Semicolons inside a PCRE pattern MUST be written as \\x3b (not as ;)
  BAD:  pcre:"/name=value;flag=1/i"
  GOOD: pcre:"/name=value\\x3bflag=1/i"
- Forward slashes inside a PCRE pattern MUST be escaped as \\/
  BAD:  pcre:"/<tag></tag>/i"
  GOOD: pcre:"/<tag><\\/tag>/i"
- A dash (-) inside a character class [...] at a non-boundary position must be \\-
  BAD:  pcre:"/[A-Z0-9---]/i"
  GOOD: pcre:"/[A-Z0-9\\-]/i"

Return ONLY the corrected rule line. No explanation."""

RULE_DIAGNOSE_ROLE = """\
You diagnose why a Suricata IDS rule failed behavioral testing.
Identify the root cause precisely.
Answer ONLY in JSON."""

RULE_SEMANTIC_REPAIR_ROLE = """\
You fix Suricata rules based on a specific diagnosis.
Fix ONLY the diagnosed issue. Change nothing else.
Return ONLY the corrected rule line. No explanation."""


class RuleGenAgent:

    def __init__(self, max_validation_rounds: int = 3,
                 max_semantic_rounds: int = 3,
                 use_template: bool = True,
                 enable_semantic_verify: bool = True,
                 no_llm_rule: bool = False,
                 sid_range: tuple[int, int] = (9000001, 9999999)):
        self.max_validation_rounds = max_validation_rounds
        self.max_semantic_rounds = max_semantic_rounds
        self.use_template = use_template
        self.enable_semantic_verify = enable_semantic_verify
        self.no_llm_rule = no_llm_rule
        self.sid_range = sid_range

    def generate(self, http_request: dict, analysis: dict,
                 ) -> str:
        """Generate and validate a Suricata rule.

        Internal orchestration:
          1. Generate initial rule via LLM with IDS engineer role
          2. Validate with Suricata -T
          3. If invalid → feed errors back to LLM repair agent → re-validate
          4. Return best rule (validated or last attempt)
        """
        logger.info("RuleGenAgent: starting rule generation")
        # Phase-2 held-out-benign FP count of the rule this call emits (read by the
        # runner's RULE_FP_GATE). Reset per call; set when Phase 2 runs.
        self.last_benign_fp = 0

        hyp = analysis.get("attack_hypothesis", {})
        dp = hyp.get("dangerous_param") or ""
        if dp.startswith("header:"):
            analysis = dict(analysis)
            analysis["attack_hypothesis"] = dict(hyp)
            analysis["attack_hypothesis"]["dangerous_param"] = dp[7:]

        # RAG retrieval of example rules is not part of the deployed method.
        examples_section = ""
        mitre_id = get_mitre_technique_id(analysis)

        cve_id = self._infer_case_id(http_request, analysis)
        method = str(http_request.get("method", "GET")).upper()

        # Step 2: Generate initial rule
        if self.use_template:
            rule = self._generate_template_rule(
                http_request, analysis, examples_section, mitre_id, cve_id)
        else:
            rule = self._generate_freeform_rule(
                http_request, analysis, examples_section, mitre_id, cve_id)
        logger.info("RuleGenAgent: initial rule (%d chars)", len(rule))

        # Step 3-4: Validation + repair loop
        last_validation = {}
        for attempt in range(self.max_validation_rounds):
            rule = postprocess_rule(
                rule, cve_id, method, sid_range=self.sid_range,
                fallback_obj=analysis)
            validation = self._validate_with_suricata(rule)
            last_validation = validation
            if validation.get("unavailable"):
                logger.error("RuleGenAgent: Suricata unavailable; returning unvalidated rule as comment")
                return f"# Rule validation unavailable: {validation.get('stderr', 'no suricata available')}\n# {rule}"
            if validation["valid"]:
                logger.info("RuleGenAgent: rule validated OK (attempt %d)", attempt)
                if self.enable_semantic_verify:
                    rule, sem = self._semantic_verify(
                        rule, http_request, analysis,
                        max_rounds=self.max_semantic_rounds)
                    logger.info("RuleGenAgent: semantic verification status=%s rounds=%s",
                                sem.get("final_status"), sem.get("rounds_used"))
                    if sem.get("final_status") == "degenerate":
                        fallback_spec = self._build_spec_from_analysis(analysis, http_request, pcre_pattern="")
                        fallback = assemble_rule(fallback_spec, cve_id, method, mitre_id, sid_range=self.sid_range)
                        if not self._is_degenerate(fallback):
                            logger.info("RuleGenAgent: degenerate after semantic verify, using content-only fallback")
                            return fallback
                        return None
                if self._is_degenerate(rule):
                    fallback_spec = self._build_spec_from_analysis(analysis, http_request, pcre_pattern="")
                    fallback = assemble_rule(fallback_spec, cve_id, method, mitre_id, sid_range=self.sid_range)
                    if not self._is_degenerate(fallback):
                        logger.info("RuleGenAgent: final rule degenerate, using content-only fallback")
                        return fallback
                    logger.warning("RuleGenAgent: final rule is degenerate, discarding")
                    return None
                return rule

            logger.warning("RuleGenAgent: validation failed (attempt %d): %s",
                          attempt, validation["errors"][:3])

            rule = self._repair_rule(rule, validation, http_request, analysis, cve_id)
            logger.info("RuleGenAgent: repaired rule (attempt %d, %d chars)", attempt + 1, len(rule))

        logger.warning("RuleGenAgent: validation exhausted %d attempts", self.max_validation_rounds)
        if last_validation.get("unavailable"):
            return f"# Rule validation unavailable: {last_validation.get('stderr', 'no suricata available')}\n# {rule}"
        final_rule = postprocess_rule(rule, cve_id, method, sid_range=self.sid_range,
                                      fallback_obj=analysis)
        if self._is_degenerate(final_rule):
            fallback_spec = self._build_spec_from_analysis(analysis, http_request, pcre_pattern="")
            fallback = assemble_rule(fallback_spec, cve_id, method, mitre_id, sid_range=self.sid_range)
            if not self._is_degenerate(fallback):
                logger.info("RuleGenAgent: validation-exhausted rule degenerate, using content-only fallback")
                return fallback
            logger.warning("RuleGenAgent: final rule is degenerate, discarding")
            return None
        return final_rule

    def _generate_freeform_rule(self, http_request: dict, analysis: dict,
                                examples_section: str, mitre_id: str,
                                cve_id: str) -> str:
        mitre_metadata = f'metadata:mitre_technique_id {mitre_id}; ' if mitre_id else ""
        prompt = f"""Generate a Suricata IDS rule to detect the following attack pattern.

## Attack Request
{json.dumps(self._prompt_request(http_request), indent=2)}

## Analysis
{json.dumps(analysis.get('attack_hypothesis', {}), indent=2)}

{examples_section}
## Requirements
1. Match the HTTP method and URI path from the request
2. Detect the attack payload pattern (the dangerous parameter)
3. Use content matches and pcre where appropriate
4. Include {mitre_metadata}in the rule metadata
5. Use a unique sid between 9000001-9999999
6. Do NOT reference any CVE number (this may be a zero-day)

Return ONLY the rule line, nothing else. /no_think"""

        messages = [
            {"role": "system", "content": RULE_GEN_ROLE},
            {"role": "user", "content": prompt},
        ]

        rule = self._extract_rule_line(
            _call_llm(messages, temperature=TEMP_STRUCTURED, max_tokens=512))
        return postprocess_rule(rule, cve_id, http_request.get("method", "GET"),
                                sid_range=self.sid_range, fallback_obj=analysis)

    def _generate_template_rule(self, http_request: dict, analysis: dict,
                                examples_section: str, mitre_id: str,
                                cve_id: str) -> str:
        attack_value = self._extract_attack_value(http_request, analysis)

        if not attack_value:
            spec = self._build_spec_from_analysis(analysis, http_request, pcre_pattern="")
            content_only = assemble_rule(
                spec, cve_id, http_request.get("method", "GET"), mitre_id,
                sid_range=self.sid_range)
            if not self._is_degenerate(content_only):
                logger.info("RuleGenAgent: attack_value empty, using content-only template")
                return content_only
            if self.max_validation_rounds == 0:
                logger.info("RuleGenAgent: attack_value empty, content-only degenerate, template-only mode")
                return None
            logger.info("RuleGenAgent: attack_value empty, falling back to freeform")
            return self._generate_freeform_rule(
                http_request, analysis, examples_section, mitre_id, cve_id)

        from ..rmin_translator import _pattern_label, PATTERN_PCRE

        label = _pattern_label(attack_value, analysis)
        pcre_pattern = ""
        extra_content = []
        if label == "path_traversal":
            # Route traversal through the mechanism pcre like every other class. The
            # pcre matches raw '../' AND its percent-encoded spellings (%2e%2e%2f) on
            # http.uri.raw, so the rule survives url-encoding evasion that a literal
            # path content misses. Apply it only when the traversal is in the URI;
            # for body-based traversal the URI has no "../" and a URI pcre would be a
            # phantom constraint (the full payload is matched on its own buffer).
            _trav_path = (http_request.get("path") or "").lower()
            if "../" in _trav_path or "%2e%2e" in _trav_path or "..%2f" in _trav_path:
                pcre_pattern = PATTERN_PCRE.get("path_traversal", "")
        elif label:
            pcre_full = PATTERN_PCRE.get(label, "")
            if pcre_full:
                pcre_pattern = pcre_full

        method = http_request.get("method", "GET")

        def _assemble(generalize):
            spec = self._build_spec_from_analysis(
                analysis, http_request, pcre_pattern, generalize=generalize)
            if extra_content:
                spec.setdefault("content_matches", []).extend(extra_content)
            return assemble_rule(spec, cve_id, method, mitre_id,
                                 sid_range=self.sid_range)

        # Conditional generalisation: when GENERALIZE_MECH drops the attack-value
        # literal, keep the class-level rule only if its mechanism pcre stays
        # wire-grounded (survives drop_phantom_pcre). If generalising would leave
        # route+param with no pcre (over-broad), fall back to the instance-specific
        # literal rule -- the generalised rule is then never less specific than the
        # literal one, so generalisation carries no FPR cost.
        if pcre_pattern and os.environ.get("GENERALIZE_MECH", "0") == "1":
            gen_rule = _assemble(True)
            if "pcre:" in drop_phantom_pcre(gen_rule, http_request):
                return gen_rule
            return _assemble(False)
        return _assemble(None)

    def _repair_rule(self, rule: str, validation: dict,
                     http_request: dict, analysis: dict, cve_id: str) -> str:
        repair_prompt = f"""The following Suricata rule has validation errors. Fix them.

## Current Rule (INVALID)
{rule}

## Validation Errors
{json.dumps(validation.get("errors", [])[:5], indent=2)}

## Suricata Stderr
{validation.get("stderr", "")[:800]}

Fix the rule and return ONLY the corrected rule line. /no_think"""

        messages = [
            {"role": "system", "content": RULE_REPAIR_ROLE},
            {"role": "user", "content": repair_prompt},
        ]

        fixed = self._extract_rule_line(
            _call_llm(messages, temperature=TEMP_STRUCTURED, max_tokens=512))
        return postprocess_rule(
            fixed, cve_id, http_request.get("method", "GET"),
            sid_range=self.sid_range, fallback_obj=analysis)

    def _semantic_repair_rule(self, rule: str, diagnosis: dict,
                              blackboard: list,
                              http_request: dict, analysis: dict,
                              cve_id: str) -> str:
        past_attempts = ""
        for entry in blackboard[-3:]:
            diag = entry.get("diagnosis", {})
            ft = entry.get("failure_type", "?")
            past_attempts += (
                f"Round {entry['round']} ({ft}): {entry['rule'][:120]}\n"
                f"  diagnosis: {diag.get('root_cause', '?')[:60]}\n")

        raw_traffic = self._format_raw_request(http_request)[:300]

        prompt = f"""Fix this Suricata rule based on the diagnosis.

Rule:
{rule}

Diagnosis:
  root_cause: {diagnosis.get('root_cause', 'unknown')}
  affected_part: {diagnosis.get('affected_part', 'unknown')}
  specific_fix: {diagnosis.get('specific_fix', 'unknown')}

HTTP traffic to match (first 300 bytes):
{raw_traffic}

Past failed attempts (do NOT reproduce):
{past_attempts or 'None'}

Fix ONLY the diagnosed issue. Change nothing else.
Return ONLY the corrected rule line. /no_think"""
        messages = [
            {"role": "system", "content": RULE_SEMANTIC_REPAIR_ROLE},
            {"role": "user", "content": prompt},
        ]
        fixed = self._extract_rule_line(
            _call_llm(messages, temperature=TEMP_STRUCTURED, max_tokens=512))
        return postprocess_rule(
            fixed, cve_id, http_request.get("method", "GET"),
            sid_range=self.sid_range, fallback_obj=analysis)

    def _semantic_verify(self, rule: str, http_request: dict,
                         analysis: dict, max_rounds: int = 3) -> tuple[str | None, dict]:
        """PCAP-driven detection CEGIS loop with blackboard and pre-analysis."""
        try:
            from src.evaluation.pcap_generator import generate_attack_pcap, generate_benign_pcap
            from src.evaluation.suricata_runner import run_suricata
        except Exception as e:
            return rule, {
                "attack_detected": False,
                "benign_clean": False,
                "rounds_used": 0,
                "final_status": "error",
                "error": f"semantic verification imports failed: {e}",
            }

        cve_id = self._infer_case_id(http_request, analysis)
        current = rule
        blackboard: list[dict] = []

        current = self._strip_mismatched_content(current, http_request)
        if current != rule:
            validation = self._validate_with_suricata(current)
            if not validation.get("valid"):
                current = rule
            else:
                logger.info("RuleGenAgent: auto-stripped mismatched content keywords")
        last_valid_rule = current
        last_diag: dict = {}

        degen_reason = self._is_degenerate(current)
        if degen_reason:
            if degen_reason == "placeholder_pcre":
                last_diag = {
                    "root_cause": "the pcre pattern contains the literal placeholder 'attack_value' instead of a real attack pattern",
                    "affected_part": "pcre",
                    "specific_fix": "Replace pcre:\"/(attack_value)/\" with a PCRE pattern derived from the actual attack payload in the HTTP request. Do not write the string 'attack_value' — it is a template variable that was not filled in.",
                }
            else:
                last_diag = {
                    "root_cause": "rule is too generic",
                    "affected_part": "content",
                    "specific_fix": "include the full endpoint path or parameter name plus an attack-specific payload fragment",
                }
            if self.no_llm_rule:
                # NO_LLM_RULE: skip LLM repair; let generate() fall back to the
                # deterministic content-only rule (no LLM ever touches the rule string).
                return None, {
                    "attack_detected": False, "benign_clean": False,
                    "rounds_used": 0, "final_status": "degenerate",
                    "rule_status": "degenerate", "diagnostic": last_diag,
                }
            candidate = self._semantic_repair_rule(
                current, last_diag, blackboard, http_request, analysis, cve_id)
            validation = self._validate_with_suricata(candidate)
            if validation.get("valid") and not self._is_degenerate(candidate):
                current = candidate
                last_valid_rule = candidate
            else:
                return None, {
                    "attack_detected": False,
                    "benign_clean": False,
                    "rounds_used": 0,
                    "final_status": "degenerate",
                    "rule_status": "degenerate",
                    "diagnostic": last_diag,
                }

        for round_idx in range(max_rounds):
            with tempfile.TemporaryDirectory(prefix="rule_semantic_") as tmp:
                tmp_path = Path(tmp)
                rules_path = tmp_path / "test.rules"
                rules_path.write_text(current + "\n", encoding="utf-8")
                attack_pcap = tmp_path / "attack.pcap"
                benign_pcap = tmp_path / "benign.pcap"
                generate_attack_pcap(http_request, str(attack_pcap))
                generate_benign_pcap(
                    http_request, str(benign_pcap),
                    vuln_class=self._analysis_vuln_class(analysis))

                sid = self._extract_sid(current)

                # Phase 1: Attack PCAP
                attack_result = run_suricata(
                    str(attack_pcap), str(rules_path),
                    str(tmp_path / "attack_logs"))
                if attack_result.get("error") == "suricata not found":
                    return current, {
                        "attack_detected": False,
                        "benign_clean": False,
                        "rounds_used": round_idx,
                        "final_status": "error",
                        "error": "suricata not found",
                    }
                attack_detected = self._result_has_sid(attack_result, sid)
                http_ok = self._result_has_http_event(attack_result)

                if not attack_detected:
                    if not http_ok:
                        last_diag = {
                            "root_cause": "pcap not parsed as HTTP by Suricata",
                            "affected_part": "pcap",
                            "specific_fix": "N/A - infrastructure issue",
                        }
                        logger.warning("RuleGenAgent: semantic round skipped, no HTTP event")
                        continue

                    failure_type = "attack_missed"
                    pre_analysis = self._pre_analyze(
                        current, failure_type, http_request,
                        eve_data=attack_result.get("http_events"))
                    diagnosis = self._diagnose_rule_failure(
                        current, failure_type, pre_analysis, blackboard)
                    blackboard.append({
                        "rule": current[:200],
                        "round": round_idx + 1,
                        "failure_type": failure_type,
                        "pre_analysis": {
                            "content_matched": pre_analysis.get("content_matched", []),
                            "content_not_matched": pre_analysis.get("content_not_matched", []),
                            "pcre_pattern": pre_analysis.get("pcre_pattern"),
                            "pcre_matched": pre_analysis.get("pcre_matched"),
                            "pcre_match_detail": str(pre_analysis.get("pcre_match_detail", ""))[:100],
                            "pcre_error": pre_analysis.get("pcre_error"),
                        },
                        "diagnosis": diagnosis,
                    })
                    candidate = self._semantic_repair_rule(
                        current, diagnosis, blackboard,
                        http_request, analysis, cve_id)
                    validation = self._validate_with_suricata(candidate)
                    if validation.get("valid") and not self._is_degenerate(candidate):
                        current = candidate
                        last_valid_rule = candidate
                    else:
                        logger.warning("RuleGenAgent: semantic repair produced invalid/degenerate rule")
                        return last_valid_rule, {
                            "attack_detected": False,
                            "benign_clean": False,
                            "rounds_used": round_idx + 1,
                            "final_status": "fail_attack",
                            "diagnostic": diagnosis,
                            "blackboard": blackboard,
                        }
                    continue

                # Attack detected → Phase 1: Benign PCAP (neutralized)
                benign_result = run_suricata(
                    str(benign_pcap), str(rules_path),
                    str(tmp_path / "benign_logs"))
                if benign_result.get("error"):
                    return current, {
                        "attack_detected": True,
                        "benign_clean": False,
                        "rounds_used": round_idx + 1,
                        "final_status": "error",
                        "error": benign_result.get("error"),
                    }
                benign_clean = not self._result_has_sid(benign_result, sid)

                if benign_clean:
                    # Phase 1: Common benign check
                    common_diag = self._check_common_benign(
                        current, sid, run_suricata, generate_attack_pcap, tmp_path)
                    if common_diag:
                        if common_diag.get("error"):
                            return current, {
                                "attack_detected": True,
                                "benign_clean": False,
                                "rounds_used": round_idx + 1,
                                "final_status": "error",
                                "error": common_diag.get("error"),
                            }

                        failure_type = "false_positive_on_common_benign"
                        benign_req = common_diag.get("common_benign_request", {})
                        pre_analysis = self._pre_analyze(
                            current, failure_type, http_request,
                            benign_request=benign_req)
                        diagnosis = self._diagnose_rule_failure(
                            current, failure_type, pre_analysis, blackboard)
                        blackboard.append({
                            "rule": current[:200],
                            "round": round_idx + 1,
                            "failure_type": failure_type,
                            "pre_analysis": {
                                "benign_request_preview": (
                                    pre_analysis.get("benign_request_preview", "")[:200]),
                                "pcre_pattern": (
                                    pre_analysis.get("benign_pcre_match") or {}
                                ).get("pcre_pattern"),
                                "pcre_matched_benign": (
                                    pre_analysis.get("benign_pcre_match") or {}
                                ).get("pcre_matched"),
                                "benign_content_matched": (
                                    (pre_analysis.get("benign_content_match") or {})
                                    .get("content_in_traffic", [])),
                            },
                            "diagnosis": diagnosis,
                        })
                        candidate = self._semantic_repair_rule(
                            current, diagnosis, blackboard,
                            http_request, analysis, cve_id)
                        validation = self._validate_with_suricata(candidate)
                        if validation.get("valid") and not self._is_degenerate(candidate):
                            current = candidate
                            last_valid_rule = candidate
                        else:
                            logger.warning("RuleGenAgent: common-benign repair invalid/degenerate")
                            return last_valid_rule, {
                                "attack_detected": True,
                                "benign_clean": False,
                                "rounds_used": round_idx + 1,
                                "final_status": "fail_common_benign",
                                "diagnostic": diagnosis,
                                "blackboard": blackboard,
                            }
                        continue

                    # All Phase 1 passed → Phase 2: benign_values.json final check
                    phase2 = self._final_benign_check(
                        current, sid, http_request, analysis,
                        run_suricata, generate_attack_pcap, tmp_path)
                    # Expose Phase-2 held-out-benign FP count for the runner's gate.
                    self.last_benign_fp = phase2.get("false_positives", 0)
                    return current, {
                        "attack_detected": True,
                        "benign_clean": True,
                        "rounds_used": round_idx + 1,
                        "final_status": "pass",
                        "phase2": phase2,
                        "blackboard": blackboard,
                    }

                # FP on neutralized benign → Pre-Analysis → Diagnose → Repair
                failure_type = "false_positive_on_benign"
                benign_req_for_analysis = self._neutralize_request(
                    http_request,
                    (analysis.get("attack_hypothesis") or {}).get("dangerous_param", ""),
                    "safe_value")
                pre_analysis = self._pre_analyze(
                    current, failure_type, http_request,
                    benign_request=benign_req_for_analysis,
                    eve_data=benign_result.get("http_events"))
                diagnosis = self._diagnose_rule_failure(
                    current, failure_type, pre_analysis, blackboard)
                blackboard.append({
                    "rule": current[:200],
                    "round": round_idx + 1,
                    "failure_type": failure_type,
                    "pre_analysis": {
                        "benign_request_preview": (
                            pre_analysis.get("benign_request_preview", "")[:200]),
                        "pcre_pattern": (
                            pre_analysis.get("benign_pcre_match") or {}
                        ).get("pcre_pattern"),
                        "pcre_matched_benign": (
                            pre_analysis.get("benign_pcre_match") or {}
                        ).get("pcre_matched"),
                        "benign_content_matched": (
                            (pre_analysis.get("benign_content_match") or {})
                            .get("content_in_traffic", [])),
                    },
                    "diagnosis": diagnosis,
                })
                candidate = self._semantic_repair_rule(
                    current, diagnosis, blackboard,
                    http_request, analysis, cve_id)
                validation = self._validate_with_suricata(candidate)
                if validation.get("valid") and not self._is_degenerate(candidate):
                    current = candidate
                    last_valid_rule = candidate
                else:
                    logger.warning("RuleGenAgent: semantic repair produced invalid/degenerate rule")
                    return last_valid_rule, {
                        "attack_detected": True,
                        "benign_clean": False,
                        "rounds_used": round_idx + 1,
                        "final_status": "fail_benign",
                        "diagnostic": diagnosis,
                        "blackboard": blackboard,
                    }
                continue

        # Loop exhausted
        status = "fail_attack"
        if blackboard:
            last_failure = blackboard[-1].get("failure_type", "")
            if last_failure == "false_positive_on_benign":
                status = "fail_benign"
            elif last_failure == "false_positive_on_common_benign":
                status = "fail_common_benign"
        elif last_diag.get("affected_part") == "pcap":
            status = "error"

        last_attack_detected = False
        if blackboard:
            last_attack_detected = any(
                e.get("failure_type") != "attack_missed" for e in blackboard)

        return last_valid_rule, {
            "attack_detected": last_attack_detected,
            "benign_clean": False,
            "rounds_used": max_rounds,
            "final_status": status,
            "diagnostic": blackboard[-1].get("diagnosis") if blackboard else last_diag,
            "blackboard": blackboard,
        }

    @staticmethod
    def _extract_rule_line(raw: str) -> str:
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"```\w*\n?", "", text).strip().rstrip("`")
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(("alert ", "drop ", "reject ", "pass ")):
                return line
        return text.splitlines()[0].strip() if text else ""

    @staticmethod
    def _extract_json(raw: str) -> dict:
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"```\w*\n?", "", text).strip().rstrip("`")
        candidates = []
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            candidates.append(match.group(0))
        candidates.append(text)
        for candidate in candidates:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                fixed = re.sub(r",\s*([}\]])", r"\1", candidate)
                try:
                    return json.loads(fixed)
                except json.JSONDecodeError:
                    pass
        raise ValueError(f"Could not parse JSON rule spec: {raw[:300]}")

    @staticmethod
    def _format_raw_request(http_request: dict) -> str:
        """Reconstruct HTTP request as wire-format string for content matching."""
        method = http_request.get("method", "GET")
        path = http_request.get("path", "/")
        params = http_request.get("params", {})
        headers = http_request.get("headers", {})
        body = http_request.get("body", "")
        body_text = ""
        if body:
            if isinstance(body, dict):
                body_text = urlencode(body)
            else:
                body_text = str(body)

        if params and "?" not in path:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            request_line = f"{method} {path}?{query} HTTP/1.1"
        else:
            request_line = f"{method} {path} HTTP/1.1"

        lines = [request_line, "Host: 192.168.1.100"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        if body_text and "Content-Length" not in headers:
            lines.append(f"Content-Length: {len(body_text)}")
            if "Content-Type" not in headers:
                lines.append("Content-Type: application/x-www-form-urlencoded")
        raw = "\r\n".join(lines) + "\r\n\r\n"
        if body_text:
            raw += body_text
        return raw

    @staticmethod
    def _content_matches_raw(content: str, raw: str, raw_lower: str) -> bool:
        c_clean = content.strip()
        if not c_clean or len(c_clean) <= 2:
            return True
        if "|" in c_clean:
            return True
        unescaped = (
            c_clean
            .replace(r"\;", ";")
            .replace(r"\"", '"')
            .replace(r"\\", "\\")
        )
        return (
            c_clean in raw
            or c_clean.lower() in raw_lower
            or unescaped in raw
            or unescaped.lower() in raw_lower
        )

    @staticmethod
    def _strip_mismatched_content(rule: str, http_request: dict) -> str:
        """Remove content keywords not matching actual HTTP traffic."""
        raw_request = RuleGenAgent._format_raw_request(http_request)
        raw_lower = raw_request.lower()
        open_idx = rule.find("(")
        close_idx = rule.rfind(")")
        if open_idx < 0 or close_idx <= open_idx:
            return rule

        options = RuleGenAgent._split_rule_options(rule[open_idx + 1:close_idx])
        if not options:
            return rule

        sticky_buffers = {
            "http.uri",
            "http.uri.raw",
            "http.request_body",
            "http.method",
            "http.header",
            "http.cookie",
            "http.host",
            "http.user_agent",
            "http.content_type",
        }
        content_modifiers = {"nocase", "fast_pattern"}
        content_modifier_prefixes = ("depth:", "offset:", "within:", "distance:")

        kept_content_count = 0
        removed_content_count = 0
        pending_buffers = []
        stripped_options = []
        last_content_kept = False

        for option in options:
            normalized = option.strip()
            lower = normalized.lower()

            if lower in sticky_buffers:
                pending_buffers.append(normalized)
                last_content_kept = False
                continue

            content_match = re.match(r'content\s*:\s*"([^"]*)"\s*$', normalized)
            if content_match:
                if RuleGenAgent._content_matches_raw(content_match.group(1), raw_request, raw_lower):
                    stripped_options.extend(pending_buffers)
                    pending_buffers = []
                    stripped_options.append(normalized)
                    kept_content_count += 1
                    last_content_kept = True
                else:
                    pending_buffers = []
                    removed_content_count += 1
                    last_content_kept = False
                continue

            if lower.startswith("pcre:"):
                pcre_m = re.match(r'pcre\s*:\s*"/(.*)/([A-Za-z]*)"', normalized, re.DOTALL)
                if pcre_m:
                    py_pat = pcre_m.group(1).replace(r"\x3b", ";").replace(r"\/", "/")
                    re_flags = re.IGNORECASE if "i" in pcre_m.group(2) else 0
                    pcre_ok = True
                    if re.search(r'\([^)]*[+*][^)]*\)[+*]', py_pat):
                        pcre_ok = True
                    else:
                        try:
                            pcre_ok = bool(re.search(py_pat, raw_request, re_flags))
                        except (re.error, RecursionError):
                            pcre_ok = True
                    if not pcre_ok:
                        logger.info("_strip_mismatched_content: removing non-matching pcre: %.60s", normalized)
                        pending_buffers = []
                        removed_content_count += 1
                        continue
                stripped_options.extend(pending_buffers)
                pending_buffers = []
                stripped_options.append(normalized)
                last_content_kept = False
                continue

            is_content_modifier = (
                lower in content_modifiers
                or any(lower.startswith(prefix) for prefix in content_modifier_prefixes)
            )
            if is_content_modifier:
                if last_content_kept:
                    stripped_options.append(normalized)
                continue

            pending_buffers = []
            stripped_options.append(normalized)
            last_content_kept = False

        if kept_content_count < 1:
            return rule
        if removed_content_count < 1:
            return rule

        prefix = rule[:open_idx + 1].rstrip() + " "
        suffix = rule[close_idx:]
        stripped = prefix + "; ".join(stripped_options) + ";" + suffix
        stripped = re.sub(r'\s+', ' ', stripped).strip()
        return stripped

    @staticmethod
    def _split_rule_options(options: str) -> list[str]:
        result = []
        buf = []
        in_quote = False
        escape = False
        for ch in options:
            if escape:
                buf.append(ch)
                escape = False
                continue
            if ch == "\\" and in_quote:
                buf.append(ch)
                escape = True
                continue
            if ch == '"':
                in_quote = not in_quote
                buf.append(ch)
                continue
            if ch == ";" and not in_quote:
                token = "".join(buf).strip()
                if token:
                    result.append(token)
                buf = []
                continue
            buf.append(ch)
        token = "".join(buf).strip()
        if token:
            result.append(token)
        return result

    @staticmethod
    def _analyze_content_mismatch(rule: str, http_request: dict) -> dict:
        """Compare rule content keywords against actual HTTP traffic bytes."""
        raw = RuleGenAgent._format_raw_request(http_request)
        raw_lower = raw.lower()
        contents = re.findall(r'content:"([^"]*)"', rule)
        methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

        found = []
        not_found = []
        for c in contents:
            if c in methods:
                continue
            if RuleGenAgent._content_matches_raw(c, raw, raw_lower):
                found.append(c)
            else:
                not_found.append(c)

        return {
            "content_in_traffic": found,
            "content_NOT_in_traffic": not_found,
            "raw_request_preview": raw[:500],
        }

    @staticmethod
    def _is_degenerate(rule: str) -> str | None:
        return _is_degenerate_fn(rule)

    def _check_common_benign(self, rule: str, sid: int | None, run_suricata,
                             generate_attack_pcap, tmp_path: Path) -> dict | None:
        common_benign_requests = [
            {"method": "GET", "path": "/", "headers": {}, "params": {}, "body": None},
            {"method": "GET", "path": "/index.html", "headers": {}, "params": {}, "body": None},
            {
                "method": "POST",
                "path": "/login",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "params": {},
                "body": "username=admin&password=admin123",
            },
        ]
        rules_path = tmp_path / "test.rules"
        for idx, benign_req in enumerate(common_benign_requests):
            pcap_path = tmp_path / f"common_benign_{idx}.pcap"
            generate_attack_pcap(benign_req, str(pcap_path), sport=32000 + idx)
            result = run_suricata(
                str(pcap_path), str(rules_path), str(tmp_path / f"common_benign_logs_{idx}"))
            if result.get("error"):
                return {
                    "failure": "common_benign_error",
                    "error": result.get("error"),
                    "common_benign_request": benign_req,
                }
            if self._result_has_sid(result, sid):
                return {
                    "failure": "false_positive_on_common_benign",
                    "common_benign_request": benign_req,
                    "common_benign_alerts": result.get("alerts", [])[:5],
                    "http_event": (result.get("http_events") or [])[:2],
                }
        return None

    # --- Pre-Analysis (deterministic, no LLM) ---

    @staticmethod
    def _analyze_pcre_mismatch(rule: str, raw_request: str) -> dict:
        """Deterministic check: does the rule's pcre match the attack traffic?"""
        pcre_match = re.search(r'pcre:"/(.*?)/([A-Za-z]*)";', rule)
        if not pcre_match:
            return {"pcre_present": False}

        pattern = pcre_match.group(1)
        flags_str = pcre_match.group(2)
        re_flags = re.IGNORECASE if "i" in flags_str else 0

        py_pattern = pattern.replace(r"\x3b", ";").replace(r"\/", "/")

        if re.search(r'\([^)]*[+*][^)]*\)[+*]', py_pattern):
            return {"pcre_present": True, "pcre_pattern": pattern,
                    "pcre_error": "ReDoS-vulnerable nested quantifier detected"}

        try:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(re.search, py_pattern, raw_request, re_flags)
                match = future.result(timeout=2.0)
            return {
                "pcre_present": True,
                "pcre_pattern": pattern,
                "pcre_matched": match is not None,
                "pcre_match_detail": match.group(0)[:100] if match else None,
            }
        except (re.error, concurrent.futures.TimeoutError) as e:
            return {"pcre_present": True, "pcre_pattern": pattern, "pcre_error": str(e)}

    @staticmethod
    def _analyze_benign_fp(rule: str, benign_request: dict) -> dict:
        """Analyze which parts of a benign request triggered a rule (FP analysis)."""
        raw = RuleGenAgent._format_raw_request(benign_request)
        content_analysis = RuleGenAgent._analyze_content_mismatch(rule, benign_request)
        pcre_analysis = RuleGenAgent._analyze_pcre_mismatch(rule, raw)
        return {
            "benign_request_preview": raw[:500],
            "benign_content_match": content_analysis,
            "benign_pcre_match": pcre_analysis,
        }

    def _pre_analyze(self, rule: str, failure_type: str,
                     http_request: dict,
                     benign_request: dict | None = None,
                     eve_data: list | None = None) -> dict:
        """Deterministic pre-analysis before LLM diagnosis."""
        result: dict = {"failure_type": failure_type}

        if failure_type == "attack_missed":
            raw = self._format_raw_request(http_request)
            content_mismatch = self._analyze_content_mismatch(rule, http_request)
            pcre_mismatch = self._analyze_pcre_mismatch(rule, raw)
            result.update({
                "content_matched": content_mismatch.get("content_in_traffic", []),
                "content_not_matched": content_mismatch.get("content_NOT_in_traffic", []),
                "pcre_pattern": pcre_mismatch.get("pcre_pattern"),
                "pcre_matched": pcre_mismatch.get("pcre_matched"),
                "pcre_match_detail": pcre_mismatch.get("pcre_match_detail"),
                "pcre_error": pcre_mismatch.get("pcre_error"),
                "raw_request_preview": raw[:300],
            })
        elif failure_type in ("false_positive_on_benign", "false_positive_on_common_benign"):
            if benign_request:
                fp_analysis = self._analyze_benign_fp(rule, benign_request)
                result.update(fp_analysis)
            raw = self._format_raw_request(http_request)
            result["pcre_analysis"] = self._analyze_pcre_mismatch(rule, raw)

        return result

    # --- Diagnose (LLM call) ---

    def _diagnose_rule_failure(self, rule: str, failure_type: str,
                               pre_analysis: dict,
                               blackboard: list) -> dict:
        """LLM-based failure diagnosis (separate from repair)."""
        history = ""
        for entry in blackboard[-3:]:
            diag = entry.get("diagnosis", {})
            ft = entry.get("failure_type", "?")
            history += (
                f"Round {entry['round']} ({ft}): "
                f"{diag.get('root_cause', 'unknown')}"
                f" [part={diag.get('affected_part', '?')}, "
                f"fix={str(diag.get('specific_fix', ''))[:60]}]\n")

        if failure_type == "attack_missed":
            failure_detail = (
                f"Content keywords found in traffic: {pre_analysis.get('content_matched', [])}\n"
                f"Content keywords NOT found: {pre_analysis.get('content_not_matched', [])}")
        elif "false_positive" in failure_type:
            benign_preview = pre_analysis.get("benign_request_preview", "N/A")
            benign_cm = pre_analysis.get("benign_content_match", {})
            matched_in_benign = benign_cm.get("content_in_traffic", [])
            failure_detail = (
                f"Benign request that triggered the rule:\n"
                f"{benign_preview}")
            if matched_in_benign:
                failure_detail += (
                    f"\nContent keywords that ALSO matched this benign request: "
                    f"{matched_in_benign}")
        else:
            failure_detail = ""

        pcre_info = ""
        pcre_pattern = pre_analysis.get("pcre_pattern")
        pcre_matched = pre_analysis.get("pcre_matched")
        if pcre_pattern is None and pre_analysis.get("pcre_analysis"):
            pcre_pattern = pre_analysis["pcre_analysis"].get("pcre_pattern")
            pcre_matched = pre_analysis["pcre_analysis"].get("pcre_matched")
        if pcre_pattern:
            pcre_detail = pre_analysis.get("pcre_match_detail")
            if pcre_detail is None and pre_analysis.get("pcre_analysis"):
                pcre_detail = pre_analysis["pcre_analysis"].get("pcre_match_detail")
            pcre_err = pre_analysis.get("pcre_error")
            if pcre_err is None and pre_analysis.get("pcre_analysis"):
                pcre_err = pre_analysis["pcre_analysis"].get("pcre_error")
            benign_pcre = pre_analysis.get("benign_pcre_match") or {}
            pcre_info = (
                f"PCRE match analysis:\n"
                f"  Pattern: {pcre_pattern}\n"
                f"  Matched attack: {pcre_matched}")
            if pcre_detail:
                pcre_info += f"\n  Matched text: {str(pcre_detail)[:100]}"
            if pcre_err:
                pcre_info += f"\n  Regex error: {pcre_err}"
            if benign_pcre.get("pcre_matched"):
                pcre_info += f"\n  Also matched benign: True"
                bd = benign_pcre.get("pcre_match_detail", "")
                if bd:
                    pcre_info += f" ({str(bd)[:80]})"

        raw_preview = pre_analysis.get("raw_request_preview", "N/A")

        prompt = f"""A Suricata rule failed testing. Identify the root cause.

Rule:
{rule}

Failure: {failure_type}
{failure_detail}

{pcre_info}

Traffic preview (first 300 bytes):
{raw_preview}

Past attempts (do NOT repeat these diagnoses):
{history or 'None'}

Answer in JSON:
{{"root_cause": "one-line explanation", "affected_part": "content | pcre | buffer | method | direction", "specific_fix": "what exactly to change"}} /no_think"""

        messages = [
            {"role": "system", "content": RULE_DIAGNOSE_ROLE},
            {"role": "user", "content": prompt},
        ]

        raw = _call_llm(messages, temperature=TEMP_STRUCTURED, max_tokens=256)
        try:
            return self._extract_json(raw)
        except ValueError:
            return {
                "root_cause": raw.strip()[:200],
                "affected_part": "unknown",
                "specific_fix": "unable to parse diagnosis",
            }

    # --- Phase 2: Final benign_values.json check ---

    def _final_benign_check(self, rule: str, sid: int | None,
                            http_request: dict, analysis: dict,
                            run_suricata, generate_attack_pcap,
                            tmp_path: Path) -> dict:
        """Phase 2: Final verification against benign_values.json (report only)."""
        benign_values_path = (
            Path(__file__).resolve().parents[3] / "data" / "benign_values.json")
        if not benign_values_path.exists():
            return {"phase2_skipped": True, "reason": "benign_values.json not found"}

        values = json.loads(benign_values_path.read_text(encoding="utf-8"))

        hyp = analysis.get("attack_hypothesis", {})
        param_name = hyp.get("dangerous_param", "")
        param_source = self._infer_param_source(http_request, param_name)

        if param_source == "body":
            category = "body"
        elif param_source == "query":
            category = "query_value"
        else:
            category = "generic"

        benign_items = values.get(category, values.get("generic", [""]))

        fps = []
        rules_path = tmp_path / "test.rules"
        rules_path.write_text(rule + "\n", encoding="utf-8")

        for idx, benign_val in enumerate(benign_items[:20]):
            benign_req = self._neutralize_request(http_request, param_name, benign_val)
            pcap_path = tmp_path / f"phase2_benign_{idx}.pcap"
            generate_attack_pcap(benign_req, str(pcap_path), sport=40000 + idx)

            result = run_suricata(
                str(pcap_path), str(rules_path),
                str(tmp_path / f"phase2_benign_logs_{idx}"))

            if result.get("error"):
                continue
            if self._result_has_sid(result, sid):
                fps.append({"benign_value": str(benign_val)[:50], "index": idx})

        return {
            "phase2_completed": True,
            "category": category,
            "total_tested": min(len(benign_items), 20),
            "false_positives": len(fps),
            "fp_details": fps[:5],
        }

    @staticmethod
    def _neutralize_request(http_request: dict, param_name: str,
                            safe_value: str) -> dict:
        """Replace the dangerous parameter with a safe benign value."""
        headers = http_request.get("headers") or {}
        if param_name and param_name in headers:
            neutralized_headers = {
                k: (safe_value if k == param_name else v)
                for k, v in headers.items()}
        else:
            neutralized_headers = dict(headers)

        req = {
            "method": http_request.get("method", "GET"),
            "path": http_request.get("path", "/").split("?")[0],
            "headers": neutralized_headers,
            "params": {},
            "body": None,
        }

        params = http_request.get("params") or {}
        if param_name and param_name in params:
            req["params"] = {k: (safe_value if k == param_name else v)
                             for k, v in params.items()}
        elif params:
            req["params"] = dict(params)

        body = http_request.get("body")
        if isinstance(body, dict) and param_name and param_name in body:
            req["body"] = {k: (safe_value if k == param_name else v)
                           for k, v in body.items()}
        elif isinstance(body, str) and body and param_name:
            try:
                parsed = parse_qs(body, keep_blank_values=True)
                if param_name in parsed:
                    parsed[param_name] = [safe_value]
                    req["body"] = "&".join(
                        f"{k}={v[0]}" for k, v in parsed.items())
                else:
                    req["body"] = body
            except Exception:
                req["body"] = body

        return req

    # --- CodeGen helpers ---

    @staticmethod
    def _extract_attack_value(http_request: dict, analysis: dict) -> str:
        """Extract the primary attack value from the request."""
        hyp = analysis.get("attack_hypothesis", {})
        param_name = hyp.get("dangerous_param", "")

        params = http_request.get("params") or {}
        if param_name and param_name in params:
            return str(params[param_name])

        body = http_request.get("body")
        if isinstance(body, dict) and param_name and param_name in body:
            return str(body[param_name])

        headers = http_request.get("headers") or {}
        if param_name and param_name in headers:
            return str(headers[param_name])

        path = http_request.get("path", "")
        if "?" in path:
            parsed = urlparse(path)
            qs = parse_qs(parsed.query)
            if param_name and param_name in qs:
                return qs[param_name][0]

        if param_name in ("path", "url", "uri"):
            req_path = http_request.get("path", "")
            if req_path and req_path != "/":
                return req_path

        # Structured string bodies (multipart / form-urlencoded / json-as-text /
        # xml) that the simple checks above miss: resolve the named param with the
        # SAME canonical parser the analyst used (parse_request_params +
        # find_param_value), so the rule matches the exact discriminator the front
        # half identified (e.g. the multipart filename / file content) rather than a
        # boundary-header chunk. Keeps front/back-half extraction consistent.
        if param_name and isinstance(body, str) and body:
            try:
                from ..skeleton import parse_request_params, find_param_value
                resolved = find_param_value(
                    parse_request_params(http_request), param_name, body)
                if resolved:
                    return str(resolved)
            except Exception:
                pass

        if params:
            return str(next(iter(params.values())))
        if isinstance(body, str) and body:
            return body[:200]

        return ""

    @staticmethod
    def _wire_content(value: str, buffer: str, wirebufs: dict,
                      maxlen: int = 80) -> str | None:
        """Return a form of ``value`` that is a contiguous substring of the on-wire
        bytes of ``buffer`` (per pcap_generator.wire_buffers), so a content match on
        it is guaranteed present in the request's own PCAP. Tries the value as-is,
        its percent-encoded form, and its percent-decoded form (covering Suricata's
        raw vs normalized buffers and the dict-body url-encoding). Returns None when
        the value is not on the wire, so the caller drops the phantom match. The
        on-wire form is truncated to ``maxlen`` (never the pre-escape source). This
        is a wire-format correctness check, independent of any specific attack."""
        buf = wirebufs.get(buffer, "")
        value = "" if value is None else str(value)
        if not buf or not value:
            return None
        seen = set()
        for cand in (value, _quote_for_query(value), unquote(value)):
            if not cand or cand in seen:
                continue
            seen.add(cand)
            if cand in buf:
                return cand[:maxlen]
        return None

    @staticmethod
    def _build_spec_from_analysis(analysis: dict, http_request: dict,
                                  pcre_pattern: str, generalize=None) -> dict:
        """Construct a rule spec dict deterministically from metadata."""
        hyp = analysis.get("attack_hypothesis", {})
        method = http_request.get("method", "GET").upper()
        path = http_request.get("path", "/").split("?")[0]
        param_name = hyp.get("dangerous_param", "")
        vuln_class = (hyp.get("vuln_class") or hyp.get("vulnerability_class")
                      or analysis.get("vuln_class") or "exploit")

        classtype = RuleGenAgent._vuln_class_to_classtype(vuln_class)
        param_source = RuleGenAgent._infer_param_source(http_request, param_name)
        param_buffer = RuleGenAgent._param_source_to_buffer(param_source, param_name)
        body_encoding = (
            RuleGenAgent._infer_body_encoding(http_request)
            if param_source == "body"
            else "urlencoded"
        )

        content_matches = []
        if path and path != "/":
            path_lower = path.lower()
            is_traversal = (
                "../" in path or "%2e%2e" in path_lower or "..%2f" in path_lower
            )
            if is_traversal:
                endpoint_prefix = (
                    path_lower.split("../")[0].split("%2e")[0].split("..%")[0]
                )
                endpoint_prefix = endpoint_prefix.rstrip("/") or "/"
                if endpoint_prefix and endpoint_prefix != "/":
                    content_matches.append({
                        "buffer": "http.uri.raw",
                        "value": endpoint_prefix,
                        "fast_pattern": True,
                    })
            else:
                content_matches.append({
                    "buffer": "http.uri",
                    "value": path,
                    "fast_pattern": True,
                })
        if param_name and param_name not in ("body", "raw_body", "none", "", "path", "url", "uri"):
            if param_source == "header":
                if param_buffer == "http.cookie":
                    content_matches.append({"buffer": param_buffer, "value": f"{param_name}="})
                elif param_buffer not in ("http.host", "http.user_agent"):
                    content_matches.append({"buffer": param_buffer, "value": f"{param_name}:"})
            elif body_encoding == "json":
                content_matches.append({"buffer": param_buffer, "value": f'"{param_name}":'})
            elif body_encoding == "xml":
                content_matches.append({"buffer": param_buffer, "value": f"<{param_name}>"})
            elif body_encoding == "urlencoded":
                content_matches.append({"buffer": param_buffer, "value": f"{param_name}="})

        attack_value = RuleGenAgent._extract_attack_value(http_request, analysis)
        # A mechanism pcre (pcre_pattern) carries the class match. The literal attack
        # value AND-ed alongside it pins the rule to the one observed payload
        # (;cat /etc/passwd; but not ;id;) and AND-suppresses the pcre on any other
        # spelling of the same mechanism. Drop the literal whenever a mechanism pcre
        # is present:
        #   - always for path_traversal (the pcre also covers percent-encoded ../),
        #   - under GENERALIZE_MECH for every mechanism class, so one rule fires on
        #     any payload of that class instead of memorising the observed instance.
        # The route + param-name content stay as anchors that keep FPR low.
        _av_traversal = "../" in attack_value or "%2e%2e" in str(attack_value).lower()
        if generalize is None:
            generalize = os.environ.get("GENERALIZE_MECH", "0") == "1"
        _drop_literal = bool(pcre_pattern) and (_av_traversal or generalize)
        if (attack_value and len(attack_value) >= 6 and not _drop_literal):
            content_matches.append({
                "buffer": param_buffer,
                "value": attack_value,
                "nocase": True,
                "_relocatable": True,
            })

        # Invariant: every content match must be a contiguous substring of the
        # on-wire bytes for its buffer, otherwise the rule cannot fire on the
        # request's own PCAP. Rewrite each value to its on-wire form (url-encoding /
        # verbatim body / normalization) and drop phantom matches. The attack-value
        # match is additionally relocated to the buffer it actually lives in, which
        # auto-corrects a mis-inferred param_source. Derived from the wire format
        # alone (RFC 3986 / Suricata buffers), independent of any specific attack.
        wirebufs = wire_buffers(http_request)
        verified = []
        for cm in content_matches:
            relocatable = cm.pop("_relocatable", False)
            wv = RuleGenAgent._wire_content(cm["value"], cm["buffer"], wirebufs)
            if wv is None and relocatable:
                for alt_buf in ("http.request_body", "http.uri", "http.uri.raw",
                                "http.cookie", "http.header"):
                    if alt_buf == cm["buffer"]:
                        continue
                    alt = RuleGenAgent._wire_content(cm["value"], alt_buf, wirebufs)
                    if alt is not None:
                        cm = dict(cm)
                        cm["buffer"] = alt_buf
                        wv = alt
                        break
            if wv is not None:
                cm = dict(cm)
                cm["value"] = wv
                verified.append(cm)
        content_matches = verified

        cve_id = str(http_request.get("case_id") or http_request.get("cve_id") or "")
        msg = f"IOT {vuln_class} attempt {cve_id}".strip()

        # Scope the mechanism pcre to the buffer the payload actually occupies on
        # the wire, so it matches the injection (e.g. a shell metachar in the body)
        # instead of whatever buffer the last content happened to set. param_source
        # inference can be wrong for nested JSON bodies, so probe the wire directly
        # -- the same authoritative basis the literal relocation uses above.
        # Traversal keeps inheriting http.uri.raw from its endpoint prefix, so its
        # pcre_buffer stays empty.
        _path_l = path.lower()
        _trav = "../" in _path_l or "%2e%2e" in _path_l or "..%2f" in _path_l
        pcre_buffer = None
        if pcre_pattern and not _trav and attack_value:
            for _buf in (param_buffer, "http.request_body", "http.uri",
                         "http.uri.raw", "http.cookie", "http.header"):
                if RuleGenAgent._wire_content(attack_value, _buf, wirebufs) is not None:
                    pcre_buffer = _buf
                    break
        return {
            "msg": msg,
            "classtype": classtype,
            "content_matches": content_matches,
            "pcre": pcre_pattern if pcre_pattern else None,
            "pcre_buffer": pcre_buffer,
        }

    @staticmethod
    def _vuln_class_to_classtype(vuln_class: str) -> str:
        mapping = {
            "command_injection": "web-application-attack",
            "path_traversal": "web-application-attack",
            "sql_injection": "web-application-attack",
            "template_injection": "web-application-attack",
            "code_injection": "web-application-attack",
            "info_leak": "attempted-recon",
            "auth_bypass": "attempted-admin",
            "InfoLeak": "attempted-recon",
            "AuthBypass": "attempted-admin",
        }
        return mapping.get(vuln_class, "web-application-attack")

    @staticmethod
    def _infer_param_source(http_request: dict, param_name: str) -> str:
        """Determine whether the dangerous param is in query or body."""
        if not param_name:
            return "query"
        method = http_request.get("method", "GET").upper()

        body = http_request.get("body")
        if isinstance(body, dict) and param_name in body:
            return "body"
        if isinstance(body, str) and body and method != "GET":
            if f"{param_name}=" in body:
                return "body"

        headers = http_request.get("headers") or {}
        if param_name in headers:
            return "header"

        params = http_request.get("params") or {}
        if param_name in params:
            return "query"

        path = http_request.get("path", "")
        if f"{param_name}=" in path:
            return "query"

        if method in ("POST", "PUT"):
            return "body"
        return "query"

    @staticmethod
    def _param_source_to_buffer(param_source: str, param_name: str) -> str:
        if param_source == "body":
            return "http.request_body"
        if param_source == "header":
            name_lower = (param_name or "").lower()
            if name_lower == "cookie":
                return "http.cookie"
            if name_lower == "host":
                return "http.host"
            if name_lower in ("user-agent", "user_agent"):
                return "http.user_agent"
            return "http.header"
        return "http.uri"

    @staticmethod
    def _infer_body_encoding(http_request: dict) -> str:
        # The PCAP writer (_build_http_payload) ALWAYS url-encodes a dict body,
        # regardless of Content-Type, so on the wire it is form-urlencoded. Only a
        # verbatim str body keeps its JSON/XML shape on the wire.
        if isinstance(http_request.get("body"), dict):
            return "urlencoded"
        headers = http_request.get("headers") or {}
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = (v or "").lower()
                break
        if "application/x-www-form-urlencoded" in ct:
            return "urlencoded"
        if "application/json" in ct:
            return "json"
        if "application/xml" in ct or "text/xml" in ct:
            return "xml"
        return "other"

    @staticmethod
    def _extract_sid(rule: str) -> int | None:
        match = re.search(r"\bsid\s*:\s*(\d+)", rule)
        return int(match.group(1)) if match else None

    @staticmethod
    def _result_has_sid(result: dict, sid: int | None) -> bool:
        if sid is None:
            return bool(result.get("triggered"))
        return sid in set(result.get("rule_sids", set()))

    @staticmethod
    def _result_has_http_event(result: dict) -> bool:
        if result.get("http_events"):
            return True
        return any(event.get("event_type") == "http" for event in result.get("events", []))

    @staticmethod
    def _infer_case_id(http_request: dict, analysis: dict) -> str:
        for source in (http_request, analysis):
            for key in ("cve_id", "case_id"):
                if source.get(key):
                    return str(source[key])
        return ""

    @staticmethod
    def _analysis_vuln_class(analysis: dict) -> str | None:
        hyp = analysis.get("attack_hypothesis", {})
        value = hyp.get("vuln_class") or hyp.get("vulnerability_class") or analysis.get("vuln_class")
        return str(value) if value else None

    @staticmethod
    def _prompt_request(http_request: dict) -> dict:
        request = dict(http_request)
        for key in ("case_id", "cve_id", "is_benign", "label", "ground_truth"):
            request.pop(key, None)
        return _truncate_request(request)

    @staticmethod
    def _make_suricata_config(rule_path_dir: str) -> str:
        return f"""%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "[80,8080,8888,9090,9091]"
default-rule-path: {rule_path_dir}
rule-files:
  - test.rules
app-layer:
  protocols:
    http:
      enabled: yes
outputs:
  - stats:
      enabled: no
threading:
  set-cpu-affinity: no
  detect-thread-ratio: 1.0
stream:
  memcap: 256mb
  checksum-validation: no
host-mode: auto
"""

    @staticmethod
    def _validate_with_suricata(rule: str) -> dict:
        with tempfile.TemporaryDirectory(prefix="rule_validate_") as tmp:
            tmp_dir = Path(tmp)
            rule_path = tmp_dir / "test.rules"
            rule_path.write_text(rule + "\n", encoding="utf-8")

            native_config = tmp_dir / "suricata.yaml"
            native_config.write_text(
                RuleGenAgent._make_suricata_config(str(tmp_dir)), encoding="utf-8")

            docker_config = tmp_dir / "suricata_docker.yaml"
            docker_config.write_text(
                RuleGenAgent._make_suricata_config("/validate"), encoding="utf-8")

            for cmd in [
                ["suricata", "-c", str(native_config), "-T", "-l", str(tmp_dir),
                 "--runmode", "single"],
                ["docker", "run", "--rm",
                 "--entrypoint", "suricata",
                 "-v", f"{tmp_dir}:/validate",
                 "suricata-eval",
                 "-c", "/validate/suricata_docker.yaml", "-T", "-l", "/validate",
                 "--runmode", "single"],
            ]:
                try:
                    proc = subprocess.Popen(
                        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                        text=True, start_new_session=True)
                    try:
                        _, stderr_text = proc.communicate(timeout=30)
                    except subprocess.TimeoutExpired:
                        # Kill the entire process group to avoid zombie suricata
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except (ProcessLookupError, OSError):
                            proc.kill()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            pass
                        return {"valid": False, "errors": ["Validation timed out"]}
                    errors = []
                    for line in stderr_text.splitlines():
                        ll = line.lower()
                        if "<error>" in ll or "errcode" in ll:
                            errors.append(line.strip())
                        elif ("invalid" in ll or "unknown" in ll) and "rule" in ll and "msg:" not in ll:
                            errors.append(line.strip())
                    return {
                        "valid": proc.returncode == 0 and len(errors) == 0,
                        "errors": errors,
                        "stderr": stderr_text[:1500],
                    }
                except FileNotFoundError:
                    continue

            logger.warning("No Suricata available for validation — skipping check")
            return {"valid": False, "errors": ["no suricata available"],
                    "stderr": "no suricata available", "unavailable": True}
