"""Analyst tool: Hypothesis generation with fixed-temperature orchestration.

Responsibilities:
  - analyze(): Single fixed-temperature hypothesis generation
  - revise(): Multi-perspective revision
  - try_alternative(): Exclude failed params, analyze from scratch
"""
from __future__ import annotations

import json
import logging

from ..analyst import (
    analyze_request,
    revise_hypothesis,
)
from ..temperature import TEMP_GENERATIVE

logger = logging.getLogger("analyst")

ANALYST_ROLE = """## Role
You are a senior security analyst examining HTTP traffic.
The traffic may or may not contain an attack.
Your job is to identify which specific parameter, if any, could enable
unintended server behavior — not to find one at all costs.

## Key Insight
Many attacks carry no syntactically malicious payload.
A parameter is exploitable not because its value looks dangerous,
but because of what the server does with it:
- A field the server uses to invoke processes, query data stores, construct file paths, or render output
- A header or cookie the server uses to grant or restrict access to resources
- A value the server uses to select a processing mode or code path
- A value the server uses to determine the size, scope, or target of an operation

Judge each parameter by its role in server-side processing, not by value syntax alone.

## Constraints
- You do NOT have access to any CVE database.
- You do NOT know what vulnerability this is.
- You see ONLY the raw HTTP request.

## Analysis Steps
For each request, reason step by step:
1. What does the path suggest about server-side processing (CGI script, REST API,
   management interface, firmware endpoint)?
2. For EACH parameter (query, form field, JSON key, cookie key, header): what would
   vulnerable server code do with this value?
3. Does any parameter — regardless of whether its value looks syntactically malicious —
   give an attacker control over how the server processes or responds to the request?
4. If yes, name the most specific exploitable element.

## Granularity
When the attack vector is a value within a structured field (cookie, JSON body,
multipart form), name the specific field key rather than the container.

## CRITICAL: Never return "body" when named fields exist
If the request body contains named fields (form parameters like `key=value`,
JSON keys, XML elements, or multipart fields), you MUST name the specific field.
- WRONG: dangerous_param: "body"  (when body = "username=admin&cmd=ls")
- RIGHT:  dangerous_param: "cmd"
- WRONG: dangerous_param: "body"  (when body = {"reportName": "exploit"})
- RIGHT:  dangerous_param: "reportName"
Only use "body" as dangerous_param when the body is entirely unstructured (raw
binary, a single opaque blob with no named fields, or the entire body structure
is itself the attack payload (e.g., a raw binary blob with no named fields).

## When to Return null
Key test: Would changing any specific parameter value prevent the unintended server behavior?
If NO — the server is vulnerable regardless of what values appear — set
dangerous_param to null.
If YES — a specific value matters — identify that parameter.

## Path-Based Attacks
When a request has NO query parameters and NO body, the URL path itself may be
the attack surface — some servers behave differently based solely on which path
is requested.
Key test: Would requesting a DIFFERENT URL path prevent the vulnerability?
If YES → dangerous_param = "path"
If NO (any URL triggers it) → dangerous_param = null

Do not force an attack interpretation where none exists.

Focus on parameter roles and server-side processing logic, not surface syntax."""

REVISION_ROLE = """## Role
You are a senior threat analyst performing a second-pass review of a failed hypothesis.
Your previous analysis was tested against a mock server and FAILED. You must now
think fundamentally differently - not tweak parameters, but reconsider the entire
interpretation of the request.

## Key Insight
Many attacks carry no syntactically malicious payload.
A parameter is exploitable not because its value looks dangerous,
but because of what the server does with it:
- A field the server uses to invoke processes, query data stores, construct file paths, or render output
- A header or cookie the server uses to grant or restrict access to resources
- A value the server uses to select a processing mode or code path
- A value the server uses to determine the size, scope, or target of an operation

Judge each parameter by its role in server-side processing, not by value syntax alone.

## Revision Framework
1. **Diagnose failure**: What specifically went wrong with the condition or parameter?
2. **Challenge assumptions**: List alternative interpretations of the same request
3. **Consider overlooked possibilities**: Could a different parameter be the vector —
   encoded params, path segments, headers, or fields you initially dismissed?
4. **Select the most plausible alternative** with clear reasoning

## CRITICAL: Never return "body" when named fields exist
If the body contains named fields (form params, JSON keys, XML elements),
name the specific field. Return "body" ONLY for raw unstructured blobs.

## Path-Based Attacks
When a request has NO query parameters and NO body, the URL path itself may be
the attack surface — some servers behave differently based solely on which path
is requested.
Key test: Would requesting a DIFFERENT URL path prevent the vulnerability?
If YES → dangerous_param = "path"
If NO (any URL triggers it) → dangerous_param = null

Do not force an attack interpretation where none exists.

## When Test Evidence Suggests No Parameter Matters
If the test framework consistently shows the server behaves identically
regardless of WHICH PARAMETER is tested — specifically if T1
(the server does not log or handle the value differently) repeatedly fails
even after trying completely DIFFERENT PARAMETERS as dangerous_param —
this is evidence that no parameter-level vulnerability exists in this request.
IMPORTANT: Trying different detection CONDITIONS for the same parameter does
NOT count as testing different hypotheses. Only switching to a fundamentally
different parameter (e.g., from "cmd" to "username" to "path") counts.
In that case, setting dangerous_param to null is appropriate.
Do not return null based on general doubt — only when repeated test
failures across multiple DIFFERENT PARAMETERS support this conclusion.

Note: At this revision stage you have typically seen failures for ONE
parameter. Failures for a single parameter under multiple detection
conditions do NOT meet the "different PARAMETERS" threshold above.
Consider: (a) is the detection approach wrong but the parameter correct?
(b) is a completely different parameter the actual attack vector?
Return null only if the request appears genuinely benign on re-examination."""

# Null criterion injected into try_alternative's exclusion prompt. Module-level
# so the no-classify variant can replace it; default keeps the production behavior.
ALT_NULL_CLAUSE = (
    "if no remaining parameter could influence how the server invokes processes,\n"
    "accesses resources, determines access rights, or evaluates inputs.")


class Analyst:

    def __init__(self):
        self._tried_params = set()

    def reset(self):
        """Reset per-trace state. Call before processing a new trace."""
        self._tried_params = set()

    def analyze(self, http_request: dict, manifest: str = "",
                candidate_params: list[str] | None = None) -> dict:
        """Generate a hypothesis using the fixed generative temperature."""
        logger.info("Analyst: starting analysis")
        extra = ("\n" + manifest + "\n") if manifest else ""

        if candidate_params:
            _names = ", ".join(f'"{n}"' for n in candidate_params)
            param_instruction = (
                f"For `dangerous_param`, follow these steps in order:\n\n"
                f"Step 1 — Is there an attack in this request at all?\n"
                f"         If the request appears benign or non-malicious,\n"
                f"         return null.\n\n"
                f"Step 2 — If an attack is present: does the URL path\n"
                f"         itself carry the attack vector (e.g., path\n"
                f"         traversal, injection in the URL path)?\n"
                f"         If so, return \"path\".\n\n"
                f"Step 3 — Only if an attack is present AND the path is\n"
                f"         not the vector: return exactly one name from\n"
                f"         this list (verbatim, case-sensitive):\n"
                f"         {_names}\n"
                f"         Do not invent or paraphrase field names."
            )
            extra = extra + f"\n\n{param_instruction}\n"

        selected = analyze_request(
            http_request, temperature=TEMP_GENERATIVE,
            extra_context=extra,
            system_prompt=ANALYST_ROLE)

        hyp = selected.get("attack_hypothesis", {})
        p = (hyp.get("dangerous_param") or "").strip()
        if p and p.lower() not in ("none", "n/a", ""):
            self._tried_params.add(p)

        logger.info("Analyst: selected param=%s, syntax=%s",
                    hyp.get("dangerous_param"), hyp.get("payload_syntax"))
        return selected

    def revise(self, http_request: dict, analysis: dict,
               counterexample: dict,
               temperature: float = TEMP_GENERATIVE,
               blackboard: dict = None) -> dict:
        """Revise hypothesis with multi-perspective guidance."""
        logger.info("Analyst: revising hypothesis (temp=%.2f)", temperature)
        revised = revise_hypothesis(
            http_request, analysis, counterexample,
            temperature=TEMP_GENERATIVE,
            system_prompt=REVISION_ROLE,
            blackboard=blackboard)

        hyp = revised.get("attack_hypothesis", {})
        p = (hyp.get("dangerous_param") or "").strip()
        if p and p.lower() not in ("none", "n/a", ""):
            self._tried_params.add(p)

        logger.info("Analyst: revised to param=%s, syntax=%s",
                    hyp.get("dangerous_param"), hyp.get("payload_syntax"))
        return revised

    def try_alternative(self, http_request: dict, manifest: str = "",
                        blackboard: dict = None,
                        excluded: list = None) -> dict:
        """Generate alternative hypothesis excluding previously tried params.

        Args:
            excluded: Override exclusion list. None (default) uses _tried_params.
                      Pass [] to retry without any exclusion (e.g. when only
                      condition synthesis failed, not the param choice itself).
        """
        if excluded is None:
            excluded = list(self._tried_params)
            if not excluded:
                logger.info("Analyst: no params to exclude, running normal analysis")
                return self.analyze(http_request, manifest=manifest)

        logger.info("Analyst: alternative hypothesis excluding %s", excluded)

        history_context = ""
        if blackboard:
            bb_parts = []

            tried = blackboard.get("tried_conditions", [])
            if tried:
                bb_parts.append("## Previously Tried Conditions (ALL FAILED)")
                for tc in tried[-5:]:
                    bb_parts.append(
                        f"- `{str(tc.get('condition', ''))[:80]}` "
                        f"-> {tc.get('failed_test', '?')}: "
                        f"{str(tc.get('reason', ''))[:60]}")

            hist = blackboard.get("diagnosis_history", [])
            if hist:
                bb_parts.append("\n## Why Previous Params Failed")
                for h in hist[-3:]:
                    bb_parts.append(
                        f"- {h.get('failed_test', '?')}: "
                        f"root_cause={str(h.get('root_cause', ''))[:80]}, "
                        f"fix={str(h.get('specific_fix', ''))[:80]}")

            failed_tests = blackboard.get("failed_tests", [])
            if failed_tests:
                bb_parts.append(f"\n## Failure Pattern: {failed_tests[-5:]}")

            if bb_parts:
                history_context = "\n" + "\n".join(bb_parts) + "\n"

        extra = ("\n" + manifest + "\n") if manifest else ""
        if excluded:
            exclusion_context = extra + f"""
## CRITICAL CONSTRAINT
Previous analyses tried these as the dangerous parameter, but ALL FAILED:
{json.dumps(excluded)}
Identify a different attack vector, or set dangerous_param to null
{ALT_NULL_CLAUSE}
{history_context}
"""
        else:
            # excluded=[] means condition synthesis failed, not the param choice.
            # Retry the same param with a fresh approach guided by blackboard context.
            exclusion_context = extra + f"""
## CONTEXT: Detection Condition Synthesis Failed
Previous detection conditions for this request were rejected during static
verification — not because the parameter choice was wrong, but because
a valid detection expression could not be generated.
Re-analyze the request and identify the dangerous parameter.
Use the failure context below to inform a different detection approach.
{history_context}
"""
        analysis = analyze_request(
            http_request, temperature=TEMP_GENERATIVE,
            extra_context=exclusion_context,
            system_prompt=ANALYST_ROLE)

        hyp = analysis.get("attack_hypothesis", {})
        logger.info("Analyst: alternative param=%s, syntax=%s",
                    hyp.get("dangerous_param"), hyp.get("payload_syntax"))
        return analysis

    @property
    def tried_params(self) -> set:
        return set(self._tried_params)
