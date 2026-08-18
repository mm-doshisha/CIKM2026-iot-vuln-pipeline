"""Filter-OFF (no-classify) analyst prompt variant.

Ablate the analyst's 2-class attack/benign filter: the analyst always names a
single best-guess target parameter (never null), matching the no-filter setting
of prior rule-generation baselines. Applied via monkey-patch in
run_hypothesis_e2e.py (--no-classify); the Runner reads NO_CLASSIFY_ACTIVE to
skip the null-rejection gate while the mechanism gate stays fixed.
"""

_EXPLOIT_STEP_DEFAULT = (
    "3. **Exploitability assessment**: Which parameter, if any, carries input that\n"
    "   could enable unintended server behavior? A value does not need to look\n"
    "   syntactically malicious; consider the parameter's role and what vulnerable\n"
    "   server code would do with it.\n"
    "   Key test: would changing this parameter's value prevent the unintended behavior?\n"
    "   If no specific parameter value matters, set dangerous_param to null.")


def _make_patched_analyze(role_prompt, user_preamble, label, exploit_step=None):
    """Create a patched analyze_request with the given prompts."""
    import src.hypothesis.analyst as _analyst
    if exploit_step is None:
        exploit_step = _EXPLOIT_STEP_DEFAULT

    def _patched(http_request, temperature=None, extra_context="",
                 system_prompt=None):
        import json
        from .temperature import TEMP_GENERATIVE
        if temperature is None:
            temperature = TEMP_GENERATIVE

        request_text = json.dumps(
            _analyst._truncate_request(http_request), indent=2,
            ensure_ascii=False)

        user_prompt = f"""{user_preamble}

## HTTP Request
{request_text}
{extra_context}
## Your Task
Examine each component of this request and reason about what the server-side
code probably does. Focus on:

1. **Path analysis**: What kind of server-side resource does this path point to?
2. **Parameter analysis**: For EACH parameter (including body if present),
   reason about what the server-side code would do with this value.
   If there are NO query params and NO body, explicitly consider whether
   the URL path alone determines what unintended server action occurs.
{exploit_step}
4. **Server behavior model**: Describe what the server-side code probably does
   with this request.

Return your analysis as JSON:
```json
{{
  "path_analysis": "<what this path suggests about the server>",
  "parameters": [
    {{
      "name": "<param name or 'body' or 'path'>",
      "value": "<the actual value>",
      "value_type": "<what this value looks like>",
      "dangerous": true/false,
      "reasoning": "<why you think this>"
    }}
  ],
  "attack_hypothesis": {{
    "dangerous_param": "<the most specific exploitable element, or null>",
    "payload_syntax": "<describe the root cause>",
    "server_action": "<what the server probably does with this value>",
    "expected_effect": "<what happens when exploited>"
  }},
  "server_behavior": "<step-by-step description of what the server does>"
}}
```

Be specific and concrete. /no_think"""

        messages = [
            {"role": "system",
             "content": system_prompt or role_prompt},
            {"role": "user", "content": user_prompt},
        ]

        last_err = None
        for attempt in range(_analyst._MAX_JSON_RETRIES + 1):
            raw = _analyst._call_llm(messages, temperature=temperature,
                                      max_tokens=7000)
            _analyst.logger.info("Analyst (%s) response: %d chars", label,
                                 len(raw))
            try:
                return _analyst._extract_json(raw, f"analyst_{label}")
            except ValueError as e:
                last_err = e
                if attempt < _analyst._MAX_JSON_RETRIES:
                    _analyst.logger.warning(
                        "JSON parse failed (attempt %d/%d): %s",
                        attempt + 1, _analyst._MAX_JSON_RETRIES + 1,
                        str(e)[:120])
        raise last_err

    return _patched


def _apply_patch(role_prompt, user_preamble, label):
    """Apply monkey-patch with given prompt variant."""
    import src.hypothesis.analyst as _analyst
    import src.hypothesis.agents.analyst_tool as _tool

    _analyst.ANALYST_SYSTEM_PROMPT = role_prompt
    _tool.ANALYST_ROLE = role_prompt

    patched = _make_patched_analyze(role_prompt, user_preamble, label)
    _analyst.analyze_request = patched
    _tool.analyze_request = patched


# ---------------------------------------------------------------------------
# Experiment 1: no-classify (Option C) variant — ablate the 2-class benign filter.
# The analyst no longer decides attack/benign; it always names the single best-guess
# target parameter (never null). patch_prompts_no_classify() sets NO_CLASSIFY_ACTIVE,
# which the Runner reads to skip the null-rejection gate (analyst-layer filter OFF).
# The pg2 mechanism gate (MECH_GATE/MECH_EXACT) is held fixed independently.
# ---------------------------------------------------------------------------
NO_CLASSIFY_ACTIVE = False

ANALYST_ROLE_NO_CLASSIFY = """## Role
You are a security analyst examining HTTP traffic from an IoT device. Your task is
NOT to decide whether this request is an attack — assume that question is already
settled upstream. Your ONLY job is to identify which single parameter is the most
likely exploitation target.

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
- You do NOT have access to any CVE database and do NOT know the vulnerability.
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

## CRITICAL: Always return a concrete parameter — never null
You MUST name the single most likely target parameter. Do NOT return null, "none",
or "no attack". Rank the parameters and return your single best guess.

## Path-Based Attacks
When a request has NO query parameters and NO body, the URL path itself may be
the attack surface. If requesting a DIFFERENT URL path would prevent the
vulnerability, return "path" as the dangerous parameter.

## Granularity
When the payload is a value inside a structured field (cookie, JSON body, multipart
form), name the specific field key, not the generic container.

Focus on parameter roles and server-side processing logic, not surface syntax."""

USER_PREAMBLE_NO_CLASSIFY = (
    "Identify the single parameter MOST LIKELY to carry an attack payload if this "
    "request were used to exploit the device. Always return a concrete parameter "
    "name (query param, form field, JSON key, header, cookie, or 'path'). Never "
    "return null or 'none' — always give your single best guess."
)


def patch_prompts_no_classify():
    """Monkey-patch to the no-classify variant (Experiment 1, Option C).

    The analyst no longer performs the attack/benign 2-class decision: it always
    names the single best-guess target parameter (never null). Also sets the
    module-level NO_CLASSIFY_ACTIVE flag, which the Runner reads to skip the
    null-rejection gate — so the 2-class filter is OFF while the pg2 mechanism gate
    (MECH_GATE=hard MECH_EXACT=1) stays fixed. Neutral 'Option C' (no affirmative
    'this is an attack' assertion, which would bias toward false positives)."""
    global NO_CLASSIFY_ACTIVE
    NO_CLASSIFY_ACTIVE = True
    _apply_patch(ANALYST_ROLE_NO_CLASSIFY, USER_PREAMBLE_NO_CLASSIFY, "no_classify")
