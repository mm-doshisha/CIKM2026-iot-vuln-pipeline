"""Hypothesis-driven security analyst agent.

The analyst receives ONLY the raw HTTP request (no CVE info, no vulnerability
class, no decoded payload) and reasons about what the server does with it.

Design principle: NO CHEATING.
- No CVE database lookup
- No vulnerability classification taxonomy
- No pre-built templates
- The LLM must reason purely from the HTTP request structure
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
from urllib.error import URLError
from urllib.request import Request, urlopen

from .temperature import TEMP_GENERATIVE

logger = logging.getLogger("analyst")

_MAX_JSON_RETRIES = 3

_LLM_PORT = os.environ.get("LLM_PORT", "8080")
LLM_ENDPOINT = f"http://127.0.0.1:{_LLM_PORT}/v1/chat/completions"
LLM_MODEL = "qwen3-8b"

_LLM_SEED: int | None = None


def set_llm_seed(seed: int | None):
    global _LLM_SEED
    _LLM_SEED = seed


def _repair_json_string(s: str) -> str:
    """Aggressively repair a JSON string that may contain unescaped quotes.

    Iterates over the string character by character, tracking whether we are
    inside a JSON string value and fixing bare " that are NOT already escaped.
    This handles embedded XML attributes like version="1.0" inside a value.
    """
    result = []
    in_string = False
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == '\\' and in_string:
            result.append(ch)
            if i + 1 < len(s):
                result.append(s[i + 1])
                i += 2
            else:
                i += 1
            continue
        if ch == '"':
            if not in_string:
                in_string = True
                result.append(ch)
            else:
                # Peek: is the next non-whitespace char a JSON structural char?
                j = i + 1
                while j < len(s) and s[j] in ' \t\r\n':
                    j += 1
                next_ch = s[j] if j < len(s) else ''
                if next_ch in (':', ',', '}', ']', ''):
                    in_string = False
                    result.append(ch)
                else:
                    result.append('\\"')
            i += 1
            continue
        if in_string and ch in '\n\r\t':
            # Escape control chars that are illegal inside JSON string values.
            # LLMs often write multi-line reasoning with bare newlines.
            _ctrl = {'\n': '\\n', '\r': '\\r', '\t': '\\t'}
            result.append(_ctrl[ch])
            i += 1
            continue
        result.append(ch)
        i += 1
    return ''.join(result)


def _extract_json(raw: str, context: str = "") -> dict:
    """Extract JSON from LLM response with fallback repair."""
    md_match = re.search(r"```(?:json)?\s*\n(.*?)\n```", raw, re.DOTALL)
    candidates = []
    if md_match:
        candidates.append(md_match.group(1))

    brace_match = re.search(r"\{.*\}", raw, re.DOTALL)
    if brace_match:
        candidates.append(brace_match.group(0))

    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    for candidate in candidates:
        try:
            fixed = candidate
            fixed = re.sub(r",\s*}", "}", fixed)
            fixed = re.sub(r",\s*]", "]", fixed)
            fixed = re.sub(r'(?<=\w)"(?=\w)', '\\"', fixed)
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass

    for candidate in candidates:
        try:
            last_brace = candidate.rfind("}")
            if last_brace > 0:
                return json.loads(candidate[:last_brace + 1])
        except json.JSONDecodeError:
            pass

    for candidate in candidates:
        try:
            fixed = re.sub(
                r'\\x([0-9a-fA-F]{2})',
                lambda m: f'\\u00{m.group(1).lower()}',
                candidate
            )
            fixed = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', fixed)
            return json.loads(fixed)
        except (json.JSONDecodeError, Exception):
            pass

    for candidate in candidates:
        try:
            result = json.loads(_repair_json_string(candidate))
            # Reject silently-misrepaired JSON that lost the required key.
            # The peek-ahead in _repair_json_string can incorrectly close a
            # string when a value ends with `"word}`, producing valid JSON
            # but with attack_hypothesis stripped. Discard those.
            if "attack_hypothesis" in result:
                return result
        except (json.JSONDecodeError, Exception):
            pass

    logger.info("Extraction failed — tail: ...%s", raw[-200:])
    raise ValueError(f"Could not extract JSON from {context} response:\n{raw[:500]}")


def _call_llm(messages, temperature: float = TEMP_GENERATIVE,
              max_tokens: int = 8192, _max_retries: int = 2) -> str:
    payload = json.dumps({
        "model": LLM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        **({"seed": _LLM_SEED} if _LLM_SEED is not None else {}),
    }).encode("utf-8")

    from .llm_server import ensure_healthy

    for attempt in range(_max_retries + 1):
        req = Request(
            LLM_ENDPOINT,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=600) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            choice = body["choices"][0]
            finish = choice.get("finish_reason", "?")
            content = choice["message"]["content"]
            if finish != "stop":
                logger.warning("LLM finish_reason=%s (len=%d)", finish, len(content))
            return content
        except (ConnectionError, OSError, URLError, socket.timeout, TimeoutError) as e:
            if attempt >= _max_retries:
                raise
            logger.warning("LLM call failed (attempt %d/%d): %s — restarting server",
                          attempt + 1, _max_retries + 1, e)
            ensure_healthy()


def _extract_request_only(trace: dict) -> dict:
    """Extract ONLY the HTTP request from a trace. No response, no CVE info,
    no vulnerability class, no decoded payload. Just what an IDS would see."""
    req = trace["trace"]["request"]
    return {
        "method": req["method"],
        "path": req["path"],
        "params": req.get("params", {}),
        "headers": req.get("headers", {}),
        "body": req.get("body"),
    }


def _extract_response(trace: dict) -> dict:
    """Extract the HTTP response from a trace for mock data configuration.

    This is used by CodeGen to configure sandbox tools — the response body
    tells the LLM what data the mock server should produce."""
    resp = trace.get("trace", {}).get("response", {})
    return {
        "status_code": resp.get("status_code", 200),
        "headers": resp.get("headers", {}),
        "body": resp.get("body", ""),
    }


def _url_decode_recursive(value: str, max_rounds: int = 5) -> str:
    """URL-decode a string repeatedly until stable.

    Control characters (newline, tab, null, etc.) are replaced with
    readable escape representations so LLM can see them without
    breaking JSON serialization.
    """
    from urllib.parse import unquote
    for _ in range(max_rounds):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    _CONTROL_MAP = {
        "\n": "\\n", "\r": "\\r", "\t": "\\t", "\x00": "\\x00",
    }
    for char, replacement in _CONTROL_MAP.items():
        value = value.replace(char, replacement)
    return value


def decode_request_for_analysis(http_request: dict) -> dict:
    """Decode all URL-encoded values in a request for LLM analysis.

    Returns a new dict with decoded path, params, and body.
    The original request should be kept for Suricata rule generation.
    """
    decoded = {
        "method": http_request["method"],
        "path": _url_decode_recursive(http_request["path"]),
        "params": {},
        "headers": dict(http_request.get("headers", {})),
        "body": http_request.get("body"),
    }
    for k, v in http_request.get("params", {}).items():
        if isinstance(v, str):
            decoded["params"][k] = _url_decode_recursive(v)
        else:
            decoded["params"][k] = v
    if decoded["body"] and isinstance(decoded["body"], str):
        decoded["body"] = _url_decode_recursive(decoded["body"])
    return decoded

ANALYST_SYSTEM_PROMPT = """## Role
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


def _truncate_request(http_request: dict, max_body_len: int = 512,
                      max_path_len: int = 300) -> dict:
    """Truncate oversized request fields to avoid crashing the LLM server."""
    req = dict(http_request)
    path = req.get("path", "")
    if isinstance(path, str) and len(path) > max_path_len:
        n = len(path) - max_path_len
        req["path"] = path[:max_path_len] + f"...[+{n} chars]"
    for field in ("body",):
        val = req.get(field)
        if isinstance(val, str) and len(val) > max_body_len:
            req[field] = val[:max_body_len] + f"... [TRUNCATED, original length: {len(val)}]"
    for dict_field in ("params", "headers"):
        if dict_field in req and isinstance(req[dict_field], dict):
            d = dict(req[dict_field])
            for k, v in d.items():
                if isinstance(v, str) and len(v) > max_body_len:
                    d[k] = v[:max_body_len] + f"... [TRUNCATED, original length: {len(v)}]"
            req[dict_field] = d
    return req


def analyze_request(http_request: dict, temperature: float = TEMP_GENERATIVE,
                    extra_context: str = "",
                    system_prompt: str = None) -> dict:
    """Phase 1+2: Observe the request and generate hypotheses.

    Returns a structured analysis with hypotheses about server behavior.
    """
    request_text = json.dumps(_truncate_request(http_request), indent=2, ensure_ascii=False)

    user_prompt = f"""Analyze this HTTP request intercepted from network traffic.
This request may be an attack or normal device communication.

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
3. **Exploitability assessment**: Does any parameter carry input that could enable
    unintended server behavior? A value does not need to look syntactically malicious;
    consider the parameter's role and what vulnerable server code would do with it.
    Key test: would changing this parameter's value prevent the unintended behavior?
    If no specific parameter value matters, set dangerous_param to null.
4. **Server behavior model**: Describe what the server-side code probably does.
   Would this request, processed by vulnerable code, cause harm or is it normal operation?

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
    "dangerous_param": "<the most specific exploitable element: a query param name, form field, JSON key, XML tag, cookie key (not 'Cookie'), or header name. Use \"path\" ONLY when no query params and no body exist and the URL path itself determines whether unintended server behavior occurs. Return null only if no specific exploitable element exists at all.>",
    "payload_syntax": "<describe the root cause: what does the server do wrong with this input?>",
    "server_action": "<what the server probably does with this value>",
    "expected_effect": "<what happens when the attack succeeds>"
  }},
  "server_behavior": "<step-by-step description of what the server does>"
}}
```

Be specific and concrete. /no_think"""

    messages = [
        {"role": "system", "content": system_prompt or ANALYST_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    last_err = None
    for attempt in range(_MAX_JSON_RETRIES + 1):
        raw = _call_llm(messages, temperature=TEMP_GENERATIVE, max_tokens=7000)
        logger.info("Analyst response: %d chars", len(raw))
        try:
            return _extract_json(raw, "analyst")
        except ValueError as e:
            last_err = e
            if attempt < _MAX_JSON_RETRIES:
                logger.warning("JSON parse failed (attempt %d/%d), retrying: %s",
                               attempt + 1, _MAX_JSON_RETRIES + 1, str(e)[:120])
    raise last_err


def revise_hypothesis(http_request: dict, analysis: dict,
                      counterexample: dict,
                      temperature: float = TEMP_GENERATIVE,
                      system_prompt: str = None,
                      blackboard: dict = None) -> dict:
    """Phase 4: CEGIS - Revise the hypothesis based on test failure.

    This is the key difference from the template approach: instead of
    fixing a Spec field, the analyst RETHINKS the hypothesis.
    """
    request_text = json.dumps(_truncate_request(http_request), indent=2, ensure_ascii=False)
    analysis_text = json.dumps(analysis, indent=2, ensure_ascii=False)
    ce_text = json.dumps(counterexample, indent=2, ensure_ascii=False)

    blackboard_section = ""
    if blackboard:
        bb_parts = []
        tried = blackboard.get("tried_conditions", [])
        if tried:
            bb_parts.append("## Previously Tried Conditions (ALL FAILED)")
            for tc in tried[-5:]:
                bb_parts.append(
                    f"- `{str(tc.get('condition', ''))[:80]}` "
                    f"-> {tc.get('failed_test', '?')}: "
                    f"{str(tc.get('reason', ''))[:200]}")
        hist = blackboard.get("diagnosis_history", [])
        if hist:
            bb_parts.append("\n## Diagnosis History")
            for h in hist[-3:]:
                bb_parts.append(
                    f"- {h.get('failed_test', '?')}: "
                    f"root_cause={str(h.get('root_cause', ''))[:80]}, "
                    f"fix={str(h.get('specific_fix', ''))[:80]}")
        tried_params = blackboard.get("tried_params", [])
        if tried_params:
            bb_parts.append(f"\n## Tried Parameters: {tried_params}")
        failed_tests = blackboard.get("failed_tests", [])
        if failed_tests:
            bb_parts.append(f"\n## Failure Pattern: {failed_tests[-5:]}")
        if bb_parts:
            blackboard_section = "\n" + "\n".join(bb_parts) + "\n"

    user_prompt = f"""## Task
Your previous security analysis of this HTTP request was tested and the test FAILED.
Revise your analysis.

## Original HTTP Request
{request_text}

## Your Previous Analysis
{analysis_text}

## What Went Wrong
{ce_text}
{blackboard_section}
## Instructions
Think about WHY the test failed. Consider fundamentally different explanations:
- Did you identify the wrong parameter as dangerous?
- Is the parameter value encoded or transformed in a way you missed?
- Is there a parameter you overlooked — a header, cookie, or nested field?
- Does the path itself carry the parameter value causing unintended behavior rather than a query or body parameter?
- Did you name the wrong granularity? Name the specific field key, not its container.

## Important
Do NOT simply tweak your previous answer. If the same approach failed, try a
completely different hypothesis about which parameter carries the exploitable value.

Return a REVISED analysis in the same JSON format as before. /no_think"""

    messages = [
        {"role": "system", "content": system_prompt or ANALYST_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    last_err = None
    for attempt in range(_MAX_JSON_RETRIES + 1):
        raw = _call_llm(messages, temperature=temperature, max_tokens=7000)
        logger.info("Revised analysis: %d chars", len(raw))
        try:
            return _extract_json(raw, "revised analysis")
        except ValueError as e:
            last_err = e
            if attempt < _MAX_JSON_RETRIES:
                logger.warning("JSON parse failed (attempt %d/%d), retrying: %s",
                               attempt + 1, _MAX_JSON_RETRIES + 1, str(e)[:120])
    raise last_err
