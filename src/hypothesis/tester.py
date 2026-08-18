"""Hypothesis tester: verify the generated Flask mock against the original request.

Tests are GENERIC - they don't know what vulnerability class this is.
They only check behavioral properties:
- T1: Does the server respond to the original request without error?
- T2: Does the dangerous parameter actually affect the server's behavior?
- T3: Is a benign version of the request handled differently?
- T4: Does the internal log show the dangerous parameter was processed?
"""
from __future__ import annotations

import http.client
import json
import logging
from urllib.parse import urlencode, urlparse

import requests

logger = logging.getLogger("tester")


def run_tests(base_url: str, http_request: dict, analysis: dict) -> dict:
    """Run all tests against the mock server.

    Args:
        base_url: server base URL
        http_request: the original HTTP request dict
        analysis: the analyst's hypothesis
    """
    results = {}
    results["T1"] = _test_positive_replay(base_url, http_request)
    results["T2"] = _test_behavioral_impact(base_url, http_request, analysis)
    results["T3"] = _test_benign_difference(base_url, http_request, analysis)
    results["T4"] = _test_log_processing(base_url, http_request, analysis)
    results["attribution"] = _extract_attribution(base_url)

    all_pass = all(results[t]["passed"] for t in ("T1", "T2", "T3", "T4"))
    logger.info("Test results: %s (all_pass=%s)",
                {k: v["passed"] for k, v in results.items() if k != "attribution"},
                all_pass)
    return results


class _RawResponse:
    """Minimal response adapter for raw http.client requests."""

    def __init__(self, http_resp: http.client.HTTPResponse):
        self.status_code = http_resp.status
        self._body = http_resp.read()
        self.text = self._body.decode("utf-8", errors="replace")
        self.headers = dict(http_resp.getheaders())

    def json(self):
        return json.loads(self.text)


def _needs_raw_path(path: str) -> bool:
    lower = path.lower()
    return "../" in path or "..%2f" in lower or "..%5c" in lower


def _send_raw(base_url: str, method: str, path: str,
              params: dict = None, headers: dict = None, body: str = None):
    """Send an HTTP request while preserving traversal sequences in path."""
    parsed = urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or 80
    if not host:
        logger.error("Raw request failed: invalid base_url=%s", base_url)
        return None

    full_path = path
    if params:
        full_path = f"{path}?{urlencode(params, doseq=True)}"

    conn = None
    try:
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.putrequest(method.upper(), full_path)
        hdrs = headers or {}
        for k, v in hdrs.items():
            conn.putheader(k, v)
        if body:
            body_bytes = body.encode("utf-8")
            if "content-length" not in {k.lower() for k in hdrs}:
                conn.putheader("Content-Length", str(len(body_bytes)))
            conn.endheaders(body_bytes)
        else:
            conn.endheaders()
        return _RawResponse(conn.getresponse())
    except Exception as e:
        logger.error("Raw request failed: %s", e)
        return None
    finally:
        if conn is not None:
            conn.close()


def _send(base_url: str, method: str, path: str,
          params: dict = None, headers: dict = None, body: str = None):
    """Send an HTTP request to the mock server."""
    headers = headers or {}
    url_path = path.split("?")[0] if params else path
    if _needs_raw_path(url_path):
        return _send_raw(base_url, method, url_path, params, headers, body)

    url = f"{base_url}{url_path}"
    try:
        method_upper = method.upper()
        if method_upper == "GET":
            return requests.get(url, params=params, headers=headers, timeout=10)
        kwargs = {"headers": headers, "timeout": 10}
        if params:
            kwargs["params"] = params
        if body:
            kwargs["data"] = body
        return requests.request(method_upper, url, **kwargs)
    except Exception as e:
        logger.error("Request failed: %s", e)
        return None


def _get_log(base_url: str) -> list:
    """Get the internal log from the mock server."""
    try:
        r = requests.get(f"{base_url}/api/log", timeout=10)
        if r.status_code == 200:
            return r.json()
        logger.warning("/api/log returned status %d: %s", r.status_code, r.text[:200])
    except Exception as e:
        logger.warning("/api/log failed: %s", e)
    return []


def _test_positive_replay(base_url: str, http_request: dict) -> dict:
    """T1: Send the original attack request. Server must respond (not 404/500)
    and the internal log must record the request."""
    log_before = len(_get_log(base_url))

    resp = _send(
        base_url,
        http_request["method"],
        http_request["path"],
        http_request.get("params"),
        http_request.get("headers"),
        http_request.get("body"),
    )

    if resp is None:
        return {"passed": False, "error": "Request failed (connection error)"}

    log_after = _get_log(base_url)
    new_entries = log_after[log_before:]

    passed = (resp.status_code not in (404, 405, 500)
              and len(new_entries) > 0)

    return {
        "passed": passed,
        "status_code": resp.status_code,
        "response_length": len(resp.text),
        "response_body": resp.text[:500],
        "new_log_entries": len(new_entries),
        "log_sample": new_entries[:2] if new_entries else [],
    }


def _test_behavioral_impact(base_url: str, http_request: dict,
                             analysis: dict) -> dict:
    """T2: The dangerous parameter must have observable impact.
    Send the request WITH the dangerous param → check log shows 'matched'.
    """
    log_before = len(_get_log(base_url))

    resp = _send(
        base_url,
        http_request["method"],
        http_request["path"],
        http_request.get("params"),
        http_request.get("headers"),
        http_request.get("body"),
    )

    if resp is None:
        return {"passed": False, "error": "Request failed"}

    log_after = _get_log(base_url)
    new_entries = log_after[log_before:]

    has_match = any(
        e.get("matched", False) for e in new_entries
    )

    return {
        "passed": has_match,
        "status_code": resp.status_code,
        "response_body": resp.text[:500],
        "new_log_entries": len(new_entries),
        "log_sample": new_entries[:2] if new_entries else [],
    }


def _neutralize_json_recursive(obj, param_name: str):
    """Recursively find and neutralize *param_name* in nested JSON (case-insensitive)."""
    pn = param_name.lower()
    if isinstance(obj, dict):
        changed = False
        result = {}
        for k, v in obj.items():
            if k.lower() == pn:
                result[k] = "safe_value"
                changed = True
            elif isinstance(v, (dict, list)):
                sub_changed, sub_result = _neutralize_json_recursive(v, param_name)
                result[k] = sub_result
                changed = changed or sub_changed
            else:
                result[k] = v
        return changed, result
    elif isinstance(obj, list):
        changed = False
        result = []
        for item in obj:
            if isinstance(item, (dict, list)):
                sub_changed, sub_result = _neutralize_json_recursive(item, param_name)
                result.append(sub_result)
                changed = changed or sub_changed
            else:
                result.append(item)
        return changed, result
    return False, obj


def _neutralize_multipart(body: str, param_name: str) -> str | None:
    """Neutralize a field name or ``filename`` inside a multipart body.

    Returns the modified body, or *None* if nothing was changed.
    """
    import re as _re
    lines = body.split("\n")
    boundary = None
    for line in lines:
        stripped = line.strip("\r\n")
        if stripped.startswith("--") and len(stripped) > 4:
            boundary = stripped[2:]
            break
    if not boundary:
        return None

    marker = "--" + boundary
    parts = body.split(marker)
    changed = False
    new_parts = []
    pn = param_name.lower()

    for part in parts:
        if pn == "filename" or pn.endswith(".filename"):
            fn_match = _re.search(
                r'(Content-Disposition:[^\r\n]*\bfilename=")([^"]*)"',
                part, _re.IGNORECASE)
            if fn_match:
                part = part[:fn_match.start(2)] + "safe_value" + part[fn_match.end(2):]
                changed = True

        nm_match = _re.search(
            r'Content-Disposition:[^\r\n]*\bname="([^"]+)"', part, _re.IGNORECASE)
        if nm_match and nm_match.group(1).lower() == pn:
            if "\r\n\r\n" in part:
                hdr, val = part.split("\r\n\r\n", 1)
                trail = "\r\n" if val.endswith("\r\n") else ""
                part = hdr + "\r\n\r\n" + "safe_value" + trail
                changed = True
            elif "\n\n" in part:
                hdr, val = part.split("\n\n", 1)
                trail = "\n" if val.endswith("\n") else ""
                part = hdr + "\n\n" + "safe_value" + trail
                changed = True

        new_parts.append(part)

    return marker.join(new_parts) if changed else None


def _neutralize_body_param(body: str, param_name: str) -> str:
    """Replace a parameter value in a JSON, form-encoded, XML, or multipart body."""
    if not body:
        return body

    try:
        data = json.loads(body)
        if isinstance(data, (dict, list)):
            changed, result = _neutralize_json_recursive(data, param_name)
            if changed:
                return json.dumps(result)
    except (json.JSONDecodeError, ValueError):
        pass

    if "Content-Disposition" in body or body.lstrip().startswith("--"):
        mp = _neutralize_multipart(body, param_name)
        if mp is not None:
            return mp

    from urllib.parse import parse_qs, urlencode
    try:
        parsed = parse_qs(body, keep_blank_values=True)
        for k in list(parsed.keys()):
            if k.lower() == param_name.lower():
                parsed[k] = ["safe_value"]
                return urlencode(parsed, doseq=True)
    except Exception:
        pass

    import re as _re
    xml_pattern = _re.compile(
        r"(<" + _re.escape(param_name) + r"[^>]*>)(.*?)(</" + _re.escape(param_name) + r">)",
        _re.DOTALL | _re.IGNORECASE)
    if xml_pattern.search(body):
        return xml_pattern.sub(r"\1safe_value\3", body)

    return body


def _send_with_replaced_param(base_url: str, http_request: dict,
                               dangerous_param: str, replacement: str):
    """Send request with dangerous_param replaced by a specific value."""
    is_header_param = dangerous_param.startswith("header:")
    actual_param = dangerous_param[7:] if is_header_param else dangerous_param

    method = http_request["method"]
    path = http_request["path"]
    params = dict(http_request.get("params", {}))
    headers = dict(http_request.get("headers", {}))
    body = http_request.get("body")
    actual_l = actual_param.lower()
    params_l = {str(k).lower() for k in params}
    headers_l = {str(k).lower() for k in headers}

    benign_body = body

    if is_header_param or actual_l in headers_l:
        headers = {k: (replacement if k.lower() == actual_param.lower() else v)
                   for k, v in headers.items()}
    elif actual_param == "path":
        path = replacement
    elif actual_param == "body":
        benign_body = replacement if replacement else "{}"
        params = {}
    elif actual_l in params_l:
        for k in list(params.keys()):
            if str(k).lower() == actual_l:
                params[k] = replacement
    elif actual_param.lower() in ("cookie", "cookies"):
        headers = {k: v for k, v in headers.items()
                   if k.lower() != "cookie"}
    elif body and actual_param not in params:
        benign_body = _neutralize_body_param(body, actual_param)
        if benign_body and "safe_value" in benign_body:
            benign_body = benign_body.replace("safe_value", replacement)

    return _send(base_url, method, path, params, headers, benign_body)


def _test_benign_difference(base_url: str, http_request: dict,
                             analysis: dict) -> dict:
    """T3: A benign version of the request should behave differently.
    Remove or neutralize the dangerous parameter, verify the server
    doesn't process an attack. Also tests against real-world benign values.
    """
    attack_hyp = analysis.get("attack_hypothesis", {})
    dangerous_param = attack_hyp.get("dangerous_param", "")

    if not dangerous_param or dangerous_param.lower() in ("none", "n/a", "null", ""):
        return {"passed": True, "note": "no dangerous param identified"}

    is_header_param = dangerous_param.startswith("header:")
    actual_param = dangerous_param[7:] if is_header_param else dangerous_param

    method = http_request["method"]
    path = http_request["path"]
    params = dict(http_request.get("params", {}))
    headers = dict(http_request.get("headers", {}))
    body = http_request.get("body")
    actual_l = actual_param.lower()
    params_l = {str(k).lower() for k in params}
    headers_l = {str(k).lower() for k in headers}
    body_l = str(body).lower() if body else ""

    param_in_request = (actual_l in params_l
                        or (body and actual_l in body_l)
                        or actual_l in headers_l)
    if not param_in_request and actual_param.lower() not in ("path", "body", "cookie", "cookies"):
        return {"passed": True, "note": f"dangerous_param '{dangerous_param}' not in request, likely info leak"}

    benign_body = body

    if is_header_param or actual_l in headers_l:
        headers = {k: v for k, v in headers.items()
                   if k.lower() != actual_param.lower()}
    elif actual_param == "path":
        path = "/safe_benign_path"
    elif actual_param == "body":
        benign_body = "{}" if body else None
        params = {}
    elif actual_l in params_l:
        for k in list(params.keys()):
            if str(k).lower() == actual_l:
                params[k] = "safe_value"
    elif actual_param.lower() in ("cookie", "cookies"):
        headers = {k: v for k, v in headers.items()
                   if k.lower() != "cookie"}
    elif body and actual_param not in params:
        benign_body = _neutralize_body_param(body, actual_param)

    log_before = len(_get_log(base_url))

    resp = _send(base_url, method, path, params, headers, benign_body)

    if resp is None:
        return {"passed": False, "error": "Benign request failed"}

    log_after = _get_log(base_url)
    safe_entries = log_after[log_before:]

    has_match = any(e.get("matched", False) for e in safe_entries)

    if has_match:
        return {
            "passed": False,
            "status_code": resp.status_code,
            "response_body": resp.text[:500],
            "new_log_entries": len(safe_entries),
            "benign_had_match": True,
            "log_sample": safe_entries[:2] if safe_entries else [],
        }

    # Benign values from benign_values.json
    from .skeleton import _load_benign_values, _param_type
    param_type = _param_type(dangerous_param)
    benign_set = _load_benign_values()
    benign_values = benign_set.get(param_type, benign_set.get("generic", []))

    # T3 invariant: benign values must differ from the actual attack value.
    # Testing condition(benign_val) where benign_val == attack_value is
    # circular — identical to re-running T2. Exclude the attack value from
    # the benign set regardless of param type. This rule is general (applies
    # to all CVEs); only empty-string attacks are practically affected since
    # no other attack values appear in benign_values.json.
    _attack_val = None
    _req_params = http_request.get("params", {})
    for _k, _v in _req_params.items():
        if str(_k).lower() == actual_param.lower():
            _attack_val = _v
            break
    if _attack_val is None and actual_param.lower() in ("path", "url"):
        _attack_val = http_request.get("path", "")
    if _attack_val is not None:
        benign_values = [bv for bv in benign_values if bv != _attack_val]

    for benign_val in benign_values:
        log_before_benign = len(_get_log(base_url))

        benign_resp = _send_with_replaced_param(
            base_url, http_request, dangerous_param, benign_val)

        if benign_resp is None:
            continue

        log_after_benign = _get_log(base_url)
        benign_entries = log_after_benign[log_before_benign:]
        benign_matched = any(e.get("matched", False) for e in benign_entries)

        if benign_matched:
            return {
                "passed": False,
                "status_code": benign_resp.status_code,
                "response_body": benign_resp.text[:500],
                "new_log_entries": len(benign_entries),
                "benign_had_match": True,
                "triggered_value": benign_val[:100],
                "log_sample": benign_entries[:2] if benign_entries else [],
            }

    return {
        "passed": True,
        "status_code": resp.status_code,
        "response_body": resp.text[:500],
        "new_log_entries": len(safe_entries),
        "benign_had_match": False,
        "log_sample": [],
    }


def _test_log_processing(base_url: str, http_request: dict,
                          analysis: dict) -> dict:
    """T4: The internal log must show that the dangerous parameter
    was received and processed (not just that a request was logged).
    """
    log_before = len(_get_log(base_url))

    _send(
        base_url,
        http_request["method"],
        http_request["path"],
        http_request.get("params"),
        http_request.get("headers"),
        http_request.get("body"),
    )

    log_after = _get_log(base_url)
    new_entries = log_after[log_before:]

    if not new_entries:
        return {"passed": False, "error": "No log entries after request"}

    attack_hyp = analysis.get("attack_hypothesis", {})
    dangerous_param = attack_hyp.get("dangerous_param", "")
    expected_name = dangerous_param[7:] if dangerous_param.startswith("header:") else dangerous_param

    has_dangerous_logged = any(
        e.get("dangerous_param") or e.get("action_taken")
        for e in new_entries
    )
    generic_params = {"", "none", "n/a", "null", "body", "raw_body", "path"}
    if expected_name and expected_name.lower() not in generic_params:
        has_param_name_logged = any(
            str(e.get("dangerous_param_name", "")).lower() == expected_name.lower()
            or str(e.get("matched_param", "")).lower() == expected_name.lower()
            for e in new_entries
        )
    else:
        has_param_name_logged = True

    has_match = any(e.get("matched", False) for e in new_entries)

    passed = has_dangerous_logged and has_param_name_logged and has_match

    return {
        "passed": passed,
        "new_log_entries": len(new_entries),
        "has_dangerous_param_logged": has_dangerous_logged,
        "has_param_name_logged": has_param_name_logged,
        "expected_param_name": expected_name,
        "has_match": has_match,
        "log_sample": new_entries[:3] if new_entries else [],
    }


def _extract_attribution(base_url: str) -> dict:
    """Extract counterfactual parameter attribution from mock server log."""
    log = _get_log(base_url)
    all_matched = set()
    for entry in log:
        for p in entry.get("all_matched_params", []):
            all_matched.add(p)
    return {"all_matched_params": sorted(all_matched)}


def build_counterexample(test_results: dict, analysis: dict):
    """Build a counterexample from test failures for CEGIS revision."""
    priority = ["T1", "T2", "T3", "T4"]

    for test_name in priority:
        result = test_results.get(test_name, {})
        if not result.get("passed", True):
            ce = {
                "failed_test": test_name,
                "test_description": {
                    "T1": "Original request was not handled by the server (404/500 or no log entry)",
                    "T2": "The dangerous parameter did not produce observable effect (no 'matched' in log)",
                    "T3": "A benign request also triggered attack processing (false positive)",
                    "T4": "Internal log did not record processing of the dangerous parameter",
                }.get(test_name, "Unknown test"),
                "details": result,
                "current_hypothesis": analysis.get("attack_hypothesis", {}),
            }
            if test_name == "T1" and result.get("status_code") in (404, 405):
                ce["fix_hint"] = "Route path doesn't match the request. Check @app.route decorator."
            elif test_name == "T1" and result.get("status_code") == 500:
                ce["fix_hint"] = f"Server error 500. Response: {result.get('response_body', '')[:200]}"
            elif test_name == "T2":
                ce["fix_hint"] = ("The dangerous parameter was not processed. "
                                 "Check: is it extracted from the correct source "
                                 "(request.args for GET, request.form for POST)? "
                                 "Is 'matched' set to True when the value is present?")
            elif test_name == "T3":
                triggered = result.get("triggered_value")
                if triggered:
                    ce["fix_hint"] = (f"A benign input ('{triggered}') also triggered matched=True. "
                                     "The detection condition is too broad — "
                                     "it must reject normal values for this parameter type.")
                else:
                    ce["fix_hint"] = ("A benign input ('safe_value') also triggered matched=True. "
                                     "The handler must check whether the input actually contains "
                                     "dangerous content before setting matched=True.")
            elif test_name == "T4":
                ce["fix_hint"] = ("Log doesn't show parameter was processed. "
                                 "Ensure dangerous_value is set and log_entry is appended.")
            return ce

    return None
