"""Deterministic mock server generator using BaseHTTPRequestHandler.

Design principles:
  - Route matching, parameter extraction, logging are ALL deterministic
  - LLM generates ONLY the detection condition (a single Python expression)
  - Static verification catches bad conditions before server startup
  - BaseHTTPRequestHandler preserves raw paths (no normalization)
"""

import ast
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET

from .analyst import _call_llm
from .temperature import TEMP_GENERATIVE

logger = logging.getLogger("skeleton")

MAX_CONDITION_RETRIES = 7
_BENIGN_CACHE = {}


class ConditionGenerationFailed(RuntimeError):
    """Raised when no verifier-passing detection condition can be generated."""

    def __init__(self, message, rejection_reasons=None):
        super().__init__(message)
        self.rejection_reasons = rejection_reasons or []


def _restore_http_line_breaks(body: str) -> str:
    """Undo analysis-display escaping when parsing structured bodies."""
    if not isinstance(body, str):
        return body
    if "\\r\\n" in body or "\\n" in body:
        return body.replace("\\r\\n", "\r\n").replace("\\n", "\n")
    return body


def _local_xml_name(tag: str) -> str:
    """Strip ElementTree namespace notation from XML tags."""
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _strip_source_prefix(param_name: str) -> str:
    """Accept source-qualified names shown in the manifest."""
    p = param_name or ""
    for prefix in ("query.", "form.", "json.", "xml.", "multipart.",
                   "cookie.", "cookies.", "body.", "params.", "data."):
        if p.lower().startswith(prefix):
            return p[len(prefix):]
    return p


def _flatten_json_leaves(obj, prefix: str = "") -> dict:
    """Flatten nested JSON leaves into dotted keys plus unambiguous aliases."""
    out = {}
    leaf_seen = {}
    ambiguous = set()

    def add_leaf(dotted: str, key: str, text: str):
        out[dotted] = text
        if key in ambiguous:
            return
        previous = leaf_seen.get(key)
        if previous is None:
            leaf_seen[key] = (dotted, text)
            out[key] = text
        elif previous != (dotted, text):
            ambiguous.add(key)
            out.pop(key, None)

    def walk(current, current_prefix: str = ""):
        if isinstance(current, dict):
            for k, v in current.items():
                key = str(k)
                dotted = f"{current_prefix}.{key}" if current_prefix else key
                if isinstance(v, (dict, list)):
                    walk(v, dotted)
                else:
                    text = str(v) if not isinstance(v, str) else v
                    add_leaf(dotted, key, text)
        elif isinstance(current, list):
            for i, v in enumerate(current):
                dotted = f"{current_prefix}[{i}]" if current_prefix else f"[{i}]"
                walk(v, dotted)

    walk(obj, prefix)
    return out


def _looks_nested_query_value(value: str) -> bool:
    """Return True if a value itself looks like multiple query params."""
    parts = str(value).split("&")
    if len(parts) < 2:
        return False
    kv_parts = [p for p in parts if "=" in p and p.split("=", 1)[0]]
    return len(kv_parts) >= 2


def _normalise_param_dict(params: dict) -> dict:
    """Normalize query params, including malformed key=value-in-key traces."""
    result = {}
    for k, v in (params or {}).items():
        key = str(k)
        val = v if isinstance(v, str) else str(v)
        if "=" in key and val == "":
            split_key, split_val = key.split("=", 1)
            result[split_key] = split_val
        else:
            result[key] = val
        if _looks_nested_query_value(val):
            try:
                nested = urllib.parse.parse_qs(val, keep_blank_values=True,
                                               separator="&")
                for nk, nv in nested.items():
                    if nk and nk not in result:
                        result[nk] = nv[0] if nv else ""
            except Exception:
                pass
    return result


def _looks_form_urlencoded(body: str, content_type: str) -> bool:
    """Return True when the body is plausibly URL-encoded form data."""
    ct = (content_type or "").lower()
    if "application/x-www-form-urlencoded" in ct:
        return True
    if ct and any(x in ct for x in ("xml", "json", "multipart")):
        return False
    stripped = (body or "").lstrip()
    if stripped.startswith("<") or stripped.startswith("{") or stripped.startswith("["):
        return False
    return "=" in stripped


# ---------------------------------------------------------------------------
# Phase 0: Deterministic request parsing
# ---------------------------------------------------------------------------

def parse_request_params(http_request: dict) -> dict:
    """Parse all parameters from an HTTP request deterministically.

    Tries every standard format and returns all successful parses.
    """
    result = {}

    # Query parameters (from params dict or path)
    params = _normalise_param_dict(http_request.get("params") or {})
    if params:
        result["query"] = params

    path = http_request.get("path", "")
    if "?" in path:
        qs = path.split("?", 1)[1]
        parsed_qs = urllib.parse.parse_qs(qs)
        if parsed_qs:
            qs_dict = _normalise_param_dict(
                {k: v[0] for k, v in parsed_qs.items()})
            result["query"] = {**result.get("query", {}), **qs_dict}

    body = http_request.get("body") or ""
    parse_body = _restore_http_line_breaks(body)

    if body:
        content_type = ""
        for hk, hv in http_request.get("headers", {}).items():
            if hk.lower() == "content-type":
                content_type = str(hv)
                break

        multipart = _parse_multipart_body(parse_body, content_type)
        if multipart:
            result["multipart"] = multipart

        # form-urlencoded
        if _looks_form_urlencoded(parse_body, content_type):
            try:
                parsed = urllib.parse.parse_qs(parse_body, keep_blank_values=True)
                if parsed:
                    result["form"] = {k: v[0] for k, v in parsed.items()}
            except Exception:
                pass

        # JSON
        try:
            j = json.loads(parse_body)
            if isinstance(j, (dict, list)):
                result["json"] = _flatten_json_leaves(j)
        except Exception:
            pass

        # XML
        try:
            root = ET.fromstring(parse_body)
            xml_params = {}
            for elem in root.iter():
                if elem.text and elem.text.strip():
                    xml_params[_local_xml_name(elem.tag)] = elem.text.strip()
            if xml_params:
                result["xml"] = xml_params
        except Exception:
            pass

        result["raw_body"] = body

    # Cookies
    cookie_header = http_request.get("headers", {}).get("Cookie", "")
    if cookie_header:
        cookies = {}
        for part in cookie_header.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        if cookies:
            result["cookies"] = cookies

    skip_hdrs = {"content-length", "content-type", "accept", "accept-encoding",
                 "accept-language", "connection", "cache-control", "pragma"}
    hdrs = {}
    for k, v in http_request.get("headers", {}).items():
        if k.lower() not in skip_hdrs:
            hdrs[k] = str(v)
    if hdrs:
        result["headers"] = hdrs

    return result


def generate_request_manifest(http_request: dict,
                              parsed_params: dict = None) -> str:
    """Generate a structured manifest of the HTTP request for agent prompts.

    Pure structural parsing - no attack pattern detection, no vulnerability
    hints. Just presents the request fields in a readable enumerated form
    so agents don't have to parse raw JSON themselves.
    """
    if parsed_params is None:
        parsed_params = parse_request_params(http_request)

    lines = ["## Parsed Request Manifest"]
    lines.append(f"Method: {http_request.get('method', 'GET')}")
    lines.append(f"Path: {http_request.get('path', '/')}")

    lines.append("")
    lines.append("Parsed fields:")

    allowed_outputs = []

    def add_allowed(name: str):
        if name not in allowed_outputs:
            allowed_outputs.append(name)

    qp = parsed_params.get("query", {})
    for k, v in qp.items():
        lines.append(f"  - query.{k} = {repr(str(v)[:120])}")
        add_allowed(k)

    body = http_request.get("body")
    if body:
        for src, label in [("json", "json"), ("multipart", "multipart"),
                           ("form", "form"), ("xml", "xml")]:
            d = parsed_params.get(src, {})
            if d:
                for k, v in d.items():
                    lines.append(f"  - {label}.{k} = {repr(str(v)[:120])}")
                    add_allowed(k)
                break
        else:
            if not any(parsed_params.get(s) for s in ("json", "multipart", "form", "xml")):
                raw = str(body)[:200]
                lines.append(f"  - body (raw) = {repr(raw)}")

    cookies = parsed_params.get("cookies", {})
    for k, v in cookies.items():
        lines.append(f"  - cookie.{k} = {repr(str(v)[:120])}")
        add_allowed(k)

    hdrs = parsed_params.get("headers", {})
    for k, v in hdrs.items():
        lines.append(f"  - header.{k} = {repr(str(v)[:120])}")
        hdr_key = f"header:{k}"
        add_allowed(hdr_key)

    add_allowed("path")
    add_allowed("null")

    lines.append("")
    lines.append("Allowed dangerous_param values:")
    for p in allowed_outputs:
        lines.append(f"  - {p}")

    lines.append("")
    lines.append("Rules:")
    lines.append("  - Choose dangerous_param from the allowed values above.")
    lines.append("  - Use JSON null, not the string \"null\", when the "
                 "vulnerability has no specific attacker-controlled parameter.")
    lines.append("  - Before choosing a parameter, check whether its value "
                 "appears structurally anomalous (unusual characters, extreme "
                 "length, embedded delimiters, traversal sequences, shell "
                 "metacharacters, encoded payloads). If all values appear "
                 "structurally normal, use null.")
    lines.append("  - Do not invent parameter names that are not in this list.")

    return "\n".join(lines)


def _parse_multipart_body(body: str, content_type: str = "") -> dict:
    """Extract simple multipart/form-data fields by Content-Disposition name."""
    boundary = ""
    m = re.search(r'boundary="?([^";\r\n]+)"?', content_type or "", re.IGNORECASE)
    if m:
        boundary = m.group(1)
    elif body.startswith("--"):
        first = body.splitlines()[0].strip()
        if first.startswith("--") and len(first) > 2:
            boundary = first[2:]

    if not boundary:
        return {}

    fields = {}
    marker = "--" + boundary
    for part in body.split(marker):
        part = part.strip("\r\n")
        if not part or part == "--":
            continue
        if "\r\n\r\n" in part:
            headers_text, value = part.split("\r\n\r\n", 1)
        elif "\n\n" in part:
            headers_text, value = part.split("\n\n", 1)
        else:
            continue
        name_match = re.search(
            r'Content-Disposition:[^\r\n]*\bname="([^"]+)"',
            headers_text, re.IGNORECASE)
        if not name_match:
            continue
        name = name_match.group(1)
        fields[name] = value.rstrip("\r\n")
        filename_match = re.search(
            r'Content-Disposition:[^\r\n]*\bfilename="([^"]*)"',
            headers_text, re.IGNORECASE)
        if filename_match:
            fields.setdefault("filename", filename_match.group(1))
            fields.setdefault(f"{name}.filename", filename_match.group(1))
    return fields


def find_param_value(parsed_params: dict, param_name: str,
                     raw_body: str = "") -> str:
    """Find a parameter value across all parsed sources."""
    if not param_name:
        return ""

    param_name = _strip_source_prefix(param_name)
    low = param_name.lower().strip()
    if low in ("none", "n/a", "null", ""):
        return ""

    if low.startswith("header:"):
        hdr_name = param_name[7:]
        headers = parsed_params.get("headers", {})
        for k, v in headers.items():
            if k.lower() == hdr_name.lower():
                return str(v)
        return ""

    sources = ("query", "form", "json", "xml", "multipart", "cookies", "headers")
    for source_name in sources:
        source = parsed_params.get(source_name, {})
        if isinstance(source, dict) and param_name in source:
            return str(source[param_name])

    for source_name in sources:
        source = parsed_params.get(source_name, {})
        if isinstance(source, dict):
            for k, v in source.items():
                if k.lower() == low:
                    return str(v)

    if low in ("body", "raw_body", "request body", "post body"):
        return parsed_params.get("raw_body", raw_body)

    # Fallback: if param_name has dot-notation (e.g. "input.file-name"),
    # try the last component as a bare field name across all sources.
    if "." in param_name:
        suffix = param_name.split(".")[-1]
        suffix_low = suffix.lower()
        for source_name in sources:
            source = parsed_params.get(source_name, {})
            if isinstance(source, dict):
                for k, v in source.items():
                    if k.lower() == suffix_low:
                        return str(v)

    return ""


# ---------------------------------------------------------------------------
# Parameter value collection
# ---------------------------------------------------------------------------

def _has_named_fields(parsed_params: dict) -> bool:
    """Return True if deterministic parsing found addressable content fields.

    Intentionally excludes "headers": HTTP infrastructure headers (Host,
    User-Agent, etc.) are not named content parameters and should not block
    path or body fallback logic.  Header-based attack vectors are addressed
    via find_param_value with the "header:" prefix.
    """
    for source_name in ("query", "form", "json", "xml", "multipart", "cookies"):
        source = parsed_params.get(source_name, {})
        if isinstance(source, dict) and source:
            return True
    return False


def _has_param_key(parsed_params: dict, param_name: str) -> bool:
    """Return True if param_name appears as a key in any parsed source."""
    low = param_name.lower().strip()
    for source_name in ("query", "form", "json", "xml", "multipart",
                        "cookies", "headers"):
        source = parsed_params.get(source_name, {})
        if isinstance(source, dict):
            for k in source:
                if k == param_name or k.lower() == low:
                    return True
    return False


def _is_body_generic(param_name: str) -> bool:
    """Return True for generic whole-body labels, not concrete fields."""
    return (param_name or "").lower().strip() in {
        "body", "raw_body", "request body", "post body",
    }


# ---------------------------------------------------------------------------
# Phase 1: Parameter identification
# ---------------------------------------------------------------------------

def _normalize_dangerous_param(dangerous_param: str,
                                http_request: dict) -> str:
    """Strict normalization: source-prefix strip + null detection only.

    No fuzzy matching, no cookie format parsing, no substring extraction.
    The LLM must output a value from the Manifest's allowed list directly.
    """
    if dangerous_param is None:
        return ""

    p = _strip_source_prefix(str(dangerous_param).strip())
    low = p.lower()

    if low in ("null", "none", "n/a"):
        return ""

    return p


def identify_param(parsed_params: dict, http_request: dict,
                   analysis: dict) -> tuple:
    """Return (param_name, attack_value) from the LLM's analysis.

    Pure lookup - no attack-pattern heuristic. Trusts the LLM's answer and
    resolves it against parsed parameters. Returns ("", "") if the LLM's
    param cannot be found or was explicitly null.
    """
    hyp = analysis.get("attack_hypothesis", {})
    raw_name = hyp.get("dangerous_param", "")
    param_name = _normalize_dangerous_param(raw_name, http_request)
    has_named_fields = _has_named_fields(parsed_params)

    # Manifest constraint: reject generic "body" when concrete fields exist.
    if has_named_fields and _is_body_generic(param_name):
        return "", ""

    # LLM explicitly said no param (null/none).
    if not param_name:
        return "", ""

    # URL path fallback: needed when dangerous_param="path" refers to the URL
    # path itself.  Two guards: (1) no named field literally called "path"
    # exists (e.g. ?path=../../etc/passwd should use the query value, not the
    # URL path); (2) no query/body/cookie fields exist — if the request has
    # addressable content fields the analyst should have named, returning ("","")
    # produces an honest unresolved_param failure (pre-CEGIS, no automatic
    # recovery) rather than silently generating a wrong path-based detection.
    if param_name.lower() in ("path", "url"):
        if not _has_param_key(parsed_params, param_name):
            path_val = http_request.get("path", "")
            if path_val:
                return "path", path_val

    # Look up the param value in parsed request.
    # find_param_value returns "" for both "not found" and "empty attack value".
    # Accept empty only when the key actually exists in a parsed source.
    value = find_param_value(parsed_params, param_name,
                             http_request.get("body", ""))
    if value or _has_param_key(parsed_params, param_name):
        return param_name, value

    return "", ""


# ---------------------------------------------------------------------------
# Phase 2: Detection condition generation + static verification
# ---------------------------------------------------------------------------

MAX_CONDITION_LENGTH = 200
SAFE_CONDITION_BUILTINS = {
    "len": len,
    "int": int,
    "float": float,
    "str": str,
    "bool": bool,
    "all": all,
    "any": any,
    "max": max,
    "min": min,
    "sum": sum,
    "abs": abs,
    "ord": ord,
    "chr": chr,
    "range": range,
    "set": set,
}


BENIGN_VALUES_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "benign_values.json"
)


def _load_benign_values() -> dict:
    """Load committed benign verifier values; fail loudly if absent."""
    if not _BENIGN_CACHE:
        if not BENIGN_VALUES_PATH.exists():
            raise FileNotFoundError(
                f"Benign value set not found: {BENIGN_VALUES_PATH}\n"
                "Run: python scripts/extract_benign_values.py")
        _BENIGN_CACHE.update(json.loads(BENIGN_VALUES_PATH.read_text(encoding="utf-8")))
    return _BENIGN_CACHE


EXTRA_BENIGN_DIR = (
    Path(__file__).resolve().parents[2] / "benchmarks" / "traces_benign"
)
_EXTRA_PATH_CACHE = None


def _load_extra_benign_paths() -> list:
    """DISABLED — this previously loaded benchmarks/traces_benign/BENIGN-CVE-*.json,
    which IS the p-series evaluation set, as runtime path counterexamples. That was
    a train/test leak (it inflated path-type TNR by verifying against the very traces
    FPR is measured on). Path counterexamples now come solely from the dev-sourced
    benign_values.json 'path' category (extracted from the held-out UNSW dev split).
    """
    return []


_KNOWN_HEADERS = frozenset({
    "User-Agent", "Referer", "Authorization", "Cookie",
    "X-Forwarded-For", "X-Real-IP", "Host", "Origin",
    "Accept-Language", "Accept-Encoding", "Connection",
    "Cache-Control", "If-None-Match", "If-Modified-Since",
    "Content-Type", "Content-Length", "Accept", "DNT",
    "Upgrade-Insecure-Requests", "Pragma", "X-Requested-With",
})


def _param_type(param_name: str) -> str:
    pn = param_name or ""
    if pn in ("path", ""):
        return "path"
    if pn.startswith("header:") or pn in _KNOWN_HEADERS:
        return "header_value"
    if pn in ("body", "raw_body", "request body", "post body"):
        return "body"
    return "query_value"


def _describe_attack_value(attack_value: str) -> str:
    """Return structural facts about attack_value. No attack classification."""
    if not attack_value:
        return "empty string"
    facts = [f"length={len(attack_value)}"]
    # Control/non-printable bytes reported by name
    control = []
    for char, name in [('\x00', 'null_byte'), ('\n', 'newline'),
                       ('\r', 'carriage_return'), ('\t', 'tab')]:
        if char in attack_value:
            control.append(name)
    if control:
        facts.append(f"control_chars: {', '.join(control)}")
    # Exhaustive non-alphanumeric printable ASCII (range 32-126) — no selection bias
    special = [repr(chr(c)) for c in range(32, 127)
               if not chr(c).isalnum() and chr(c) in attack_value]
    if special:
        facts.append(f"special_chars: {', '.join(special)}")
    else:
        facts.append("special_chars: none (alphanumeric only)")
    # Repetitiveness threshold: ≥20 chars with ≤5 unique chars. Fixed pre-experiment.
    if len(attack_value) >= 20 and len(set(attack_value)) <= 5:
        facts.append(f"highly_repetitive (unique_chars={len(set(attack_value))})")
    return ", ".join(facts)


# --- Mechanism-grounding gate (CWE-derived; NOT extracted from the eval set) ---
# Attack-mechanism vocabulary encoding vulnerability-class DEFINITIONS (CWE), used
# to distinguish mechanism-grounded detection conditions from "shape-only" ones
# (length / char-class / counts) that overfit and fire on benign values. Fixed by
# vulnerability-class definition; MUST NOT be extended by inspecting evaluation
# payloads. Markers are matched inside the condition's string/regex LITERALS (the
# tokens it searches for in `value`), never against Python operators.
#
# Symbolic markers: substring-matched inside a literal (regex literals are
# de-escaped first, so r'\.\./' -> '../', r'[<>]' keeps '<' '>').
_SYM_MARKERS = (
    "../", "..\\", "..%2f", "..;", "%2e%2e", "%2f", "%5c", "%252e",   # CWE-22 traversal
    ";", "|", "&", "`", "$(", "${", "&&", "||",                       # CWE-78 cmd injection
    "'", '"', "--", "/*", "0x",                                       # CWE-89 SQLi punctuation
    "<", ">", "<%", "<?", "/>",                                       # CWE-79 XSS / markup
    "{{", "}}", "#{",                                                 # CWE-1336 template injection
    "%00", "%0d", "%0a", "\\x00", "\\r", "\\n",                       # CWE-158 null / CWE-93 CRLF
    "%n", "%s", "%x", "%p",                                           # CWE-134 format string
    "$ne", "$gt", "$where", "$regex",                                 # CWE-943 NoSQL injection
    "/etc/", "/proc/", "/bin/", "file://", "php://", "gopher://",     # LFI / CWE-918 SSRF
    "dict://", "expect://", "data://",
    "<!entity", "<!doctype",                                          # CWE-611 XXE
)
# Word markers: alphabetic, matched with word boundaries so e.g. 'selection'
# does not match 'select'.
_WORD_MARKERS = (
    "union", "select", "sleep", "benchmark", "waitfor",              # SQLi keywords
    "javascript", "onerror", "onload", "onmouseover", "alert",       # XSS handlers
    "script", "iframe", "svg", "img",
    "eval", "system", "exec", "passthru", "popen", "shell_exec",     # code/cmd exec
    "passwd", "shadow", "etc",                                       # file targets
    "entity", "doctype",
)
_WORD_RE = re.compile(r"(?<![a-z0-9_])(?:" +
                      "|".join(re.escape(w) for w in _WORD_MARKERS) +
                      r")(?![a-z0-9_])")
# Regex metacharacters that indicate a SHAPE pattern (char class / quantifier).
_REGEX_SHAPE_HINTS = ("[", "{", "\\d", "\\D", "\\w", "\\W", "\\s", "\\S")
_REGEX_FUNCS = ("search", "match", "fullmatch", "findall", "finditer")

# Param types whose conditions must be mechanism-grounded under the gate.
# "path" is exempt: traversal/path-injection conditions use structural patterns.
_GATED_PARAM_TYPES = ("query_value", "body", "header_value")
# CWE-119/120/190: a length threshold this large is an overflow mechanism, not
# incidental shape — exempt it so overflow-class attacks are not rejected.
_EXTREME_LEN = 1024


def _mech_gate_mode() -> str:
    """Mechanism-grounding gate mode: 'off' (default, baseline unchanged),
    'soft' (log only), or 'hard' (reject shape-only conditions). Set via the
    MECH_GATE env var so the baseline pipeline is untouched until validated."""
    return os.environ.get("MECH_GATE", "off").strip().lower()


def _literal_has_mechanism(s: str, is_regex: bool = False) -> bool:
    """True if a string the condition searches for carries an attack mechanism."""
    low = s.lower()
    if is_regex:
        low = low.replace("\\", "")   # de-escape: \.\./ -> ../, [<>] keeps < >
    if any(m in low for m in _SYM_MARKERS):
        return True
    return bool(_WORD_RE.search(low))


def _condition_is_shape_only(condition_str: str) -> bool:
    """True iff the condition relies ONLY on incidental value SHAPE (length,
    character class, digit/letter counts) with NO attack mechanism — whether the
    shape test is spelled with len()/.isXXX()/comprehensions OR a regex
    char-class/quantifier pattern. Mechanism-grounded conditions return False
    (kept). Errs toward False (keep) on ambiguity to protect attack TPR; the
    benign-counterexample check remains the authoritative FP filter.

    Markers are scanned only inside string/regex LITERALS (never the raw
    expression), so Python's own `and`/`or` operators are not mistaken for SQL.
    """
    try:
        tree = ast.parse(condition_str, mode="eval")
    except SyntaxError:
        return False
    plain_literals, regex_patterns = [], []
    shape = False
    uses_ord = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            plain_literals.append(node.value)
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                if f.id in ("len", "sum", "max", "min"):
                    shape = True
                elif f.id == "ord":
                    uses_ord = True
            elif isinstance(f, ast.Attribute):
                if f.attr in ("isalnum", "isdigit", "isalpha", "isupper",
                              "islower", "isspace", "isnumeric", "count"):
                    shape = True
                elif f.attr in _REGEX_FUNCS:
                    for a in node.args:
                        if isinstance(a, ast.Constant) and isinstance(a.value, str):
                            regex_patterns.append(a.value)
                            break
        elif isinstance(node, (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
            shape = True
        elif isinstance(node, ast.Compare):
            operands = [node.left] + list(node.comparators)
            has_ord = any(isinstance(o, ast.Call) and isinstance(o.func, ast.Name)
                          and o.func.id == "ord" for o in operands)
            for o in operands:
                if isinstance(o, ast.Constant) and isinstance(o.value, int):
                    if has_ord and (o.value <= 32 or o.value >= 127):
                        return False          # control / non-printable byte = mechanism
                    if not has_ord and o.value >= _EXTREME_LEN:
                        return False          # overflow length threshold = mechanism
    if any(_literal_has_mechanism(s) for s in plain_literals):
        return False
    if any(_literal_has_mechanism(p, is_regex=True) for p in regex_patterns):
        return False
    if uses_ord:                  # ord used for printable-range char-class = shape
        shape = True
    for p in regex_patterns:      # regex char-class/quantifier scan, no mechanism = shape
        if any(h in p for h in _REGEX_SHAPE_HINTS):
            shape = True
    return shape


def _mech_gate_exact() -> bool:
    """Whether to also reject exact-literal-overfit conditions (env MECH_EXACT).
    Separate toggle from MECH_GATE so its TPR effect can be A/B-isolated."""
    return os.environ.get("MECH_EXACT", "0").strip().lower() in ("1", "true", "on", "yes")


def _condition_is_exact_overfit(condition_str: str) -> bool:
    """True if the condition is an exact match against a specific literal value
    that carries NO attack mechanism (e.g. value == 'warn', re.fullmatch(r'warn',
    value)). Such conditions memorize one observed value and do not generalize —
    on benign traffic they are pure overfit. Real payload exact-matches (which
    contain mechanism markers, e.g. value == ';cat /etc/passwd') are NOT flagged,
    so genuine syntactic attacks are preserved."""
    try:
        tree = ast.parse(condition_str, mode="eval")
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for op, comp in zip(node.ops, node.comparators):
                if isinstance(op, ast.Eq) and isinstance(comp, ast.Constant) \
                        and isinstance(comp.value, str) \
                        and not _literal_has_mechanism(comp.value):
                    return True
            if node.ops and isinstance(node.ops[0], ast.Eq) \
                    and isinstance(node.left, ast.Constant) \
                    and isinstance(node.left.value, str) \
                    and not _literal_has_mechanism(node.left.value):
                return True
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ("fullmatch", "match"):
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    if not re.search(r"[\[\]{}().*+?\\|^$]", a.value) \
                            and not _literal_has_mechanism(a.value, is_regex=True):
                        return True
                    break
    return False


# Bound condition evaluation against pathological inputs/regexes. Overflow CVEs
# carry attack values of tens of KB; an LLM-written nested-quantifier regex
# (e.g. (a+)+) against them backtracks catastrophically and hangs the worker
# indefinitely — re holds the GIL during matching, so no thread/signal timeout can
# interrupt it. We reject such regexes up front and cap the value length for eval.
MAX_EVAL_VALUE_LEN = 4096
_REDOS_RE = re.compile(r'\([^()]*[+*][^()]*\)\s*[+*{]|\{\s*\d{4,}')

# A condition regex can still backtrack catastrophically on a long overflow value
# even after the static _REDOS_RE check (which cannot recognise every dangerous
# shape). Worker threads make signal.alarm useless, so route long-value evals
# through a throwaway subprocess that is SIGKILLed if it overruns. This bounds
# wall-clock per eval regardless of the regex.
EVAL_TIMEOUT_SEC = 2.0
_CONDITION_USES_RE = re.compile(
    r'\bre\.(search|match|fullmatch|finditer|findall|sub|subn|split)\b')
_GUARD_CHILD = (
    "import sys,json,re,builtins\n"
    "cond,val=json.loads(sys.stdin.read())\n"
    "B={k:getattr(builtins,k) for k in "
    "('len','int','float','str','bool','all','any','max','min','sum','abs',"
    "'ord','chr','range','set')}\n"
    "ns={'re':re,'__builtins__':B,'value':val}\n"
    "sys.stdout.write('1' if eval(compile(cond,'<cond>','eval'),ns) else '0')\n"
)


class _GuardTimeout(Exception):
    """A condition eval exceeded EVAL_TIMEOUT_SEC and was killed."""


def _eval_condition_guarded(condition_str: str, value: str,
                            timeout_sec: float = EVAL_TIMEOUT_SEC) -> tuple:
    """Eval `condition_str` (with `value` bound) in a subprocess; kill on overrun.
    Returns ("ok", bool) | ("timeout", None) | ("error", str)."""
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _GUARD_CHILD],
            input=json.dumps([condition_str, value]),
            capture_output=True, text=True, timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        return "timeout", None
    except Exception as e:  # spawn failure → fail-safe reject by the caller
        return "error", "spawn: %s" % e
    if proc.returncode != 0:
        return "error", (proc.stderr or "").strip()[-200:]
    return "ok", proc.stdout.strip() == "1"


def _safe_eval_condition(condition_str: str, compiled, value: str) -> bool:
    """Eval the condition on `value`. A long value combined with a regex goes
    through the subprocess guard (hard timeout); short or regex-free values run
    inline (no catastrophic-backtracking risk, zero spawn overhead). Raises
    _GuardTimeout on overrun, or the underlying exception on eval error."""
    if len(value) > 200 and _CONDITION_USES_RE.search(condition_str):
        status, res = _eval_condition_guarded(condition_str, value)
        if status == "timeout":
            raise _GuardTimeout()
        if status == "error":
            raise RuntimeError(res)
        return bool(res)
    ns = {"re": re, "__builtins__": SAFE_CONDITION_BUILTINS, "value": value}
    return bool(eval(compiled, ns))


def verify_condition(condition_str: str, attack_value: str,
                     param_type: str = "generic") -> tuple:
    """Verify detection condition fires on attack value, not on benign values."""
    if len(condition_str) > MAX_CONDITION_LENGTH:
        return False, "too long - write a shorter expression"

    if "safe_value" in condition_str:
        return False, "contains hardcoded test value"

    if re.search(r'\bset\s*\(\s*range\s*\(', condition_str):
        return False, "set(range(...)) not allowed - use len() comparison instead"

    if _REDOS_RE.search(condition_str):
        return False, ("regex prone to catastrophic backtracking (nested quantifier "
                       "like (X+)+ or huge {N}) - match the mechanism directly instead")

    try:
        compiled = compile(condition_str, "<cond>", "eval")
    except SyntaxError as e:
        return False, f"syntax: {e}"

    # Cap the value fed to eval: bounds linear cost on tens-of-KB overflow payloads.
    # len-thresholds above the cap are shape-overfit and rejected by the gate anyway.
    _eval_value = attack_value[:MAX_EVAL_VALUE_LEN]

    try:
        _attack_ok = _safe_eval_condition(condition_str, compiled, _eval_value)
    except _GuardTimeout:
        return False, ("attack eval exceeded the time budget (catastrophic-backtracking "
                       "guard) — detect the mechanism with a literal substring or len() "
                       "check, not a quantified regex group/class")
    except Exception as e:
        return False, f"error on attack value: {e}"
    if not _attack_ok:
        return False, f"False for attack: {attack_value[:60]!r} ({_describe_attack_value(attack_value)})"

    # Mechanism-grounding gate: a syntax-class condition that overfits to the
    # value's incidental shape (length/char-class) or memorizes a specific literal
    # (exact match) without any attack mechanism matches benign values. Reject it
    # so codegen produces a mechanism-grounded condition or the hypothesis is
    # exhausted (correct rejection of a non-attack). MECH_EXACT additionally gates
    # exact-literal overfit (separate toggle so its TPR effect is A/B-isolated).
    _mode = _mech_gate_mode()
    if _mode in ("soft", "hard") and param_type in _GATED_PARAM_TYPES:
        _msg = None
        if _condition_is_shape_only(condition_str):
            _msg = ("shape-only condition (length/char-class, no attack mechanism) "
                    "— match the exploit mechanism (traversal ../, shell/SQL "
                    "metacharacters, script tags, etc.), not the value's shape")
        elif _mech_gate_exact() and _condition_is_exact_overfit(condition_str):
            _msg = ("exact-literal match memorizing one value with no attack "
                    "mechanism — overfits to a specific observed value; match the "
                    "exploit mechanism instead")
        if _msg:
            if _mode == "hard":
                return False, _msg
            logger.info("[mech-gate:soft] would reject cond=%r param_type=%s (%s)",
                        condition_str[:80], param_type, _msg[:40])

    benign_set = _load_benign_values()
    benign_list = benign_set.get(param_type, benign_set.get("generic", []))
    extra_benign = _load_extra_benign_paths() if param_type == "path" else []
    combined = list(benign_list) + extra_benign
    seen = set()
    for bv in combined:
        if bv == attack_value or bv in seen:
            continue
        seen.add(bv)
        try:
            if _safe_eval_condition(condition_str, compiled, bv):
                return False, (f"condition also matched benign input {bv[:60]!r} "
                               f"— make it more specific to reject normal values")
        except _GuardTimeout:
            return False, ("condition eval timed out on a benign input "
                           "(catastrophic-backtracking guard) — use a simpler match")
        except Exception:
            pass

    return True, "passed"


_SHAPE_STRATEGY = """## Strategy
Use the structural properties of the attack value (listed below) to write
a condition that detects its distinguishing features:
- If the value contains non-alphanumeric characters or control sequences, their presence is often sufficient
- If the value is unusually long or contains repetitive patterns, a length or count threshold may work
- Prefer general structural patterns over exact substring copies when possible
- NEVER check for the parameter name (e.g., "id", "page") inside `value`
- CRITICAL: Your condition MUST return False for typical benign inputs.
  Do NOT use overly broad conditions like `len(value) > 0` or `"." in value`
  that would match normal, non-malicious parameter values.
- Your condition will be tested against real benign values and rejected if
  any match. Write conditions that capture ATTACK-SPECIFIC patterns."""

# Mechanism-grounded codegen guidance (used when MECH_GATE is on). Replaces the
# shape nudge above, which actively encouraged the length/char-class overfitting.
_MECH_STRATEGY = """## Strategy
Detect the ATTACK MECHANISM, not the value's incidental shape. Identify the
specific dangerous tokens or structure that make this value an exploit and match
THOSE:
- Path traversal: ../  ..\\  encoded ..%2f
- OS command injection: ; | & ` $( ) and other shell metacharacters
- SQL injection: quotes, OR/UNION/SELECT, comment sequences (-- /*)
- XSS / markup: <script, on* event handlers, javascript:
- Code / file / SSRF: <?php, eval(, /etc/, file://, php://, null bytes
- NEVER check for the parameter name (e.g., "id", "page") inside `value`
- Do NOT write conditions based ONLY on length, character class, or digit/letter
  counts (e.g. `len(value)==6 and value.isalnum()`): shape-only conditions match
  benign values by accident and will be REJECTED. If the value carries no attack
  mechanism, there is no valid condition — returning none is the correct outcome."""


def _generate_detection_condition(attack_value: str, param_name: str,
                                   analysis: dict,
                                   failure_hint: str = None,
                                   temperature: float = TEMP_GENERATIVE,
                                   direction: str = None) -> str:
    """Ask LLM for a minimal detection condition."""
    value_desc = _describe_attack_value(attack_value)
    strategy_block = _MECH_STRATEGY if _mech_gate_mode() != "off" else _SHAPE_STRATEGY
    prompt = f"""## Task
Write a single Python boolean expression that returns True when `value`
contains an attack payload and False for normal input.

## Critical: what `value` is
`value` is ONLY the parameter value string — not the full URL, not the full
request body, not "key=value". For a request like username=admin, `value`
is just "admin". Never check for the parameter name inside `value`.

{strategy_block}

## Inputs
- Observed value: {attack_value[:200]}
- Structural properties: {value_desc}

## Constraints
- Variable: `value` (str)
- You may use `re` (already imported)
- Allowed builtins: len, int, float, str, bool, all, any, max, min, sum, abs, ord, chr
- MUST be under 200 characters
- NEVER chain .isXxx() methods (isalnum, isdigit, islower, isupper, etc.)
- Do not repeat previously rejected expressions
- Return ONLY the expression, no explanation"""

    if _param_type(param_name) == "path":
        prompt += """
- For URL path values, focus on traversal sequences (../), injected
  delimiters (;, |), or abnormal length — not the specific path string."""

    if direction:
        prompt += f"\n\n## Detection Direction (MUST follow this approach)\n{direction}"

    if failure_hint:
        prompt += f"\n\nPrevious attempt failed: {failure_hint}\nWrite a DIFFERENT expression."

    messages = [
        {"role": "system",
         "content": "## Output\nOutput ONLY a Python boolean expression. No markdown, no explanation. /no_think"},
        {"role": "user", "content": prompt},
    ]

    raw = _call_llm(messages, temperature=TEMP_GENERATIVE, max_tokens=256)

    cond = raw.strip().strip("`").strip()
    if cond.startswith("```"):
        cond = re.sub(r"```\w*\s*\n?", "", cond).strip().rstrip("`").strip()
    cond = re.sub(r"^(return |matched\s*=\s*)", "", cond).strip()
    if "\n" in cond:
        cond = cond.split("\n")[0].strip()

    return cond


def generate_detection(attack_value: str, param_name: str,
                       analysis: dict, temperature: float = TEMP_GENERATIVE,
                       counterexample: dict = None,
                       blackboard: dict = None,
                       direction: str = None) -> str:
    """Generate and verify a detection condition with rejection sampling."""
    if not attack_value:
        return 'value == ""'

    hint = None
    if counterexample:
        hint = json.dumps(counterexample, ensure_ascii=False, default=str)[:300]

    # Blackboard: append previously failed conditions to hint
    if blackboard and blackboard.get("tried_conditions"):
        bb_lines = []
        for tc in blackboard["tried_conditions"][-3:]:
            bb_lines.append(f"  `{tc['condition']}` -> {tc['failed_test']}: {tc['reason']}")
        bb_text = "\nPreviously failed conditions (DO NOT repeat):\n" + "\n".join(bb_lines)
        hint = (hint + bb_text) if hint else bb_text

    initial_hint = hint
    failed_attempts = []
    param_type = _param_type(param_name)

    for attempt in range(MAX_CONDITION_RETRIES):
        cond = _generate_detection_condition(
            attack_value, param_name, analysis,
            failure_hint=hint, temperature=TEMP_GENERATIVE,
            direction=direction)

        passed, reason = verify_condition(cond, attack_value, param_type=param_type)
        if passed:
            logger.info("Detection verified (attempt %d): %s", attempt + 1, cond)
            return cond

        logger.info("Condition rejected (attempt %d): %s - %s",
                     attempt + 1, cond, reason)
        failed_attempts.append(f"'{cond}' failed: {reason}")
        hint = ((initial_hint + "\n\n") if initial_hint else "")
        hint += "Rejected attempts:\n" + "\n".join(failed_attempts)

    logger.warning("All %d condition attempts failed", MAX_CONDITION_RETRIES)
    raise ConditionGenerationFailed(
        f"no verifier-passing condition after {MAX_CONDITION_RETRIES} attempts",
        rejection_reasons=failed_attempts)


# ---------------------------------------------------------------------------
# Phase 3: Code assembly (template)
# ---------------------------------------------------------------------------

MOCK_TEMPLATE = r'''
from http.server import HTTPServer, BaseHTTPRequestHandler
import http.client
import json
import re
import urllib.parse

import posixpath

http.client._MAXHEADERS = max(http.client._MAXHEADERS, 200)

port = __PORT__
EXPECTED_PATH = __EXPECTED_PATH__
PARAM_NAME = __PARAM_NAME__
ATTACK_VALUE = __ATTACK_VALUE__

internal_log = []


def local_xml_name(tag):
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def looks_form_urlencoded(body, content_type):
    ct = (content_type or "").lower()
    if "application/x-www-form-urlencoded" in ct:
        return True
    if ct and any(x in ct for x in ("xml", "json", "multipart")):
        return False
    stripped = (body or "").lstrip()
    if stripped.startswith("<") or stripped.startswith("{") or stripped.startswith("["):
        return False
    return "=" in stripped


def normalize_param_dict(params):
    result = {}
    for k, v in (params or {}).items():
        key = str(k)
        val = v if isinstance(v, str) else str(v)
        if "=" in key and val == "":
            split_key, split_val = key.split("=", 1)
            result[split_key] = split_val
        else:
            result[key] = val
        parts = val.split("&")
        kv_parts = [p for p in parts if "=" in p and p.split("=", 1)[0]]
        if len(parts) >= 2 and len(kv_parts) >= 2:
            try:
                nested = urllib.parse.parse_qs(val, keep_blank_values=True,
                                               separator="&")
                for nk, nv in nested.items():
                    if nk and nk not in result:
                        result[nk] = nv[0] if nv else ""
            except Exception:
                pass
    return result


def parse_params(handler):
    result = {}
    parsed_url = urllib.parse.urlparse(handler.path)
    if parsed_url.query:
        qs = urllib.parse.parse_qs(parsed_url.query)
        result["query"] = {k: v[0] for k, v in qs.items()}
        result["query"] = normalize_param_dict(result["query"])

    content_length = int(handler.headers.get("Content-Length", 0))
    body = handler.rfile.read(content_length).decode("utf-8") if content_length else ""

    if body:
        content_type = handler.headers.get("Content-Type", "")
        boundary = ""
        m = re.search(r'boundary="?([^";\r\n]+)"?', content_type, re.IGNORECASE)
        if m:
            boundary = m.group(1)
        elif body.startswith("--"):
            first = body.splitlines()[0].strip()
            if first.startswith("--") and len(first) > 2:
                boundary = first[2:]
        if boundary:
            multipart = {}
            marker = "--" + boundary
            for part in body.split(marker):
                part = part.strip("\r\n")
                if not part or part == "--":
                    continue
                if "\r\n\r\n" in part:
                    headers_text, value = part.split("\r\n\r\n", 1)
                elif "\n\n" in part:
                    headers_text, value = part.split("\n\n", 1)
                else:
                    continue
                nm = re.search(r'Content-Disposition:[^\r\n]*\bname="([^"]+)"',
                               headers_text, re.IGNORECASE)
                if nm:
                    multipart[nm.group(1)] = value.rstrip("\r\n")
                    fn = re.search(r'Content-Disposition:[^\r\n]*\bfilename="([^"]*)"',
                                   headers_text, re.IGNORECASE)
                    if fn:
                        multipart.setdefault("filename", fn.group(1))
                        multipart.setdefault(nm.group(1) + ".filename", fn.group(1))
            if multipart:
                result["multipart"] = multipart

        if looks_form_urlencoded(body, content_type):
            try:
                parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
                if parsed:
                    result["form"] = {k: v[0] for k, v in parsed.items()}
            except Exception:
                pass
        try:
            j = json.loads(body)
            if isinstance(j, (dict, list)):
                flat = {}
                leaf_seen = {}
                ambiguous = set()
                def add_leaf(dotted, key, text):
                    flat[dotted] = text
                    if key in ambiguous:
                        return
                    previous = leaf_seen.get(key)
                    if previous is None:
                        leaf_seen[key] = (dotted, text)
                        flat[key] = text
                    elif previous != (dotted, text):
                        ambiguous.add(key)
                        flat.pop(key, None)
                def flatten_json(obj, prefix=""):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            key = str(k)
                            dotted = prefix + "." + key if prefix else key
                            if isinstance(v, (dict, list)):
                                flatten_json(v, dotted)
                            else:
                                text = str(v) if not isinstance(v, str) else v
                                add_leaf(dotted, key, text)
                    elif isinstance(obj, list):
                        for i, v in enumerate(obj):
                            dotted = prefix + "[" + str(i) + "]" if prefix else "[" + str(i) + "]"
                            flatten_json(v, dotted)
                flatten_json(j)
                result["json"] = flat
        except Exception:
            pass
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(body)
            xp = {}
            for elem in root.iter():
                if elem.text and elem.text.strip():
                    xp[local_xml_name(elem.tag)] = elem.text.strip()
            if xp:
                result["xml"] = xp
        except Exception:
            pass
        result["raw_body"] = body

    cookie_header = handler.headers.get("Cookie", "")
    if cookie_header:
        cookies = {}
        for part in cookie_header.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        if cookies:
            result["cookies"] = cookies

    skip_hdrs = {"content-length", "content-type", "accept", "accept-encoding",
                 "accept-language", "connection", "cache-control", "pragma"}
    hdrs = {}
    for key, val in handler.headers.items():
        if key.lower() not in skip_hdrs and key not in hdrs:
            hdrs[key] = val
    if hdrs:
        result["headers"] = hdrs

    return result, body


def extract_value(params, raw_body, path=None):
    pn = PARAM_NAME
    if pn.startswith("header:"):
        hdr_name = pn[7:]
        for k, v in params.get("headers", {}).items():
            if k.lower() == hdr_name.lower():
                return str(v)
    for src in ("query", "form", "json", "xml", "multipart", "cookies", "headers"):
        d = params.get(src, {})
        if isinstance(d, dict) and pn in d:
            return str(d[pn])
    for src in ("query", "form", "json", "xml", "multipart", "cookies", "headers"):
        d = params.get(src, {})
        if isinstance(d, dict):
            for k, v in d.items():
                if k.lower() == pn.lower():
                    return str(v)
    if pn in ("body", "raw_body"):
        return raw_body
    if pn in ("path", ""):
        if path is not None:
            return str(path).split("?")[0]
        return ""
    return ""


def detect(value):
    try:
        return bool(__DETECTION__)
    except Exception:
        return False


def detect_all(params, raw_body, handler):
    """Apply detection to all parameter values for attribution."""
    matched = []
    for src in ("query", "form", "json", "xml", "multipart", "cookies"):
        d = params.get(src, {})
        if isinstance(d, dict):
            for k, v in d.items():
                if detect(str(v)):
                    matched.append(k)
    for k, v in params.get("headers", {}).items():
        if detect(str(v)):
            matched.append("header:" + k)
    path = urllib.parse.unquote(handler.path.split("?")[0])
    if detect(path) and "path" not in matched:
        matched.append("path")
    if raw_body and detect(raw_body):
        if not any(m in ("body", "raw_body") for m in matched):
            matched.append("body")
    return matched


def params_from_request_json(query_req):
    """Build the same parameter shape from an oracle JSON request."""
    params = {}
    raw_path = str(query_req.get("path") or "/")
    parsed_url = urllib.parse.urlparse(raw_path)
    if parsed_url.query:
        qs = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
        params["query"] = normalize_param_dict({k: v[0] for k, v in qs.items()})
    explicit_params = query_req.get("params") or {}
    if isinstance(explicit_params, dict):
        merged = dict(params.get("query", {}))
        merged.update(normalize_param_dict(explicit_params))
        if merged:
            params["query"] = merged

    headers = query_req.get("headers") or {}
    if isinstance(headers, dict):
        hdrs = {str(k): str(v) for k, v in headers.items()}
        if hdrs:
            params["headers"] = hdrs
        cookie_header = hdrs.get("Cookie") or hdrs.get("cookie") or ""
        if cookie_header:
            cookies = {}
            for part in cookie_header.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()
            if cookies:
                params["cookies"] = cookies

    body_obj = query_req.get("body")
    raw_body = "" if body_obj is None else (body_obj if isinstance(body_obj, str) else json.dumps(body_obj))
    if raw_body:
        content_type = ""
        if isinstance(headers, dict):
            content_type = headers.get("Content-Type") or headers.get("content-type") or ""
        if isinstance(body_obj, dict):
            params["json"] = {str(k): str(v) for k, v in body_obj.items()
                              if not isinstance(v, (dict, list))}
        if looks_form_urlencoded(raw_body, content_type):
            try:
                parsed = urllib.parse.parse_qs(raw_body, keep_blank_values=True)
                if parsed:
                    params["form"] = {k: v[0] for k, v in parsed.items()}
            except Exception:
                pass
        try:
            j = json.loads(raw_body)
            if isinstance(j, dict):
                params["json"] = {str(k): str(v) for k, v in j.items()
                                  if not isinstance(v, (dict, list))}
        except Exception:
            pass
        params["raw_body"] = raw_body
    return params, raw_body


def detect_all_for_oracle(params, raw_body, path):
    matched = []
    for src in ("query", "form", "json", "xml", "multipart", "cookies"):
        d = params.get(src, {})
        if isinstance(d, dict):
            for k, v in d.items():
                if detect(str(v)):
                    matched.append(k)
    for k, v in params.get("headers", {}).items():
        if detect(str(v)):
            matched.append("header:" + k)
    if detect(str(path).split("?")[0]) and "path" not in matched:
        matched.append("path")
    if raw_body and detect(raw_body):
        if not any(m in ("body", "raw_body") for m in matched):
            matched.append("body")
    return matched


class Handler(BaseHTTPRequestHandler):
    MAX_HEADERS = 200

    def _handle(self):
        raw_path = self.path.split("?")[0]
        decoded_path = urllib.parse.unquote(raw_path)

        if raw_path == "/api/log" and self.command == "GET":
            body = json.dumps(internal_log).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if raw_path == "/_oracle/reset" and self.command == "POST":
            internal_log.clear()
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if raw_path == "/_oracle/query" and self.command == "POST":
            content_length = int(self.headers.get("Content-Length", 0))
            req_body = self.rfile.read(content_length).decode("utf-8") if content_length else ""
            try:
                query_req = json.loads(req_body) if req_body else {}
                if "value" in query_req and len(query_req) <= 2:
                    value = str(query_req.get("value", ""))
                    matched = detect(value)
                    all_matched = [PARAM_NAME] if matched else []
                else:
                    params, raw_body_for_query = params_from_request_json(query_req)
                    value = extract_value(
                        params, raw_body_for_query,
                        path=query_req.get("path", "/"))
                    matched = detect(value)
                    all_matched = detect_all_for_oracle(
                        params, raw_body_for_query, query_req.get("path", "/"))
                resp = json.dumps({
                    "detected": bool(matched),
                    "triggered": bool(matched),
                    "sink_type": PARAM_NAME,
                    "sink_value": str(value)[:200],
                    "param_name": PARAM_NAME,
                    "all_matched": all_matched,
                }).encode()
            except Exception as e:
                resp = json.dumps({"detected": False, "triggered": False,
                                   "error": str(e)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        if PARAM_NAME not in ("path", "url"):
            norm_expected = posixpath.normpath(EXPECTED_PATH)
            if (raw_path not in (EXPECTED_PATH, norm_expected)
                    and decoded_path not in (EXPECTED_PATH, norm_expected)):
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

        params, raw_body = parse_params(self)
        value = extract_value(params, raw_body, path=decoded_path)

        matched = detect(value)
        all_matched = detect_all(params, raw_body, self)
        action_taken = f"processed: {value[:100]}" if matched else "no match"

        log_entry = {
            "path": raw_path,
            "params": params.get("query", {}),
            "dangerous_param_name": PARAM_NAME,
            "dangerous_param": value,
            "action_taken": action_taken,
            "matched": matched,
            "all_matched_params": all_matched,
        }
        internal_log.append(log_entry)
        print(json.dumps(log_entry), flush=True)

        resp = b"OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_DELETE(self): self._handle()
    def do_PATCH(self): self._handle()
    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
'''.lstrip("\n")


def _assemble_mock(path: str, param_name: str,
                   detection_condition: str, attack_value: str = "",
                   port: int = 8080) -> str:
    """Fill the template with deterministic values + LLM condition."""
    code = MOCK_TEMPLATE
    code = code.replace("__PORT__", str(port))
    code = code.replace("__EXPECTED_PATH__", repr(path))
    code = code.replace("__PARAM_NAME__", repr(param_name))
    code = code.replace("__ATTACK_VALUE__", repr(attack_value))
    code = code.replace("__DETECTION__", detection_condition)
    return code


# ---------------------------------------------------------------------------
# Public API (signature kept for backward compatibility)
# ---------------------------------------------------------------------------

def generate_flask_from_skeleton(http_request: dict, analysis: dict,
                                  counterexample: dict = None,
                                  temperature: float = TEMP_GENERATIVE,
                                  system_prompt: str = None,
                                  trace_response: dict = None,
                                  blackboard: dict = None) -> str:
    """Generate mock server code.

    Despite the name, this now generates BaseHTTPRequestHandler code.
    Signature kept for backward compatibility with callers.
    """
    path = http_request["path"].split("?")[0]

    # Phase 0: Deterministic parse
    parsed = parse_request_params(http_request)
    logger.info("Parsed params: %s",
                {k: (v if k != "raw_body" else f"({len(v)} chars)")
                 for k, v in parsed.items()})

    # Phase 1: Identify dangerous parameter
    param_name, attack_value = identify_param(parsed, http_request, analysis)
    logger.info("Param: %s = %s", param_name, attack_value[:80] if attack_value else "")

    # Phase 2: Generate + verify detection condition
    direction = None
    if isinstance(counterexample, dict):
        direction = counterexample.get("direction")
        if not direction:
            rp = counterexample.get("repair_plan")
            if isinstance(rp, dict):
                direction = rp.get("direction")
    condition = generate_detection(
        attack_value, param_name, analysis,
        temperature=TEMP_GENERATIVE, counterexample=counterexample,
        blackboard=blackboard, direction=direction)

    # Phase 3: Assemble
    code = _assemble_mock(path, param_name, condition, attack_value)

    try:
        compile(code, "<mock>", "exec")
    except SyntaxError as e:
        logger.error("Assembly syntax error: %s", e)
        raise ConditionGenerationFailed(f"assembled detection code is invalid: {e}")

    return code
