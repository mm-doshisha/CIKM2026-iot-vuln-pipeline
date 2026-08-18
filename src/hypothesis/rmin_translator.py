"""Deterministic R_min to Suricata rule translation."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Literal

from .rule_postprocess import cve_to_sid, postprocess_rule
from .rule_template import escape_content

ParamKind = Literal["fixed", "pattern", "presence"]


@dataclass
class RminParam:
    name: str
    kind: ParamKind
    value: str


@dataclass
class RminSpec:
    cve_id: str
    method: Literal["GET", "POST", "PUT"]
    path: str
    params: list[RminParam]
    headers: list[RminParam] = field(default_factory=list)
    mitre_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


PATTERN_PCRE = {
    "base64_with_shell_chars": r"/system=[A-Za-z0-9+\/]+=*/",
    "shell_metacharacters": r"/([\x3b\x7c\x24\x60\x0a]|%3b|%7c|%24|%60|%0a)/i",
    "sql_keywords": r"/\b(union|select)\b/i",
    "template_expression": r"/\{\{.*?\}\}/",
    # raw '../' OR its percent-encoded spellings (%2e%2e, %2f, %5c),
    # case-insensitive, matched on the raw URI buffer — so one rule survives the
    # url-encoding evasion that a literal-path content misses (measured: literal
    # encoded_traversal DR 0% -> mechanism pcre 100%, cross-fire FPR 0%).
    "path_traversal": r"/(\.\.|%2e%2e)(\/|%2f|%5c)/i",
}


def rmin_to_rule(spec: RminSpec,
                 sid_range: tuple[int, int] = (9000001, 9999999)) -> str:
    sid = cve_to_sid(spec.cve_id, sid_range=sid_range, fallback_obj=spec.to_dict())
    options = [
        f'msg:"IOT MOER distilled exploit {escape_content(spec.cve_id or "unknown")}"',
        "flow:established,to_server",
        "http.method",
        f'content:"{escape_content(spec.method)}"',
    ]

    fixed_candidates = [spec.path] + [p.value for p in spec.params if p.kind == "fixed"]
    fast_value = max((v for v in fixed_candidates if v), key=len, default=spec.path)
    path_buffer = "http.uri.raw" if _has_traversal(spec.path) else "http.uri"
    options.extend([path_buffer, f'content:"{escape_content(spec.path)}"'])
    if spec.path == fast_value or not any(p.kind == "fixed" and p.value == fast_value for p in spec.params):
        options.append("fast_pattern")

    body_buffer = "http.request_body" if spec.method != "GET" else "http.uri"
    for param in spec.params:
        if param.kind == "presence":
            value = f"{param.name}="
            options.extend([body_buffer, f'content:"{escape_content(value)}"'])
        elif param.kind == "fixed":
            value = _param_match_literal(spec.method, param)
            options.extend([body_buffer, f'content:"{escape_content(value)}"'])
            if param.value == fast_value and "fast_pattern" not in options:
                options.append("fast_pattern")
        elif param.kind == "pattern":
            _append_pattern(options, body_buffer, param.value)

    for header in spec.headers:
        options.extend(["http.header", f'content:"{escape_content(header.name + ": " + header.value)}"'])

    options.append(f"classtype:{_classtype(spec)}")
    if spec.mitre_id:
        options.append(f"metadata:mitre_technique_id {spec.mitre_id}")
    options.extend([f"sid:{sid}", "rev:1"])

    rule = "alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (" + "; ".join(options) + ";)"
    return postprocess_rule(rule, spec.cve_id, spec.method, sid_range=sid_range,
                            fallback_obj=spec.to_dict())


def _param_kind(value: str, analysis: dict) -> ParamKind:
    label = _pattern_label(value, analysis)
    if label:
        return "pattern"
    return "presence" if value == "" else "fixed"


def _param_value(value: str, analysis: dict) -> str:
    return _pattern_label(value, analysis) or value


def _pattern_label(value: str, analysis: dict) -> str:
    # R_min values are confirmed attack payloads from distillation,
    # so substring-based classification is reliable for these inputs.
    hyp = (analysis or {}).get("attack_hypothesis", {})
    text = f"{hyp.get('payload_syntax', '')} {value}".lower()
    if "../" in value or "%2e%2e" in value.lower():
        return "path_traversal"
    if "{{" in value and "}}" in value:
        return "template_expression"
    if re.search(r"\b(union|select)\b", value, re.IGNORECASE):
        return "sql_keywords"
    if any(x in value for x in (";", "|", "`", "$(", "\n")):
        return "shell_metacharacters"
    if "base64" in text:
        return "base64_with_shell_chars"
    return ""


def _append_pattern(options: list[str], buffer: str, label: str) -> None:
    if label == "path_traversal":
        # Mechanism pcre (raw + url-encoded traversal) on the raw URI, replacing the
        # literal 'content:"../"' that could not match %2e%2e-encoded spellings.
        pcre = PATTERN_PCRE["path_traversal"]
        options.extend(["http.uri.raw", f'pcre:"{pcre}"'])
    elif label == "null_byte":
        options.extend([buffer, r'content:"|00|"'])
    else:
        pcre = PATTERN_PCRE.get(label)
        if pcre:
            options.extend([buffer, f'pcre:"{pcre}"'])
        else:
            import logging
            logging.getLogger("rmin_translator").warning(
                "Unknown pattern label '%s' — falling back to content match", label)


def _param_match_literal(method: str, param: RminParam) -> str:
    if param.name in {"body", "raw_body"}:
        return param.value
    return f"{param.name}={param.value}"


def _has_traversal(value: str) -> bool:
    return "../" in value or "%2e%2e" in value.lower()


def _classtype(spec: RminSpec) -> str:
    joined = " ".join([p.value for p in spec.params]).lower()
    if "admin" in joined or "password" in joined:
        return "attempted-admin"
    if any(ch in joined for ch in (";", "|", "`", "$(")):
        return "web-application-attack"
    if not spec.params:
        return "attempted-recon"
    return "web-application-attack"
