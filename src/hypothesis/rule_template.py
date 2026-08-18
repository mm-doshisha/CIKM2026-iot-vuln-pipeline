"""Template-constrained Suricata rule assembly."""

from __future__ import annotations

import re
from typing import Any

from .rule_postprocess import cve_to_sid, postprocess_rule

DEFAULT_CLASSTYPE = "web-application-attack"
ALLOWED_BUFFERS = {
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


def escape_content(value: Any) -> str:
    """Escape a value for use inside a Suricata content:"..." keyword.

    Suricata content strings treat only three constructs specially:
      - |XX| hex notation  → pipe must be escaped
      - \\"   escaped quote → quote must be escaped
      - \\    before " is escape; elsewhere literal
    Semicolons are literal inside content quotes — do NOT escape them.
    """
    text = "" if value is None else str(value)
    text = text.replace("|", "|7C|")
    text = text.replace("\\", "|5C|")
    text = text.replace('"', r"\"")
    text = text.replace(";", "|3B|")
    # Hex-escape control bytes (CR, LF, TAB, …) so a payload that carries line
    # breaks renders as a valid single-line content instead of breaking the rule.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        text = "".join(
            "|%02X|" % ord(c) if (ord(c) < 0x20 or ord(c) == 0x7F) else c
            for c in text)
    return text


def normalize_pcre(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    if text.startswith("/") and text.count("/") >= 2:
        last_slash = text.rfind("/")
        pattern = text[1:last_slash]
        flags = text[last_slash + 1:]
    else:
        pattern = text.strip("/")
        flags = ""
    flags = flags if re.fullmatch(r"[A-Za-z]*", flags) else ""
    pattern = pattern.replace(";", r"\x3b")
    pattern = re.sub(r"(?<!\\)/", r"\/", pattern)
    return f"/{pattern}/{flags}"


def _safe_msg(value: Any, cve_id: str) -> str:
    text = str(value or f"IOT exploit attempt {cve_id or 'unknown'}")
    return escape_content(text)


def _safe_classtype(value: Any) -> str:
    text = str(value or DEFAULT_CLASSTYPE).strip()
    if re.fullmatch(r"[A-Za-z0-9_-]+", text):
        return text
    return DEFAULT_CLASSTYPE


def _pcre_references_absent_param(pcre_pattern: str, content_values: list[str]) -> bool:
    """Return True if PCRE requires a named parameter not found in any content value."""
    param_refs = re.findall(r'([a-zA-Z_]\w{2,})=', pcre_pattern)
    if not param_refs:
        return False
    content_joined = " ".join(content_values)
    return not any(param in content_joined for param in param_refs)


def _normalize_buffer(buffer: Any) -> str:
    text = str(buffer or "http.uri").strip()
    if text not in ALLOWED_BUFFERS:
        return "http.uri"
    return text


def _is_shape_only_filler(value: str) -> bool:
    """True if a content value is overflow/padding filler — one byte makes up >=80%
    of a >=20-byte run (e.g. a buffer-overflow Host header 'aaaa...'). Such a value is
    the attack's incidental shape, not a mechanism; matching it yields an over-fit and
    often syntactically invalid rule. A mechanism that repeats a real token (e.g. '../'
    traversal) has no single dominant byte and is NOT flagged. General, no per-CVE logic."""
    if len(value) < 20:
        return False
    from collections import Counter
    return max(Counter(value).values()) / len(value) >= 0.8


def assemble_rule(spec: dict[str, Any], cve_id: str, http_method: str,
                  mitre_id: str = "",
                  sid_range: tuple[int, int] = (9000001, 9999999)) -> str:
    """Assemble one Suricata rule from a constrained JSON spec."""
    method = str(http_method or "GET").upper()
    sid = cve_to_sid(cve_id, sid_range=sid_range, fallback_obj=spec)
    options: list[str] = [
        f'msg:"{_safe_msg(spec.get("msg"), cve_id)}"',
        "flow:established,to_server",
        "http.method",
        f'content:"{escape_content(method)}"',
    ]

    fast_pattern_used = False
    last_buffer: str | None = None
    added_per_buffer: dict[str, list[str]] = {}
    for item in spec.get("content_matches") or []:
        if not isinstance(item, dict):
            continue
        buffer = _normalize_buffer(item.get("buffer"))
        if method == "GET" and buffer == "http.request_body":
            continue
        value = item.get("value")
        if value is None or str(value) == "":
            continue
        val_str = str(value)
        if _is_shape_only_filler(val_str):
            # Overflow/padding filler (one byte dominates a long run): matching it as
            # content:"aaaa…" over-fits to incidental padding and yields a non-
            # generalising (often syntactically invalid) rule, so drop it. The attack
            # is still detected by its content signature — a parameter name, endpoint,
            # or shell/SQL metacharacters — when one is present. A pure-length-only
            # overflow with no other signal is a known limitation: Suricata caps the
            # inspected request body (request-body-limit), so a length keyword cannot
            # separate it from benign traffic of comparable length (measured: bsize
            # recovered 8/48 vs 27/48 for plain filler-drop, so it was removed).
            continue
        if "../" in val_str and buffer == "http.uri":
            buffer = "http.uri.raw"

        existing = added_per_buffer.get(buffer, [])
        if val_str in existing:
            continue
        if val_str in ("../", "..", "../..") and any(
            "../" in v and len(v) > len(val_str) for v in existing
        ):
            continue

        added_per_buffer.setdefault(buffer, []).append(val_str)
        options.append(buffer)
        last_buffer = buffer
        content = f'content:"{escape_content(value)}"'
        if item.get("negated"):
            content = "!" + content
        options.append(content)
        if item.get("nocase"):
            options.append("nocase")
        if item.get("fast_pattern") and not fast_pattern_used:
            options.append("fast_pattern")
            fast_pattern_used = True

    pcre = normalize_pcre(spec.get("pcre"))
    if pcre:
        content_values = [v for vs in added_per_buffer.values() for v in vs]
        if _pcre_references_absent_param(pcre, content_values):
            pcre = None
    if pcre:
        # Scope the pcre to the buffer where the payload lives. A pcre with no
        # sticky buffer inherits the LAST content's buffer; once the attack-value
        # literal (on the param buffer) is dropped, the pcre can silently fall onto
        # the route buffer (http.uri) and never match a body injection. Restate the
        # intended buffer ONLY when it differs from the buffer the pcre would
        # otherwise inherit -- restating the already-current buffer needlessly
        # disrupts matching and stops drop_phantom_pcre from removing a phantom
        # pcre. Empty pcre_buffer keeps the inherit behaviour (traversal ->
        # http.uri.raw from its endpoint prefix).
        pcre_buffer = _normalize_buffer(spec.get("pcre_buffer")) if spec.get("pcre_buffer") else None
        if pcre_buffer and pcre_buffer != last_buffer:
            options.append(pcre_buffer)
        options.append(f'pcre:"{pcre}"')

    raw_options = str(spec.get("raw_options") or "").strip()
    if raw_options:
        raw_options = raw_options.strip().rstrip(";")
        if raw_options:
            options.append(raw_options)

    options.append(f"classtype:{_safe_classtype(spec.get('classtype'))}")
    if mitre_id:
        options.append(f"metadata:mitre_technique_id {mitre_id}")
    options.append(f"sid:{sid}")
    options.append("rev:1")

    rule = (
        "alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ("
        + "; ".join(options)
        + ";)"
    )
    return postprocess_rule(rule, cve_id, method, sid_range=sid_range, fallback_obj=spec)
