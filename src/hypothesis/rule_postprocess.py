"""Post-process generated Suricata rules into safer Suricata 7.x syntax."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from typing import Any

_logger = logging.getLogger(__name__)

BUFFER_KEYWORD_MAP = {
    "http_uri": "http.uri",
    "http_request_body": "http.request_body",
    "http.body": "http.request_body",
    "http.url": "http.uri",
    "http.query": "http.uri",
    "http_header": "http.header",
    "http_method": "http.method",
}

STICKY_BUFFERS = {
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

METADATA_OPTION_KEYS = {
    "affected_product",
    "attack_target",
    "confidence",
    "created_at",
    "deployment",
    "former_category",
    "mitre_tactic_id",
    "mitre_tactic_name",
    "mitre_technique_id",
    "mitre_technique_name",
    "performance_impact",
    "signature_severity",
    "updated_at",
}

CONTENT_MODIFIERS = {
    "distance",
    "within",
    "offset",
    "depth",
    "startswith",
    "endswith",
    "nocase",
    "fast_pattern",
}

# Buffer transforms sit BETWEEN a sticky buffer and its content (e.g.
# "http.uri; url_decode; content:..."). _reorder_sticky_buffers must treat a content
# preceded by <sticky buffer> <transform...> as already buffered, or it mis-reads the
# transform as an unbuffered gap and pulls the NEXT buffer in front of the content.
BUFFER_TRANSFORMS = {
    "url_decode",
    "strip_whitespace",
    "compress_whitespace",
    "dotprefix",
    "to_lowercase",
    "to_uppercase",
    "header_lowercase",
}


def cve_to_sid(cve_id: str | None, sid_range: tuple[int, int] = (9000001, 9999999),
               fallback_obj: Any = None) -> int:
    """Map a CVE/case identifier into the local-rule SID range."""
    lo, hi = sid_range
    span = hi - lo + 1
    text = cve_id or ""
    match = re.match(r"^CVE-(\d{4})-(\d+)$", text)
    if match:
        year = int(match.group(1))
        seq = int(match.group(2))
        sid = 9000000 + (year % 100) * 10000 + (seq % 10000)
        if lo <= sid <= hi:
            return sid

    if not text:
        text = json.dumps(fallback_obj or {}, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return lo + (int(digest[:12], 16) % span)


def _split_header_options(rule: str) -> tuple[str, list[str], str]:
    text = _extract_rule_line(rule)
    open_idx = text.find("(")
    close_idx = text.rfind(")")
    if open_idx < 0 or close_idx < open_idx:
        return "alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS", [], ""
    header = text[:open_idx].strip()
    body = text[open_idx + 1:close_idx]
    suffix = text[close_idx + 1:].strip()
    return header, _split_options(body), suffix


def _extract_rule_line(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"```\w*\n?", "", text).strip().rstrip("`")
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("alert ", "drop ", "reject ", "pass ")):
            return line
    return text.splitlines()[0].strip() if text else ""


def _split_options(body: str) -> list[str]:
    options: list[str] = []
    cur: list[str] = []
    in_quote = False
    escaped = False
    for ch in body:
        if ch == "\\" and in_quote:
            cur.append(ch)
            escaped = not escaped
            continue
        if ch == '"' and not escaped:
            in_quote = not in_quote
        escaped = False
        if ch == ";" and not in_quote:
            opt = "".join(cur).strip()
            if opt:
                options.append(opt)
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        options.append(tail)
    return options


def _replace_legacy_keywords(text: str) -> str:
    for old, new in BUFFER_KEYWORD_MAP.items():
        text = re.sub(rf"\b{re.escape(old)}\b", new, text)
    return text


def _fix_header_direction(header: str) -> str:
    if not header:
        return "alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS"
    parts = header.split()
    action = parts[0] if parts else "alert"
    proto = parts[1] if len(parts) > 1 else "http"
    return f"{action} {proto} $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS"


def _option_key(option: str) -> str:
    head = option.split(":", 1)[0].strip()
    return head.split(None, 1)[0] if head else ""


def _is_metadata_standalone(option: str) -> bool:
    return _option_key(option) in METADATA_OPTION_KEYS


def _normalize_metadata_entry(option: str) -> str:
    """Normalize a standalone metadata option to 'key value' format for metadata block."""
    if ":" in option:
        key, _, val = option.partition(":")
        return f"{key.strip()} {val.strip()}" if val.strip() else key.strip()
    return option.strip()


def _strip_get_body_matches(options: list[str]) -> list[str]:
    out: list[str] = []
    skipping_body_match = False
    for option in options:
        key = _option_key(option)
        if key == "http.request_body":
            skipping_body_match = True
            continue
        if skipping_body_match:
            if key in STICKY_BUFFERS or key in {"flow", "msg", "classtype", "sid", "rev", "metadata"}:
                skipping_body_match = False
            elif key in {"content", "pcre"} or key in CONTENT_MODIFIERS:
                continue
        if not skipping_body_match or key in STICKY_BUFFERS or key in {"flow", "msg", "classtype", "sid", "rev", "metadata"}:
            out.append(option)
    return out


def _is_empty_content(option: str) -> bool:
    return bool(re.fullmatch(r'content\s*:\s*""', option.strip()))


def _escape_inner_content_quotes(option: str) -> str:
    match = re.match(r'content\s*:\s*"(.*)"$', option.strip())
    if not match:
        return option
    value = match.group(1)
    fixed: list[str] = []
    escaped = False
    for ch in value:
        if ch == "\\" and not escaped:
            fixed.append(ch)
            escaped = True
            continue
        if ch == '"' and not escaped:
            fixed.append(r"\x22")
        else:
            fixed.append(ch)
        escaped = False
    return 'content:"' + "".join(fixed) + '"'


# HTTP method-only tokens are never discriminative on their own.
_HTTP_METHODS: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
)


def reorder_sticky_buffers(rule: str) -> str:
    """Reorder sticky buffers in a raw rule string (no other transforms).

    Safe to call at eval time on already-postprocessed rules — only moves
    buffer keywords (http.uri, http.method, etc.) before their content/pcre
    keywords, without stripping body matches or reassigning SIDs.
    """
    header, options, suffix = _split_header_options(rule)
    options = _reorder_sticky_buffers(options)
    return f"{header} (" + "; ".join(options) + ";)" + (f" {suffix}" if suffix else "")


def is_degenerate(rule: str) -> str | None:
    """Return None if the rule has discriminative content; a reason string if degenerate.

    Reason strings (truthy):
    - ``"placeholder_pcre"``          — pcre contains literal template variable ``attack_value``
    - ``"no_discriminative_content"`` — no content beyond HTTP method names and no pcre
    - ``"root_path_only"``            — only content keyword is ``"/"``
    - ``"content_too_short"``         — total discriminative content < 4 bytes and no pcre
    """
    # Checked first: a placeholder rule with real content is still degenerate,
    # and its repair diagnosis must target the pcre, not the content.
    if re.search(r'pcre:"[^"]*attack_value[^"]*"', rule or "", re.IGNORECASE):
        return "placeholder_pcre"
    contents = re.findall(r'content:"([^"]*)"', rule or "")
    discriminative = [c for c in contents if c not in _HTTP_METHODS]
    has_pcre = "pcre:" in (rule or "")
    if not discriminative and not has_pcre:
        return "no_discriminative_content"
    if discriminative == ["/"]:
        return "root_path_only"
    total_bytes = sum(len(c) for c in discriminative)
    if total_bytes < 4 and not has_pcre:
        return "content_too_short"
    return None


def _pcre_escape_semicolons(pattern: str) -> str:
    """Replace unescaped ; with \\x3b inside a PCRE pattern body."""
    result: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            result.append(ch)
            result.append(pattern[i + 1])
            i += 2
            continue
        if ch == ";":
            result.append(r"\x3b")
        else:
            result.append(ch)
        i += 1
    return "".join(result)


def _pcre_escape_inner_slashes(pattern: str) -> str:
    """Escape unescaped / inside a PCRE pattern body (Suricata delimiter)."""
    result: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            result.append(ch)
            result.append(pattern[i + 1])
            i += 2
            continue
        if ch == "/":
            result.append(r"\/")
        else:
            result.append(ch)
        i += 1
    return "".join(result)


def _pcre_escape_charclass_dash(pattern: str) -> str:
    """No-op: preserve character-class dashes as written by the LLM.

    Previously this escaped non-boundary dashes inside [...], but that
    destroys valid ranges like [A-Z] → [A\\-Z].  Since we cannot
    distinguish intended ranges from literal dashes without semantic
    context, the safest behaviour is to leave them untouched.
    """
    return pattern


def postprocess_pcre(pcre_option: str) -> str:
    """Sanitize a pcre:"..." option value for Suricata 7.x compatibility.

    Applies deterministic, syntax-only fixes (no semantic changes):
      1. Escape unescaped semicolons inside the pattern (-> \\x3b)
      2. Escape unescaped forward slashes inside the pattern (-> \\/)
      3. Character-class dashes are left as-is (no-op); invalid ranges
         are caught downstream by ``_is_valid_pcre``.

    Returns the original string unchanged if the option cannot be parsed.
    """
    match = re.match(r'^pcre\s*:\s*"(.*)"$', pcre_option.strip(), re.DOTALL)
    if not match:
        return pcre_option
    inner = match.group(1)
    delim_match = re.match(r"^(/)(.*)(/[A-Za-z]*)$", inner, re.DOTALL)
    if not delim_match:
        if inner.startswith("/") and inner.count("/") == 1:
            inner = inner + "/"
            delim_match = re.match(r"^(/)(.*)(/[A-Za-z]*)$", inner, re.DOTALL)
        if not delim_match:
            return pcre_option
    pattern = delim_match.group(2)
    close_part = delim_match.group(3)
    pattern = _pcre_escape_semicolons(pattern)
    pattern = _pcre_escape_inner_slashes(pattern)
    pattern = _pcre_escape_charclass_dash(pattern)
    return f'pcre:"/{pattern}{close_part}"'


def _is_valid_pcre(pcre_option: str) -> bool:
    """Pre-check PCRE pattern compilability using Python's re module.

    Not identical to PCRE2 but catches the most common syntax errors
    (unclosed brackets, invalid quantifiers, etc.) that cause Suricata
    to reject the entire rule.
    """
    match = re.match(r'^pcre\s*:\s*"(.*)"$', pcre_option.strip(), re.DOTALL)
    if not match:
        return False
    inner = match.group(1)
    delim_match = re.match(r"^/(.*)/([A-Za-z]*)$", inner, re.DOTALL)
    if not delim_match:
        return False
    pattern = delim_match.group(1)
    test_pattern = pattern.replace(r"\/", "/")
    try:
        re.compile(test_pattern)
        return True
    except re.error:
        return False


def _dedupe_fast_pattern(options: list[str]) -> list[str]:
    seen = False
    out: list[str] = []
    for option in options:
        if _option_key(option) == "fast_pattern":
            if seen:
                continue
            seen = True
        out.append(option)
    return out


def _merge_metadata(options: list[str], moved: list[str]) -> list[str]:
    if not moved:
        return options
    for i, option in enumerate(options):
        if _option_key(option) == "metadata":
            value = option.split(":", 1)[1].strip() if ":" in option else ""
            joined = ", ".join([p for p in [value, *moved] if p])
            options[i] = f"metadata:{joined}"
            return options
    insert_at = len(options)
    for i, option in enumerate(options):
        if _option_key(option) in {"sid", "rev"}:
            insert_at = i
            break
    options.insert(insert_at, "metadata:" + ", ".join(moved))
    return options


def _reorder_sticky_buffers(options: list[str]) -> list[str]:
    """Move sticky buffer keywords before their content/pcre keywords.

    Suricata 6.x+ treats http.uri, http.method, etc. as sticky buffers
    that apply to the NEXT content keyword. LLMs often generate the
    legacy modifier syntax (content first, buffer after), which is
    silently ignored. This function reorders to the correct syntax:
      content:"X"; http.uri;  →  http.uri; content:"X";
    Content modifiers (nocase, depth, etc.) stay with their content.
    Idempotent: if a sticky buffer already precedes the content, skip.
    """
    result: list[str] = []
    i = 0
    while i < len(options):
        key = _option_key(options[i])
        if key in ("content", "pcre") and i + 1 < len(options):
            # A content is already buffered if it is preceded by a sticky buffer,
            # possibly with buffer transforms (url_decode, ...) in between. Walk back
            # over any transforms before testing for the sticky buffer, so a
            # "http.uri; url_decode; content:..." triple is not mis-read as unbuffered.
            m = len(result) - 1
            while m >= 0 and _option_key(result[m]) in BUFFER_TRANSFORMS:
                m -= 1
            already_buffered = m >= 0 and _option_key(result[m]) in STICKY_BUFFERS
            content_opt = options[i]
            modifiers: list[str] = []
            j = i + 1
            while j < len(options) and _option_key(options[j]) in CONTENT_MODIFIERS:
                modifiers.append(options[j])
                j += 1
            if (not already_buffered
                    and j < len(options)
                    and _option_key(options[j]) in STICKY_BUFFERS):
                result.append(options[j])
                result.append(content_opt)
                result.extend(modifiers)
                i = j + 1
                continue
            result.append(content_opt)
            result.extend(modifiers)
            i = j
            continue
        result.append(options[i])
        i += 1
    return result


# Sticky buffers whose on-wire bytes carry percent-encoded payload that libhtp does
# NOT fully decode by default (notably %2F, kept encoded as an anti-traversal
# measure; the urlencoded variant encodes '/'->%2F, so a literal built from the
# decoded payload misses). http.uri.raw is excluded on purpose: it is the raw,
# un-normalised buffer the traversal encoded pcre relies on.
URL_DECODE_BUFFERS = {"http.uri", "http.request_body"}


def _url_decode_alters(content_option: str) -> bool:
    """True if url_decode would change the literal in this content keyword. url_decode
    rewrites '+'->space and '%HH'->byte across the whole buffer, so a literal that
    carries either would no longer match its own buffer after the transform. Such a
    content must NOT be url_decoded: a route with a literal '+' (e.g. Cisco ASA
    /+CSCOE+/logon.html, where '+' is a real path byte, not a space) or an
    already-percent-encoded payload literal (carrying %27/%3B). ';' is rendered as
    |3B| by escape_content, so it does not trigger the %HH test."""
    m = re.match(r'!?content\s*:\s*"(.*)"\s*$', content_option.strip())
    if not m:
        return True  # not a plain content -> don't transform its buffer
    lit = m.group(1)
    return "+" in lit or re.search(r"%[0-9A-Fa-f]{2}", lit) is not None


def _apply_url_decode(options: list[str]) -> list[str]:
    """Insert Suricata's url_decode transform after a percent-decodable sticky buffer
    when the literal it guards is url_decode-safe, so that literal matches the buffer
    in its decoded form and survives url-encoding of the payload (the urlencoded
    evasion: '/'->%2F etc.). Opt-in via URL_DECODE_NORM. url_decode is a no-op on
    already-decoded bytes (clean firing unchanged) and adds no breadth (the literal is
    preserved). Only applied before a content whose literal url_decode would NOT alter
    (no '+', no %HH) -- so a route with a literal '+' or an already-encoded payload
    literal keeps matching. Not applied before pcre (mechanism pcres already carry
    encoded forms). Runs after _reorder_sticky_buffers. Idempotent: the main cleaning
    pass strips any existing url_decode before this re-inserts."""
    if os.environ.get("URL_DECODE_NORM", "0") != "1":
        return options
    out: list[str] = []
    for idx, option in enumerate(options):
        out.append(option)
        if _option_key(option) in URL_DECODE_BUFFERS:
            nxt = options[idx + 1] if idx + 1 < len(options) else ""
            if _option_key(nxt) == "content" and not _url_decode_alters(nxt):
                out.append("url_decode")
    return out


def _ensure_flow(options: list[str]) -> list[str]:
    if any(_option_key(option) == "flow" for option in options):
        return options
    insert_at = 1 if options and _option_key(options[0]) == "msg" else 0
    options.insert(insert_at, "flow:established,to_server")
    return options


def _assign_sid_rev(options: list[str], cve_id: str, sid_range: tuple[int, int],
                    fallback_obj: Any = None) -> list[str]:
    sid = cve_to_sid(cve_id, sid_range=sid_range, fallback_obj=fallback_obj)
    out = [opt for opt in options if _option_key(opt) not in {"sid", "rev"}]
    out.append(f"sid:{sid}")
    out.append("rev:1")
    return out


def postprocess_rule(rule: str, cve_id: str = "", http_method: str = "GET",
                     sid_range: tuple[int, int] = (9000001, 9999999),
                     fallback_obj: Any = None) -> str:
    """Normalize a generated Suricata rule without claiming engine validation."""
    rule = _replace_legacy_keywords(rule)
    header, options, suffix = _split_header_options(rule)
    header = _fix_header_direction(header)

    moved_metadata: list[str] = []
    cleaned: list[str] = []
    skip_modifiers = False
    for option in options:
        option = _replace_legacy_keywords(option.strip())
        if not option or _is_empty_content(option):
            continue
        key = _option_key(option)
        if key == "url_decode":
            # Strip any existing url_decode; _apply_url_decode re-inserts it after
            # reorder so postprocess stays idempotent across repeated passes
            # (drop_phantom_pcre / finalize call postprocess more than once).
            continue
        if skip_modifiers:
            if key in CONTENT_MODIFIERS:
                continue
            if key in ("content", "pcre"):
                skip_modifiers = False
        if _is_metadata_standalone(option):
            moved_metadata.append(_normalize_metadata_entry(option))
            continue
        if key == "content":
            option = _escape_inner_content_quotes(option)
        if key == "pcre":
            option = postprocess_pcre(option)
            if not _is_valid_pcre(option):
                _logger.warning("postprocess: dropping invalid PCRE: %s", option[:80])
                skip_modifiers = True
                continue
        cleaned.append(option)

    if http_method.upper() == "GET":
        cleaned = _strip_get_body_matches(cleaned)

    cleaned = _reorder_sticky_buffers(cleaned)
    cleaned = _dedupe_fast_pattern(cleaned)
    cleaned = _apply_url_decode(cleaned)
    cleaned = _ensure_flow(cleaned)
    cleaned = _merge_metadata(cleaned, moved_metadata)
    cleaned = _assign_sid_rev(cleaned, cve_id, sid_range, fallback_obj=fallback_obj)

    return f"{header} (" + "; ".join(cleaned) + ";)" + (f" {suffix}" if suffix else "")
