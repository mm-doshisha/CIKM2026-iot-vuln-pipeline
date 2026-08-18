"""Drop a phantom PCRE guard that cannot match its own buffer's wire bytes.

Background. A template/LLM-emitted command-injection rule often appends a guard
like  pcre:"/[\\x3b\\|$\\x60\\x0a]/"  (raw shell metacharacters) AFTER a content
match on the attack payload. When the attack payload is URL-encoded on the wire
(e.g. body  username=admin%27%3Bcat...  carries %3B, not a raw ';'), the guard
matches no byte in that buffer, so the content-AND-pcre rule never fires on its
own attack — even though the CEGIS validator (which scanned the whole formatted
request, header newlines included, and so matched the guard's \\x0a) marked it
"verified". Real Suricata applies the guard to a single sticky buffer, where the
encoded payload has no raw metachar → no fire.

This is the command-injection analogue of the path_traversal phantom-marker fix
(rule_agent._generate_template_rule): the full payload is already matched on its
own buffer, so a guard that cannot match that buffer is redundant and is dropped.

Safety. The guard is dropped ONLY when, after removal, the rule still carries at
least one content: match (on the same buffer) that DOES occur in the attack's
wire bytes. The retained content is the attack-specific payload, so dropping a
non-matching guard cannot widen the rule onto benign traffic — it only lets the
rule fire on inputs that already contain the attack payload. FPR is re-measured
on the full benign cohorts to confirm.
"""

from __future__ import annotations

import re

# Map a sticky-buffer keyword to the attack wire string it inspects.
_URI_BUFFERS = {"http.uri", "http.uri.raw"}
_BODY_BUFFERS = {"http.request_body"}


def _suricata_pcre_to_python(pattern: str) -> str:
    """Convert a Suricata pcre body (already without /.../ delimiters) to a
    Python-re-compatible pattern. Suricata escapes ';' as \\x3b and '/' as \\/;
    \\xHH hex escapes are valid in Python re too, so keep them — but normalize the
    ones we know the renderer emits so re.search sees the literal byte."""
    p = pattern
    p = p.replace(r"\/", "/")
    return p


def _wire_for_buffer(buffer: str, http_request: dict) -> str:
    path = http_request.get("path", "") or ""
    body = http_request.get("body", "")
    if isinstance(body, (dict, list)):
        import json
        body = json.dumps(body)
    body = "" if body is None else str(body)
    if buffer in _BODY_BUFFERS:
        return body
    if buffer in _URI_BUFFERS:
        return path
    # http.header / http.cookie / unknown: fall back to the whole request line +
    # headers + body so we never *spuriously* drop a guard that could match.
    headers = http_request.get("headers", {}) or {}
    hdr = "\n".join(f"{k}: {v}" for k, v in headers.items())
    return f"{path}\n{hdr}\n{body}"


def _split_options(options: str) -> list[str]:
    """Split a Suricata option string on ';' that are not inside a quoted value."""
    out, buf, in_q, esc = [], [], False, False
    for ch in options:
        if esc:
            buf.append(ch)
            esc = False
            continue
        if ch == "\\":
            buf.append(ch)
            esc = True
            continue
        if ch == '"':
            in_q = not in_q
            buf.append(ch)
            continue
        if ch == ";" and not in_q:
            tok = "".join(buf).strip()
            if tok:
                out.append(tok)
            buf = []
            continue
        buf.append(ch)
    tok = "".join(buf).strip()
    if tok:
        out.append(tok)
    return out


def _pcre_matches_wire(pcre_token: str, wire: str) -> bool:
    m = re.match(r'pcre:"/(.*)/([A-Za-z]*)"\s*$', pcre_token)
    if not m:
        return True  # not a parseable bare pcre → leave it alone
    pat = _suricata_pcre_to_python(m.group(1))
    flags = re.IGNORECASE if "i" in m.group(2) else 0
    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(re.search, pat, wire, flags).result(timeout=2.0) is not None
    except Exception:
        return True  # on any error, do not drop (conservative)


def _content_value(token: str) -> str | None:
    m = re.match(r'content:"(.*)"\s*$', token)
    return m.group(1) if m else None


def _decode_content(content_val: str) -> str:
    s = content_val
    s = re.sub(r"\|([0-9A-Fa-f]{2})\|", lambda mm: chr(int(mm.group(1), 16)), s)
    s = s.replace('\\"', '"')
    return s


def _content_matches_wire(content_val: str, wire: str) -> bool:
    # Decode Suricata content escapes back to literal bytes for a substring test.
    return _decode_content(content_val) in wire


# A retained content carries enough attack signal to safely replace the dropped
# guard when it embeds an encoded metacharacter / command-substitution byte, a
# shell command word, or is long enough to be payload-specific rather than a bare
# parameter name (which a benign request could also carry).
_ENCODED_METACHAR = re.compile(
    r"%2[47Ee]|%3[Bb]|%60|%0[Aa]|%7[Cc]|[;`|]|\$\(|\$\{")
_SHELL_WORD = re.compile(
    r"\b(cat|wget|curl|nc|bash|sh|chmod|rm|id|whoami|/etc/passwd)\b")


def _content_is_attack_specific(content_val: str) -> bool:
    s = _decode_content(content_val)
    if _ENCODED_METACHAR.search(content_val) or _ENCODED_METACHAR.search(s):
        return True
    if _SHELL_WORD.search(s):
        return True
    # A bare "param=" (e.g. submit-url=) is NOT specific; require real length.
    stripped = s.rstrip("=")
    return len(stripped) >= 20 and "=" not in stripped[-1:]


def drop_phantom_pcre(rule: str, http_request: dict) -> str:
    """Return rule with any buffer-non-matching pcre guard removed, provided a
    content match on the same buffer still covers the attack. Idempotent; returns
    the rule unchanged when nothing qualifies."""
    head = re.match(r"^(.*?\()(.*)\)\s*$", rule, re.DOTALL)
    if not head:
        return rule
    prefix, options = head.group(1), head.group(2)
    toks = _split_options(options)

    # Track the sticky buffer in effect for each token.
    cur = "http.uri"
    buf_of: list[str] = []
    for t in toks:
        base = t.split(":", 1)[0].strip()
        if base in _URI_BUFFERS or base in _BODY_BUFFERS or base in {
            "http.method", "http.header", "http.cookie", "http.host",
            "http.user_agent", "http.content_type",
        }:
            cur = base
        buf_of.append(cur)

    # Which buffers retain an attack-SPECIFIC content that occurs in the attack
    # wire? Only such a buffer is safe to strip a guard from: a bare "param="
    # content could also match benign traffic, so dropping the guard there would
    # widen the rule onto benign.
    covered: set[str] = set()
    for t, b in zip(toks, buf_of):
        cv = _content_value(t)
        if cv is not None and b not in {"http.method"}:
            if (_content_matches_wire(cv, _wire_for_buffer(b, http_request))
                    and _content_is_attack_specific(cv)):
                covered.add(b)

    keep: list[str] = []
    dropped = False
    for t, b in zip(toks, buf_of):
        if t.startswith("pcre:"):
            wire = _wire_for_buffer(b, http_request)
            if not _pcre_matches_wire(t, wire) and b in covered:
                dropped = True
                continue  # drop this phantom guard
        keep.append(t)

    if not dropped:
        return rule
    return f"{prefix}{'; '.join(keep)};)"
