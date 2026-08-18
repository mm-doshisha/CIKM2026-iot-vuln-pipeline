#!/usr/bin/env python3
"""Write the DEPLOYED (Path-X) ruleset from a nollm synthesis dir: apply the
deterministic filler-drop to each saved rule (exactly what the patched assemble_rule
omits), so eval_suricata_e2e runs the rules the deployed method would actually emit.
Usage: make_pathx_rules.py <src_seed_dir> <dst_seed_dir>
"""
import json, os, re, sys
sys.path.insert(0, "/workspace")
from src.hypothesis.rule_template import _is_shape_only_filler
from src.hypothesis.rule_postprocess import is_degenerate

_BUFFERS = {"http.uri", "http.uri.raw", "http.request_body", "http.method",
            "http.header", "http.cookie", "http.host", "http.user_agent",
            "http.content_type"}


def _unescape_content(v):
    return (v.replace('\\"', '"').replace("|3B|", ";").replace("|7C|", "|")
            .replace("|5C|", "\\"))


def drop_filler(rule):
    head, _, rest = rule.partition("(")
    if not rest or not rest.rstrip().endswith(";)"):
        return rule, 0
    inner = rest.rstrip()[:-2]
    opts = [o.strip() for o in inner.split("; ") if o.strip()]
    out, dropped = [], 0
    for o in opts:
        m = re.fullmatch(r'!?content:"(.*)"', o)
        if m and _is_shape_only_filler(_unescape_content(m.group(1))):
            if out and out[-1] in _BUFFERS:
                out.pop()
            dropped += 1
            continue
        out.append(o)
    return head + "(" + "; ".join(out) + ";)", dropped


src, dst = sys.argv[1], sys.argv[2]
os.makedirs(dst, exist_ok=True)
n_drop = n_degen = 0
for f in sorted(os.listdir(src)):
    if not f.endswith(".json"):
        continue
    d = json.load(open(os.path.join(src, f)))
    rule = (d.get("suricata_rule") or "").strip()
    if rule and not rule.startswith("#"):
        new_rule, dropped = drop_filler(rule)
        if dropped:
            n_drop += 1
            if is_degenerate(new_rule):
                new_rule = ""       # degenerate after drop -> no deployable rule
                n_degen += 1
        d["suricata_rule"] = new_rule
    with open(os.path.join(dst, f), "w") as w:
        json.dump(d, w)
print("pathx rules written: %s -> %s (filler-dropped=%d, degenerate=%d)"
      % (src, dst, n_drop, n_degen))
