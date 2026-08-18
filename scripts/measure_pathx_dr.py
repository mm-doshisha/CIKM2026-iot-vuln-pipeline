#!/usr/bin/env python3
"""Exact honest attack DR for the deployed Path-X method (filler-drop, no bsize),
measured ON THE nollm realization by surgically applying the filler-drop to each
saved nollm rule and re-firing. assemble_rule's filler-drop = "do not emit the
<buffer>; content:"<filler>" pair", so removing exactly those pairs from the final
rule reproduces the deployed renderer with no LLM re-synthesis (same hypotheses).

Fires BOTH the original rule (sanity: should reproduce nollm 79.1%) and the
surgically dropped rule (honest DR). Run in cegis-ids container, PYTHONPATH=/workspace.
Usage: measure_pathx_dr.py <nollm_seed_dir> <attack_traces_dir>
"""
import json, os, re, sys, tempfile
sys.path.insert(0, "/workspace")
from src.evaluation.pcap_generator import generate_attack_pcap
from src.evaluation.suricata_runner import run_suricata
from src.hypothesis.analyst import _extract_request_only
from src.hypothesis.rule_template import _is_shape_only_filler
from src.hypothesis.rule_postprocess import is_degenerate

D = sys.argv[1]
TRACES = sys.argv[2] if len(sys.argv) > 2 else "/workspace/benchmarks/traces"

_BUFFERS = {"http.uri", "http.uri.raw", "http.request_body", "http.method",
            "http.header", "http.cookie", "http.host", "http.user_agent",
            "http.content_type"}


def _unescape_content(v):
    # filler is plain single-byte runs (no escapes); decode the few that matter
    return (v.replace('\\"', '"').replace("|3B|", ";").replace("|7C|", "|")
            .replace("|5C|", "\\"))


def drop_filler(rule):
    """Remove each `<buffer>; content:"<filler>"` pair whose content is shape-only
    filler — exactly what the patched assemble_rule omits. Returns (new_rule, n_dropped)."""
    head, _, rest = rule.partition("(")
    if not rest or not rest.rstrip().endswith(";)"):
        return rule, 0
    inner = rest.rstrip()[:-2]
    opts = [o.strip() for o in inner.split("; ") if o.strip()]
    out, dropped = [], 0
    for o in opts:
        m = re.fullmatch(r'!?content:"(.*)"', o)
        if m and _is_shape_only_filler(_unescape_content(m.group(1))):
            if out and out[-1] in _BUFFERS:   # drop the orphaned sticky-buffer too
                out.pop()
            dropped += 1
            continue
        out.append(o)
    return head + "(" + "; ".join(out) + ";)", dropped


def fires(rule, req):
    if not rule or rule.startswith("#"):
        return False
    if not re.search(r"sid:\s*\d+", rule):
        rule = rule.rstrip(")") + " sid:9900002; rev:1;)"
    with tempfile.TemporaryDirectory() as t:
        rp = os.path.join(t, "r.rules"); open(rp, "w").write(rule + "\n")
        pc = os.path.join(t, "b.pcap"); generate_attack_pcap(req, pc)
        sr = run_suricata(pc, rp, os.path.join(t, "log"))
        return bool(sr.get("triggered"))


tot = orig_fire = pathx_fire = touched = pathx_degen = 0
for f in sorted(os.listdir(D)):
    if not (f.startswith("CVE") and f.endswith(".json")):
        continue
    r = json.load(open(os.path.join(D, f)))
    cid = r.get("case_id") or f[:-5]
    rule = (r.get("suricata_rule") or "").strip()
    req = r.get("http_request")
    if not req:
        tf = os.path.join(TRACES, cid + ".json")
        req = _extract_request_only(json.load(open(tf))) if os.path.exists(tf) else None
    if not req:
        continue
    tot += 1
    of = fires(rule, req)
    new_rule, dropped = drop_filler(rule)
    if dropped:
        touched += 1
        if is_degenerate(new_rule):
            new_rule = ""                       # degenerate after drop -> no deployable rule
            pathx_degen += 1
    pf = fires(new_rule, req)
    orig_fire += of
    pathx_fire += pf
    if dropped:
        print(f"  {cid:18s} dropped={dropped} orig_fire={of} pathx_fire={pf}"
              f"{' (degenerate)' if not new_rule else ''}")

print(f"DIR {D}")
print(f"  total={tot} filler_touched={touched} pathx_degenerate={pathx_degen}")
print(f"  orig(nollm)_DR  = {orig_fire}/{tot} = {orig_fire/tot*100:.1f}%")
print(f"  pathx(honest)_DR= {pathx_fire}/{tot} = {pathx_fire/tot*100:.1f}%")
