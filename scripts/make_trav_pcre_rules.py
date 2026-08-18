#!/usr/bin/env python3
"""Minimal symbiosis experiment (path_traversal class): rewrite traversal rules from
literal-path content to a MECHANISM pcre that matches raw OR url-encoded traversal,
on http.uri.raw. This is the surgical (B+E) widening: only traversal-specific encoded
forms, NOT the catch-all /%[0-9a-f]{2}/i that caused hardening -36.5pp. Tests whether
covering url-encoded variants raises variant DR while keeping cross-fire FPR at 0.
Usage: make_trav_pcre_rules.py <src_seed_dir> <dst_seed_dir>
"""
import json, os, re, sys, glob

# matches '../', '..\', '%2e%2e/', '..%2f', '%2e%2e%2f' on the raw URI buffer.
# /i = case-insensitive, so uppercase-encoded forms (%2E%2E%2F, %5C) also match.
TRAV_PCRE = r'pcre:"/(\.\.|%2e%2e)(\/|%2f|%5c)/i"'

src, dst = sys.argv[1], sys.argv[2]
os.makedirs(dst, exist_ok=True)
n = 0
for f in sorted(glob.glob(os.path.join(src, "CVE-*.json"))):
    d = json.load(open(f))
    r = (d.get("suricata_rule") or "").strip()
    if r and not r.startswith("#") and "http.uri.raw" in r and "../" in r:
        # replace each content:"...have ..." (the literal traversal path) with the mechanism pcre
        new_r, k = re.subn(r'content:"[^"]*\.\.[^"]*"', lambda m: TRAV_PCRE, r)
        if k:
            # The replaced content may have carried a trailing `nocase` (a content
            # modifier). After content->pcre that nocase has no preceding content and
            # Suricata rejects the whole rule ("nocase needs preceding content
            # option"). The pcre's /i flag already gives case-insensitivity, so drop
            # the now-dangling nocase.
            new_r = re.sub(r'(pcre:"[^"]*";)\s*nocase\s*;', r'\1', new_r)
            d["suricata_rule"] = new_r
            n += 1
    with open(os.path.join(dst, os.path.basename(f)), "w") as w:
        json.dump(d, w)
print("traversal rules -> mechanism pcre:", n)
