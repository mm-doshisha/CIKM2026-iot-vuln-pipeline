#!/usr/bin/env python3
"""A/B regeneration for the URL_DECODE_NORM transform on the generalized config.

Holds GENERALIZE_MECH=1 fixed (the candidate operating point) and toggles ONLY
URL_DECODE_NORM, reusing the SAME cached analyses + deterministic compiler, so the
A/B isolates the url_decode transform's effect on urlencoded-DR, clean-DR and FPR.
url_decode is inserted in rule_postprocess after each http.uri/http.request_body
sticky buffer; it is a no-op on already-decoded bytes (clean firing unchanged) and
adds no breadth (the discriminative literal is preserved). Pure-deterministic,
CPU-only, no LLM call (max_validation_rounds=0 disables every LLM path).
"""
import argparse
import glob
import json
import os
import sys

sys.path.insert(0, ".")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--url-decode", required=True, choices=["0", "1"])
    args = ap.parse_args()

    from src.hypothesis.agents.rule_agent import RuleGenAgent
    from src.hypothesis.rule_pcre_guard import drop_phantom_pcre
    agent = RuleGenAgent(max_validation_rounds=0, max_semantic_rounds=0,
                         use_template=True, enable_semantic_verify=False,
                         no_llm_rule=True)
    # generalized config fixed; only url_decode toggles
    os.environ["GENERALIZE_MECH"] = "1"
    os.environ["URL_DECODE_NORM"] = args.url_decode

    def finalize(rule, req):
        # Replicate the runner's post-generate step (drop_phantom_pcre) so the regen
        # matches the deployed pipeline; hardening is OFF in the proposed method.
        if rule and not rule.startswith("#"):
            try:
                return drop_phantom_pcre(rule, req)
            except Exception:
                return rule
        return rule

    os.makedirs(args.out, exist_ok=True)
    n = ok = ud = 0
    for f in sorted(glob.glob(os.path.join(args.src, "CVE-*.json"))):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        n += 1
        name = os.path.basename(f)
        req = d.get("http_request") or {}
        ana = d.get("verified_analysis") or d.get("final_analysis") or {}
        try:
            rule = finalize(agent.generate(dict(req), dict(ana)), req)
        except Exception as e:
            rule = None
            print("ERR %s: %s" % (name, e))
        d2 = dict(d)
        if rule:
            d2["suricata_rule"] = rule
            ok += 1
            if "url_decode" in rule:
                ud += 1
        with open(os.path.join(args.out, name), "w") as fh:
            json.dump(d2, fh)

    print("url_decode=%s  CVEs=%d  ok=%d  rules_with_url_decode=%d"
          % (args.url_decode, n, ok, ud))


if __name__ == "__main__":
    main()
