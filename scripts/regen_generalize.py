#!/usr/bin/env python3
"""A/B regeneration for the GENERALIZE_MECH sanity.

Reuses the SAME cached analyses (the LLM analyst is stochastic, so re-synthesising
would confound the flag's effect) and only re-runs the deterministic rule compiler:
  - lit-out: the original literal-pinned rule, unchanged (BEFORE).
  - gen-out: the rule regenerated with GENERALIZE_MECH=1 (AFTER) -- attack-value
    literal dropped, route+param anchors + mechanism pcre kept.
Both dirs hold the SAME CVE subset, so eval_suricata_e2e gives a clean A/B on the
new payload_substitution variant + FPR. Pure-deterministic, CPU-only, no LLM call
(max_validation_rounds=0 disables every LLM path in RuleGenAgent.generate).
"""
import argparse
import glob
import json
import os
import sys

sys.path.insert(0, ".")

SHELL_META = (";", "|", chr(96), "$(", "\n")


def mech_class(d: dict) -> str:
    fa = d.get("verified_analysis") or d.get("final_analysis") or {}
    v = str(d.get("attack_value")
            or fa.get("attack_hypothesis", {}).get("payload_syntax") or "")
    low = v.lower()
    if "../" in v or "%2e%2e" in low:
        return "path_traversal"
    if "{{" in v and "}}" in v:
        return "template"
    if "union" in low or "select" in low:
        return "sql"
    if any(x in v for x in SHELL_META):
        return "shell"
    return ""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--lit-out", required=True)
    ap.add_argument("--gen-out", required=True)
    ap.add_argument("--classes", default="shell",
                    help="comma list of mech classes to include (default shell)")
    args = ap.parse_args()
    want = set(c.strip() for c in args.classes.split(",") if c.strip())

    from src.hypothesis.agents.rule_agent import RuleGenAgent
    from src.hypothesis.rule_pcre_guard import drop_phantom_pcre
    agent = RuleGenAgent(max_validation_rounds=0, max_semantic_rounds=0,
                         use_template=True, enable_semantic_verify=False,
                         no_llm_rule=True)

    def finalize(rule, req):
        # Replicate the runner's post-generate step so the regen matches the
        # deployed pipeline (runner.py applies drop_phantom_pcre after generate;
        # hardening is OFF in the proposed pg2 method, so it is not applied here).
        if rule and not rule.startswith("#"):
            try:
                return drop_phantom_pcre(rule, req)
            except Exception:
                return rule
        return rule

    os.makedirs(args.lit_out, exist_ok=True)
    os.makedirs(args.gen_out, exist_ok=True)

    n = gen_ok = changed = 0
    for f in sorted(glob.glob(os.path.join(args.src, "CVE-*.json"))):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        if "all" not in want and mech_class(d) not in want:
            continue
        n += 1
        name = os.path.basename(f)
        req = d.get("http_request") or {}
        ana = d.get("verified_analysis") or d.get("final_analysis") or {}
        # BEFORE: regenerate with the flag OFF (literal kept) on the SAME
        # buffer-fixed compiler, so the A/B isolates only the GENERALIZE_MECH flag
        # (not the buffer fix, which applies to both).
        os.environ["GENERALIZE_MECH"] = "0"
        try:
            lit_rule = finalize(agent.generate(dict(req), dict(ana)), req)
        except Exception as e:
            lit_rule = None
            print("LIT-ERR %s: %s" % (name, e))
        d_lit = dict(d)
        if lit_rule:
            d_lit["suricata_rule"] = lit_rule
        with open(os.path.join(args.lit_out, name), "w") as fh:
            json.dump(d_lit, fh)
        # AFTER: regenerate with the flag ON (literal dropped, route+param+pcre).
        os.environ["GENERALIZE_MECH"] = "1"
        try:
            new_rule = finalize(agent.generate(dict(req), dict(ana)), req)
        except Exception as e:
            new_rule = None
            print("REGEN-ERR %s: %s" % (name, e))
        # (Conditional generalisation now lives in the compiler: rule_agent
        # _generate_template_rule falls back to the literal rule when the
        # generalised one loses its pcre, so the regen just mirrors the pipeline.)
        d2 = dict(d)
        if new_rule:
            d2["suricata_rule"] = new_rule
            gen_ok += 1
            if lit_rule and new_rule.strip() != lit_rule.strip():
                changed += 1
        with open(os.path.join(args.gen_out, name), "w") as fh:
            json.dump(d2, fh)

    print("classes=%s  CVEs=%d  gen_ok=%d  rule_changed=%d" %
          (",".join(sorted(want)), n, gen_ok, changed))


if __name__ == "__main__":
    main()
