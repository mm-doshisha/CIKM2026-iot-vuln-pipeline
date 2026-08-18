"""Canonical parameter matching logic for evaluation.

Both run_hypothesis_e2e.py and eval_hypothesis.py import from here
to ensure consistent param_match results.
"""
from __future__ import annotations


def normalise_param(param) -> str:
    if param is None:
        return ""
    p = str(param).strip().lower()
    if p in ("none", "n/a", "null", ""):
        return ""
    return p


def param_aliases(param: str) -> set:
    """Return explicit, structure-preserving aliases for a parameter name."""
    p = normalise_param(param)
    if not p:
        return {""}

    aliases = {p}
    for prefix in ("header:", "var:", "params.", "param.", "body.param.",
                   "body.", "query.", "form.", "json.", "xml.",
                   "multipart.", "cookie.", "cookies."):
        if p.startswith(prefix):
            aliases.add(p[len(prefix):])

    expanded = set(aliases)
    for a in list(aliases):
        if a.endswith("[]"):
            expanded.add(a[:-2])
        if "." in a:
            expanded.add(a.split(".")[-1])
    return {a for a in expanded if a}


def match_param(predicted, ground_truth) -> bool:
    """Check if predicted param matches ground truth using explicit aliases."""
    if isinstance(ground_truth, list):
        return any(match_param(predicted, gt) for gt in ground_truth)
    if isinstance(predicted, list):
        return any(match_param(pred, ground_truth) for pred in predicted)

    pred = normalise_param(predicted)
    gt = normalise_param(ground_truth)

    if pred == gt:
        return True

    if not gt:
        return not pred

    if not pred:
        return False

    return bool(param_aliases(pred) & param_aliases(gt))
