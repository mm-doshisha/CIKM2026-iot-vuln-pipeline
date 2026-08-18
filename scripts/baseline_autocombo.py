"""Baseline AC-AutoCombo: Reimplementation of AutoCombo combination rule mining
for signature generation (Du et al., "AutoCombo: Automatic Malware Signature
Generation Through Combination Rule Mining," ACM CIKM 2021, Palo Alto Networks;
corresponding patent US11743286B2).

Official implementation referenced (read-only, via raw.githubusercontent.com,
no clone into the working tree):
    https://github.com/PaloAltoNetworks/autocombo
    - worker/combo_property_sorter.py  (MF-IBF property ranking)
    - worker/combo_generator.py        (greedy combo enumeration + pruning)
    - worker/combo_selection.py        (best-remaining greedy set cover)
    - config/common_config.ini         (default thresholds)
    - utils/misc.py                    (property sets, subset matching)

AutoCombo is NON-LLM. It mines, from a population of malicious samples and a
population of benign samples, property *combinations* that are frequent among
malicious samples but rare among benign ones. A signature is a set S of
properties; a sample is "hit" when S is a subset of the sample's property set
(the official code's `first_in_second` / subset relation over property sets).
No --llm-endpoint is used; the flag is accepted only for harness compatibility.

================================================================================
Faithful reproduction of the AutoCombo pipeline (what we mirror from the code)
================================================================================
1. Property extraction: every sample (malicious or benign) is reduced to a SET
   of string "properties" (official: utils/misc.load_property_sets builds
   `set([str(bhr) for bhr in properties])` per sample). See INPUT ADAPTER below
   for the HTTP->property mapping.
2. property_index_mapping: each distinct property string is assigned an integer
   index (official: generate_property_index_mapping.py /
   property_index_mapping.json). We build the same mapping deterministically by
   first-appearance order over a deterministically sorted file list.
3. MF-IBF property sorting (worker/combo_property_sorter.py):
       ratio_to_hit_more = cnt_in_malicious / total_malicious
       ratio_to_hit_less = cnt_in_benign    / total_benign
       heuristic_score    = ratio_to_hit_more / ratio_to_hit_less
   Properties are sorted in DESCENDING score (frequent-in-malicious /
   rare-in-benign first). Benign count uses a +1 smoothing so a property absent
   from benign is still finite and ranked highest (matches the code guarding a
   zero denominator). Properties never seen in malicious are dropped.
4. Greedy combo generation with pruning (worker/combo_generator.py):
       for new_property in sorted_properties:
           grow combinations from singletons, expanding a candidate only while
           it still hits enough malicious samples; a candidate becomes a valid
           IS_COMBO when  hits_malicious > (min_threshold - 1)  AND
                          hits_benign   <= max_threshold .
       The official code computes IS_COMBO via
           hit_many(integers_to_hit_more, min_threshold - 1)  (malicious side) AND
           hit_many(integers_to_hit_less, max_threshold)      (benign side),
       and hit_many(values, max_cnt) returns True iff cnt > max_cnt. Hence the
       faithful malicious gate is hits_malicious > (min_threshold - 1), i.e.
       hits_malicious >= min_threshold (NOT > min_threshold), and the benign gate
       is hits_benign <= max_threshold. We match this hit_many semantics exactly.
       is_pruned() drops supersets of already-accepted/rejected combos to avoid
       redundant work. Subset hit-counting (`get_hit_hashes` /
       `first_in_second`) uses the subset relation over property sets.
5. Best-remaining greedy set cover (worker/combo_selection.py,
   combo_selection_approach = 'best-remaining'): repeatedly pick the candidate
   combo that maximizes the selection score
       get_selection_score(corrects, incorrects) = corrects / (incorrects + 1e-7)
   computed over still-uncovered malicious samples, until all malicious samples
   are covered or no positive-gain combo remains. This yields one signature per
   selected combo.

================================================================================
INPUT ADAPTER  (pre-registered, deterministic, fully automated; HTTP -> property
set). Applied identically to every attack and benign trace; NOT tuned per-CVE.
================================================================================
From trace.trace.request {method, path, params, headers, body} we emit these
property strings (each string is one AutoCombo "property"; order irrelevant):

  - "method=<METHOD>"                       HTTP method, upper-cased.
  - "seg=<segment>"                         each non-empty '/'-split path segment
                                            (percent-decoded), one property each.
  - "ext=<ext>"                             lower-cased extension of the last
                                            path segment, if it has a '.'.
  - "param=<name>"                          each query-parameter name.
  - "bparam=<name>"                         each body parameter name when the
                                            body is a dict or an x-www-form-
                                            urlencoded string (k=v&...).
  - "ct=<value>"                            Content-Type header value, lower-cased
                                            (full, e.g. application/json), if set.
  - "danger=<name>"                         presence of a dangerous shell/markup
                                            metacharacter anywhere in the URI or
                                            body wire bytes. Fixed alphabet:
                                              semicolon ';'  -> danger=semicolon
                                              ampersand '&'  -> danger=ampersand
                                              pipe '|'       -> danger=pipe
                                              backtick '`'   -> danger=backtick
                                              dollar '$'     -> danger=dollar
                                              lparen '('     -> danger=lparen
                                              rparen ')'     -> danger=rparen
                                              lt '<'         -> danger=lt
                                              gt '>'         -> danger=gt
                                              dotdot '..'    -> danger=dotdot
   (The '&' that merely separates query params is NOT counted; '&' is only
   flagged when it appears inside the URI string after query assembly, matching
   how it would appear on the wire. See _extract_properties.)
  - "tok=<token>"                           distinctive alphanumeric tokens
                                            (length >= 4) extracted from the URI
                                            and body wire bytes, lower-cased,
                                            after percent-decoding. Capped and
                                            stop-listed (see _DANGER / _STOP).
                                            These are the "characteristic tokens /
                                            n-grams" the task asks for; we use
                                            whole alnum tokens (a 1-gram over the
                                            tokenization) for determinism.

The wire bytes used for danger/token scanning are produced by the harness's own
serializer (src.evaluation.pcap_generator.wire_buffers) so the properties match
exactly what Suricata will see on the PCAP. This keeps the input adapter aligned
with the output adapter and the PCAP writer (single source of truth).

================================================================================
OUTPUT ADAPTER  (pre-registered, deterministic, fully automated; mined property
combination -> Suricata rule). Applied identically to every signature.
================================================================================
Each property in the selected combination maps to a Suricata content/keyword,
and the rule ANDs them together (one alert per signature):

  - method=<M>     -> http.method; content:"<M>";
  - seg=<s>        -> http.uri;    content:"/<s>"; nocase;   (segment with slash)
  - ext=<e>        -> http.uri;    content:".<e>"; nocase;
  - param=<n>      -> http.uri;    content:"<n>="; nocase;
  - bparam=<n>     -> http.request_body; content:"<n>="; nocase;
  - ct=<v>         -> http.header; content:"Content-Type|3a 20|<v>"; nocase;
  - danger=<name>  -> content:"<char>"; on the buffer where the char actually
                      occurs on the wire: http.request_body if it is in the body,
                      else http.uri if it survives URI normalization, else
                      http.uri.raw. Characters that normalization erases (e.g.
                      '..', a collapsed '//') are emitted on http.uri.raw, which
                      keeps the un-normalized URI bytes, so the rule can fire;
                      putting them on the normalized http.uri would be unmatchable
                      (libhtp resolves '../' away). Special chars are hex bytes.
  - tok=<t>        -> content:"<t>"; nocase; on http.uri if the token appears in
                      the normalized URI, else http.request_body, else
                      http.uri.raw.

content strings are hex-escaped for Suricata-significant bytes (";" -> |3b|,
'"' -> |22|, backslash -> |5c|) via _suricata_content. A fixed sticky-buffer
ordering (method, uri, uri.raw, header, request_body) is applied so the emitted
rule parses. If a combination contains no property that yields a content match,
the case is reported status="failed" (honest: AutoCombo produced a signature
with no network-observable surface).

================================================================================
HONEST LIMITATIONS / DEVIATIONS FROM THE ORIGINAL (原典との適応・乖離)
================================================================================
- Domain transfer (adaptation, not in the original). AutoCombo's properties are
  static/behavioral malware attributes (PE features, observed behaviors). We
  transfer the *method* (combination rule mining over property sets) to HTTP
  attack traces by defining the HTTP->property adapter above. The mining
  algorithm, MF-IBF scoring, greedy enumeration with pruning, and best-remaining
  set cover are reproduced as-is; only the property vocabulary is new.
- Per-CVE emission over a globally mined model (adaptation). The official tool
  outputs a SET of signatures covering a malicious *population*. Our harness
  scores one CVE at a time, so we (a) mine combos once over the whole attack
  population + benign population, (b) run best-remaining selection to get the
  signature set, then (c) for each CVE emit the SELECTED signature whose
  combination is a subset of that CVE's property set with the highest selection
  score (the signature that "covers" this sample). A CVE not covered by any
  selected signature falls back to the single highest-MF-IBF combo that is a
  subset of it; if none exists it is status="failed". This is the determinate,
  pre-registered tie-break; no per-CVE manual tuning.
- INPUT ASYMMETRY (faithful to the paper, called out honestly). AutoCombo
  *requires benign traffic as input* to compute IBF and to bound benign hits.
  This baseline therefore consumes --benign-dir; with no benign samples the IBF
  denominator degenerates and max_threshold has no effect, so results are not
  comparable to runs that ignore benign data. This asymmetry is inherent to the
  method, not an artifact of our harness.
- Thresholds. Official defaults (min_threshold=30, max_threshold=3,
  max_combo_size=200) assume tens-of-thousands of samples. Our benchmark has a
  few hundred attacks, so absolute support counts are tiny. We expose
  --min-threshold / --max-threshold / --max-combo-size and pre-register scaled
  defaults (min_threshold=1, max_threshold=0, max_combo_size=4) that preserve the
  *inequalities* (combo must hit > min_threshold-1 malicious, i.e. >= 1 malicious
  at the default, and <= max_threshold=0 benign). These are dataset-size
  adaptations of the same hit_many inequalities, fixed before looking at results,
  applied uniformly. Documented as an adaptation, not present in the original
  config.
- 'prestore' / multiprocessing / ablation toggles, the integer-subset bit-vector
  optimization, and the CSV time-window dataset plumbing are NOT reproduced; they
  are performance/orchestration concerns that do not change which combos are
  mined. We use plain Python set subset tests (semantically identical to the
  official subset relation, just unoptimized).
- We could not read utils/misc.py's exact `first_in_second` body (the raw URL
  404'd for util.py and misc.py exposed only loaders), so the subset semantics
  are reconstructed from the README ("a signature matches when all its
  constituent properties appear in a target sample") and the generator analysis.
  This is documented rather than guessed silently.
- Output-adapter buffer routing (adaptation, not in the original; the original
  emits no network rules). When a danger= or tok= property maps to a content
  match, the buffer is chosen by where the byte string actually appears on the
  wire. Suricata's http.uri is percent-decoded and path-normalized by libhtp, so
  a traversal byte string like '..' is erased there (path '/../../etc/passwd'
  normalizes to '/etc/passwd'); we route such normalization-fragile content to
  http.uri.raw, which preserves the raw URI, so the emitted content can match.
  Content that survives normalization stays on http.uri. This keeps the rule
  faithful to the property (the '..' really is on the wire) instead of emitting a
  content on http.uri that could never fire.

Dependencies: Python 3 stdlib only (argparse, json, itertools, urllib, etc.)
plus the project's src.evaluation.{pcap_generator, suricata_runner}. No third-
party packages, no network model. NON-LLM.

Usage (inside Docker; baseline NOT run on this dev machine — fire test on Mac):
    python scripts/baseline_autocombo.py \
        --traces-dir benchmarks/traces \
        --output-dir output/autocombo_baseline/seed_42 \
        --benign-dir benchmarks/traces_benign \
        --seed 42 --workers 4
"""

import argparse
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import combinations
from pathlib import Path
from urllib.parse import unquote, urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.evaluation.pcap_generator import generate_attack_pcap, wire_buffers
from src.evaluation.suricata_runner import run_suricata, validate_rules

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("baseline_autocombo")

# SID base distinct from the other baselines to avoid collision: gridai 6000001,
# moreno 7000001, rulexploit 8000001, direct_suricata 9000001, cmirgen 10000001.
# AutoCombo uses 11000001.
SID_BASE = 11000001

# Pre-registered, dataset-size-adapted thresholds (see DEVIATIONS in docstring).
# Semantics preserved from official common_config.ini + combo_generator.py:
#   IS_COMBO  <=>  hits_malicious > (MIN_THRESHOLD - 1)  AND  hits_benign <= MAX_THRESHOLD
# (official gates malicious on hit_many(..., min_threshold - 1); hit_many is True
#  for cnt > max_cnt, so this is hits_malicious >= MIN_THRESHOLD.)
DEFAULT_MIN_THRESHOLD = 1      # combo must hit >= 1 malicious (> 1-1 = 0)
DEFAULT_MAX_THRESHOLD = 0      # combo must hit at most 0 benign
DEFAULT_MAX_COMBO_SIZE = 4     # cap on combination size (perf bound; was 200)
DEFAULT_MAX_CANDIDATES_PER_PROP = 4000  # safety bound on per-seed greedy frontier

# Dangerous metacharacter alphabet (fixed, pre-registered). name -> literal char.
_DANGER = {
    "semicolon": ";",
    "ampersand": "&",
    "pipe": "|",
    "backtick": "`",
    "dollar": "$",
    "lparen": "(",
    "rparen": ")",
    "lt": "<",
    "gt": ">",
    "dotdot": "..",
}

# Stop tokens for the alnum token property (too generic to be discriminative).
_STOP = {
    "http", "https", "html", "index", "true", "false", "null", "none",
    "text", "json", "form", "data", "type", "name", "user", "host",
    "utf", "www", "urlencoded", "application", "encoding", "version",
}

_MAX_TOKENS = 8       # cap distinct tok= properties per sample (determinism/perf)
_MIN_TOK_LEN = 4


# ---------------------------------------------------------------------------
# Suricata content escaping (shared with the rule template's invariant)
# ---------------------------------------------------------------------------

def _suricata_content(s: str) -> str:
    """Escape a literal string for use inside content:"..." as hex for the
    Suricata-significant bytes. Mirrors the project's rule-template convention."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append("|22|")
        elif ch == ";":
            out.append("|3b|")
        elif ch == "\\":
            out.append("|5c|")
        elif ch == "|":
            out.append("|7c|")
        elif 32 <= o < 127:
            out.append(ch)
        else:
            out.append("|%02x|" % o)
    return "".join(out)


# ---------------------------------------------------------------------------
# INPUT ADAPTER: HTTP request -> set of AutoCombo property strings
# ---------------------------------------------------------------------------

def _decode_body_params(body) -> list:
    """Return body parameter names if the body is a dict or x-www-form-urlencoded."""
    if isinstance(body, dict):
        return [str(k) for k in body.keys()]
    if isinstance(body, str) and "=" in body:
        names = []
        for part in body.split("&"):
            if "=" in part:
                names.append(part.split("=", 1)[0])
        return names
    return []


def _alnum_tokens(text: str) -> list:
    """Deterministic tokenization: maximal [A-Za-z0-9_-] runs, lower-cased."""
    toks = []
    cur = []
    for ch in text:
        if ch.isalnum() or ch in "_-":
            cur.append(ch)
        else:
            if cur:
                toks.append("".join(cur))
                cur = []
    if cur:
        toks.append("".join(cur))
    return [t.lower() for t in toks]


def _extract_properties(req: dict) -> set:
    """Map one HTTP request dict to its AutoCombo property set.

    Deterministic and identical for attack and benign traces. See the module
    docstring INPUT ADAPTER section for the full property vocabulary.
    """
    props = set()

    method = str(req.get("method", "GET")).upper()
    props.add(f"method={method}")

    # Wire buffers from the SAME serializer the PCAP writer uses, so danger/token
    # scanning sees exactly what Suricata will see.
    try:
        bufs = wire_buffers(req)
    except Exception:
        bufs = {}
    uri_wire = bufs.get("http.uri.raw") or bufs.get("http.uri") or req.get("path", "/")
    body_wire = bufs.get("http.request_body", "")
    if not body_wire:
        body = req.get("body")
        if isinstance(body, dict):
            body_wire = urlencode(body)
        elif body:
            body_wire = str(body)

    # Path segments + extension (percent-decoded path part only).
    path = req.get("path", "/")
    path_only = path.split("?", 1)[0]
    decoded_path = unquote(path_only)
    segments = [s for s in decoded_path.split("/") if s]
    for seg in segments:
        props.add(f"seg={seg}")
    if segments and "." in segments[-1]:
        ext = segments[-1].rsplit(".", 1)[-1].lower()
        if ext:
            props.add(f"ext={ext}")

    # Query parameter names.
    for name in (req.get("params") or {}).keys():
        props.add(f"param={name}")
    # Also parse params embedded in the path query string.
    if "?" in path:
        q = path.split("?", 1)[1]
        for part in q.split("&"):
            if "=" in part:
                props.add(f"param={part.split('=', 1)[0]}")

    # Body parameter names.
    for name in _decode_body_params(req.get("body")):
        props.add(f"bparam={name}")

    # Content-Type.
    for k, v in (req.get("headers") or {}).items():
        if str(k).lower() == "content-type":
            props.add(f"ct={str(v).lower()}")

    # Dangerous metacharacters in the wire URI and wire body.
    scan = uri_wire + " " + body_wire
    for name, ch in _DANGER.items():
        if ch in scan:
            props.add(f"danger={name}")

    # Characteristic tokens (decoded), URI first then body, capped.
    seen = set()
    for source in (unquote(uri_wire), unquote(body_wire)):
        for tok in _alnum_tokens(source):
            if len(tok) < _MIN_TOK_LEN or tok in _STOP or tok in seen:
                continue
            if tok.isdigit():
                continue
            seen.add(tok)
            props.add(f"tok={tok}")
            if len(seen) >= _MAX_TOKENS:
                break
        if len(seen) >= _MAX_TOKENS:
            break

    return props


def _props_for_trace(trace: dict) -> set:
    req = trace.get("trace", {}).get("request", {})
    return _extract_properties(req)


# ---------------------------------------------------------------------------
# MF-IBF property sorting (worker/combo_property_sorter.py)
# ---------------------------------------------------------------------------

def _mfibf_sorted_properties(mal_sets: list, ben_sets: list) -> list:
    """Return properties sorted DESCENDING by MF-IBF.

        ratio_more = cnt_in_malicious / total_malicious
        ratio_less = cnt_in_benign    / total_benign   (with +1 smoothing)
        score      = ratio_more / ratio_less

    Properties absent from all malicious samples are dropped (they cannot be part
    of a combo that hits malicious traffic). Tie-break on property string for
    determinism.
    """
    total_mal = max(len(mal_sets), 1)
    total_ben = max(len(ben_sets), 1)

    cnt_more = {}
    for s in mal_sets:
        for p in s:
            cnt_more[p] = cnt_more.get(p, 0) + 1
    cnt_less = {}
    for s in ben_sets:
        for p in s:
            cnt_less[p] = cnt_less.get(p, 0) + 1

    scored = []
    for p, cm in cnt_more.items():
        ratio_more = cm / total_mal
        # +1 smoothing on benign count so absent-in-benign stays finite & top-ranked
        ratio_less = (cnt_less.get(p, 0) + 1) / (total_ben + 1)
        score = ratio_more / ratio_less
        scored.append((score, p))

    scored.sort(key=lambda x: (-x[0], x[1]))
    return [p for _, p in scored]


# ---------------------------------------------------------------------------
# Greedy combo generation with pruning (worker/combo_generator.py)
# ---------------------------------------------------------------------------

def _hits(combo: frozenset, sample_sets: list) -> int:
    """Count samples whose property set is a SUPERSET of combo (subset relation:
    combo is a subset of the sample => the signature matches the sample).
    Mirrors first_in_second / get_hit_hashes over property sets."""
    n = 0
    for s in sample_sets:
        if combo <= s:
            n += 1
    return n


def _hit_indices(combo: frozenset, sample_sets: list) -> set:
    return {i for i, s in enumerate(sample_sets) if combo <= s}


def generate_combos(mal_sets: list, ben_sets: list,
                    min_threshold: int, max_threshold: int,
                    max_combo_size: int,
                    max_candidates: int) -> list:
    """Greedy enumeration of valid combos (IS_COMBO).

    A combo is valid when  hits_malicious > (min_threshold - 1)  AND
                           hits_benign   <= max_threshold .
    The malicious gate mirrors the official hit_many(..., min_threshold - 1)
    semantics (hit_many is True for cnt > max_cnt), i.e. hits_malicious >=
    min_threshold; the benign gate mirrors hit_many(..., max_threshold).

    Following worker/combo_generator.py: build combinations incrementally over
    MF-IBF-sorted properties, expanding a candidate only while it still hits
    enough malicious samples; prune supersets of already-accepted combos
    (is_pruned) so signatures stay minimal and the frontier stays bounded.
    """
    sorted_props = _mfibf_sorted_properties(mal_sets, ben_sets)
    if not sorted_props:
        return []

    accepted = []          # list of (frozenset combo, mal_hits, ben_hits)
    accepted_sets = []     # for is_pruned superset check

    def is_pruned(combo: frozenset) -> bool:
        # Drop combos that are supersets of an already-accepted (minimal) combo.
        for a in accepted_sets:
            if a <= combo:
                return True
        return False

    # Seed frontier with singletons that hit enough malicious samples.
    # Official combo_generator.py gates on hit_many(..., min_threshold - 1), and
    # hit_many returns True for cnt > max_cnt, so the faithful predicate is
    # hits_malicious > (min_threshold - 1)  (i.e. hits_malicious >= min_threshold).
    frontier = []
    for p in sorted_props:
        single = frozenset([p])
        if _hits(single, mal_sets) > (min_threshold - 1):
            frontier.append(single)
    frontier = frontier[:max_candidates]

    size = 1
    while frontier and size <= max_combo_size:
        next_frontier = []
        next_seen = set()
        for combo in frontier:
            if is_pruned(combo):
                continue
            mal_h = _hits(combo, mal_sets)
            if mal_h <= (min_threshold - 1):
                continue  # cannot reach support; pruned (supersets only shrink)
            ben_h = _hits(combo, ben_sets)
            if ben_h <= max_threshold:
                # Valid minimal combo: accept and do NOT expand (keep minimal).
                accepted.append((combo, mal_h, ben_h))
                accepted_sets.append(combo)
                continue
            # Too many benign hits: expand by adding higher-ranked properties.
            if size < max_combo_size:
                for p in sorted_props:
                    if p in combo:
                        continue
                    child = combo | {p}
                    if child in next_seen:
                        continue
                    # Child only added if it still meets malicious support.
                    if _hits(child, mal_sets) > (min_threshold - 1):
                        next_seen.add(child)
                        next_frontier.append(child)
                    if len(next_frontier) >= max_candidates:
                        break
            if len(next_frontier) >= max_candidates:
                break
        frontier = next_frontier[:max_candidates]
        size += 1

    return accepted


# ---------------------------------------------------------------------------
# Best-remaining greedy set cover (worker/combo_selection.py)
# ---------------------------------------------------------------------------

def _selection_score(corrects: int, incorrects: int) -> float:
    """get_selection_score for the 'mfibf' criterion: corrects / (incorrects+eps)."""
    return corrects / (incorrects + 1e-7)


def select_combos(combos: list, mal_sets: list, ben_sets: list) -> list:
    """best-remaining greedy set cover.

    Repeatedly pick the combo maximizing the selection score over still-uncovered
    malicious samples (corrects = newly-covered malicious; incorrects = benign it
    hits). Stop when all malicious covered or no positive-gain combo remains.

    Returns the ordered list of selected (combo, mal_hits, ben_hits) with their
    malicious hit-index sets, in selection order (best first).
    """
    if not combos:
        return []

    # Precompute hit index sets once.
    combo_mal_idx = [(_hit_indices(c, mal_sets), c, mh, bh) for (c, mh, bh) in combos]
    covered = set()
    remaining = list(combo_mal_idx)
    selected = []

    all_mal = set(range(len(mal_sets)))
    while remaining and covered != all_mal:
        best = None
        best_new = None
        # Fully-ordered selection key (all comparable, deterministic):
        #   maximize selection score, then new coverage, then minimal combo size,
        #   then lexicographically smallest sorted combo (final tie-break).
        best_key = None
        for entry in remaining:
            mal_idx, combo, mh, bh = entry
            new_cov = mal_idx - covered
            corrects = len(new_cov)
            if corrects == 0:
                continue
            score = _selection_score(corrects, bh)
            key = (score, corrects, -len(combo), tuple(sorted(combo)))
            # combo-tuple breaks ties; smaller is preferred, so negate by
            # comparing keys where larger-is-better for the first 3 fields and
            # smaller-is-better for the last. Encode the last as a value to
            # minimize by ranking the whole tuple with the combo reversed.
            if best_key is None or _key_better(key, best_key):
                best_key = key
                best = entry
                best_new = new_cov
        if best is None:
            break
        mal_idx, combo, mh, bh = best
        selected.append((combo, mh, bh, mal_idx))
        covered |= best_new
        remaining = [e for e in remaining if e is not best]

    return selected


def _key_better(a: tuple, b: tuple) -> bool:
    """True if selection key `a` is strictly preferred over `b`.

    Key = (score, corrects, -size, sorted_combo_tuple). The first three fields
    are larger-is-better; the final combo tuple is smaller-is-better (stable,
    deterministic tie-break)."""
    if a[:3] != b[:3]:
        return a[:3] > b[:3]
    return a[3] < b[3]


# ---------------------------------------------------------------------------
# OUTPUT ADAPTER: property combination -> Suricata rule
# ---------------------------------------------------------------------------

# Sticky-buffer emission order so the rule parses (buffer set once, then content).
# http.uri.raw carries danger chars that URI normalization destroys (e.g. '..',
# collapsed '//'); it is the un-normalized request URI buffer in Suricata.
_BUFFER_ORDER = ["http.method", "http.uri", "http.uri.raw",
                 "http.header", "http.request_body"]

# Danger characters whose presence is lost by http.uri normalization (libhtp
# percent-decodes the URI and posixpath-normalizes the path, collapsing '..',
# './' and '//'); see src/evaluation/pcap_generator.wire_buffers. These must be
# matched on http.uri.raw, which preserves the raw on-wire URI bytes. '..' is the
# only entry in _DANGER that normalization erases; the '//'-collapse class has no
# _DANGER entry but is covered by the same raw-vs-normalized check below.
_URI_NORM_FRAGILE = {".."}


def _property_to_clause(prop: str, uri_raw_wire: str, uri_norm_wire: str,
                        body_wire: str) -> tuple:
    """Map one property to (buffer, content_token) or None if not observable.

    Returns (buffer_name, raw_content_string) — raw, not yet hex-escaped.

    Buffer routing is by *actual presence on the wire*: http.uri is Suricata's
    percent-decoded, path-normalized URI (libhtp), while http.uri.raw is the
    un-normalized request URI. A content token that normalization would erase
    (e.g. '..', a collapsed '//') is matched on http.uri.raw so the rule can fire;
    one that survives normalization stays on http.uri. body_wire is the raw
    request body (not normalized).
    """
    if prop.startswith("method="):
        return ("http.method", prop[len("method="):])
    if prop.startswith("seg="):
        return ("http.uri", "/" + prop[len("seg="):])
    if prop.startswith("ext="):
        return ("http.uri", "." + prop[len("ext="):])
    if prop.startswith("param="):
        return ("http.uri", prop[len("param="):] + "=")
    if prop.startswith("bparam="):
        return ("http.request_body", prop[len("bparam="):] + "=")
    if prop.startswith("ct="):
        # Content-Type appears in the header buffer; emit "Content-Type: <v>".
        return ("http.header", "Content-Type|3a 20|" + prop[len("ct="):])
    if prop.startswith("danger="):
        name = prop[len("danger="):]
        ch = _DANGER.get(name)
        if ch is None:
            return None
        # Decide buffer by where the char actually appears on the wire.
        if body_wire and ch in body_wire:
            return ("http.request_body", ch)
        # Normalization-fragile chars (e.g. '..') survive only in the raw URI.
        if ch in uri_raw_wire and ch not in uri_norm_wire:
            return ("http.uri.raw", ch)
        if ch in uri_norm_wire:
            return ("http.uri", ch)
        # Present in the raw URI but not (cleanly) in the normalized one: use raw.
        if ch in uri_raw_wire:
            return ("http.uri.raw", ch)
        return ("http.uri", ch)
    if prop.startswith("tok="):
        tok = prop[len("tok="):]
        # token appears in URI or body wire bytes (decoded comparison). Prefer the
        # normalized URI; fall back to the raw URI if normalization dropped it.
        if tok in uri_norm_wire.lower() or tok in unquote(uri_norm_wire).lower():
            return ("http.uri", tok)
        if body_wire and tok in unquote(body_wire).lower():
            return ("http.request_body", tok)
        if tok in uri_raw_wire.lower() or tok in unquote(uri_raw_wire).lower():
            return ("http.uri.raw", tok)
        # default to uri
        return ("http.uri", tok)
    return None


def combo_to_rule(combo: frozenset, trace: dict, sid: int) -> str:
    """Render a mined property combination as a single Suricata rule.

    Returns "" if the combination yields no network-observable content match.
    """
    req = trace.get("trace", {}).get("request", {})
    try:
        bufs = wire_buffers(req)
    except Exception:
        bufs = {}
    raw_path = req.get("path", "/")
    uri_raw_wire = bufs.get("http.uri.raw") or raw_path
    uri_norm_wire = bufs.get("http.uri") or uri_raw_wire
    body_wire = bufs.get("http.request_body", "")

    # Group content tokens by buffer.
    by_buffer = {}
    is_content = {}  # buffer -> bool whether the token is already hex-encoded
    for prop in sorted(combo):  # deterministic order before regrouping
        clause = _property_to_clause(prop, uri_raw_wire, uri_norm_wire, body_wire)
        if clause is None:
            continue
        buf, raw = clause
        by_buffer.setdefault(buf, []).append((prop, raw))

    if not by_buffer:
        return ""

    parts = ['alert http any any -> any any (',
             'msg:"AUTOCOMBO mined signature"; flow:established,to_server;']

    emitted_any = False
    for buf in _BUFFER_ORDER:
        if buf not in by_buffer:
            continue
        parts.append(f"{buf};")
        for prop, raw in by_buffer[buf]:
            if prop.startswith("ct="):
                # already contains a hex token (|3a 20|); escape the rest.
                head, _, tail = raw.partition("|3a 20|")
                content = _suricata_content(head) + "|3a 20|" + _suricata_content(tail)
            else:
                content = _suricata_content(raw)
            nocase = "" if buf == "http.method" else " nocase;"
            parts.append(f'content:"{content}";{nocase}')
            emitted_any = True

    if not emitted_any:
        return ""

    parts.append(f"sid:{sid}; rev:1;)")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Validation helpers (mirrors gridai/moreno)
# ---------------------------------------------------------------------------

def _validate_syntax(rule_text: str) -> tuple:
    tmp_dir = tempfile.mkdtemp(prefix="autocombo_syntax_")
    try:
        rules_path = os.path.join(tmp_dir, "test.rules")
        Path(rules_path).write_text(rule_text + "\n", encoding="utf-8")
        result = validate_rules(rules_path, log_dir=tmp_dir)
        if result["valid"]:
            return True, ""
        err = "; ".join(result["errors"][:5]) if result["errors"] else "unknown"
        return False, err
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _validate_detection(rule_text: str, trace: dict) -> tuple:
    tmp_dir = tempfile.mkdtemp(prefix="autocombo_detect_")
    try:
        http_req = trace.get("trace", {}).get("request", {})
        pcap_path = os.path.join(tmp_dir, "attack.pcap")
        rules_path = os.path.join(tmp_dir, "detect.rules")
        generate_attack_pcap(http_req, pcap_path)
        Path(rules_path).write_text(rule_text + "\n", encoding="utf-8")
        log_dir = os.path.join(tmp_dir, "suricata_detect")
        result = run_suricata(pcap_path, rules_path, log_dir=log_dir)
        if result.get("error"):
            return False, f"suricata_error: {result['error']}"
        return bool(result["triggered"]), ""
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Per-CVE emission over the globally mined model
# ---------------------------------------------------------------------------

def build_model(attack_traces: dict, benign_sets: list,
                min_threshold: int, max_threshold: int,
                max_combo_size: int, max_candidates: int) -> dict:
    """Mine the AutoCombo model once over the whole attack + benign population.

    attack_traces: {cve_id: trace_dict}
    Returns a dict with the per-CVE property set, the MF-IBF property order, the
    selected signatures (best-remaining), and the full accepted-combo list (for
    fallback). All derived from the population, not from any single CVE.
    """
    cve_ids = sorted(attack_traces.keys())
    mal_sets = [_props_for_trace(attack_traces[c]) for c in cve_ids]

    logger.info("Mining combos: %d malicious, %d benign samples",
                len(mal_sets), len(benign_sets))
    combos = generate_combos(mal_sets, benign_sets,
                             min_threshold, max_threshold,
                             max_combo_size, max_candidates)
    logger.info("Generated %d valid combos", len(combos))

    selected = select_combos(combos, mal_sets, benign_sets)
    logger.info("Selected %d signatures (best-remaining set cover)", len(selected))

    # MF-IBF score per accepted combo, for the fallback ranking.
    sorted_props = _mfibf_sorted_properties(mal_sets, benign_sets)
    rank = {p: i for i, p in enumerate(sorted_props)}

    def combo_rank_key(combo):
        # best = combo whose worst (largest-index) property is highest-ranked,
        # then fewest properties (most general / minimal).
        idxs = sorted(rank.get(p, len(rank)) for p in combo)
        return (idxs, len(combo))

    return {
        "cve_ids": cve_ids,
        "mal_sets": mal_sets,
        "cve_index": {c: i for i, c in enumerate(cve_ids)},
        "selected": selected,           # [(combo, mh, bh, mal_idx_set), ...]
        "all_combos": combos,           # [(combo, mh, bh), ...]
        "combo_rank_key": combo_rank_key,
    }


def signature_for_cve(cve_id: str, model: dict):
    """Pick the signature this CVE is covered by.

    Priority (pre-registered, deterministic):
      1. Among SELECTED signatures whose combo is a subset of this CVE's property
         set, take the one with the highest selection score (corrects/(incorr+eps)).
         Selection order already reflects that, so take the earliest selected.
      2. Else, among ALL accepted combos that are a subset of this CVE, take the
         highest MF-IBF-ranked (most discriminative, then most minimal) combo.
      3. Else None (CVE not covered by any mined combo).
    """
    idx = model["cve_index"][cve_id]
    my_set = model["mal_sets"][idx]

    for combo, mh, bh, mal_idx in model["selected"]:
        if combo <= my_set:
            return combo, mh, bh, "selected"

    subset_combos = [(c, mh, bh) for (c, mh, bh) in model["all_combos"]
                     if c <= my_set]
    if subset_combos:
        best = min(subset_combos, key=lambda x: model["combo_rank_key"](x[0]))
        return best[0], best[1], best[2], "fallback_mfibf"

    return None


def run_autocombo_one(cve_id: str, trace: dict, model: dict,
                      sid: int) -> dict:
    start = time.time()
    sig = signature_for_cve(cve_id, model)

    if sig is None:
        elapsed = time.time() - start
        return {
            "case_id": cve_id, "status": "failed",
            "error": "no_combo_covers_sample",
            "suricata_rule": "", "baseline": "autocombo",
            "elapsed_seconds": elapsed,
        }

    combo, mal_hits, ben_hits, source = sig
    rule = combo_to_rule(combo, trace, sid)

    if not rule:
        elapsed = time.time() - start
        return {
            "case_id": cve_id, "status": "failed",
            "error": "combo_has_no_observable_content",
            "suricata_rule": "", "baseline": "autocombo",
            "combo": sorted(combo), "combo_source": source,
            "combo_malicious_hits": mal_hits, "combo_benign_hits": ben_hits,
            "elapsed_seconds": elapsed,
        }

    syntax_ok, syntax_err = _validate_syntax(rule)
    detect_ok, _ = (False, "")
    if syntax_ok:
        detect_ok, _ = _validate_detection(rule, trace)

    status = "success" if (syntax_ok and detect_ok) else "failed"
    elapsed = time.time() - start
    logger.info("[%s] %s (%s combo, size=%d, mal=%d ben=%d, %.1fs)",
                cve_id, status, source, len(combo), mal_hits, ben_hits, elapsed)

    result = {
        "case_id": cve_id,
        "status": status,
        "suricata_rule": rule,
        "baseline": "autocombo",
        "combo": sorted(combo),
        "combo_source": source,
        "combo_malicious_hits": mal_hits,
        "combo_benign_hits": ben_hits,
        "syntax_valid": syntax_ok,
        "detection_triggered": detect_ok,
        "elapsed_seconds": elapsed,
    }
    if not syntax_ok:
        result["error"] = f"syntax_invalid: {syntax_err[:200]}"
    elif not detect_ok:
        result["error"] = "rule_did_not_trigger"
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Baseline AC-AutoCombo: combination rule mining (non-LLM)")
    parser.add_argument("--traces-dir", default="benchmarks/traces")
    parser.add_argument("--pattern", default="CVE-*.json",
                        help="Glob pattern for attack trace files")
    parser.add_argument("--output-dir", default="output/autocombo_baseline/seed_42")
    parser.add_argument("--llm-endpoint",
                        default="http://127.0.0.1:8080/v1/chat/completions",
                        help="Accepted for harness compatibility; AutoCombo is "
                             "NON-LLM and never calls this endpoint.")
    parser.add_argument("--benign-dir", default="benchmarks/traces_benign",
                        help="REQUIRED by AutoCombo (input asymmetry): benign "
                             "property sets bound benign hits and drive IBF.")
    parser.add_argument("--benign-pattern", default="BENIGN-*.json")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--seed", type=int, default=None,
                        help="Recorded for reproducibility; mining is "
                             "deterministic so the seed does not alter output.")
    parser.add_argument("--cve-list", default=None)
    parser.add_argument("--min-threshold", type=int, default=DEFAULT_MIN_THRESHOLD,
                        help="IS_COMBO requires hits_malicious > this.")
    parser.add_argument("--max-threshold", type=int, default=DEFAULT_MAX_THRESHOLD,
                        help="IS_COMBO requires hits_benign <= this.")
    parser.add_argument("--max-combo-size", type=int, default=DEFAULT_MAX_COMBO_SIZE)
    parser.add_argument("--max-candidates", type=int,
                        default=DEFAULT_MAX_CANDIDATES_PER_PROP,
                        help="Safety bound on the greedy frontier width.")
    args = parser.parse_args()

    if args.seed is not None:
        logger.info("Seed recorded: %d (mining is deterministic)", args.seed)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    traces_dir = Path(args.traces_dir)

    cve_filter = None
    if args.cve_list:
        with open(args.cve_list, encoding="utf-8") as f:
            cve_filter = set(json.load(f))

    # --- Load the FULL attack population (mining needs the whole set) ---
    attack_traces = {}
    for trace_file in sorted(traces_dir.glob(args.pattern)):
        cve_id = trace_file.stem
        try:
            attack_traces[cve_id] = json.loads(
                trace_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Skip unreadable attack trace %s: %s", cve_id, e)

    # --- Load benign population (input asymmetry: AutoCombo requires it) ---
    benign_sets = []
    benign_dir = Path(args.benign_dir)
    if benign_dir.exists():
        for bf in sorted(benign_dir.glob(args.benign_pattern)):
            try:
                bt = json.loads(bf.read_text(encoding="utf-8"))
                benign_sets.append(_props_for_trace(bt))
            except (json.JSONDecodeError, OSError):
                continue
    if not benign_sets:
        logger.warning("No benign samples found in %s; IBF degenerates and "
                       "max_threshold has no effect (see docstring asymmetry).",
                       args.benign_dir)

    # --- Mine the model ONCE over the population ---
    model = build_model(attack_traces, benign_sets,
                        min_threshold=args.min_threshold,
                        max_threshold=args.max_threshold,
                        max_combo_size=args.max_combo_size,
                        max_candidates=args.max_candidates)

    # --- Tasks: which CVEs to emit for ---
    tasks = []
    for cve_id in model["cve_ids"]:
        if cve_filter and cve_id not in cve_filter:
            continue
        out_file = out_dir / f"{cve_id}.json"
        if args.skip_existing and out_file.exists():
            continue
        tasks.append(cve_id)

    logger.info("Emitting AutoCombo rules for %d CVEs with %d workers",
                len(tasks), args.workers)

    completed = 0
    failed = 0
    start_time = time.time()

    def _process(item):
        idx, cve_id = item
        trace = attack_traces[cve_id]
        sid = SID_BASE + idx * 5
        result = run_autocombo_one(cve_id, trace, model, sid=sid)
        out_file = out_dir / f"{cve_id}.json"
        out_file.write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return cve_id, result["status"]

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(_process, (i, c)): c
                   for i, c in enumerate(tasks)}
        for future in as_completed(futures):
            cve_id = futures[future]
            try:
                _, status = future.result()
                completed += 1
                if status != "success":
                    failed += 1
                if completed % 10 == 0:
                    elapsed = time.time() - start_time
                    rate = completed / elapsed * 3600 if elapsed > 0 else 0
                    logger.info("Progress: %d/%d (%.0f CVE/hr), failed=%d",
                                completed, len(tasks), rate, failed)
            except Exception as e:
                failed += 1
                completed += 1
                logger.error("Error on %s: %s", cve_id, e)

    total_time = time.time() - start_time
    logger.info("Done: %d completed, %d failed, %.1f seconds total",
                completed, failed, total_time)


if __name__ == "__main__":
    main()
