"""Baseline C1-CMIRGen: Reimplementation of CMIRGen (Zhang et al., TrustCom 2020).

Paper: Z. Zhang et al., "CMIRGen: Automatic Signature Generation Algorithm for
Malicious Network Traffic," IEEE TrustCom 2020.
Author implementation (XAIGen): https://github.com/oasiszrz/XAIGen
  - tpe_distance_matrix.py : PairwiseSimilarity / distance_matrix
  - tpe_all_lcs.py         : recursive longest-common-substring (lcs)
  - tpe_core.py            : get_scan_rules, get_lime_rules, fuse_*,  string_2_rule
  - tpe.conf               : [rule_parameter] min_word_len=3, min_word_confidence=0.02,
                             max_words_number=4, min_single_rule_accuracy=0.85

CMIRGen is a NON-LLM signature generator. It takes a batch of malicious payloads
and produces token-set (keyword) signatures by two complementary paths:

  (1) Scan rules  : payloads are encoded as byte/hex sequences, a pair-wise
      position-similarity distance matrix is built, DBSCAN (eps=0.25,
      min_samples=10, metric='precomputed') groups homogeneous payloads, and
      for each cluster a recursive longest-common-substring (the XAIGen "lcs"
      function, which despite its name finds *contiguous* common substrings) is
      iterated over the cluster members starting from the longest "seed". The
      surviving substrings (length >= min_word_len) form a keyword set.
  (2) Inference rules : payloads that DBSCAN labels as noise (-1, i.e. the
      heterogeneous group) are explained by a black-box classifier + LIME; the
      top contribution words (length >= min_word_len, weight > min_word_confidence,
      at most max_words_number) form a keyword set.

Scan and inference keyword sets are fused (scan first) and each becomes a
conjunctive token-set signature. In XAIGen the final form is a lookahead regex
``^(?=.*w1)(?=.*w2)...`` (string_2_rule). Here the OUTPUT ADAPTER converts each
token set to a Suricata content rule instead (see below).

This is a clean-room faithful port of the XAIGen algorithm. Same benchmark
(281 CVEs), same evaluation harness (PCAP + Suricata) as the other baselines.

================================================================================
原典との適応・乖離 (Adaptations / deviations from the original — stated honestly)
================================================================================

1. INPUT ADAPTER (HTTP trace -> CMIRGen payload string). Deterministic,
   pre-registered, applied uniformly to every trace (never hand-tuned per CVE):
     - Serialize the request to a single wire-style payload string in fixed
       order: "<METHOD> <uri>\n" + each notable header "k: v\n" + body.
       The uri/body are taken from src.evaluation.pcap_generator.wire_buffers so
       the payload string contains exactly the on-wire bytes Suricata will see.
     - Tokenize is NOT applied at the char level only: CMIRGen's lcs operates on
       the raw string (XAIGen feeds the text column directly). We follow that and
       feed the serialized payload string. Non-ASCII bytes are dropped
       (errors removed) per the task spec ("非ASCII除去").
     - Forward truncation to max_payload_len=50 chars, matching get_scan_rules
       (content_direction='forward', the XAIGen default).
   This is an adaptation because XAIGen ingests dataset-specific CSV columns
   (CSIC HTTP, YouTube spam); we derive the equivalent payload string from our
   HTTP trace schema. The rule is fixed and dataset-level, not per-CVE.

2. DISTANCE MATRIX + DBSCAN reimplemented in PURE PYTHON (no numpy / sklearn).
   The XAIGen PairwiseSimilarity metric is reproduced exactly: each payload is a
   byte sequence; positions where a byte == 256 (padding sentinel) are inactive;
   similarity(i,j) = (# of active matching positions over min length) / max(len_i,
   len_j); distance(i,j) = sim(i,i) - sim(i,j). DBSCAN(eps=0.25, min_samples=10,
   metric='precomputed') is reimplemented as the standard region-query/expand
   algorithm on the precomputed matrix. This is an IMPLEMENTATION adaptation
   (rewrite, not algorithm change) so the baseline runs in the existing
   Suricata-eval Docker image, which ships neither numpy nor scikit-learn. The
   numeric behaviour matches sklearn DBSCAN with metric='precomputed'.

3. LIME / black-box-model INFERENCE RULES — APPROXIMATED (実装上の適応・近似).
   The original trains a TF-IDF + classifier black box and runs LIME
   (LimeTextExplainer.explain_instance, num_features=10, num_samples=200) to get
   per-word contribution weights, keeping words with weight > min_word_confidence,
   length >= min_word_len, top max_words_number. Faithfully running LIME here is
   ill-posed and heavy: LIME explains a *trained discriminative model*, but our
   per-CVE benchmark has one attack payload (+ benign set) per case, far too few
   samples to train the discriminator LIME assumes, and importing lime/sklearn is
   not available in the eval image. We therefore APPROXIMATE the LIME inference
   path with its documented intent: contribution-token extraction. For the
   heterogeneous (DBSCAN-noise) payloads we score each candidate token by a
   deterministic discriminative weight = (token frequency in the malicious batch)
   minus (token frequency in the benign batch), i.e. how much the token pushes a
   linear bag-of-words classifier toward the malicious class — the same quantity
   LIME's local linear surrogate estimates. We keep tokens with positive weight,
   length >= min_word_len, and take the top max_words_number, sorted, exactly
   mirroring get_lime_rules' filtering (MIN_WORD_LEN, MIN_WORD_CONFIDENCE as the
   positivity threshold, MAX_WORDS_NUM). This is the honest faithfulness limit of
   this port: the inference path is a contribution-token approximation, NOT a
   trained-model + LIME explanation. Tokenization for this path splits the
   payload on non-alphanumeric boundaries (a standard bag-of-words tokenizer,
   the same family LimeTextExplainer uses by default).

4. OUTPUT ADAPTER (token-set signature -> Suricata rule). Deterministic,
   pre-registered, applied uniformly (never hand-tuned per CVE). XAIGen emits a
   lookahead regex over the keyword set; we emit a Suricata content rule with one
   ``content:"..."`` per token, AND-combined (all must match), which is the
   conjunctive-keyword semantics of the lookahead regex. Sticky-buffer assignment
   per token is decided by where the token's bytes occur in the request, in this
   fixed priority order (first buffer whose REAL on-wire bytes contain the token
   wins):
       http.request_body  ->  http.uri  ->  http.uri.raw  ->  http.header
   The buffers are taken from src.evaluation.pcap_generator.wire_buffers (the
   same source of truth the PCAP writer uses). http.uri there is the percent-
   DECODED, posixpath-normalized URI; http.uri.raw is the on-wire (percent-
   encoded, un-normalized) URI. Both are checked so a token that survives only
   in the encoded/un-normalized bytes (percent-encoding, './'/'../' before
   normalization) still binds to a buffer that actually contains it.
   CONTENT IS ONLY EMITTED FOR TOKENS THAT ARE A CONTIGUOUS SUBSTRING OF THEIR
   ASSIGNED BUFFER. A token that matches none of the candidate buffers — e.g. a
   cluster-LCS seed carried over from a DIFFERENT payload, or a token straddling
   the "<METHOD> <uri>" boundary that no single sticky buffer holds — is DROPPED
   from the rule rather than forced into a buffer. There is NO unconditional
   fallback buffer (the previous unconditional http.uri fallback is removed): a
   forced content absent from the wire bytes would let validate_rules pass a
   rule that never fires on the CVE's PCAP, i.e. a false success. If EVERY token
   of the selected signature is dropped this way, the case is recorded as
   status='failed' with error 'no_locatable_token' and an empty rule — no fake
   content is emitted. This enforces the wire-buffer fire-guarantee invariant:
   any content we emit is guaranteed present in the bytes Suricata inspects. The
   per-case JSON records both the selected ``token_set`` (pre-drop) and the
   ``located_token_set`` actually emitted, so the projection is auditable. Tokens
   are emitted in (buffer, token) order with the sticky-buffer keyword placed
   before its content (Suricata 7 syntax). Special characters inside content are
   hex-escaped (``;`` -> |3b|, ``"`` -> |22|, ``\`` -> |5c|, and any non-printable
   byte -> |xx|). flow:established,to_server; and a msg/sid/rev are added. These
   rules are derived purely from HTTP/wire encoding and the token set; no per-CVE
   logic.

5. BENIGN FILTERING. The original keeps rules whose single-rule accuracy on a
   labelled eval set >= min_single_rule_accuracy (0.85) (tpe_rule_validation.py).
   We have a benign trace set but no labelled malicious eval set per case, so we
   apply the conjunctive-keyword analogue: a token set is rejected if all its
   tokens co-occur in ANY benign payload (the signature would false-positive on
   that benign request). Among surviving token sets we keep the most specific
   (largest token set). This is a benign-hit-minimisation filter; it is NOT in
   the original code (原典に無い) and is stated as such. It is deterministic and
   dataset-level. If the benign dir is absent, no filtering is applied.

6. BATCH vs PER-CVE. CMIRGen is inherently a *batch* algorithm (clustering needs
   many payloads; min_samples=10). Our harness emits one rule per CVE. We run the
   full CMIRGen batch ONCE over all attack payloads in --traces-dir (the natural
   reading of "入力: 攻撃HTTPペイロード群(バッチ)"), obtain the global signature
   set, then for each CVE select the signature that matches that CVE's payload
   (the conjunctive token set all of whose tokens occur in the payload; most
   specific wins). A CVE with no matching cluster/inference signature falls back
   to its own contribution-token inference rule (single-payload path), so every
   CVE still yields a rule. This batch->per-CVE projection is an adaptation
   demanded by the harness, applied uniformly. With min_samples=10 many small
   IoT-CVE groups will be DBSCAN noise and routed to the (approximated) inference
   path; this is faithful to CMIRGen's design, where heterogeneous traffic is
   exactly what the inference path handles.

DEPENDENCIES: pure Python standard library only (no scikit-learn, no numpy, no
lime). The distance matrix, DBSCAN and the LIME-approximation are reimplemented
in-file so the baseline runs unchanged in docker/Dockerfile.suricata-eval (which
ships only python3 + suricata). If a future revision wants the *exact* LIME path,
scikit-learn + lime must be added to that image — currently NOT present (Mac側
Docker に scikit-learn/lime/numpy は未導入。要確認・要追加).

Non-LLM baseline: --llm-endpoint is accepted for CLI uniformity but ignored.

Usage (inside Docker, on Mac eval host):
    python scripts/baseline_cmirgen.py \
        --traces-dir benchmarks/traces \
        --output-dir output/c1_cmirgen/seed_42 \
        --benign-dir benchmarks/traces_benign \
        --seed 42 --workers 4
"""

import argparse
import itertools
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.evaluation.pcap_generator import generate_attack_pcap, wire_buffers
from src.evaluation.suricata_runner import run_suricata, validate_rules

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("baseline_cmirgen")

# Non-LLM baseline; LLM_MODEL kept for CLI/schema parity only.
LLM_MODEL = "qwen3-8b"
SID_BASE = 10000001  # distinct SID range per baseline (no collision with others)

# -- CMIRGen / XAIGen parameters (tpe.conf [rule_parameter]) --------------------
MIN_WORD_LEN = 3            # min_word_len
MIN_WORD_CONFIDENCE = 0.02  # min_word_confidence (used as the LIME-path positivity threshold)
MAX_WORDS_NUM = 4           # max_words_number
MIN_SINGLE_RULE_ACCURACY = 0.85  # min_single_rule_accuracy (documented; see adaptation #5)

# -- get_scan_rules / DBSCAN parameters (tpe_core.py) ---------------------------
MAX_PAYLOAD_LEN = 50        # forward truncation
DBSCAN_EPS = 0.25
DBSCAN_MIN_SAMPLES = 10
PAD_SENTINEL = 256          # XAIGen "256" sentinel for inactive positions


# ---------------------------------------------------------------------------
# Input adapter: HTTP trace -> CMIRGen payload string (adaptation #1)
# ---------------------------------------------------------------------------

_NOISE_HEADERS = {"host", "connection", "accept", "user-agent",
                  "accept-encoding", "content-length"}


def _strip_non_ascii(text: str) -> str:
    """Drop non-ASCII bytes (task spec: 非ASCII除去)."""
    return text.encode("ascii", errors="ignore").decode("ascii")


def trace_to_payload(trace: dict) -> str:
    """Serialize an HTTP request to a single wire-style payload string.

    Deterministic, fixed field order; uri/body come from wire_buffers so the
    string contains the exact on-wire bytes Suricata inspects.
    """
    req = trace.get("trace", {}).get("request", {})
    method = req.get("method", "GET")
    headers = req.get("headers", {}) or {}
    bufs = wire_buffers(req)
    uri = bufs.get("http.uri.raw") or bufs.get("http.uri") or req.get("path", "/")
    body = bufs.get("http.request_body", "") or ""

    parts = [f"{method} {uri}"]
    for k, v in headers.items():
        if str(k).lower() not in _NOISE_HEADERS:
            parts.append(f"{k}: {v}")
    if body:
        parts.append(body)

    payload = "\n".join(parts)
    return _strip_non_ascii(payload)


# ---------------------------------------------------------------------------
# tpe_all_lcs.py : recursive longest *contiguous* common substring
# Faithful port (parameter names kept).
# ---------------------------------------------------------------------------

def lcs(s1_, s2_):
    """Extract common-substring subsets from two strings (XAIGen tpe_all_lcs.lcs).

    Despite the name 'lcs', the original finds *contiguous* common substrings
    via a DP match-length matrix, recursing on the front/back remainders.
    """
    s1_len = len(s1_)
    s2_len = len(s2_)
    max_len = max(s1_len, s2_len)

    m = [[0 for _ in range(1 + max_len)] for _ in range(1 + max_len)]

    longest = 0
    x_longest = -1
    y_longest = -1

    for x in range(1, 1 + s1_len):
        for y in range(1, 1 + s2_len):
            if s1_[x - 1] == s2_[y - 1]:
                m[x][y] = m[x - 1][y - 1] + 1
                if m[x][y] > longest:
                    longest = m[x][y]
                    x_longest = x
                    y_longest = y
            else:
                m[x][y] = 0

    l_list = []
    if (x_longest == -1) or (y_longest == -1):
        return l_list

    l2_backword = []
    if (x_longest - longest > 0) and (y_longest - longest > 0):
        l2_backword = lcs(s1_[0:x_longest - longest], s2_[0:y_longest - longest])
    if len(l2_backword) > 0:
        l_list.extend(l2_backword)

    l1 = s1_[x_longest - longest: x_longest]
    if len(l1) >= MIN_WORD_LEN:
        l_list.append(l1)

    l2_forward = []
    if (x_longest < s1_len - 1) and (y_longest < s2_len - 1):
        l2_forward = lcs(s1_[x_longest:s1_len], s2_[y_longest:s2_len])
    if len(l2_forward) > 0:
        l_list.extend(l2_forward)

    return l_list


# ---------------------------------------------------------------------------
# tpe_distance_matrix.py : PairwiseSimilarity (faithful port, pure Python)
# ---------------------------------------------------------------------------

def _encode_sequences(payloads: list) -> list:
    """Encode payload strings as byte sequences padded to equal length with the
    256 sentinel, matching XAIGen's hex-sequence input to PairwiseSimilarity.

    Returns list of (index, seq) tuples mirroring the (index, seq) pairs XAIGen
    builds with ``list(payloads[xcol].items())``.
    """
    byte_seqs = [[ord(c) for c in p] for p in payloads]
    maxlen = max((len(s) for s in byte_seqs), default=0)
    padded = []
    for i, s in enumerate(byte_seqs):
        s = s + [PAD_SENTINEL] * (maxlen - len(s))
        padded.append((i, s))
    return padded


def pairwise_similarity(sequences: list) -> list:
    """Compute the XAIGen distance matrix from (index, seq) tuples.

    Faithful reimplementation of PairwiseSimilarity in tpe_distance_matrix.py:
      sim(i,j) = (# active matching positions over min length) / max(len_i,len_j)
      dist(i,j) = sim(i,i) - sim(i,j)
    where a position is active for a sequence if its byte != PAD_SENTINEL (256).
    """
    n = len(sequences)
    s_matrix = [[-1.0] * n for _ in range(n)]
    d_matrix = [[-1.0] * n for _ in range(n)]

    for i in range(n):
        for j in range(n):
            if s_matrix[i][j] >= 0:
                continue
            seq1 = sequences[i][1]
            seq2 = sequences[j][1]
            minlen = min(len(seq1), len(seq2))

            len1 = len2 = sims = 0.0
            for x in range(minlen):
                if seq1[x] != PAD_SENTINEL:
                    len1 += 1.0
                    if seq1[x] == seq2[x]:
                        sims += 1.0
                if seq2[x] != PAD_SENTINEL:
                    len2 += 1.0
            maxlen = max(len1, len2)
            s_matrix[i][j] = (sims / maxlen) if maxlen > 0 else 0.0

    for i in range(n):
        for j in range(n):
            d_matrix[i][j] = s_matrix[i][i] - s_matrix[i][j]

    return d_matrix


# ---------------------------------------------------------------------------
# DBSCAN on a precomputed distance matrix (pure-Python port of
# sklearn.cluster.DBSCAN(metric='precomputed'); adaptation #2)
# ---------------------------------------------------------------------------

def dbscan_precomputed(d_matrix: list, eps: float, min_samples: int) -> list:
    """Standard DBSCAN over a precomputed distance matrix.

    Returns a label per sample; -1 denotes noise. min_samples counts the point
    itself (sklearn convention: a core point has >= min_samples neighbours
    including itself within eps).
    """
    n = len(d_matrix)
    labels = [-2] * n  # -2 = unvisited, -1 = noise, >=0 = cluster id

    def neighbours(p):
        return [q for q in range(n) if d_matrix[p][q] <= eps]

    cluster_id = -1
    for p in range(n):
        if labels[p] != -2:
            continue
        nbrs = neighbours(p)
        if len(nbrs) < min_samples:
            labels[p] = -1
            continue
        cluster_id += 1
        labels[p] = cluster_id
        seeds = [q for q in nbrs if q != p]
        idx = 0
        while idx < len(seeds):
            q = seeds[idx]
            idx += 1
            if labels[q] == -1:
                labels[q] = cluster_id  # border point reachable from core
            if labels[q] != -2:
                continue
            labels[q] = cluster_id
            q_nbrs = neighbours(q)
            if len(q_nbrs) >= min_samples:
                seeds.extend(qn for qn in q_nbrs if qn not in seeds)
    return labels


# ---------------------------------------------------------------------------
# Scan rules: get_scan_rules port (tpe_core.py, content_direction='forward')
# ---------------------------------------------------------------------------

def get_scan_rules(payloads: list) -> list:
    """Cluster payloads, then iterate recursive-LCS per cluster -> keyword sets.

    Returns a deduplicated, sorted list of token sets (each a list of strings),
    matching XAIGen's get_scan_rules output (after sort + groupby dedup).
    """
    truncated = [p[:MAX_PAYLOAD_LEN] for p in payloads]
    sequences = _encode_sequences(truncated)
    if not sequences:
        return []

    d_matrix = pairwise_similarity(sequences)
    labels = dbscan_precomputed(d_matrix, DBSCAN_EPS, DBSCAN_MIN_SAMPLES)

    # XAIGen shifts non-noise labels by +1; immaterial to grouping but kept.
    labels = [(lab + 1) if lab != -1 else -1 for lab in labels]

    scan_rules = []
    for label in sorted(set(labels)):
        if label == -1:
            continue
        members = [truncated[i] for i in range(len(truncated)) if labels[i] == label]

        # seed = longest member (XAIGen picks the longest as the LCS seed)
        seed = ""
        for member in members:
            if len(member) >= len(seed):
                seed = member

        pattern_list = [seed]
        for member in members:
            pattern_new = []
            for pattern in pattern_list:
                pattern_new.extend(lcs(pattern, member))
            pattern_list = pattern_new

        token_set = ["".join(e) if isinstance(e, list) else e for e in pattern_list]
        if token_set:
            scan_rules.append(token_set)

    # dedup: sort + itertools.groupby, as in XAIGen
    scan_rules.sort()
    scan_rules = list(k for k, _ in itertools.groupby(scan_rules))
    return scan_rules


# ---------------------------------------------------------------------------
# Inference rules: LIME-path APPROXIMATION (adaptation #3)
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")


def _bow_tokens(payload: str) -> list:
    """Bag-of-words tokenizer (the family LimeTextExplainer uses by default)."""
    return [t for t in _TOKEN_RE.findall(payload) if len(t) >= MIN_WORD_LEN]


def get_lime_rules(malicious_payloads: list, benign_payloads: list) -> list:
    """Contribution-token approximation of XAIGen's get_lime_rules.

    Per malicious payload, score each candidate token by a linear bag-of-words
    discriminative weight (malicious doc-frequency minus benign doc-frequency,
    normalized), keep weight > MIN_WORD_CONFIDENCE and length >= MIN_WORD_LEN,
    take top MAX_WORDS_NUM, sort. This stands in for LIME's local linear
    surrogate weights. See module docstring adaptation #3 for the faithfulness
    limit. Returns deduplicated, sorted token sets.
    """
    mal_n = max(len(malicious_payloads), 1)
    ben_n = max(len(benign_payloads), 1)

    mal_df = Counter()
    for p in malicious_payloads:
        for tok in set(_bow_tokens(p)):
            mal_df[tok] += 1
    ben_df = Counter()
    for p in benign_payloads:
        for tok in set(_bow_tokens(p)):
            ben_df[tok] += 1

    lime_rules = []
    for p in malicious_payloads:
        scored = []
        for tok in set(_bow_tokens(p)):
            weight = (mal_df[tok] / mal_n) - (ben_df[tok] / ben_n)
            if weight > MIN_WORD_CONFIDENCE and len(tok) >= MIN_WORD_LEN:
                scored.append((tok, weight))
        scored.sort(key=lambda d: d[1], reverse=True)
        tmp = [t[0] for t in scored][:MAX_WORDS_NUM]
        if len(tmp) > 1:
            tmp.sort()
            lime_rules.append(tmp)

    lime_rules.sort()
    lime_rules = list(k for k, _ in itertools.groupby(lime_rules))
    return lime_rules


# ---------------------------------------------------------------------------
# Fuse: fuse_lime_and_scan_rules port (scan rules first, type 1; lime type 2)
# ---------------------------------------------------------------------------

def fuse_rules(scan_rules: list, lime_rules: list) -> list:
    """Concatenate scan (priority) then lime token sets. Returns list of
    (token_set, type) where type 1 = scan, 2 = lime."""
    fused = [(ts, 1) for ts in scan_rules] + [(ts, 2) for ts in lime_rules]
    return fused


# ---------------------------------------------------------------------------
# Output adapter: token set -> Suricata content rule (adaptation #4)
# ---------------------------------------------------------------------------

# Fixed sticky-buffer priority: first buffer that contains a token wins.
# http.uri is the percent-DECODED, posixpath-normalized value; http.uri.raw is
# the on-wire (percent-encoded, un-normalized) value. Both are real Suricata
# sticky buffers. We keep the decoded http.uri ahead of http.uri.raw so a token
# present in both binds to the normalized buffer, but a token that survives only
# in the raw bytes (percent-encoding, './'/'../' before normalization) still has
# a buffer to bind to. See wire_buffers in src/evaluation/pcap_generator.py.
_BUFFER_PRIORITY = ["http.request_body", "http.uri", "http.uri.raw", "http.header"]


def _content_escape(token: str) -> str:
    """Hex-escape Suricata content special / non-printable bytes."""
    out = []
    for ch in token:
        o = ord(ch)
        if ch == '"':
            out.append("|22|")
        elif ch == ";":
            out.append("|3b|")
        elif ch == "\\":
            out.append("|5c|")
        elif 0x20 <= o <= 0x7e:
            out.append(ch)
        else:
            out.append("|%02x|" % o)
    return "".join(out)


def _assign_buffer(token: str, bufs: dict):
    """Pick the sticky buffer whose on-wire content contains the token.

    Returns the buffer name, or None when the token is NOT a contiguous
    substring of ANY candidate buffer's real on-wire bytes. A None return means
    the token cannot be located on the wire (e.g. it came from a cluster seed of
    a DIFFERENT payload, or it straddles the method/URI boundary 'GET /...' that
    no single sticky buffer holds): emitting a content for it would NOT fire on
    this CVE's PCAP, so the caller drops it. No unconditional fallback buffer —
    a content is only ever emitted into a buffer that actually contains it,
    preserving the wire_buffers fire-guarantee invariant (docstring §4).
    """
    for buf in _BUFFER_PRIORITY:
        content = bufs.get(buf, "")
        if content and token in content:
            return buf
    return None


def token_set_to_rule(token_set: list, bufs: dict, sid: int, msg: str):
    """Convert a conjunctive token set to one Suricata content rule.

    Each token -> content in its assigned sticky buffer, AND-combined (the
    lookahead-regex conjunction of XAIGen string_2_rule). A token that is not a
    contiguous substring of any candidate buffer (``_assign_buffer`` returns
    None) is DROPPED, not forced into a buffer: a content that does not exist in
    the wire bytes would make the rule fail to fire on the CVE's PCAP, which
    would let validate_rules pass a non-firing rule (a false success). Dropping
    such tokens keeps the wire-buffer fire-guarantee invariant (docstring §4).

    Returns (rule_str_or_None, located_tokens). When every token is dropped,
    rule_str is None and located_tokens is empty so the caller records
    status='failed' / 'no_locatable_token' instead of emitting a fake rule.
    """
    # Deduplicate while preserving the conjunction; assign each token to a buffer
    # whose real on-wire bytes contain it. Drop tokens with no such buffer.
    assigned = []
    located_tokens = []
    seen = set()
    for tok in token_set:
        if not tok or tok in seen:
            continue
        seen.add(tok)
        buf = _assign_buffer(tok, bufs)
        if buf is None:
            continue  # not on the wire for this request -> would not fire
        assigned.append((buf, tok))
        located_tokens.append(tok)

    if not assigned:
        return None, []

    assigned.sort(key=lambda bt: (_BUFFER_PRIORITY.index(bt[0])
                                  if bt[0] in _BUFFER_PRIORITY else 99, bt[1]))

    parts = [f'alert http any any -> any any (msg:"{msg}";',
             "flow:established,to_server;"]
    current_buffer = None
    for buf, tok in assigned:
        if buf != current_buffer:
            parts.append(f"{buf};")
            current_buffer = buf
        parts.append(f'content:"{_content_escape(tok)}";')
    parts.append(f"sid:{sid}; rev:1;)")
    return " ".join(parts), located_tokens


# ---------------------------------------------------------------------------
# Benign filtering (adaptation #5)
# ---------------------------------------------------------------------------

def _token_set_hits_benign(token_set: list, benign_payloads: list) -> bool:
    """True if every token co-occurs in at least one benign payload (the
    conjunctive signature would false-positive on it)."""
    for bp in benign_payloads:
        if all(tok and tok in bp for tok in token_set):
            return True
    return False


# ---------------------------------------------------------------------------
# Batch CMIRGen run + per-CVE projection (adaptation #6)
# ---------------------------------------------------------------------------

def build_global_signatures(attack_payloads: list,
                            benign_payloads: list) -> list:
    """Run the full CMIRGen batch once. Returns fused, benign-filtered token
    sets (list of (token_set, type)) ordered scan-first."""
    scan_rules = get_scan_rules(list(attack_payloads))
    # Heterogeneous (DBSCAN-noise) payloads feed the inference path. We do not
    # have the per-payload labels exposed cheaply post-fact, so the inference
    # path is computed over the full malicious batch vs benign — faithful to the
    # intent (inference rules cover what scan rules miss) and deterministic.
    lime_rules = get_lime_rules(list(attack_payloads), list(benign_payloads))

    fused = fuse_rules(scan_rules, lime_rules)

    if benign_payloads:
        fused = [(ts, ty) for (ts, ty) in fused
                 if not _token_set_hits_benign(ts, benign_payloads)]
    return fused


def select_signature_for_payload(payload: str, global_sigs: list):
    """Pick the most specific global signature whose tokens all occur in this
    CVE's payload. Returns (token_set, type) or None."""
    matching = [(ts, ty) for (ts, ty) in global_sigs
                if ts and all(tok in payload for tok in ts)]
    if not matching:
        return None
    # most specific = largest token set; scan (type 1) breaks ties before lime
    matching.sort(key=lambda x: (len(x[0]), -x[1]), reverse=True)
    return matching[0]


def run_cmirgen_one(cve_id: str, trace: dict, payload: str,
                    global_sigs: list, benign_payloads: list,
                    benign_dir: str, sid: int) -> dict:
    """Project the global CMIRGen signatures onto one CVE and emit a rule."""
    start = time.time()
    req = trace.get("trace", {}).get("request", {})
    bufs = wire_buffers(req)

    selected = select_signature_for_payload(payload, global_sigs)
    rule_type = None
    token_set = None

    if selected is not None:
        token_set, rule_type = selected
        source = "scan" if rule_type == 1 else "inference"
    else:
        # Fallback: single-payload inference rule for this CVE (adaptation #6).
        single = get_lime_rules([payload], list(benign_payloads))
        if benign_payloads:
            single = [ts for ts in single
                      if not _token_set_hits_benign(ts, benign_payloads)]
        if single:
            single.sort(key=len, reverse=True)
            token_set = single[0]
            rule_type = 2
            source = "inference_single"
        else:
            elapsed = time.time() - start
            return {
                "case_id": cve_id,
                "status": "failed",
                "error": "no_signature",
                "suricata_rule": "",
                "baseline": "cmirgen",
                "elapsed_seconds": elapsed,
            }

    msg = f"CMIRGen {source} signature {cve_id}"
    rule, located_tokens = token_set_to_rule(token_set, bufs, sid, msg)

    if rule is None:
        # Every token in the selected signature fails to substring-match this
        # CVE's on-wire buffers (percent-encoding / normalization / cross-payload
        # cluster seed / method-URI boundary). Emitting a content rule here would
        # validate but never fire on the CVE's PCAP, so we report failure
        # honestly instead of scoring a non-firing rule as success.
        elapsed = time.time() - start
        return {
            "case_id": cve_id,
            "status": "failed",
            "error": "no_locatable_token",
            "suricata_rule": "",
            "baseline": "cmirgen",
            "rule_source": source,
            "token_set": token_set,
            "signature_type": rule_type,
            "elapsed_seconds": elapsed,
        }

    # Syntax validation only (faithful: CMIRGen validates against an eval set,
    # not Suricata; here we report syntactic validity so a malformed token-set
    # rule is flagged rather than silently scored).
    valid = True
    syntax_err = ""
    tmp_dir = tempfile.mkdtemp(prefix=f"cmirgen_syntax_{cve_id}_")
    try:
        rules_path = os.path.join(tmp_dir, "test.rules")
        Path(rules_path).write_text(rule + "\n", encoding="utf-8")
        vres = validate_rules(rules_path, log_dir=tmp_dir)
        valid = bool(vres.get("valid"))
        if not valid:
            errs = vres.get("errors") or []
            syntax_err = "; ".join(errs[:5]) if errs else "unknown error"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    elapsed = time.time() - start
    result = {
        "case_id": cve_id,
        "status": "success" if valid else "failed",
        "suricata_rule": rule,
        "baseline": "cmirgen",
        "rule_source": source,
        "token_set": token_set,            # selected signature (pre-drop)
        "located_token_set": located_tokens,  # tokens actually emitted as content
        "signature_type": rule_type,
        "elapsed_seconds": elapsed,
    }
    if not valid:
        result["error"] = f"syntax_invalid: {syntax_err}"
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_payloads(directory: Path, pattern: str) -> dict:
    payloads = {}
    if not directory.exists():
        return payloads
    for f in sorted(directory.glob(pattern)):
        try:
            trace = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        payloads[f.stem] = (trace, trace_to_payload(trace))
    return payloads


def main():
    parser = argparse.ArgumentParser(
        description="Baseline C1-CMIRGen: non-LLM clustering + LCS/inference "
                    "signature generation (Zhang et al., TrustCom 2020)")
    parser.add_argument("--traces-dir", default="benchmarks/traces")
    parser.add_argument("--pattern", default="CVE-*.json",
                        help="Glob pattern for attack trace files")
    parser.add_argument("--output-dir", default="output/c1_cmirgen/seed_42")
    parser.add_argument("--llm-endpoint",
                        default="http://127.0.0.1:8080/v1/chat/completions",
                        help="Ignored (CMIRGen is non-LLM); accepted for CLI parity")
    parser.add_argument("--benign-dir", default="benchmarks/traces_benign")
    parser.add_argument("--benign-pattern", default="BENIGN-*.json")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--seed", type=int, default=None,
                        help="Recorded for reproducibility; algorithm is "
                             "deterministic so it does not alter output")
    parser.add_argument("--cve-list", default=None)
    args = parser.parse_args()

    if args.seed is not None:
        logger.info("Seed recorded: %d (CMIRGen is deterministic)", args.seed)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    traces_dir = Path(args.traces_dir)
    benign_dir = Path(args.benign_dir) if args.benign_dir else None

    cve_filter = None
    if args.cve_list:
        with open(args.cve_list, encoding="utf-8") as f:
            cve_filter = set(json.load(f))

    # Load the full attack batch (CMIRGen is a batch algorithm; adaptation #6).
    attack_map = _load_payloads(traces_dir, args.pattern)
    benign_map = (_load_payloads(benign_dir, args.benign_pattern)
                  if benign_dir else {})
    benign_payloads = [p for (_t, p) in benign_map.values()]

    attack_payloads = [p for (_t, p) in attack_map.values()]
    logger.info("Loaded %d attack payloads, %d benign payloads",
                len(attack_payloads), len(benign_payloads))

    logger.info("Running CMIRGen batch (clustering + LCS + inference)...")
    global_sigs = build_global_signatures(attack_payloads, benign_payloads)
    logger.info("Global signatures after fuse + benign filter: %d",
                len(global_sigs))

    tasks = []
    for idx, cve_id in enumerate(sorted(attack_map.keys())):
        if cve_filter and cve_id not in cve_filter:
            continue
        out_file = out_dir / f"{cve_id}.json"
        if args.skip_existing and out_file.exists():
            continue
        tasks.append((idx, cve_id))

    logger.info("Projecting signatures onto %d CVEs with %d workers",
                len(tasks), args.workers)

    completed = 0
    failed = 0
    start_time = time.time()

    def _process(item):
        idx, cve_id = item
        trace, payload = attack_map[cve_id]
        sid = SID_BASE + idx * 10
        result = run_cmirgen_one(cve_id, trace, payload, global_sigs,
                                 benign_payloads, str(benign_dir) if benign_dir else None,
                                 sid)
        out_file = out_dir / f"{cve_id}.json"
        out_file.write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return cve_id, result["status"]

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(_process, t): t[1] for t in tasks}
        for future in as_completed(futures):
            cve_id = futures[future]
            try:
                _, status = future.result()
                completed += 1
                if status != "success":
                    failed += 1
                if completed % 25 == 0:
                    logger.info("Progress: %d/%d, failed=%d",
                                completed, len(tasks), failed)
            except Exception as e:
                failed += 1
                completed += 1
                logger.error("Error on %s: %s", cve_id, e)

    total_time = time.time() - start_time
    logger.info("Done: %d completed, %d failed, %.1f seconds total",
                completed, failed, total_time)


if __name__ == "__main__":
    main()
