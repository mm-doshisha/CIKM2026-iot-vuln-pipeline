"""Extract verifier benign values from committed benign trace datasets.

Selection methodology:
  k-medoids clustering on 12-dimensional character-feature vectors.
  Path category gets MAX_VALUES_PATH (50) representatives; others get
  MAX_VALUES_DEFAULT (20).

Sources (STRICT dev/eval separation — no train/test leakage):
  - DEV pool: benchmarks/traces_benign_full (full UNSW-IoTraffic corpus),
    with every request whose signature appears in the evaluation set
    (benchmarks/traces_benign) HELD OUT. The evaluation traces themselves
    are never used to build counterexamples.
  - IoT protocol synthetic values (UPnP, IPP/eSCL, OMA LwM2M specs) — public.
  - CICIoT2023 benign HTTP body values — independent dataset.

Build the dev pool first (the evaluation set is held out automatically):
  python3 scripts/convert_unsw_benign_full.py <protocols.zip>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
FULL_DIR = ROOT / "benchmarks" / "traces_benign_full"
SAMPLE_DIR = ROOT / "benchmarks" / "traces_benign"
CICIOT_BODY_PATH = ROOT / "data" / "ciciot2023_benign_bodies.json"
OUT_PATH = ROOT / "data" / "benign_values.json"
MAX_VALUES_PATH = 50
MAX_VALUES_DEFAULT = 20
MAX_PER_DEVICE = 4
SEED = 42


def _trace_files() -> tuple[list[Path], list[Path], list[Path]]:
    """Return (full_files, sample_files, cve_paired_files).

    full has path+headers only (11K traces, no params/body).
    sample has all fields (281 traces with params).
    cve_paired has benign requests to the same endpoints as attack CVEs.
    Both are used: full for path/header diversity, sample for query/body.
    CVE-paired provides independent path counterexamples.
    """
    full_files = sorted(FULL_DIR.glob("BENIGN-UNSW-*.json")) if FULL_DIR.exists() else []
    sample_files = sorted(SAMPLE_DIR.glob("BENIGN-UNSW-*.json"))
    cve_paired_files = sorted(SAMPLE_DIR.glob("BENIGN-CVE-*.json"))
    if not full_files and not sample_files:
        raise FileNotFoundError(
            "No BENIGN-UNSW traces found under benchmarks/traces_benign_full "
            "or benchmarks/traces_benign")
    return full_files, sample_files, cve_paired_files


def _request_signature(trace: dict) -> tuple:
    """Identity of a trace at the request level: (method, path, sorted params)."""
    r = (trace.get("trace") or {}).get("request") or {}
    params = r.get("params") or {}
    if isinstance(params, dict):
        pj = ";".join(sorted(f"{k}={v}" for k, v in params.items()))
    else:
        pj = str(params)
    return (r.get("method"), r.get("path"), pj)


def _eval_signatures() -> set:
    """Request signatures of the held-out EVALUATION set (benchmarks/traces_benign).

    These (BENIGN-UNSW-* = u-series eval, BENIGN-CVE-* = p-series eval) are the
    traces FPR/TNR is measured on. They are excluded from the dev pool so that
    no counterexample is derived from an evaluation request — preventing
    train/test leakage.
    """
    sigs = set()
    for f in sorted(SAMPLE_DIR.glob("*.json")):
        try:
            sigs.add(_request_signature(json.loads(f.read_text(encoding="utf-8"))))
        except Exception:
            pass
    return sigs


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _add(candidates: dict[str, list[tuple[str, str]]],
         kind: str, value, device: str) -> None:
    text = _as_text(value)
    if len(text) > 500:
        text = text[:500]
    candidates.setdefault(kind, []).append((text, device or "unknown"))


def _dedupe(items: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen = set()
    out = []
    for value, device in items:
        if value in seen:
            continue
        seen.add(value)
        out.append((value, device))
    return out


# --- k-medoids clustering (no sklearn dependency) ---

def _feature_vector(value: str) -> list[float]:
    """12-dimensional character-feature vector for clustering."""
    n = len(value)
    n_alpha = sum(1 for c in value if c.isalpha())
    n_digit = sum(1 for c in value if c.isdigit())
    n_special = n - n_alpha - n_digit
    n_slashes = value.count("/")
    # Prefix hash: first 20 chars as a normalized value to separate
    # structurally similar strings (e.g., /obfuscated-otav3-9/xxx vs /api/xxx)
    prefix = value[:20]
    # Deterministic hash (Python's built-in hash() is salted per-process via
    # PYTHONHASHSEED, which made benign_values.json non-reproducible across runs).
    prefix_hash = (int(hashlib.sha1(prefix.encode("utf-8")).hexdigest(), 16) % 1000) / 1000.0
    return [
        min(n / 500.0, 1.0),           # normalized length
        n_alpha / max(n, 1),           # alpha ratio
        n_digit / max(n, 1),           # digit ratio
        n_special / max(n, 1),         # special char ratio
        1.0 if "/" in value else 0.0,
        1.0 if "." in value else 0.0,
        1.0 if ":" in value else 0.0,
        1.0 if "=" in value else 0.0,
        1.0 if ";" in value else 0.0,
        1.0 if "<" in value else 0.0,
        min(n_slashes / 5.0, 1.0),     # path depth proxy
        prefix_hash,                    # structural prefix class
    ]


def _manhattan(a: list[float], b: list[float]) -> float:
    return sum(abs(x - y) for x, y in zip(a, b))


def _kmedoids(values: list[str], k: int, max_iter: int = 30) -> list[int]:
    """Simple k-medoids (PAM) returning indices of medoids.

    Uses precomputed distance matrix for performance.
    For pools > 300, pre-samples to keep runtime reasonable.
    """
    n = len(values)
    if n <= k:
        return list(range(n))

    # Pre-sample large pools
    rng = random.Random(SEED)
    if n > 300:
        sample_idx = rng.sample(range(n), 300)
        values = [values[i] for i in sample_idx]
        n = 300
    else:
        sample_idx = None

    features = [_feature_vector(v) for v in values]

    # Precompute distance matrix
    dist = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            d = _manhattan(features[i], features[j])
            dist[i][j] = d
            dist[j][i] = d

    medoid_indices = rng.sample(range(n), k)

    for _ in range(max_iter):
        # Assign each point to nearest medoid
        assignments = [0] * n
        for i in range(n):
            best_m = medoid_indices[0]
            best_d = dist[i][best_m]
            for m in medoid_indices[1:]:
                d = dist[i][m]
                if d < best_d:
                    best_d = d
                    best_m = m
            assignments[i] = best_m

        # Update medoids
        new_medoids = []
        changed = False
        for m in medoid_indices:
            members = [i for i in range(n) if assignments[i] == m]
            if not members:
                new_medoids.append(m)
                continue
            best = m
            best_cost = sum(dist[m][j] for j in members)
            for candidate in members:
                cost = sum(dist[candidate][j] for j in members)
                if cost < best_cost:
                    best_cost = cost
                    best = candidate
            if best != m:
                changed = True
            new_medoids.append(best)

        medoid_indices = new_medoids
        if not changed:
            break

    # Map back to original indices if we pre-sampled
    if sample_idx is not None:
        return [sample_idx[m] for m in medoid_indices]
    return medoid_indices


def _prefix_dedupe(values: list[str], max_per_prefix: int = 3) -> list[str]:
    """Limit values sharing the same structural prefix (first path segment)."""
    prefix_counts: dict[str, int] = {}
    result = []
    for v in values:
        non_empty = [p for p in v.split("/") if p]
        prefix = non_empty[0] if non_empty else v[:10]
        prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1
        if prefix_counts[prefix] <= max_per_prefix:
            result.append(v)
    return result


def _pick_clustered(items: list[tuple[str, str]], max_values: int = MAX_VALUES_DEFAULT) -> list[str]:
    """Select representative values using k-medoids clustering."""
    unique = _dedupe(items)
    values_only = [v for v, _d in unique]

    # Always include empty string
    selected = [""]
    pool = [v for v in values_only if v != ""]

    # Limit structural duplicates (e.g., /obfuscated-otav3-9/xxx paths)
    pool = _prefix_dedupe(pool, max_per_prefix=3)

    if not pool or max_values <= 1:
        return selected[:max_values]

    k = min(max_values - 1, len(pool))  # -1 for mandatory empty
    if k < 1:
        return selected[:max_values]
    medoid_indices = _kmedoids(pool, k)
    for idx in medoid_indices:
        selected.append(pool[idx])

    return selected[:max_values]


# --- Legacy method (for comparison) ---

def _pick_diverse(items: list[tuple[str, str]], max_values: int = MAX_VALUES_DEFAULT) -> list[str]:
    """Old ternary-search selection (kept for --method=diversity)."""
    unique = _dedupe(items)
    by_value = {value: device for value, device in unique}
    selected = [""]
    device_counts = Counter()
    if "" in by_value:
        device_counts[by_value[""]] += 1

    pool = [(value, device) for value, device in unique if value != ""]
    pool.sort(key=lambda item: (len(item[0]), item[0]))
    if not pool:
        return selected

    order = []
    left, right = 0, len(pool) - 1
    while left <= right:
        mid = (left + right) // 2
        for idx in (left, mid, right):
            if 0 <= idx < len(pool) and idx not in order:
                order.append(idx)
        left += 1
        right -= 1

    for idx in order:
        value, device = pool[idx]
        if value in selected:
            continue
        if device_counts[device] >= MAX_PER_DEVICE:
            continue
        selected.append(value)
        device_counts[device] += 1
        if len(selected) >= max_values:
            break

    if len(selected) < max_values:
        for value, device in pool:
            if value in selected:
                continue
            selected.append(value)
            if len(selected) >= max_values:
                break

    return selected[:max_values]


def _load_ciciot_bodies() -> list[tuple[str, str]]:
    """Load CICIoT2023 benign HTTP body values if available."""
    if not CICIOT_BODY_PATH.exists():
        return []
    data = json.loads(CICIOT_BODY_PATH.read_text(encoding="utf-8"))
    return [(body, "CICIoT2023") for body in data if body]


def _print_summary(summary: dict[str, dict[str, int | str]]) -> None:
    print("param_type     | unique_values | selected | source")
    print("-" * 60)
    for kind in ("path", "query_value", "header_value", "body", "generic"):
        row = summary[kind]
        print(
            f"{kind:<14} | {str(row['unique_values']):>13} | "
            f"{row['selected']:>8} | {row.get('source', 'UNSW')}")
    for kind, row in summary.items():
        unique_values = row["unique_values"]
        if isinstance(unique_values, int) and unique_values < 5:
            print(
                f"WARNING: param_type '{kind}' has only {unique_values} "
                "unique values (< 5). Consider adding more data sources.")


def _summary(items: list[tuple[str, str]]) -> tuple[int, int]:
    values = {value for value, _device in items}
    devices = {device for _value, device in items if device != "mandatory_empty"}
    return len(values), len(devices)


def extract(method: str = "cluster") -> tuple[dict[str, list[str]], dict[str, dict[str, int | str]]]:
    pick_fn = _pick_clustered if method == "cluster" else _pick_diverse

    candidates: dict[str, list[tuple[str, str]]] = {
        "path": [],
        "query_value": [],
        "header_value": [],
        "body": [],
        "generic": [],
    }

    full_files, _eval_unsw, _eval_cve = _trace_files()
    eval_sigs = _eval_signatures()  # held-out evaluation set — never extracted from

    def _process_trace(path: Path, source: str = "UNSW") -> None:
        trace = json.loads(path.read_text(encoding="utf-8"))
        request = trace.get("trace", {}).get("request", {})
        device = trace.get("original_device") or trace.get("product") or "unknown"

        req_path = _as_text(request.get("path") or "/")
        parsed = urlparse(req_path)
        _add(candidates, "path", parsed.path or "/", f"{device}_{source}")
        for values in parse_qs(parsed.query, keep_blank_values=True).values():
            if values:
                _add(candidates, "query_value", values[0], f"{device}_{source}")

        params = request.get("params") or {}
        if isinstance(params, dict):
            for value in params.values():
                _add(candidates, "query_value", value, f"{device}_{source}")

        headers = request.get("headers") or {}
        if isinstance(headers, dict):
            for value in headers.values():
                _add(candidates, "header_value", value, f"{device}_{source}")

        body = request.get("body")
        if body not in (None, ""):
            _add(candidates, "body", body, f"{device}_{source}")

    # DEV split: full UNSW corpus MINUS every request whose signature appears
    # in the held-out evaluation set. This makes the dev pool signature-disjoint
    # from the evaluation traces (instance-level separation; no train/test leak).
    dev_files = []
    skipped = 0
    for path in full_files:
        try:
            tr = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if _request_signature(tr) in eval_sigs:
            skipped += 1
            continue
        dev_files.append(path)

    if not dev_files:
        raise FileNotFoundError(
            "Dev pool is empty — the full UNSW corpus has not been built.\n"
            "Build it first (the evaluation set is held out automatically):\n"
            "    python3 scripts/convert_unsw_benign_full.py <protocols.zip>\n"
            "This writes benchmarks/traces_benign_full/. The evaluation traces "
            "(benchmarks/traces_benign) are NOT used as a counterexample source.")

    print(f"[dev-split] full={len(full_files)} "
          f"eval-signatures-held-out={skipped} dev={len(dev_files)}")

    # Process the dev pool only. The evaluation sets
    # (benchmarks/traces_benign/{BENIGN-UNSW,BENIGN-CVE}-*.json) are intentionally
    # NOT processed: they are what FPR/TNR is measured on.
    for path in dev_files:
        _process_trace(path, source="UNSW-dev")

    # Add CICIoT2023 body data if available
    ciciot_bodies = _load_ciciot_bodies()
    if ciciot_bodies:
        candidates["body"].extend(ciciot_bodies)
        body_source = "UNSW+CICIoT2023"
    else:
        body_source = "UNSW (insufficient)"

    # Mandatory empty in all categories
    for kind in candidates:
        candidates[kind].append(("", "mandatory_empty"))

    # Generic = union of all categories + synthetic baselines
    all_dataset_values = (
        candidates["path"]
        + candidates["query_value"]
        + candidates["header_value"]
        + candidates["body"]
    )
    candidates["generic"] = all_dataset_values + [
        ("safe_value", "synthetic_baseline"),
        ("hello", "synthetic_baseline"),
        ("test", "synthetic_baseline"),
        ("normal", "synthetic_baseline"),
    ]

    # Use larger MAX_VALUES for path (50) to accommodate CVE-paired paths
    selected = {}
    for kind, values in candidates.items():
        mv = MAX_VALUES_PATH if kind == "path" else MAX_VALUES_DEFAULT
        selected[kind] = pick_fn(values, max_values=mv)

    # --- Synthetic adversarial corner-cases ---
    # These are not derived from traffic data. They are manually curated to catch
    # overly broad detection conditions (e.g., len(value) > 10, "/" in value).
    # IoT protocol paths are from public specs: UPnP Device Architecture 2.0,
    # IETF RFC 8011 (IPP), Mopria eSCL, OMA LwM2M, TR-069.
    _SYNTHETIC = {
        "query_value": ["1", "0", "100", "true", "false", "on", "off", "admin",
                        "default", "en", "asc", "json", "test", "GET", "ok"],
        "header_value": ["gzip", "text/html", "close", "keep-alive", "0", "100",
                         "en-US", "application/json", "no-cache", "*/*",
                         "Bearer AAAAAAAAAA", "chunked", "4096",
                         "DLNADOC/1.50", "UPnP/1.0 DLNADOC/1.50"],
        "path": ["/api/v1/status", "/login", "/admin", "/favicon.ico",
                 "/cgi-bin/index.cgi", "/images/logo.png", "/index.html",
                 "/api/device", "/config", "/health", "/status.json",
                 "/v2/keys", "/metrics",
                 # UPnP Device Architecture 2.0 (Section 2.1, 2.5)
                 "/rootDesc.xml", "/setup.xml", "/deviceinfo.xml",
                 "/firmwareupdate.xml", "/upnp/control/basicevent1",
                 # IPP/eSCL (RFC 8011, Mopria eSCL spec)
                 "/ipp/printer", "/eSCL/ScanJobs", "/eSCL/ScannerStatus",
                 # OTA/firmware update (OMA LwM2M §5.1.1, TR-069 §A.3.2.3)
                 "/firmware/v3/latest.bin", "/ota/check",
                 "/firmware/update", "/update/check"],
        "body": ["id=1", "action=view", "page=home", "q=test", "limit=10",
                 "format=json", "enabled=true", "mode=auto"],
        "generic": ["hello", "test", "12345", "192.168.1.1", "user@example.com",
                     "application/json", "null", "undefined", "3.14", "%20"],
    }
    for kind, synth_values in _SYNTHETIC.items():
        existing = set(selected.get(kind, []))
        for sv in synth_values:
            if sv not in existing:
                selected.setdefault(kind, []).append(sv)

    summary: dict[str, dict[str, int | str]] = {}
    for kind, values in candidates.items():
        unique_values, devices = _summary(values)
        source = "UNSW-dev+synth"
        if kind == "body":
            source = body_source
        elif kind == "generic":
            source = "union"
        elif kind in ("query_value", "header_value"):
            source = "UNSW-dev"
        summary[kind] = {
            "unique_values": unique_values if kind != "generic" else "---",
            "selected": len(selected[kind]),
            "source": source,
        }
    return selected, summary


def main() -> None:
    global MAX_VALUES_PATH, MAX_VALUES_DEFAULT

    parser = argparse.ArgumentParser(description="Extract benign values for T3 verification")
    parser.add_argument("--method", choices=["cluster", "diversity"], default="cluster",
                        help="Selection method: cluster (k-medoids) or diversity (legacy)")
    parser.add_argument("--max-k-path", type=int, default=MAX_VALUES_PATH,
                        help=f"Max k-medoids representatives for path (default: {MAX_VALUES_PATH})")
    parser.add_argument("--max-k-default", type=int, default=MAX_VALUES_DEFAULT,
                        help=f"Max k-medoids representatives for other categories (default: {MAX_VALUES_DEFAULT})")
    parser.add_argument("--output", type=Path, default=OUT_PATH,
                        help=f"Output file path (default: {OUT_PATH})")
    args = parser.parse_args()

    MAX_VALUES_PATH = args.max_k_path
    MAX_VALUES_DEFAULT = args.max_k_default
    out_path = args.output

    values, summary = extract(method=args.method)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(values, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")
    _print_summary(summary)
    print(f"\nMethod: {args.method}")
    print(f"k-medoids: path={MAX_VALUES_PATH}, default={MAX_VALUES_DEFAULT}")
    print(f"Wrote {out_path}")
    if not CICIOT_BODY_PATH.exists():
        print(f"\nNOTE: {CICIOT_BODY_PATH} not found.")
        print("  Run scripts/extract_ciciot_bodies.py to generate body data.")
        print("  Without it, body category will have insufficient values.")


if __name__ == "__main__":
    main()
