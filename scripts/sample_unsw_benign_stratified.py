"""Stratified sampling of UNSW-IoTraffic for benign rejection experiment.

Produces 281 benign trace JSONs with stratification by:
  - Layer 1: device category (21 device types)
  - Layer 2: HTTP method (GET/POST/etc.)

Diversity constraints:
  - Per-device cap (MAX_PER_DEVICE=30) prevents single-device bias
  - Minimum 1 per device guarantees all device types are represented
  - Within-device path diversity: prefers unique URL paths over duplicates

Source: Wannigama et al., "UNSW IoT Traffic Data with Packets, Flows, and
Protocols," IEEE Data Descriptions, 2025. DOI: 10.5061/dryad.w0vt4b94b
License: CC0 1.0

Can re-sample from:
  1. benchmarks/traces_benign_full/ (pre-converted JSON, no ZIP needed)
  2. protocols.zip (original dataset, if full traces not available)
"""

import collections
import json
import random
import sys
from pathlib import Path


TARGET_COUNT = 281
SEED = 42
MAX_PER_DEVICE = 30


def _load_population_from_json(full_dir: Path) -> list[dict]:
    """Load population from pre-converted full trace JSONs."""
    population = []
    for f in sorted(full_dir.glob("BENIGN-*.json")):
        with open(f, encoding="utf-8") as fh:
            d = json.load(fh)
        req = d["trace"]["request"]
        population.append({
            "device_name": d["original_device"],
            "method": req["method"],
            "path": req["path"],
            "params": req.get("params", {}),
            "headers": req.get("headers", {}),
            "body": req.get("body"),
            "source_file": f.name,
            "vendor": d.get("vendor", ""),
            "product": d.get("product", ""),
        })
    return population


def stratified_sample(population: list[dict], target: int, seed: int,
                      max_per_device: int) -> list[dict]:
    """Stratified sampling with enforced per-device cap at every phase."""
    rng = random.Random(seed)

    by_device = collections.defaultdict(list)
    for r in population:
        by_device[r["device_name"]].append(r)

    device_taken = collections.Counter()
    selected = []
    selected_ids = set()

    def _add(item):
        selected.append(item)
        selected_ids.add(id(item))
        device_taken[item["device_name"]] += 1

    # Phase 1: guarantee minimum representation from ALL devices
    # Prefer path diversity within each device
    for device in sorted(by_device.keys()):
        reqs = by_device[device]
        rng.shuffle(reqs)
        # Deduplicate by path to maximize diversity
        seen_paths = set()
        diverse_first = []
        rest = []
        for r in reqs:
            if r["path"] not in seen_paths:
                seen_paths.add(r["path"])
                diverse_first.append(r)
            else:
                rest.append(r)
        ordered = diverse_first + rest
        min_take = min(1, len(ordered))
        for r in ordered[:min_take]:
            _add(r)

    # Phase 2: proportional allocation with per-device cap
    pool = [r for r in population if id(r) not in selected_ids]
    rng.shuffle(pool)

    by_stratum = collections.defaultdict(list)
    for r in pool:
        stratum = f"{r['device_name']}_{r['method']}"
        by_stratum[stratum].append(r)

    remaining_target = target - len(selected)
    total_eligible = sum(
        len([r for r in reqs if device_taken[r["device_name"]] < max_per_device])
        for reqs in by_stratum.values()
    )

    for stratum in sorted(by_stratum.keys()):
        reqs = by_stratum[stratum]
        device = stratum.rsplit("_", 1)[0]
        cap_remaining = max_per_device - device_taken.get(device, 0)
        if cap_remaining <= 0:
            continue

        eligible = [r for r in reqs if id(r) not in selected_ids]
        if not eligible:
            continue

        # Proportional allocation
        proportion = len(eligible) / max(total_eligible, 1)
        n = min(cap_remaining, max(1, round(proportion * remaining_target)))

        # Prefer path diversity within stratum
        seen_paths = {r["path"] for r in selected if r["device_name"] == device}
        diverse = [r for r in eligible if r["path"] not in seen_paths]
        rest = [r for r in eligible if r["path"] in seen_paths]
        rng.shuffle(diverse)
        rng.shuffle(rest)
        ordered = diverse + rest

        for r in ordered[:n]:
            if device_taken[device] >= max_per_device:
                break
            _add(r)

    # Phase 3: fill to target, RESPECTING per-device cap
    if len(selected) < target:
        remaining = [r for r in population
                     if id(r) not in selected_ids
                     and device_taken[r["device_name"]] < max_per_device]
        # Prefer path diversity
        seen_paths_global = {(r["device_name"], r["path"]) for r in selected}
        diverse = [r for r in remaining
                   if (r["device_name"], r["path"]) not in seen_paths_global]
        rest = [r for r in remaining
                if (r["device_name"], r["path"]) in seen_paths_global]
        rng.shuffle(diverse)
        rng.shuffle(rest)
        fill_pool = diverse + rest

        for r in fill_pool:
            if len(selected) >= target:
                break
            if device_taken[r["device_name"]] < max_per_device:
                _add(r)

    # Phase 4: trim if overshot
    if len(selected) > target:
        rng.shuffle(selected)
        selected = selected[:target]

    return selected


def to_trace_json(req: dict) -> dict:
    """Convert a population record to pipeline trace format."""
    return {
        "cve_id": "",
        "vendor": req["vendor"],
        "product": req["product"],
        "vuln_class": None,
        "severity": None,
        "source": "UNSW-IoTraffic (Wannigama et al., 2025, DOI:10.5061/dryad.w0vt4b94b)",
        "trace": {
            "request": {
                "method": req["method"],
                "path": req["path"],
                "params": req["params"],
                "headers": req["headers"],
                "body": req["body"],
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "OK\n",
            },
        },
        "payload_encoding": "none",
        "decoded_payload": None,
        "is_benign": True,
        "dataset": "UNSW-IoTraffic",
        "original_device": req["device_name"],
    }


def main():
    full_dir = Path(__file__).parent.parent / "benchmarks" / "traces_benign_full"
    output_dir = Path(__file__).parent.parent / "benchmarks" / "traces_unsw_benign"

    if full_dir.exists() and any(full_dir.glob("BENIGN-*.json")):
        print(f"Loading population from {full_dir}...")
        population = _load_population_from_json(full_dir)
    else:
        zip_path = sys.argv[1] if len(sys.argv) > 1 else str(
            Path.home() / "Downloads" / "protocols.zip"
        )
        print(f"Loading population from {zip_path}...")
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from scripts.convert_unsw_benign import extract_unique_requests
        raw = extract_unique_requests(zip_path)
        from urllib.parse import parse_qs
        population = []
        for r in raw:
            uri = r["uri"]
            path = uri.split("?")[0] if "?" in uri else uri
            params = {}
            if "?" in uri:
                for k, v in parse_qs(uri.split("?", 1)[1]).items():
                    params[k] = v[0] if len(v) == 1 else v
            population.append({
                "device_name": r["device_name"],
                "method": r["method"],
                "path": path,
                "params": params,
                "headers": {"User-Agent": r["user_agent"]} if r["user_agent"] else {},
                "body": None,
                "source_file": "",
                "vendor": "",
                "product": "",
            })

    print(f"Population size: {len(population)}")

    # Population statistics
    device_counts = collections.Counter(r["device_name"] for r in population)
    method_counts = collections.Counter(r["method"] for r in population)
    paths_per_device = collections.defaultdict(set)
    for r in population:
        paths_per_device[r["device_name"]].add(r["path"])

    print(f"\n=== Population Statistics ===")
    print(f"Devices: {len(device_counts)}")
    print(f"Methods: {dict(method_counts.most_common())}")

    # Stratified sampling
    sampled = stratified_sample(population, TARGET_COUNT, SEED, MAX_PER_DEVICE)
    print(f"\nSampled: {len(sampled)}")

    # Verify cap
    sample_device_counts = collections.Counter(r["device_name"] for r in sampled)
    max_device = sample_device_counts.most_common(1)[0]
    assert max_device[1] <= MAX_PER_DEVICE, (
        f"Cap violated: {max_device[0]}={max_device[1]} > {MAX_PER_DEVICE}")

    sample_method_counts = collections.Counter(r["method"] for r in sampled)
    sample_paths = collections.defaultdict(set)
    for r in sampled:
        sample_paths[r["device_name"]].add(r["path"])

    # Report
    print(f"\n=== Stratification Report ===")
    print(f"{'Device':<30s} {'Pop':>5s} {'Pop%':>6s} {'Samp':>5s} {'S%':>6s} "
          f"{'Paths(pop)':>10s} {'Paths(samp)':>11s}")
    print("-" * 80)
    for device in sorted(device_counts.keys()):
        pop_n = device_counts[device]
        pop_pct = pop_n / len(population) * 100
        samp_n = sample_device_counts.get(device, 0)
        samp_pct = samp_n / len(sampled) * 100
        pop_paths = len(paths_per_device[device])
        samp_paths_n = len(sample_paths.get(device, set()))
        print(f"  {device:<28s} {pop_n:>5d} {pop_pct:>5.1f}% {samp_n:>5d} "
              f"{samp_pct:>5.1f}% {pop_paths:>10d} {samp_paths_n:>11d}")

    print(f"\n{'Method':<12s} {'Pop':>5s} {'Pop%':>6s} {'Samp':>5s} {'S%':>6s}")
    print("-" * 40)
    for method in sorted(method_counts.keys()):
        pop_n = method_counts[method]
        pop_pct = pop_n / len(population) * 100
        samp_n = sample_method_counts.get(method, 0)
        samp_pct = samp_n / len(sampled) * 100
        print(f"  {method:<10s} {pop_n:>5d} {pop_pct:>5.1f}% {samp_n:>5d} {samp_pct:>5.1f}%")

    # Write trace JSONs
    output_dir.mkdir(parents=True, exist_ok=True)
    # Remove old files
    for old in output_dir.glob("BENIGN-*.json"):
        old.unlink()

    for i, req in enumerate(sampled):
        trace = to_trace_json(req)
        trace["cve_id"] = f"BENIGN-UNSW-{i:04d}"
        trace["sampling"] = {
            "method": "stratified",
            "seed": SEED,
            "source_population": len(population),
            "target_n": TARGET_COUNT,
            "max_per_device": MAX_PER_DEVICE,
            "device": req["device_name"],
            "http_method": req["method"],
        }
        out_path = output_dir / f"{trace['cve_id']}.json"
        out_path.write_text(
            json.dumps(trace, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    print(f"\nWrote {len(sampled)} traces to {output_dir}")

    # Save report
    report = {
        "dataset": "UNSW-IoTraffic",
        "citation": "Wannigama et al., IEEE Data Descriptions, 2025. DOI:10.5061/dryad.w0vt4b94b",
        "license": "CC0 1.0",
        "total_population": len(population),
        "sample_size": len(sampled),
        "seed": SEED,
        "max_per_device": MAX_PER_DEVICE,
        "stratification_variables": ["device_category", "http_method"],
        "population_device_distribution": dict(device_counts.most_common()),
        "sample_device_distribution": dict(sample_device_counts.most_common()),
        "population_method_distribution": dict(method_counts.most_common()),
        "sample_method_distribution": dict(sample_method_counts.most_common()),
        "path_diversity": {
            device: {
                "population_paths": len(paths_per_device[device]),
                "sample_paths": len(sample_paths.get(device, set())),
                "sample_count": sample_device_counts.get(device, 0),
            }
            for device in sorted(device_counts.keys())
        },
    }
    report_path = output_dir / "_sampling_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Sampling report: {report_path}")


if __name__ == "__main__":
    main()
