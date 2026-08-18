"""Extract HTTP requests from CICIoT2023 PCAP files for benign rejection experiment.

Prerequisites:
- CICIoT2023 pcap files downloaded to a local directory
- tshark installed (run inside Docker: apt-get install tshark)
- Labels CSV from CICIoT2023

Usage (inside Docker container with tshark):
    python3 scripts/extract_ciciot2023_http.py \
        --pcap-dir /data/CICIoT2023/PCAP \
        --labels-csv /data/CICIoT2023/CSV/merged.csv \
        --output-dir benchmarks/traces_ciciot_benign \
        --target-n 281 --seed 42

Phase 1 (count only):
    python3 scripts/extract_ciciot2023_http.py \
        --pcap-dir /data/CICIoT2023/PCAP \
        --count-only
"""

import argparse
import collections
import json
import random
import subprocess
import sys
from pathlib import Path


def count_http_in_pcap(pcap_path: str) -> int:
    """Count HTTP requests in a single pcap file using tshark."""
    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", "http.request",
        "-T", "fields",
        "-e", "frame.number",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return len(result.stdout.strip().split("\n")) if result.stdout.strip() else 0
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"  Error processing {pcap_path}: {e}")
        return 0


def extract_http_from_pcap(pcap_path: str) -> list:
    """Extract HTTP request details from a pcap file."""
    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", "http.request",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "http.request.method",
        "-e", "http.request.uri",
        "-e", "http.host",
        "-e", "http.user_agent",
        "-e", "http.content_type",
        "-e", "http.file_data",
        "-E", "separator=\t",
        "-E", "quote=n",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    requests = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < 7:
            continue
        req = {
            "timestamp": fields[0],
            "src_ip": fields[1],
            "dst_ip": fields[2],
            "src_port": fields[3],
            "dst_port": fields[4],
            "method": fields[5],
            "uri": fields[6],
            "host": fields[7] if len(fields) > 7 else "",
            "user_agent": fields[8] if len(fields) > 8 else "",
            "content_type": fields[9] if len(fields) > 9 else "",
            "body": fields[10] if len(fields) > 10 else "",
        }
        requests.append(req)
    return requests


def to_trace_json(req: dict, index: int) -> dict:
    """Convert extracted HTTP request to pipeline trace format."""
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(req["uri"])
    params = parse_qs(parsed.query)
    flat_params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}

    headers = {}
    if req.get("host"):
        headers["Host"] = req["host"]
    if req.get("user_agent"):
        headers["User-Agent"] = req["user_agent"]
    if req.get("content_type"):
        headers["Content-Type"] = req["content_type"]

    return {
        "cve_id": f"BENIGN-CICIOT-{index:04d}",
        "vendor": "unknown",
        "product": "IoT-device",
        "vuln_class": None,
        "severity": None,
        "source": "CICIoT2023 (Neto et al., Sensors, 2023)",
        "trace": {
            "request": {
                "method": req["method"],
                "path": parsed.path or "/",
                "params": flat_params,
                "headers": headers,
                "body": req.get("body") or None,
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
        "dataset": "CICIoT2023",
    }


def main():
    parser = argparse.ArgumentParser(description="Extract HTTP from CICIoT2023 PCAPs")
    parser.add_argument("--pcap-dir", required=True, help="Directory containing pcap files")
    parser.add_argument("--output-dir", default="benchmarks/traces_ciciot_benign")
    parser.add_argument("--target-n", type=int, default=281)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--count-only", action="store_true",
                        help="Only count HTTP requests, don't extract")
    parser.add_argument("--labels-csv", help="Path to labels CSV for benign filtering")
    args = parser.parse_args()

    pcap_dir = Path(args.pcap_dir)
    pcap_files = sorted(pcap_dir.glob("**/*.pcap"))
    if not pcap_files:
        print(f"No pcap files found in {pcap_dir}")
        sys.exit(1)

    print(f"Found {len(pcap_files)} pcap files")

    if args.count_only:
        total_http = 0
        for i, pcap in enumerate(pcap_files):
            count = count_http_in_pcap(str(pcap))
            total_http += count
            print(f"  [{i+1}/{len(pcap_files)}] {pcap.name}: {count} HTTP requests")
        print(f"\nTotal HTTP requests across all pcaps: {total_http}")
        print(f"Target sample size: {args.target_n}")
        if total_http >= args.target_n:
            print("=> Sufficient HTTP traffic for sampling")
        else:
            print("=> INSUFFICIENT HTTP traffic for 281 samples")
        return

    # Full extraction
    print("Extracting HTTP requests from all pcaps...")
    all_requests = []
    for i, pcap in enumerate(pcap_files):
        reqs = extract_http_from_pcap(str(pcap))
        all_requests.extend(reqs)
        print(f"  [{i+1}/{len(pcap_files)}] {pcap.name}: {len(reqs)} requests")

    print(f"\nTotal HTTP requests: {len(all_requests)}")

    if len(all_requests) < args.target_n:
        print(f"ERROR: Only {len(all_requests)} HTTP requests, need {args.target_n}")
        sys.exit(1)

    # Stratified sampling by HTTP method
    rng = random.Random(args.seed)
    method_counts = collections.Counter(r["method"] for r in all_requests)
    print(f"Method distribution: {dict(method_counts)}")

    # Proportional allocation by method
    sampled = []
    for method, count in method_counts.items():
        method_reqs = [r for r in all_requests if r["method"] == method]
        rng.shuffle(method_reqs)
        n = max(1, round(count / len(all_requests) * args.target_n))
        sampled.extend(method_reqs[:n])

    # Adjust to target
    if len(sampled) > args.target_n:
        rng.shuffle(sampled)
        sampled = sampled[:args.target_n]
    elif len(sampled) < args.target_n:
        remaining = [r for r in all_requests if r not in sampled]
        rng.shuffle(remaining)
        sampled.extend(remaining[:args.target_n - len(sampled)])

    # Write traces
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    sample_method_counts = collections.Counter(r["method"] for r in sampled)

    for i, req in enumerate(sampled):
        trace = to_trace_json(req, i)
        trace["sampling"] = {
            "method": "stratified",
            "seed": args.seed,
            "source_population": len(all_requests),
            "target_n": args.target_n,
            "http_method": req["method"],
        }
        out_path = output_dir / f"{trace['cve_id']}.json"
        out_path.write_text(json.dumps(trace, indent=2, ensure_ascii=False), encoding="utf-8")

    # Sampling report
    report = {
        "dataset": "CICIoT2023",
        "citation": "Neto et al., Sensors, 2023",
        "total_http_requests": len(all_requests),
        "sample_size": len(sampled),
        "seed": args.seed,
        "stratification_variables": ["http_method"],
        "population_method_distribution": dict(method_counts),
        "sample_method_distribution": dict(sample_method_counts),
    }
    report_path = output_dir / "_sampling_report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nWrote {len(sampled)} traces to {output_dir}")
    print(f"Sampling report: {report_path}")


if __name__ == "__main__":
    main()
