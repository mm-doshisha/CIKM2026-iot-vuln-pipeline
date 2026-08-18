"""Convert UNSW-IoTraffic httpAttributes.csv to benign trace JSON files (FULL).

Exports ALL unique HTTP requests (no sampling) for comprehensive FPR evaluation.
Also reports stratification statistics.

Source: Wannigama et al., "UNSW IoT Traffic Data with Packets, Flows, and
Protocols," IEEE Data Descriptions, 2025. DOI: 10.5061/dryad.w0vt4b94b
License: CC0 1.0
"""

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scripts.convert_unsw_benign import (
    extract_unique_requests,
    parse_uri,
    DEVICE_META,
)


def main():
    zip_path = sys.argv[1] if len(sys.argv) > 1 else str(
        Path.home() / "Downloads" / "protocols.zip"
    )
    output_dir = Path(__file__).parent.parent / "benchmarks" / "traces_benign_full"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Reading {zip_path}...")
    requests = extract_unique_requests(zip_path)
    print(f"Total unique requests: {len(requests)}")

    by_device = collections.Counter(r["device_name"] for r in requests)
    print("\nPer device:")
    for d, c in by_device.most_common():
        print(f"  {d}: {c}")

    for idx, req in enumerate(requests, 1):
        path, params = parse_uri(req["uri"])
        trace = {
            "cve_id": f"BENIGN-UNSW-{idx:05d}",
            "vendor": DEVICE_META.get(req["device_name"], {}).get("vendor", req["device_name"]),
            "product": DEVICE_META.get(req["device_name"], {}).get("product", "Unknown"),
            "vuln_class": None,
            "severity": None,
            "source": "UNSW-IoTraffic (Wannigama et al., 2025, DOI:10.5061/dryad.w0vt4b94b)",
            "trace": {
                "request": {
                    "method": req["method"],
                    "path": path,
                    "params": params,
                    "headers": {"User-Agent": req["user_agent"]} if req["user_agent"] else {},
                    "body": None,
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
        out_path = output_dir / f"{trace['cve_id']}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(trace, f, indent=2, ensure_ascii=False)

    print(f"\nWrote {len(requests)} benign traces to {output_dir}")
    print(f"\nNote: PhilipsHue = {by_device['PhilipsHue']}/{len(requests)} ({100*by_device['PhilipsHue']/len(requests):.1f}%)")
    print("Consider reporting per-device FPR to address concentration bias.")


if __name__ == "__main__":
    main()
