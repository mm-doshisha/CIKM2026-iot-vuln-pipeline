"""Convert UNSW-IoTraffic httpAttributes.csv to benign trace JSON files.

Reads protocols.zip from the UNSW-IoTraffic dataset, extracts unique HTTP
requests across all 27 IoT devices, and samples 281 diverse benign traces
for mixed-traffic evaluation.

Source: Wannigama et al., "UNSW IoT Traffic Data with Packets, Flows, and
Protocols," IEEE Data Descriptions, 2025. DOI: 10.5061/dryad.w0vt4b94b
License: CC0 1.0
"""

import collections
import csv
import io
import json
import random
import sys
import zipfile
from pathlib import Path
from urllib.parse import parse_qs

TARGET_COUNT = 281
SEED = 42

DEVICE_META = {
    "AmazonEcho": {"vendor": "Amazon", "product": "Echo"},
    "AugustDoorBell": {"vendor": "August", "product": "DoorBell"},
    "AwairAirQuality": {"vendor": "Awair", "product": "Air Quality Monitor"},
    "BelkinCamera": {"vendor": "Belkin", "product": "NetCam"},
    "BelkinWemoMotionSensor": {"vendor": "Belkin", "product": "WeMo Motion Sensor"},
    "BelkinWemoSwitch": {"vendor": "Belkin", "product": "WeMo Switch"},
    "BlipCareBPMeter": {"vendor": "BlipCare", "product": "BP Meter"},
    "CanaryCamera": {"vendor": "Canary", "product": "Security Camera"},
    "HelloBarbie": {"vendor": "Mattel", "product": "Hello Barbie"},
    "HPPrinter": {"vendor": "HP", "product": "Printer"},
    "iHome": {"vendor": "iHome", "product": "Smart Plug"},
    "LiFXBulb": {"vendor": "LIFX", "product": "Smart Bulb"},
    "NetatmoWeatherStation": {"vendor": "Netatmo", "product": "Weather Station"},
    "NetatmoWelcome": {"vendor": "Netatmo", "product": "Welcome Camera"},
    "NestDropCam": {"vendor": "Nest", "product": "Dropcam"},
    "NestProtect": {"vendor": "Nest", "product": "Protect"},
    "PhilipsHue": {"vendor": "Philips", "product": "Hue Bridge"},
    "PixStarPhotoFrame": {"vendor": "Pix-Star", "product": "Photo Frame"},
    "RingDoorBell": {"vendor": "Ring", "product": "Video Doorbell"},
    "SamsungCamera": {"vendor": "Samsung", "product": "SmartCam"},
    "SamsungSmartThings": {"vendor": "Samsung", "product": "SmartThings Hub"},
    "TPLinkCamera": {"vendor": "TP-Link", "product": "Cloud Camera"},
    "TPLinkSmartPlug": {"vendor": "TP-Link", "product": "Smart Plug"},
    "TribySpeaker": {"vendor": "Invoxia", "product": "Triby Speaker"},
    "WithingsBabyMonitor": {"vendor": "Withings", "product": "Baby Monitor"},
    "WithingsSleepSensor": {"vendor": "Withings", "product": "Sleep Sensor"},
    "WithingsSmartScale": {"vendor": "Withings", "product": "Smart Scale"},
}


def extract_unique_requests(zip_path: str) -> list[dict]:
    z = zipfile.ZipFile(zip_path)
    all_requests = []

    for name in sorted(z.namelist()):
        if "request/httpattributes.csv" not in name:
            continue
        device_full = name.split("/")[2]
        device_name = device_full.rsplit("_", 1)[0]

        data = z.read(name).decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(data))

        seen_keys = set()
        for r in reader:
            method = r.get("method", "").strip()
            uri = r.get("uri", "").strip()
            host = r.get("host", "").strip()
            ua = r.get("user-agent", "").strip()

            if not method or not uri:
                continue

            key = (method, uri, host)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            all_requests.append({
                "device_name": device_name,
                "method": method,
                "uri": uri,
                "host": host,
                "user_agent": ua,
            })

    return all_requests


def parse_uri(uri: str) -> tuple[str, dict]:
    uri = uri.strip()
    if "?" in uri:
        path, query = uri.split("?", 1)
        params = {}
        for k, v in parse_qs(query).items():
            params[k] = v[0] if len(v) == 1 else v
        return path, params
    return uri, {}


def sample_diverse(requests: list[dict], target: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    per_device_cap = 40

    by_device = collections.defaultdict(list)
    for r in requests:
        by_device[r["device_name"]].append(r)

    selected = []

    # Phase 1: take all from small devices (≤15 unique requests)
    large_devices = {}
    for device, reqs in sorted(by_device.items()):
        if len(reqs) <= 15:
            selected.extend(reqs)
        else:
            large_devices[device] = reqs

    remaining = target - len(selected)
    if remaining <= 0:
        rng.shuffle(selected)
        return selected[:target]

    # Phase 2: capped sampling from larger devices
    for device, reqs in sorted(large_devices.items()):
        rng.shuffle(reqs)
        quota = min(per_device_cap, len(reqs))
        selected.extend(reqs[:quota])

    # Phase 3: if we overshot, trim; if under, add more
    if len(selected) > target:
        rng.shuffle(selected)
        selected = selected[:target]
    elif len(selected) < target:
        all_remaining = [r for r in requests if r not in selected]
        rng.shuffle(all_remaining)
        selected.extend(all_remaining[: target - len(selected)])

    return selected


def to_trace_json(req: dict, idx: int) -> dict:
    path, params = parse_uri(req["uri"])
    meta = DEVICE_META.get(req["device_name"], {
        "vendor": req["device_name"],
        "product": "Unknown",
    })

    headers = {}
    if req["user_agent"]:
        headers["User-Agent"] = req["user_agent"]

    return {
        "cve_id": f"BENIGN-UNSW-{idx:04d}",
        "vendor": meta["vendor"],
        "product": meta["product"],
        "vuln_class": None,
        "severity": None,
        "source": "UNSW-IoTraffic (Wannigama et al., 2025, DOI:10.5061/dryad.w0vt4b94b)",
        "trace": {
            "request": {
                "method": req["method"],
                "path": path,
                "params": params,
                "headers": headers,
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


def main():
    zip_path = sys.argv[1] if len(sys.argv) > 1 else str(
        Path.home() / "Downloads" / "protocols.zip"
    )
    output_dir = Path(__file__).parent.parent / "benchmarks" / "traces_benign"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Reading {zip_path}...")
    requests = extract_unique_requests(zip_path)
    print(f"Total unique requests: {len(requests)}")

    sampled = sample_diverse(requests, TARGET_COUNT, SEED)
    print(f"Sampled: {len(sampled)}")

    by_device = collections.Counter(r["device_name"] for r in sampled)
    print("\nPer device:")
    for d, c in by_device.most_common():
        print(f"  {d}: {c}")

    # Remove old synthetic benign traces
    old_count = 0
    for f in output_dir.glob("BENIGN-CVE-*.json"):
        f.unlink()
        old_count += 1
    if old_count:
        print(f"\nRemoved {old_count} old synthetic traces")

    for idx, req in enumerate(sampled, 1):
        trace = to_trace_json(req, idx)
        out_path = output_dir / f"{trace['cve_id']}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(trace, f, indent=2, ensure_ascii=False)

    print(f"\nWrote {len(sampled)} benign traces to {output_dir}")


if __name__ == "__main__":
    main()
