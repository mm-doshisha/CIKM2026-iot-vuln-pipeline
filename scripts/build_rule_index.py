"""Download ET Open Rules and build an ATT&CK-indexed rule database.

Usage:
    python scripts/build_rule_index.py [--output data/et_rules_index.json]

Downloads the latest ET Open ruleset, parses all rules, extracts
MITRE ATT&CK technique IDs from metadata, and builds a searchable index.
"""

import argparse
import json
import re
from pathlib import Path
from typing import List, Optional
from urllib.request import urlopen

ET_OPEN_URL = "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules"

ATTACK_CATEGORY_MAP = {
    "command_injection": ["T1059", "T1059.004"],
    "path_traversal": ["T1005", "T1083"],
    "info_leak": ["T1005", "T1592"],
    "auth_bypass": ["T1078", "T1556"],
    "sql_injection": ["T1190"],
    "xss": ["T1059.007"],
    "file_inclusion": ["T1055"],
    "rce": ["T1203"],
}

SID_RE = re.compile(r"sid:\s*(\d+)")
MSG_RE = re.compile(r'msg:\s*"([^"]*)"')
MITRE_RE = re.compile(r"mitre_technique_id\s+(T\d+(?:\.\d+)?)")
CLASSTYPE_RE = re.compile(r"classtype:\s*([^;]+)")
CONTENT_RE = re.compile(r'content:\s*"([^"]*)"')
METADATA_RE = re.compile(r"metadata:\s*([^;]+(?:;[^;(]*)*?)(?:\s*;\s*(?:sid|rev|classtype|reference|flow))")


def parse_rule(line: str) -> Optional[dict]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if not line.startswith(("alert", "drop", "reject", "pass")):
        return None

    sid_m = SID_RE.search(line)
    msg_m = MSG_RE.search(line)
    classtype_m = CLASSTYPE_RE.search(line)

    mitre_ids = MITRE_RE.findall(line)

    contents = CONTENT_RE.findall(line)

    metadata_m = METADATA_RE.search(line)
    metadata_raw = metadata_m.group(1).strip() if metadata_m else ""

    if not mitre_ids and metadata_raw:
        mitre_ids = MITRE_RE.findall(metadata_raw)

    keywords = []
    for kw in ["http.uri", "http.request_body", "http.header", "http.method",
                "http.cookie", "http.host", "http.user_agent", "http.content_type",
                "http.request_line", "pcre"]:
        if kw in line:
            keywords.append(kw)

    return {
        "sid": int(sid_m.group(1)) if sid_m else None,
        "msg": msg_m.group(1) if msg_m else "",
        "classtype": classtype_m.group(1).strip() if classtype_m else "",
        "mitre_ids": mitre_ids,
        "contents": contents[:5],
        "keywords": keywords,
        "rule": line,
    }


def categorize_rule(parsed: dict) -> List[str]:
    """Infer attack categories from rule content and metadata."""
    categories = []
    msg_lower = parsed["msg"].lower()
    rule_lower = parsed["rule"].lower()

    if any(t.startswith("T1059") for t in parsed["mitre_ids"]):
        categories.append("command_injection")
    if any(t in ("T1005", "T1083") for t in parsed["mitre_ids"]):
        categories.append("path_traversal")

    cmdi_patterns = [
        "command injection", "os command", "cmd injection",
        "shell command", "rce", "remote code execution",
        "remote command", "code execution",
    ]
    if any(p in msg_lower for p in cmdi_patterns):
        categories.append("command_injection")

    pt_patterns = ["directory traversal", "path traversal", "../", "..\\"]
    if any(p in msg_lower for p in pt_patterns):
        categories.append("path_traversal")

    info_patterns = ["information disclosure", "info leak", "sensitive data",
                     "debug", "phpinfo", "server-status"]
    if any(p in msg_lower for p in info_patterns):
        categories.append("info_leak")

    auth_patterns = ["authentication bypass", "auth bypass", "unauthorized",
                     "privilege escalation", "default password", "default credentials"]
    if any(p in msg_lower for p in auth_patterns):
        categories.append("auth_bypass")

    return list(set(categories)) if categories else ["other"]


def download_rules(url: str = ET_OPEN_URL) -> List[str]:
    print(f"Downloading rules from {url} ...")
    resp = urlopen(url, timeout=120)
    content = resp.read().decode("utf-8", errors="replace")
    lines = content.splitlines()
    print(f"Downloaded {len(lines)} lines")
    return lines


def build_index(lines: List[str]) -> dict:
    rules_by_category = {}
    rules_by_mitre = {}
    all_rules = []
    skipped = 0

    for line in lines:
        parsed = parse_rule(line)
        if not parsed or not parsed["sid"]:
            skipped += 1
            continue

        categories = categorize_rule(parsed)
        parsed["categories"] = categories
        all_rules.append(parsed)

        for cat in categories:
            rules_by_category.setdefault(cat, []).append(parsed["sid"])

        for tid in parsed["mitre_ids"]:
            rules_by_mitre.setdefault(tid, []).append(parsed["sid"])

    sid_to_rule = {r["sid"]: r for r in all_rules}

    print(f"\nParsed {len(all_rules)} rules (skipped {skipped} lines)")
    print(f"Categories: {', '.join(f'{k}({len(v)})' for k, v in sorted(rules_by_category.items()))}")
    print(f"MITRE techniques: {len(rules_by_mitre)}")

    return {
        "metadata": {
            "source": ET_OPEN_URL,
            "total_rules": len(all_rules),
            "categories": {k: len(v) for k, v in rules_by_category.items()},
            "mitre_techniques": {k: len(v) for k, v in rules_by_mitre.items()},
        },
        "rules_by_category": rules_by_category,
        "rules_by_mitre": rules_by_mitre,
        "rules": sid_to_rule,
    }


def main():
    parser = argparse.ArgumentParser(description="Build ET Open Rules index")
    parser.add_argument("--output", "-o", default="data/et_rules_index.json")
    parser.add_argument("--url", default=ET_OPEN_URL)
    args = parser.parse_args()

    lines = download_rules(args.url)
    index = build_index(lines)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(index, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\nIndex saved to {out_path}")
    print(f"File size: {out_path.stat().st_size / 1024 / 1024:.1f} MB")


if __name__ == "__main__":
    main()
