"""Run Suricata against pcap files and parse alert results.

Designed to run inside a Docker container with Suricata installed.
Uses offline mode: suricata -r <pcap> -S <rules> -l <log_dir>
"""

import json
import logging
import os
import signal
import subprocess
import tempfile
import types
from pathlib import Path

logger = logging.getLogger("suricata_runner")


def _write_suricata_yaml(config_path: str, rules_path: str):
    """Write a minimal Suricata configuration for offline pcap analysis."""
    config = f"""%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "[80,8080,8888,9090,9091]"

default-rule-path: {Path(rules_path).parent}

rule-files:
  - {Path(rules_path).name}

app-layer:
  protocols:
    http:
      enabled: yes
      request-body-limit: 1048576
    tls:
      enabled: no
    dns:
      enabled: no
    smtp:
      enabled: no
    ftp:
      enabled: no
    ssh:
      enabled: no

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            http: yes
            http-body: yes
        - http:
            extended: yes

  - stats:
      enabled: no

threading:
  set-cpu-affinity: no
  detect-thread-ratio: 1.0

stream:
  memcap: 256mb
  checksum-validation: no

host-mode: auto
"""
    Path(config_path).write_text(config, encoding="utf-8")
    logger.info("Suricata config written to %s", config_path)


def run_suricata(pcap_path: str, rules_path: str,
                 log_dir: str = None) -> dict:
    """Run Suricata on a single pcap file with the given rules.

    Returns dict with:
      - alerts: list of alert dicts from eve.json
      - triggered: bool (any alert fired)
      - rule_sids: set of triggered SIDs
      - error: str if Suricata failed
    """
    if log_dir is None:
        log_dir = tempfile.mkdtemp(prefix="suricata_eval_")
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    config_path = os.path.join(log_dir, "suricata.yaml")
    _write_suricata_yaml(config_path, rules_path)

    eve_path = os.path.join(log_dir, "eve.json")
    if os.path.exists(eve_path):
        os.remove(eve_path)

    cmd = [
        "suricata",
        "-r", pcap_path,
        "-c", config_path,
        "-l", log_dir,
        "--runmode", "single",
        "--set", "stream.checksum-validation=no",
        "--set", "threading.set-cpu-affinity=no",
        "-v",
    ]

    logger.info("Running: %s", " ".join(cmd))
    stderr_path = os.path.join(log_dir, "suricata_stderr.txt")
    try:
        with open(stderr_path, "w") as sf:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=sf,
                start_new_session=True)
            try:
                proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                logger.warning("Suricata timed out after 60s, killing pgid")
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                # Also try direct kill in case pgid didn't reach suricata
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                return {"alerts": [], "triggered": False, "rule_sids": set(),
                        "error": "timeout"}
        rc = proc.returncode
        if rc in (124, 137):
            return {"alerts": [], "triggered": False, "rule_sids": set(),
                    "error": "timeout"}
        stderr_text = Path(stderr_path).read_text(encoding="utf-8",
                                                   errors="replace")
        proc = types.SimpleNamespace(
            returncode=rc, stdout="", stderr=stderr_text)
    except FileNotFoundError:
        return {"alerts": [], "triggered": False, "rule_sids": set(),
                "error": "suricata not found"}

    if proc.returncode != 0:
        logger.warning("Suricata returned %d: %s", proc.returncode,
                       proc.stderr[:500])
    elif not os.path.exists(eve_path) or os.path.getsize(eve_path) == 0:
        logger.warning("Suricata returned 0 but eve.json missing/empty: %s",
                       proc.stderr[:500])

    alerts = []
    events = []
    http_events = []
    rule_sids = set()
    if os.path.exists(eve_path):
        with open(eve_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                events.append(event)
                if event.get("event_type") == "alert":
                    alert_info = event.get("alert", {})
                    alerts.append({
                        "sid": alert_info.get("signature_id"),
                        "signature": alert_info.get("signature", ""),
                        "severity": alert_info.get("severity"),
                        "category": alert_info.get("category", ""),
                        "src_ip": event.get("src_ip"),
                        "dest_ip": event.get("dest_ip"),
                        "http": event.get("http", {}),
                    })
                    if alert_info.get("signature_id"):
                        rule_sids.add(alert_info["signature_id"])
                elif event.get("event_type") == "http":
                    http_events.append(event.get("http", {}))

    return {
        "alerts": alerts,
        "events": events,
        "http_events": http_events,
        "triggered": len(alerts) > 0,
        "rule_sids": rule_sids,
        "error": None,
        "suricata_stderr": proc.stderr[:1000],
        "suricata_returncode": proc.returncode,
    }


def validate_rules(rules_path: str, log_dir: str = None) -> dict:
    """Validate Suricata rules by running engine-analysis mode.

    Returns dict with valid (bool), errors (list of str).
    """
    if log_dir is None:
        log_dir = tempfile.mkdtemp(prefix="suricata_validate_")
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    config_path = os.path.join(log_dir, "suricata.yaml")
    _write_suricata_yaml(config_path, rules_path)

    cmd = [
        "suricata",
        "-c", config_path,
        "-T",
        "-l", log_dir,
        "--runmode", "single",
        "--set", "stream.checksum-validation=no",
        "--set", "threading.set-cpu-affinity=no",
    ]

    stderr_path = os.path.join(log_dir, "suricata_stderr.txt")
    try:
        with open(stderr_path, "w") as sf:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=sf,
                start_new_session=True)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                raise
        rc = proc.returncode
        stderr_text = Path(stderr_path).read_text(encoding="utf-8",
                                                   errors="replace")
        proc = types.SimpleNamespace(
            returncode=rc, stdout="", stderr=stderr_text)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"valid": False, "errors": [str(e)]}

    errors = []
    for line in proc.stderr.splitlines():
        if "error" in line.lower() or "invalid" in line.lower():
            errors.append(line.strip())

    return {
        "valid": proc.returncode == 0,
        "errors": errors,
        "stderr": proc.stderr[:1000],
    }
