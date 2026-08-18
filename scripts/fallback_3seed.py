#!/usr/bin/env python3
"""3-seed ISOLATION measurement of the stage-2 FALLBACK (param=none recovery): a
post-hoc NOEX extract-or-NONE prompt + fix(c) wire-format rendering, applied to the
param=none cases (analyst said attack but could not localize a field).

PROVENANCE / STATUS (read before citing these numbers):
- This is NOT pre-registered. The NOEX prompt was designed after observing that
  param=none cases cost ~15% DR; it is a post-hoc improvement. The prompt is a
  generic extract-or-NONE form not fitted to the eval set, but no pre-registration
  document predates it. Do not label it pre-registered.
- This is an ISOLATION measurement, NOT end-to-end. The fallback stage is NOT wired
  into the pipeline (runner.py rejects param=none). It loads the analyst outputs
  produced by a prior pg2-norepair run and applies the NOEX LLM on top. A fresh full
  run of the committed code produces 77.4% (multipart only), NOT 78.9%.
- MULTIPART_FIRE below are the per-seed firing counts of the committed multipart fix
  (status=success, /281), measured by scripts/remeasure_deployed.py on the evaluation server
  server last session: 214/220/218 = per-seed DR 76.2/78.3/77.6% = mean 77.4%
  (matches memory project_template-fix-tradeoff.md). They are hardcoded here because
  output/ablation/ is gitignored and lives on the remote; the raw run logs are not
  committed (reproducibility gap, tracked as remaining work).

Reports per seed: attack recovery (= DR gain, disjoint from the multipart-fixed
status=success rules) and benign emit (= FPR cost). Total DR = multipart-fixed
firing + fallback recovery = projected 78.9% IF the fallback were integrated."""
import json, glob, os, re, sys, tempfile
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, "/workspace")
from src.hypothesis.analyst import _call_llm
from src.hypothesis.rule_template import escape_content
from src.evaluation.pcap_generator import generate_attack_pcap, wire_buffers
from src.evaluation.suricata_runner import run_suricata
from src.hypothesis.agents.rule_agent import RuleGenAgent

SYS_NOEX = ("You are an intrusion-detection analyst. You receive ONE HTTP request and "
            "must decide whether it carries an attack payload: a byte sequence that is "
            "malicious on its own, independent of application context. A normal request to "
            "a sensitive endpoint, or an ordinary parameter value, is NOT an attack "
            "payload. Be strict: name a payload only when the substring is unambiguously "
            "malicious by itself; when in doubt, answer NONE.")
USER_TMPL = ("HTTP request:\n%s\n\nRespond with EXACTLY one line:\n"
             "`PAYLOAD: <the exact malicious substring, copied verbatim from the request>`\n"
             "or\n`NONE`")
WIRE_BUFFERS = ("http.request_body", "http.uri", "http.uri.raw", "http.cookie",
                "http.header", "http.user_agent", "http.host")
# multipart-fixed firing counts (status=success, /281) from remeasure_deployed.py
# (evaluation server, prior session). 214/220/218 = 76.2/78.3/77.6% = mean 77.4% (deployed).
# See PROVENANCE note in the module docstring. Raw logs not committed (remaining work).
MULTIPART_FIRE = {"42": 214, "123": 220, "456": 218}


def isnone(p):
    return (p is None) or (str(p).strip().lower() in ("", "none", "null", "n/a"))


def stage2(req):
    rj = json.dumps({k: req.get(k) for k in ("method", "path", "params", "headers", "body")},
                    indent=2, ensure_ascii=False)
    msgs = [{"role": "system", "content": SYS_NOEX}, {"role": "user", "content": USER_TMPL % rj}]
    try:
        out = _call_llm(msgs, temperature=0.0, max_tokens=200).strip()
    except Exception:
        return ("ERROR", "")
    m = re.search(r"PAYLOAD:\s*(.+)", out)
    if m:
        return ("PAYLOAD", m.group(1).strip().strip('`"\' '))
    if re.search(r"\bNONE\b", out, re.I):
        return ("NONE", "")
    return ("UNPARSED", "")


def blob(req):
    b = req.get("body")
    bs = json.dumps(b) if isinstance(b, (dict, list)) else (str(b) if b else "")
    return str(req.get("path") or "") + " " + bs + " " + str(req.get("params") or {})


def _run(req, rule):
    if not rule:
        return False
    for _ in range(3):
        with tempfile.TemporaryDirectory() as t:
            rp = os.path.join(t, "r.rules"); open(rp, "w").write(rule + "\n")
            pc = os.path.join(t, "a.pcap"); generate_attack_pcap(req, pc)
            ld = os.path.join(t, "log"); sr = run_suricata(pc, rp, ld)
            serr = os.path.join(ld, "suricata_stderr.txt")
            if os.path.exists(serr) and "thread spawn failed" in open(serr, errors="replace").read():
                continue
            return bool(sr.get("triggered"))
    return False


def fires_wire(req, token):
    if not token:
        return False
    wb = wire_buffers(req)
    for buf in WIRE_BUFFERS:
        wv = RuleGenAgent._wire_content(token, buf, wb)
        if wv:
            return _run(req, 'alert http any any -> any any (flow:established,to_server; '
                            '%s; content:"%s"; sid:9900100; rev:1;)' % (buf, escape_content(wv)))
    return False


def load(sub, pre, seed):
    out = []
    for f in sorted(glob.glob(os.path.join("output/ablation", sub, "seed_" + seed, pre + "*.json"))):
        s = json.load(open(f))
        if (s.get("analyst_benign_judgment") is False and s.get("status") != "success"
                and isnone(s.get("identified_param"))):
            r = s.get("http_request") or {}
            if r:
                out.append((os.path.basename(f)[:-5], r))
    return out


def recover_count(cases):
    with ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(lambda c: (c[1], stage2(c[1])), cases))
    rec = 0
    for req, (verdict, val) in results:
        if verdict == "PAYLOAD" and val and val in blob(req) and fires_wire(req, val):
            rec += 1
    return rec


print("=== Stage-2 FALLBACK 3-seed confirmation (NOEX + fix(c) wire-render) ===", flush=True)
dr_after = []
for seed in ("42", "123", "456"):
    print("##### SEED %s #####" % seed, flush=True)
    atk = recover_count(load("bh4b_atk", "CVE-", seed))
    bcve = recover_count(load("bh4b_cve", "BENIGN-", seed))
    bunsw = recover_count(load("bh4b_unsw", "BENIGN-", seed))
    base = MULTIPART_FIRE[seed]
    total = base + atk
    dr_after.append(total)
    print("  ATTACK fallback recover(fire) = %d  -> DR = multipart %d + fallback %d = %d/281 = %.1f%%"
          % (atk, base, atk, total, total / 281 * 100), flush=True)
    print("  BENIGN-CVE fallback emit(fire) = %d (=FPR cost)   BENIGN-UNSW = %d" % (bcve, bunsw), flush=True)
mean = sum(dr_after) / 3
print("=== 3-seed mean DR (multipart+fallback) = %.1f/281 = %.1f%%  (Syrius=77.6%%) ===" % (mean, mean / 281 * 100), flush=True)
print("DONE fallback", flush=True)
