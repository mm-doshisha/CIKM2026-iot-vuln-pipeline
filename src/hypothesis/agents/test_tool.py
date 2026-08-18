"""TestRunner tool: Mock server management + behavioral testing + failure diagnosis.

Responsibilities:
  - test(): Start mock, run T1-T4, diagnose failures with LLM
  - Internal: crash retry (regenerate code on startup failure)
  - Internal: LLM-powered failure analysis for richer counterexamples
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ..analyst import _call_llm, _extract_json
from ..tester import run_tests, build_counterexample
from ..temperature import TEMP_GENERATIVE, TEMP_STRUCTURED

logger = logging.getLogger("test_runner")

TEST_DIAGNOSIS_ROLE = """\
You are a QA engineer specializing in behavioral testing of HTTP mock servers \
for automated CEGIS-based verification.

## Your Expertise
- Expert at diagnosing why a mock server's behavior deviates from the expected attack scenario
- Deep understanding of Flask request handling (args, form, json, path, cookies, headers)
- Knows how subtle parameter extraction bugs cause test failures

## Your Testing Framework
You run 4 behavioral equivalence tests:
- T1 (Positive Replay): Original attack request → server must respond (not 404/500) and log it
- T2 (Behavioral Impact): Attack parameter must trigger matched=True in server logs
- T3 (Benign Rejection): Safe input (param="safe_value") must NOT trigger matched=True
- T4 (Oracle Satisfaction): Server log must record dangerous_param processing with matched=True

## Your Diagnosis Framework
When a test fails, you analyze:
1. **Root cause**: Why exactly did this test fail? (wrong route, wrong param source, missing logic)
2. **Evidence**: What do the response body, status code, and server logs tell us?
3. **Hypothesis impact**: Is the failure due to bad code generation, or a fundamentally wrong hypothesis?
4. **Actionable fix**: What specific change would fix this? (be concrete, reference Flask APIs)"""


class TestRunner:

    def __init__(self, port: int = 9090, max_crash_retries: int = 1):
        self.port = port
        self.max_crash_retries = max_crash_retries
        self._mock_process = None
        self._work_dir = None
        atexit.register(self.cleanup)

    def test(self, flask_code: str, http_request: dict, analysis: dict,
             codegen=None, temperature: float = TEMP_GENERATIVE,
             decoded_request: dict = None,
             trace_response: dict = None,
             keep_mock_alive: bool = False) -> dict:
        """Run tests with internal crash retry orchestration.

        Internal orchestration:
          1. Start mock server
          2. If crash → ask CodeGen to regenerate → retry
          3. Run T1-T4 tests
          4. If tests fail → LLM-powered failure diagnosis
          5. Build enriched counterexample
        """
        logger.info("TestRunner: starting test cycle")

        # Step 1: Start mock with crash retry
        current_code = flask_code
        mock_started = False
        last_error = None

        for attempt in range(self.max_crash_retries + 1):
            try:
                self._start_mock(current_code)
                mock_started = True
                break
            except (RuntimeError, TimeoutError) as e:
                last_error = e
                if attempt < self.max_crash_retries and codegen:
                    logger.warning("TestRunner: mock crashed (attempt %d), requesting regeneration",
                                  attempt + 1)
                    crash_ce = {"failed_test": "MOCK_CRASH", "details": str(e)}
                    codegen_request = decoded_request or http_request
                    regen = codegen.generate(
                        codegen_request, analysis, crash_ce,
                        temperature=TEMP_GENERATIVE,
                        trace_response=trace_response)
                    if regen["success"]:
                        current_code = regen["flask_code"]
                    else:
                        break
                else:
                    logger.error("TestRunner: mock crashed, no more retries")

        if not mock_started:
            self.cleanup()
            return {
                "passed": False,
                "test_results": None,
                "counterexample": {
                    "failed_test": "MOCK_CRASH",
                    "details": str(last_error),
                },
                "flask_code": current_code,
                "mock_log": "",
                "error": f"mock_crash: {last_error}",
            }

        # Step 2: Run T1-T4 tests
        logger.info("TestRunner: running T1-T4")
        base_url = f"http://localhost:{self.port}"
        test_results = run_tests(base_url, http_request, analysis)

        mock_log = self._get_mock_log()
        if mock_log:
            logger.info("TestRunner: mock log:\n%s", mock_log[:500])

        all_pass = all(test_results[t]["passed"] for t in ("T1", "T2", "T3", "T4"))

        # Step 3: Build counterexample with LLM diagnosis if tests failed
        counterexample = None
        if not all_pass:
            base_ce = build_counterexample(test_results, analysis)
            counterexample = self._diagnose_failure(
                base_ce, test_results, http_request, analysis,
                current_code, mock_log)
            logger.info("TestRunner: tests failed (%s)",
                       counterexample["failed_test"] if counterexample else "unknown")
        else:
            logger.info("TestRunner: ALL TESTS PASSED")

        if not (keep_mock_alive and all_pass):
            self.cleanup()

        return {
            "passed": all_pass,
            "test_results": test_results,
            "counterexample": counterexample,
            "flask_code": current_code,
            "mock_log": mock_log,
            "error": None,
        }

    def _diagnose_failure(self, base_ce: dict, test_results: dict,
                          http_request: dict, analysis: dict,
                          flask_code: str, mock_log: str) -> dict:
        """Use LLM to diagnose test failure and enrich the counterexample."""
        if not base_ce:
            return base_ce

        try:
            failed_test = base_ce.get("failed_test", "unknown")
            test_detail = test_results.get(failed_test, {})

            diagnosis_prompt = f"""A behavioral test failed on a Flask mock server. Diagnose the root cause.

## Failed Test: {failed_test}
{base_ce.get("test_description", "")}

## Test Result Details
{json.dumps(test_detail, indent=2, default=str)[:1000]}

## HTTP Request
{http_request["method"]} {http_request["path"]}
Params: {json.dumps(http_request.get("params", {}), ensure_ascii=False)}

## Current Hypothesis
dangerous_param: {analysis.get("attack_hypothesis", {}).get("dangerous_param")}

## Flask Code (last 1500 chars)
{flask_code[-1500:]}

## Mock Server Log
{mock_log[:500]}

## Your Task
Analyze why {failed_test} failed. Return JSON:
{{
  "root_cause": "<one sentence: what exactly went wrong>",
  "is_hypothesis_wrong": true/false,
  "fix_type": "code_fix" | "hypothesis_revision" | "both",
  "specific_fix": "<concrete actionable fix for the code or hypothesis>"
}}
/no_think"""

            messages = [
                {"role": "system", "content": TEST_DIAGNOSIS_ROLE},
                {"role": "user", "content": diagnosis_prompt},
            ]
            diagnosis = _extract_json(
                _call_llm(messages, temperature=TEMP_STRUCTURED, max_tokens=256),
                "test_diagnosis")

            base_ce["llm_diagnosis"] = diagnosis
            if diagnosis.get("specific_fix"):
                base_ce["fix_hint"] = diagnosis["specific_fix"]
            logger.info("TestRunner: LLM diagnosis: %s (fix_type=%s)",
                       diagnosis.get("root_cause", "?")[:100],
                       diagnosis.get("fix_type", "?"))

        except Exception as e:
            logger.warning("TestRunner: LLM diagnosis failed: %s", e)

        return base_ce

    def cleanup(self):
        if self._mock_process and self._mock_process.poll() is None:
            self._mock_process.terminate()
            try:
                self._mock_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._mock_process.kill()
        self._mock_process = None

    def _start_mock(self, flask_code: str):
        self.cleanup()
        self._kill_port()

        work_dir = Path(tempfile.mkdtemp(prefix="hypothesis_mock_"))
        self._work_dir = work_dir
        app_path = work_dir / "app.py"

        patched_code = re.sub(r"(?m)^port\s*=\s*\d+", f"port = {self.port}", flask_code)
        if f"port = {self.port}" not in patched_code and f"port={self.port}" not in patched_code:
            patched_code = re.sub(r"port\s*=\s*\d+", f"port={self.port}", flask_code)
        if f"port" not in patched_code:
            patched_code = patched_code.replace(
                "app.run(",
                f"app.run(host='0.0.0.0', port={self.port}, "
            )

        app_path.write_text(patched_code, encoding="utf-8")

        mock_log = work_dir / "mock.log"
        log_fh = open(mock_log, "w")

        self._mock_process = subprocess.Popen(
            [sys.executable, str(app_path)],
            cwd=str(work_dir),
            stdout=log_fh,
            stderr=log_fh,
        )

        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                from urllib.request import urlopen
                from urllib.error import HTTPError
                urlopen(f"http://localhost:{self.port}", timeout=2)
                return
            except HTTPError:
                return
            except Exception:
                if self._mock_process.poll() is not None:
                    log_content = mock_log.read_text(encoding="utf-8", errors="replace")[:2000]
                    raise RuntimeError(f"Mock crashed on startup:\n{log_content}")
                time.sleep(1)

        log_content = mock_log.read_text(encoding="utf-8", errors="replace")[:2000]
        raise TimeoutError(f"Mock did not start within 30s:\n{log_content}")

    def _kill_port(self):
        my_pid = os.getpid()
        killed = False
        for cmd_args in [
            ["fuser", "-k", f"{self.port}/tcp"],
            ["ss", "-tlnp", f"sport = :{self.port}"],
        ]:
            try:
                result = subprocess.run(cmd_args, capture_output=True,
                                        text=True, timeout=5)
                if cmd_args[0] == "ss":
                    for m in re.finditer(r'pid=(\d+)', result.stdout):
                        pid = int(m.group(1))
                        if pid != my_pid:
                            os.kill(pid, signal.SIGKILL)
                            killed = True
                else:
                    killed = result.returncode == 0
                if killed:
                    return
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
            except Exception:
                continue
        try:
            port_hex = f'{self.port:04X}'
            with open('/proc/net/tcp', 'r') as f:
                for line in f:
                    fields = line.split()
                    if len(fields) < 10:
                        continue
                    local = fields[1]
                    if ':' not in local:
                        continue
                    if local.split(':')[1].upper() == port_hex:
                        inode = fields[9]
                        if inode == '0':
                            continue
                        self._kill_by_inode(inode, my_pid)
        except (FileNotFoundError, PermissionError):
            pass

    @staticmethod
    def _kill_by_inode(inode: str, my_pid: int):
        target = f'socket:[{inode}]'
        try:
            for entry in os.scandir('/proc'):
                if not entry.name.isdigit():
                    continue
                fd_dir = os.path.join(entry.path, 'fd')
                try:
                    for fd in os.scandir(fd_dir):
                        try:
                            if os.readlink(fd.path) == target:
                                pid = int(entry.name)
                                if pid != my_pid:
                                    os.kill(pid, signal.SIGKILL)
                                return
                        except (OSError, ValueError):
                            continue
                except (PermissionError, FileNotFoundError):
                    continue
        except Exception:
            pass

    def _get_mock_log(self) -> str:
        if self._work_dir:
            log_path = self._work_dir / "mock.log"
            if log_path.exists():
                return log_path.read_text(encoding="utf-8", errors="replace")[:2000]
        return ""
