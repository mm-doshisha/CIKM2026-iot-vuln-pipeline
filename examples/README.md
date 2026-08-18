# Pipeline Output Examples

Five complete pipeline runs on real CVE attack traces. Each CVE has two files:

- **`.json`** — raw pipeline output (machine-readable, all fields)
- **`.md`** — step-by-step walkthrough (human-readable, key fields extracted)

## Examples

| CVE | attack type | CEGIS iterations | walkthrough |
|---|---|---|---|
| [CVE-2010-5330](CVE-2010-5330.md) | Command injection | 1 (first attempt) | [view](CVE-2010-5330.md) |
| [CVE-2014-8361](CVE-2014-8361.md) | Command injection via UPnP | 2 (counterexample feedback) | [view](CVE-2014-8361.md) |
| [CVE-2018-10561](CVE-2018-10561.md) | Command injection (GPON) | 1 (first attempt) | [view](CVE-2018-10561.md) |
| [CVE-2019-16057](CVE-2019-16057.md) | Command injection via login | 2 (counterexample feedback) | [view](CVE-2019-16057.md) |
| [CVE-2015-2051](CVE-2015-2051.md) | Command injection via SOAP header | 1 (first attempt) | [view](CVE-2015-2051.md) |

CVE-2014-8361 and CVE-2019-16057 demonstrate the CEGIS feedback loop: the
initial condition fails verification, the system diagnoses the cause, and a
revised condition passes on the next attempt.

## What each walkthrough shows

Each `.md` follows the same structure:

1. **Input** — the raw HTTP request (the only input)
2. **LLM analysis** — the dangerous parameter identified by the LLM
3. **Detection condition** — the Python condition generated for CEGIS verification (NOT a Suricata rule)
4. **CEGIS verification** — T1-T4 test results; counterexample feedback if iteration > 0
5. **Deterministic compiler** — what the compiler receives (HTTP request + parameter name) and what it extracts deterministically (method, path, attack value, attack type, pcre pattern)
6. **Output Suricata rule** — the final rule

The key design point visible in every example: the LLM determines **which
parameter** to look at. The compiler determines **everything else** (method,
path, attack value extraction, attack type classification, pcre pattern, buffer
assignment) deterministically from the HTTP request. The detection condition is
used only for CEGIS verification and is not forwarded to the compiler.

## Prompts

The six main pipeline-stage prompts are in [`prompts/`](../prompts/).
Additional prompts used internally by the agentic tools are in the
source files (`agents/analyst_tool.py`, `agents/test_tool.py`, `agents/runner.py`):

| file | role | pipeline stage |
|---|---|---|
| [`1_attack_analysis.txt`](../prompts/1_attack_analysis.txt) | identify the dangerous parameter | front half: analyst |
| [`2_condition_generation.txt`](../prompts/2_condition_generation.txt) | generate Python detection condition | front half: CEGIS synthesizer |
| [`3_counterexample_diagnosis.txt`](../prompts/3_counterexample_diagnosis.txt) | diagnose CEGIS failure and direct next attempt | front half: CEGIS feedback |
| [`4_reflection.txt`](../prompts/4_reflection.txt) | reflect on verification failure | front half: CEGIS feedback |
| [`5_alternative_hypothesis.txt`](../prompts/5_alternative_hypothesis.txt) | propose alternative parameter | front half: fallback |
| [`6_mock_server_generation.txt`](../prompts/6_mock_server_generation.txt) | generate Flask mock server for verification | front half: CEGIS verifier |
