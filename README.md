# IoT Vulnerability Detection Pipeline

Reproduction artifact for our CIKM 2026 paper. The pipeline takes a single
captured **HTTP attack request** and produces a **verified Suricata rule** that
detects the attack. A local LLM proposes a semantic detection condition; the
condition is checked with counterexample-guided inductive synthesis (CEGIS)
against benign traffic; a deterministic compiler then emits the Suricata rule.
The LLM never writes Suricata syntax. Everything runs locally — the only model
is a local `llama.cpp` server (no external API).

## Repository layout

```
src/hypothesis/      proposed method
  analyst*.py          LLM that identifies the dangerous parameter
  skeleton.py          mock-server / detection-condition synthesis
  agents/runner.py     CEGIS orchestration (synthesize <-> verify loop)
  agents/rule_agent.py rule generation; calls the deterministic compiler
  rule_template.py     assemble_rule — the deterministic Suricata compiler
  rmin_translator.py   mechanism pcre patterns / sid assignment
  rule_postprocess.py  url_decode normalization + post-processing
  rule_pcre_guard.py   drop phantom pcre guards
  mitre_mapping.py     ATT&CK technique id for rule metadata
src/evaluation/      firing-layer harness
  pcap_generator.py    build attack/benign PCAPs
  suricata_runner.py   run Suricata, collect alerts
  metrics.py           detection-rate / FPR aggregation
scripts/             entry points, baselines, table/figure generation
benchmarks/          attack traces (281 CVEs), benign traffic, ground truth
data/                extracted benign values, ATT&CK rule index
docker/              container build files for the Suricata / WAF eval targets
prompts/             all main pipeline-stage LLM prompts as plain text
examples/            5 complete pipeline output walkthroughs (JSON + markdown)
```

## Requirements

- Python 3.11; `pip install -r requirements.txt` (requests, numpy, matplotlib, flask)
- A local `llama.cpp` server hosting an instruction-tuned model (the paper uses
  Qwen3-8B in BF16). Start it yourself and point the pipeline at it with
  `LLM_PORT` (default 8080). Optional auto-start uses `LLAMA_SERVER_BIN` /
  `LLAMA_MODEL_PATH`.
- Suricata 7.x on `PATH` (firing-layer evaluation).
- `apptainer` or `docker` for the containerized evaluation targets under `docker/`.

## Data

`benchmarks/` ships everything needed to reproduce the main tables:

| path | content |
|---|---|
| `traces/` | 281 attack CVEs (one HTTP request each) |
| `traces_benign/` | self-benign traffic (synthesis-hygiene FPR) |
| `traces_unsw_benign/` | real IoT benign (cross-fire / deployment FPR) |
| `traces_benign_dev/` | held-out benign pool for CEGIS counterexample values |
| `heldout/`, `specs/` | held-out CVEs / request specs |
| `ground_truth.json` | per-CVE dangerous-parameter ground truth |
| `data/benign_values.json` | benign values used as CEGIS counterexamples |
| `data/et_rules_index.json` | ET Open rule index (ATT&CK metadata; third-party) |

`benchmarks/traces_benign_dev/` (held-out filter pool) is bundled; the larger
source pool `traces_benign_full/` (~45 MB) is omitted and is regenerable with
`scripts/make_dev_benign.py` + `scripts/sample_unsw_benign_stratified.py`.

## Reproduce

Start the local LLM server first and export `LLM_PORT`. All commands run from the
repository root.

### 1. Synthesize rules — proposed method

```bash
MECH_GATE=hard MECH_EXACT=1 RULE_FP_GATE=off ABLATE_REPAIR=1 \
FALLBACK_PARAM_NONE=1 FALLBACK_NULL=1 \
NO_LLM_RULE=1 URL_DECODE_NORM=1 GENERALIZE_MECH=1 \
python3 scripts/run_hypothesis_e2e.py \
    --traces-dir benchmarks/traces --pattern 'CVE-*.json' \
    --ground-truth benchmarks/ground_truth.json \
    --output-dir output/proposed/seed_42 \
    --seed 42 --workers 8 --max-iterations 10 \
    --no-classify --skip-existing
```

Repeat for `--seed 123` and `--seed 456` (the paper reports 3-seed results).

### 2. Evaluate — detection rate, cross-fire FPR

```bash
python3 scripts/eval_suricata_e2e.py \
    --pipeline-output output/proposed/seed_42 \
    --traces-dir benchmarks/traces \
    --ground-truth benchmarks/ground_truth.json \
    --benign-traces-dir benchmarks/traces_unsw_benign \
    --output-dir output/eval/proposed/seed_42 --workers 8
```

The report contains the detection rate and the cross-fire FPR on real IoT
benign traffic.

### 3. Ablation

Each component is removed by one flag, holding the rest of the proposed
configuration fixed:

| component (paper) | how to remove |
|---|---|
| iteration (CEGIS loop) | `--max-iterations 1` |
| agentic mechanism | `--no-agentic-policy` |
| counterexample diagnosis | env `ABLATE_DIRECT=1` |
| deterministic compiler | env `ABLATE_TEMPLATE=1` |
| memory | `--stateless-loop` |

Run each as in step 1, then evaluate as in step 2. Statistical tests:
`scripts/mcnemar_ablation.py`. Recovery-curve table: `scripts/cegis_recovery_table.py`.

### 4. Baselines

```bash
python3 scripts/baseline_gridai.py \
    --traces-dir benchmarks/traces --pattern 'CVE-*.json' \
    --output-dir output/gridai/seed_42 --seed 42 \
    --llm-endpoint http://127.0.0.1:$LLM_PORT/v1/chat/completions --workers 8
# then eval_suricata_e2e.py on output/gridai/seed_42 (as in step 2)
```

The five compared baselines are `baseline_{gridai,rulexploit,cmirgen,autocombo,moreno}.py`.
The non-LLM baselines (cmirgen, autocombo) take `--benign-dir`; pass the held-out
`benchmarks/traces_benign_dev` for the leakage-free numbers reported in the paper.

## Configuration reference

Pipeline behavior is controlled by environment variables (deployed values shown):

| variable | deployed | meaning |
|---|---|---|
| `NO_LLM_RULE` | `1` | LLM never writes rule syntax; compiler is fully deterministic |
| `URL_DECODE_NORM` | `1` | normalize buffers before literal matching (encoding robustness) |
| `GENERALIZE_MECH` | `1` | conditional mechanism generalization (pcre instead of literal) |
| `MECH_GATE` / `MECH_EXACT` | `hard` / `1` | mechanism gate (operating point pg2) |
| `ABLATE_REPAIR` | `1` | semantic-verify repair loop off (found neutral/harmful) |
| `FALLBACK_PARAM_NONE` / `FALLBACK_NULL` | `1` / `1` | param-localization fallbacks |
| `RULE_FP_GATE` | `off` | benign-FPR gate for rule acceptance (`off` = no gate) |

`MAX_ITERATIONS` / `ALT_ITERATIONS` set the CEGIS budget; `ABLATE_*` flags drive
the ablation. `LLM_PORT` selects the llama.cpp server.

## Prompts

The six main pipeline-stage prompts are extracted as plain text in `prompts/`,
numbered by pipeline stage:
`1_attack_analysis.txt` (parameter identification),
`2_condition_generation.txt` (CEGIS detection condition synthesis),
`3_counterexample_diagnosis.txt` (CEGIS failure diagnosis),
`4_reflection.txt` (re-synthesis direction),
`5_alternative_hypothesis.txt` (alternative parameter proposal),
`6_mock_server_generation.txt` (Flask mock server for verification).

## Pipeline output examples

`examples/` contains five complete pipeline outputs for representative CVEs
(command injection, path traversal, authentication bypass, header-based attack).
Each JSON records the full trace: input request, LLM analyst output, CEGIS
iteration history with counterexample feedback, and the final Suricata rule.
Two of the five (CVE-2014-8361, CVE-2019-16057) required CEGIS counterexample
refinement (iter > 0), demonstrating the feedback loop. See `examples/README.md`
for a walkthrough.

## Citation

If you use this work in your research, please cite:

```bibtex
@inproceedings{yamamoto2026cikm,
  author    = {Yamamoto, Kohei and Katsurai, Marie},
  booktitle = {Proceedings of the 35th ACM International Conference on Information and Knowledge Management (CIKM 2026)},
  title     = {Verification-Guided Specification Synthesis with Large Language Models for Intrusion Detection Rules},
  year      = {2026}
}
```

## License

Code is released under the MIT License (see `LICENSE`).
`data/et_rules_index.json` is derived from the third-party Emerging Threats Open
ruleset and retains its original license; its rule strings contain public
malware-detection indicators (domains, certificate subjects) that are part of the
dataset, not author information.
