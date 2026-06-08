# TRACE

TRACE (Trajectory Analysis for Conversational Evidence) is forensic software for analyzing AI-human conversational evidence with repeatable classification, benchmark governance, and auditable evidence packages.

TRACE implements the AI Behavioral Trajectory Forensics methodology. It ingests conversational transcripts, classifies system behavior and user vulnerability, computes repeatable forensic findings, and exports reviewable evidence packages for legal, investigative, and expert-review use.

The project is being built as a serious forensic workflow candidate rather than a research demo. The design priorities are repeatability, auditability, and bounded hosted-model risk.

## Start here

- Executive overview: `docs/EXECUTIVE_SUMMARY.md`
- External-facing brief: `docs/PARTNER_BRIEF.md`
- Adoption posture: `docs/ADOPTION_READINESS.md`
- Pilot plan: `docs/PILOT_EVALUATION.md`
- Lab operations: `docs/LAB_DEPLOYMENT_NOTES.md`
- First-run quickstart: `docs/FIRST_10_MINUTES.md`
- Install and release notes: `docs/INSTALL_AND_RELEASE.md`
- Packaging and demo: `docs/PACKAGING_AND_DEMO.md`
- CI and release automation: `.github/workflows/`
- Hosted provider setup: `docs/HOSTED_PROVIDER_SETUP.md`
- Adapter registry: `docs/ADAPTER_REGISTRY.md`
- Live-provider hardening: `docs/LIVE_PROVIDER_HARDENING.md`

## Status

TRACE is currently a working pre-production implementation with:

- transcript ingest, normalization, hashing, and chain-of-custody logging
- classification workflows with deterministic local heuristics, mock LLM mode, and hosted-provider integration paths
- rolling-window state summaries and human review modes
- correlation analysis for inappropriate response rate, pattern distribution, and crisis failure rate
- dual-coder import and Cross-Competence Reliability (CCR) computation via Gwet AC1/AC2, with Cohen's kappa and Krippendorff's alpha retained as secondary
- structured evidence-package export with manifest, verification output, audit log, schema versions, prompt templates, classified transcript outputs, Markdown report output, and PDF report output
- package verification and manifest signing commands
- detached manifest signature verification
- trust metadata for signed packages
- signing-certificate verification against a supplied CA file
- optional CRL-backed revocation checks during signing-certificate verification
- validation fixtures and automated tests

Current gaps to broader production deployment are primarily operational: deeper parser coverage, broader adversarial validation fixtures, and additional hardening for higher-volume hosted-model execution. See `docs/ROADMAP.md`.

## Forensic position

TRACE is a decision-support and evidence-packaging tool for trained examiners.

- TRACE does **not** make final forensic determinations.
- TRACE does **not** replace expert review.
- TRACE is designed to preserve provenance, human overrides, and repeatable outputs.

## Core capabilities

### Ingest

TRACE accepts conversational transcripts, computes source hashes before transformation, normalizes messages to an internal schema, and creates custody records suitable for later evidentiary review.

Supported inputs currently include:

- JSON transcripts
- CSV transcripts
- plain-text formatted transcripts
- court-style plain-text transcripts
- AXIOM-style JSON message exports
- UFED-style XML message exports

### Classification

TRACE classifies:

- **system messages** against the Zhang et al. (2025) behavioral taxonomy
- **user messages** against the TRACE C-SSRS-derived vulnerability scale

Classification can run through:

- deterministic local heuristics
- mock hosted-model mode for testability
- hosted-provider inference
- manual review pathways with accept / flag / override behavior
- examiner override rationale capture in classified output

### Correlation and reporting

From the classified transcript, TRACE computes:

- inappropriate response rate
- pattern distribution
- crisis failure rate

It then exports an evidence package containing machine-readable artifacts, a Markdown report summary, a PDF report, verification metadata, signing-ready manifests, and calibration-summary artifacts that make hosted-provider adjustments inspectable.

## Repository layout

```text
src/trace_forensics/
  cli.py          Command-line interface
  ingest.py       Input parsing, normalization, hashing, custody logging
  classify.py     Classification pipeline, windows, review loop
  heuristics.py   Deterministic fallback rules
  llm.py          Provider-backed model integration and normalization
  irr.py          Inter-rater reliability import and computation
  report.py       Correlation analysis and evidence package export
  schemas.py      Classification schema definitions
  prompts.py      Version-pinned prompt templates
  validation.py   Validation workflow
tests/
  test_trace.py   Automated verification
validation/
  companion_incident.json  Reference transcript fixture
  reference_benign_case.json  Baseline benign fixture
  reference_long_case.json    Long-form distress fixture
  reference_mixed_case.json   Mixed benign/harmful fixture
  reference_noisy_case.json   Noisy real-world style fixture
  parsers/                   Parser-format reference fixtures
```

## Installation

```bash
cd trace
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
trace init --root ./trace-workspace
./scripts/demo_trace.sh ./demo-workspace
```

## Quick start

### Check installation

```bash
trace version
trace init --root ./trace-workspace
trace config-check --provider heuristic
trace config-check --provider hosted
```

### Run validation

```bash
trace validate --reference ./validation/companion_incident.json
trace validate --reference ./validation/reference_long_case.json
trace validate --reference ./validation/companion_incident.json --root ./trace-workspace/validation_runs
trace benchmark --validation-dir ./validation
trace benchmark --validation-dir ./validation --profile mock-hosted --output-dir ./benchmark_artifacts
trace benchmark --validation-dir ./validation --profile live-hosted --output-dir ./benchmark_artifacts_live
trace benchmark --validation-dir ./validation --profile live-hosted --replay-dir ./replay_artifacts --replay-mode record --output-dir ./benchmark_artifacts_live
trace benchmark-replay --validation-dir ./validation --profile live-hosted --replay-dir ./replay_artifacts --output-dir ./benchmark_artifacts_replay
trace benchmark-compare --validation-dir ./validation --baseline-profile heuristic --candidate-profile mock-hosted --output-dir ./benchmark_comparison
trace benchmark-compare --validation-dir ./validation --baseline-profile heuristic --candidate-profile live-hosted --output-dir ./benchmark_comparison_live
trace benchmark-trend --history-dir ./benchmark_history --prefix benchmark_heuristic_latest
trace benchmark --validation-dir ./validation --output-dir ./benchmark_artifacts --history-dir ./benchmark_history --sign-private-key ./keys/benchmark_signer.pem --sign-public-key ./keys/benchmark_signer_public.pem --signing-certificate ./keys/benchmark_signer.crt
```

### End-to-end demo

```bash
trace ingest \
  --input ./validation/companion_incident.json \
  --format json \
  --case-id DEMO-001 \
  --examiner "Examiner-01" \
  --root ./trace-workspace

trace classify \
  --case-id DEMO-001 \
  --provider heuristic \
  --review-mode auto \
  --root ./trace-workspace

trace report \
  --case-id DEMO-001 \
  --examiner "Examiner-01" \
  --output ./trace-workspace/evidence_exports \
  --root ./trace-workspace
```

## CLI commands

### Initialize workspace

```bash
trace init --root ./trace-workspace
```

### Ingest

```bash
trace ingest --input transcript.json --format json --case-id CASE-001 --examiner "Examiner-01" --root ./trace-workspace
trace ingest --input court_transcript.txt --format court --case-id CASE-002 --examiner "Examiner-01" --root ./trace-workspace
trace ingest --input axiom_messages.json --format axiom --case-id CASE-003 --examiner "Examiner-01" --root ./trace-workspace
trace ingest --input ufed_messages.xml --format ufed --case-id CASE-004 --examiner "Examiner-01" --root ./trace-workspace
```

### Classify

```bash
trace classify --case-id CASE-001 --provider heuristic --root ./trace-workspace
trace classify --case-id CASE-001 --provider mock --model mock-model --window-size 4 --root ./trace-workspace
trace classify --case-id CASE-001 --provider hosted --model provider-default --root ./trace-workspace
trace classify --case-id CASE-001 --provider hosted --model provider-default --replay-dir ./trace-workspace/replay_artifacts --replay-mode record --root ./trace-workspace
trace classify --case-id CASE-001 --provider hosted --model provider-default --replay-dir ./trace-workspace/replay_artifacts --replay-mode replay-only --root ./trace-workspace
trace classify --case-id CASE-001 --manual --root ./trace-workspace
```

### Hosted-provider setup

TRACE’s hosted integration surface is:

- `TRACE_HOSTED_API_KEY`
- `TRACE_HOSTED_BASE_URL`
- `TRACE_HOSTED_MODEL` (optional)
- `TRACE_HOSTED_ADAPTER` (optional, defaults to `openai-compatible`)

TRACE currently supports explicit hosted adapters:

- `openai-compatible`
- `anthropic-messages`

Minimal setup:

```bash
cp .env.example .env
trace config-check --provider hosted
trace config-check --provider hosted --hosted-adapter anthropic-messages --hosted-base-url https://provider.example/v1/messages
```

### Cross-Competence Reliability (inter-rater reliability)

```bash
trace irr-import --case-id CASE-001 --coder-2-file ./coder2_classified_transcript.json --root ./trace-workspace
trace irr-compute --case-id CASE-001 --root ./trace-workspace
```

`irr-compute` reports Cross-Competence Reliability (CCR) as the primary metric:
Gwet AC1 for nominal judgment surfaces (behavioral category, AI role) and AC2 for
the ordinal vulnerability scale, each with standard error, a 95% confidence
interval, and a probabilistic benchmark band. AC1/AC2 stay stable under the
skewed marginals typical of forensic judgment, where Cohen's kappa and
Krippendorff's alpha — retained as secondary figures — collapse into the
prevalence paradox. The coefficient is a reproducibility measure; validity
against a reference standard is reported in a separate field. See the CCR Method
Specification v1.0 for the method, grounding, and abandonment criteria.

### Report export

```bash
trace report --case-id CASE-001 --examiner "Examiner-01" --output ./trace-workspace/evidence_exports --root ./trace-workspace
```

### Package verification and signing

```bash
trace verify-package --package ./evidence/CASE-001
trace sign-package --package ./evidence/CASE-001 --private-key ./keys/trace_manifest_signing.pem --public-key ./keys/trace_manifest_signing.pub.pem --signing-certificate ./keys/trace_manifest_signing.crt
trace verify-signature --package ./evidence/CASE-001 --public-key ./keys/trace_manifest_signing.pub.pem --ca-file ./keys/trace_ca.pem --crl-file ./keys/trace_ca.crl
```

### Validation

```bash
trace validate --reference ./validation/companion_incident.json
trace benchmark --validation-dir ./validation
trace benchmark --validation-dir ./validation --profile mock-hosted --output-dir ./benchmark_artifacts
trace benchmark --validation-dir ./validation --profile live-hosted --output-dir ./benchmark_artifacts_live
trace benchmark --validation-dir ./validation --profile live-hosted --replay-dir ./replay_artifacts --replay-mode record --output-dir ./benchmark_artifacts_live
trace benchmark-replay --validation-dir ./validation --profile live-hosted --replay-dir ./replay_artifacts --output-dir ./benchmark_artifacts_replay
trace benchmark-compare --validation-dir ./validation --baseline-profile heuristic --candidate-profile mock-hosted --output-dir ./benchmark_comparison
trace benchmark-history --history-dir ./benchmark_history --prefix benchmark_heuristic_latest
trace benchmark-trend --history-dir ./benchmark_history --prefix benchmark_heuristic_latest
```

## Quality and forensic controls

TRACE is designed around the following controls:

- hashing before transformation
- explicit chain-of-custody artifacts
- version-pinned schema and prompt metadata
- audit logging for ingest, classification, IRR, and export events
- deterministic fallback behavior when provider output is unavailable or malformed
- dual-coder support and IRR computation
- package verification against exported manifest hashes
- examiner override rationale preservation in classified output
- detached signature verification for signed manifests
- signer trust metadata preserved alongside manifest signatures
- malformed parser fixtures included for regression coverage
- optional examiner notes included in exported reports
- report appendices include artifact checklist and correlation snapshot
- benchmark artifacts can be signed and archived as history snapshots

## Project policies

- Contribution guidance: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Product intent: `docs/PRODUCT_GOALS.md`
- Adoption readiness: `docs/ADOPTION_READINESS.md`
- Executive summary: `docs/EXECUTIVE_SUMMARY.md`
- Partner brief: `docs/PARTNER_BRIEF.md`
- Pilot evaluation guide: `docs/PILOT_EVALUATION.md`
- Lab deployment notes: `docs/LAB_DEPLOYMENT_NOTES.md`
- Roadmap: `docs/ROADMAP.md`
- Validation posture: `docs/VALIDATION.md`
- Benchmark governance: `docs/BENCHMARK_GOVERNANCE.md`
- Provider drift policy: `docs/PROVIDER_DRIFT_POLICY.md`
- Live-provider hardening notes: `docs/LIVE_PROVIDER_HARDENING.md`
- Release checklist: `docs/RELEASE_CHECKLIST.md`
- Release tagging: `docs/RELEASE_TAGGING.md`
- Evidence package specification: `docs/EVIDENCE_PACKAGE_SPEC.md`
- Architecture: `docs/ARCHITECTURE.md`
- Threat model: `docs/THREAT_MODEL.md`
- Example exported artifacts: `examples/README.md`

The repository also includes a signed `live_hosted` benchmark example and a signed `heuristic` vs `live-hosted` comparison example so external reviewers can inspect real provider drift rather than only mock-hosted behavior. The current committed live-provider example records observed drift against the heuristic baseline instead of presenting a sanitized pass-only story.

The repository also includes replay-hardened live-provider example artifacts under `examples/benchmark_artifacts/live_hosted_hardened/` and `examples/benchmark_comparison_live_hosted_hardened/` so reviewers can inspect the post-hardening bounded-drift state described in `docs/LIVE_PROVIDER_HARDENING.md`.

The companion evidence package example under `examples/companion_incident_package/` is also committed in signed form and includes `calibration_summary.json`, `manifest.sig`, and `trust_metadata.json` so reviewers can inspect package-level calibration and signing outputs directly.

## Development notes

- Python 3.11+ is recommended.
- Hosted-model execution may require API credentials and network access.
- Hosted-provider testing is supported, but hosted providers may return schema-drifting output; TRACE normalizes common deviations and falls back safely when needed.
- The `live-hosted` benchmark profile requires `TRACE_HOSTED_API_KEY` and `TRACE_HOSTED_BASE_URL`, and defaults to `provider-default` unless `TRACE_HOSTED_MODEL` is set.
- Hosted execution currently supports the `openai-compatible` and `anthropic-messages` adapter contracts. See `docs/HOSTED_PROVIDER_SETUP.md`.
- Hosted replay harness support is available through `trace classify --replay-dir ... --replay-mode record|replay-only` so provider outputs can be captured once and replayed locally.
- Exported reports, manifests, and benchmark artifacts now preserve provider, model, and adapter metadata for later review.

## License

MIT. See `LICENSE`.
