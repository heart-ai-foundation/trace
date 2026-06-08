# TRACE Evidence Package Specification

TRACE exports an evidence package intended to preserve the full analytical path from transcript ingest through report generation.

## Purpose

The evidence package is designed to support:

- reproducibility
- adversarial review
- chain-of-custody inspection
- output verification
- examiner transparency

## Core package contents

TRACE currently exports the following artifacts:

```text
evidence_package/
  manifest.json
  manifest.sig
  trust_metadata.json
  verification.json
  override_summary.json
  calibration_summary.json
  forensic_report.pdf
  chain_of_custody.json
  source_transcript.json
  classified_transcript.json
  classified_transcript.csv
  correlation_analysis.json
  irr_statistics.json
  forensic_report.json
  forensic_report.md
  audit_log.jsonl
  configuration/
    model_config.json
    schema_versions.json
    prompt_templates/
```

## Artifact roles

### `manifest.json`

Contains package-level metadata including:

- case identifier
- export timestamp
- examiner identifier
- source hash
- classified transcript hash
- package hash
- schema versions
- prompt template versions
- classification mode
- IRR statistics summary

The package hash is computed over exported package contents while excluding `verification.json` and any detached signature file. The `package_hash_sha256` field is blanked during hash derivation so the manifest can verify itself without circular dependence.

### `manifest.sig`

Optional detached signature generated for `manifest.json`. TRACE can verify this signature against a supplied public key through the CLI.

### `trust_metadata.json`

Stores signing-context metadata including:

- signature algorithm
- signer label
- public key filename
- public key hash
- optional signing certificate path
- optional certificate-chain file hashes
- signer label and verification context used during detached-signature review

### `verification.json`

Stores verification results for:

- source hash presence
- classified transcript hash match
- package hash match
- aggregate verification pass/fail

### `override_summary.json`

Stores a case-level summary of:

- accepted classifications
- flagged classifications
- overridden classifications
- per-message override rationales when present

### `calibration_summary.json`

Stores a case-level summary of vulnerability calibration behavior, including:

- user messages reviewed for calibration provenance
- messages where calibration rules were applied
- counts of raised, lowered, and unchanged outcomes
- per-rule application counts
- per-message calibration detail for turns where rules fired

### `chain_of_custody.json`

Records ingest and handling events from source acquisition into TRACE processing.

### `source_transcript.json`

Stores the normalized source transcript used for TRACE analysis.

### `classified_transcript.json`

Stores per-message classifications, reasoning, confidence, review state, override rationale, state summaries, and calibration provenance for user-vulnerability turns.

### `classified_transcript.csv`

Provides a spreadsheet-friendly export for inspection and interoperability.

### `correlation_analysis.json`

Stores the raw findings computation, including:

- inappropriate response rate
- pattern distribution
- crisis failure rate
- supporting correlation pairs

### `irr_statistics.json`

Stores inter-rater reliability outputs when dual-coder workflows are used.

The primary metric is the Cross-Competence Reliability (CCR) coefficient set under
`cross_competence_reliability`: Gwet AC1 for the nominal judgment surfaces
(`behavioral_category`, `ai_role`) and AC2 for the ordinal surface
(`vulnerability_level`), each reported with its standard error, 95% confidence
interval, and a probabilistic benchmark band. The figure is a reproducibility
measure; the distinct `validity` field stays null unless a reference standard is
attached (CCR Method Specification v1.0 §5.6). Cohen's kappa and Krippendorff's
alpha are retained as secondary keys for continuity. Under the skewed marginals
typical of forensic judgment, AC1/AC2 stay stable where kappa and alpha collapse
into the prevalence paradox.

### `forensic_report.json`, `forensic_report.md`, and `forensic_report.pdf`

Provide machine-readable, Markdown, and PDF report outputs, including:

- case overview metrics
- findings summary metrics
- review summary counts
- calibration summary counts and rule distribution
- methodology notes
- examiner notes when supplied
- artifact inventory references

### `audit_log.jsonl`

Records operational events, including ingest, classification, IRR, and export steps.

### `configuration/`

Preserves configuration context:

- model/provider metadata
- schema versions
- prompt template versions and contents

## Design principles

The evidence package is designed to be:

- inspectable without TRACE-specific hidden state
- reproducible from stored artifacts
- explicit about provider/model context
- explicit about schema and prompt versions
- suitable for review by opposing experts and counsel

## Current limitations

The current package format does not yet include:

- authenticated timestamping or external attestation
- embedded certificate-chain handling for signed manifests
- trust-store integration beyond explicit CA / CRL inputs

Those are planned future enhancements rather than current guarantees.
