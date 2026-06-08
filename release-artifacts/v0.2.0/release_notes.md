# TRACE v0.2.0 Release Notes

Release date: 2026-06-08

## Release scope

TRACE v0.2.0 introduces **Cross-Competence Reliability (CCR)** as the primary
inter-rater reliability metric, implementing the Coefficient Engine of the
Cross-Competence Reliability: Method Specification v1.0 (Heart AI Foundation).

This is the first feature release since v0.1.x. It is additive: existing evidence
packages and the `irr_statistics.json` schema remain backward compatible.

## What changed

- **Gwet AC1/AC2 coefficient engine** (`src/trace_forensics/irr.py`):
  - `gwet_ac1` for nominal judgment surfaces (`behavioral_category`, `ai_role`)
  - `gwet_ac2` for the ordinal `vulnerability_level` surface, with quadratic
    agreement weights
  - Gwet's linearization standard error, 95% confidence interval, and a
    probabilistic benchmark band per coefficient
- **`compute_irr`** now emits a `cross_competence_reliability` block as the primary
  metric in `irr_statistics.json`, retaining Cohen's kappa and Krippendorff's alpha
  as secondary keys.
- **Probabilistic benchmarking** replaces fixed-threshold interpretation. Numeric
  benchmark bands only; Landis-Koch verbal labels are not applied to AC1/AC2.
- **Reproducibility/validity separation**: the CCR figure is labeled
  `reproducibility`, with a distinct `validity` field that stays null unless a
  reference standard is attached.
- New documentation: `docs/CROSS_COMPETENCE_RELIABILITY.md`.
- Updated `README.md`, `docs/VALIDATION.md`, `docs/EVIDENCE_PACKAGE_SPEC.md`.
- Version bumped to `0.2.0` in `pyproject.toml` and `src/trace_forensics/__init__.py`.

## Why this release exists

Forensic transcript classification has skewed marginals, under which Cohen's kappa
and Krippendorff's alpha hit the prevalence paradox — high observed agreement
collapses into a low coefficient. Gwet's AC1/AC2 remain stable under that skew, and
probabilistic benchmarking reports reliability with its error margin rather than
against a brittle fixed cutoff. CCR makes TRACE's reliability reporting defensible
under the conditions forensic judgment actually creates.

## Implementation notes

- Pure standard library. No new dependencies; the normal CDF for benchmarking uses
  `math.erf`.
- The AC1/AC2 point estimates and variance follow the published Gwet (2008, 2014)
  linearization and were cross-checked against a reference computation.
- Confidence intervals are reported unclamped; an upper bound above 1.0 at high
  agreement is the standard normal-approximation artifact and matches the reference
  implementation.

## Scope boundary

TRACE implements the CCR **Coefficient Engine** only. The Overlap Surface Registry,
Codebook Lifecycle Manager, Blind Coding Harness, Standing Reliability Ledger, and
Attestation Record components of the full CCR instrument are out of scope for TRACE.

## Validation posture at release

- unit and regression suite pass (92 tests)
- end-to-end `irr-import` → `irr-compute` verified on the bundled companion fixture
- evidence-package export remains backward compatible
- heuristic benchmark: 5/5 fixtures, 100% pass
- mock-hosted benchmark: 5/5 fixtures, 100% pass
- heuristic-vs-mock-hosted comparison: drift-free (0 drift across 5 references)

## Release artifacts

Bundled under `release-artifacts/v0.2.0/`:

- `benchmark_heuristic/` — heuristic profile bundle
- `benchmark_mock_hosted/` — mock-hosted profile bundle
- `benchmark_compare_heuristic_vs_mock-hosted/` — drift-free comparison
- `benchmark_history/` — dated history snapshots and trend summaries
- `release_notes.md`

Deferred operator steps (not included in this tag):

- **Signed bundles.** No project signing private key is available in this
  environment; bundles are unsigned. Signing with the Foundation's release key is
  an operator step per `docs/RELEASE_TAGGING.md`.
- **Live-hosted benchmark and heuristic-vs-live-hosted comparison.** These require
  `TRACE_HOSTED_API_KEY` / `TRACE_HOSTED_BASE_URL` and were not run for this tag.

## Current maturity

TRACE v0.2.0 remains a serious pre-production evaluation release.
