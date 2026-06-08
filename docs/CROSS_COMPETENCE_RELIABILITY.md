# Cross-Competence Reliability (CCR) in TRACE

Cross-Competence Reliability is the reliability metric TRACE reports for dual-coded
cases. It replaces a fixed-threshold Cohen's kappa / Krippendorff's alpha posture
with Gwet's AC1 and AC2 coefficients, reported with confidence intervals and a
probabilistic benchmark. This document explains what CCR measures, why TRACE uses
it, how to read the output, and where the method's authority and boundaries lie.

The method is defined externally in the **Cross-Competence Reliability: Method
Specification v1.0** (Heart AI Foundation, Mobley, 2026). This document covers the
TRACE implementation of that method's Coefficient Engine; it does not restate the
method's grounding or abandonment criteria.

## What CCR measures

CCR measures **reproducibility of interpretive judgment**: whether two independent
coders, applying the same codebook to the same transcript under blind conditions,
reproduce one another's classifications. The figure is a chance-corrected agreement
coefficient on the surface of judgments both coders are scoped to make.

CCR measures reproducibility, not accuracy. A high coefficient says the judgment is
repeatable, not that it is correct. Where a defensible reference standard exists
(for example, a labeled public dataset), agreement against that standard is a
*validity* check and is reported in a separate field — it is never blended into the
reproducibility figure.

## Why Gwet AC1/AC2 instead of kappa/alpha

Forensic transcript classification has skewed marginals: most messages are benign,
and the categories that matter forensically (acute crisis, harmful response) are
rare. Under that skew, Cohen's kappa and Krippendorff's alpha exhibit the
**prevalence paradox** — observed agreement is high, but the coefficient collapses
toward zero because the chance-correction term is inflated by the dominant category
(Feinstein and Cicchetti, 1990).

Gwet's AC1 (for nominal judgments) and AC2 (for ordinal judgments) use a chance
model that remains stable under marginal imbalance (Gwet, 2008; Wongpakaran et al.,
2013). They are the primary CCR coefficients for that reason. Kappa and alpha are
retained as secondary figures for continuity and cross-comparison.

A worked illustration of the divergence, on two coders that agree on 48 of 50 items
with a 92/8 split between categories:

| Coefficient | Value |
|-------------|-------|
| Observed agreement | 0.960 |
| Gwet AC1 | 0.953 |
| Cohen's kappa | 0.730 |

Same data, same 96% observed agreement. Kappa reads the raters as substantially less
reliable than they are; AC1 tracks the observed agreement faithfully.

## How TRACE applies CCR

TRACE coding produces three judgment surfaces per transcript. CCR is computed
independently on each:

| Surface | Type | Coefficient |
|---------|------|-------------|
| `behavioral_category` (Zhang et al. 2025 taxonomy) | nominal | Gwet AC1 |
| `ai_role` | nominal | Gwet AC1 |
| `vulnerability_level` (C-SSRS-derived scale) | ordinal | Gwet AC2 |

AC2 weights disagreements by how far apart the two ordinal levels are, using
quadratic agreement weights: a coder pair that disagrees by one vulnerability level
is penalized far less than one that disagrees by four.

The two coded vectors come from `trace classify` (coder 1) and an imported second
coding via `trace irr-import` (coder 2). When coder 2 is a reference-standard label
set rather than a second examiner, the same engine computes the figure, but the
result should be read as a validity check — see the reproducibility/validity note
above.

## Output structure

`trace irr-compute` writes `irr_statistics.json`. CCR is the primary block;
kappa/alpha follow as secondary keys.

```json
{
  "cross_competence_reliability": {
    "method": "Gwet AC1/AC2",
    "method_specification": "Cross-Competence Reliability: Method Specification v1.0",
    "interpretation": "reproducibility",
    "validity": null,
    "surfaces": {
      "behavioral_category": {
        "coefficient": 0.9531,
        "standard_error": 0.0341,
        "ci_95": [0.8863, 1.0199],
        "n": 50,
        "coefficient_type": "AC1",
        "benchmark": { "range": [0.8, 1.0], "cumulative_probability": 1.0, "threshold": 0.95 }
      },
      "ai_role": { "...": "AC1" },
      "vulnerability_level": { "...": "AC2" }
    }
  },
  "krippendorff_alpha_behavioral": 0.73,
  "krippendorff_alpha_vulnerability": 0.81,
  "cohen_kappa_behavioral": 0.73,
  "cohen_kappa_ai_roles": 0.78
}
```

Per-surface fields:

- `coefficient` — the AC1 or AC2 point estimate.
- `standard_error` — Gwet's linearization standard error (Gwet, 2008, 2014).
- `ci_95` — 95% Wald confidence interval. The interval is reported unclamped; an
  upper bound above 1.0 is the standard normal-approximation artifact at high
  agreement and is left as-is to match the reference implementation.
- `n` — number of coded units on that surface.
- `coefficient_type` — `AC1` (nominal) or `AC2` (ordinal).
- `benchmark` — the probabilistic benchmark band (below).

The `interpretation` field is `reproducibility`. The `validity` field is `null`
unless a reference standard is attached.

## Probabilistic benchmarking, not fixed cutoffs

TRACE does not classify a coefficient against a single cutoff such as "α ≥ 0.80".
A point estimate placed in a band ignores its error margin, and fixed cutoffs are
unreasonable for coders with high training variance — which cross-competence pairing
creates by design (Gwet, 2014; Wong, Paritosh, and Aroyo, 2021).

Instead, TRACE reports the highest benchmark band for which the cumulative
probability that the true coefficient sits at or above the band's lower edge exceeds
**0.95**. The bands are numeric ranges (`[0.8, 1.0]`, `[0.6, 0.8]`, …). Per the
method specification, Landis-Koch verbal labels ("substantial", "almost perfect")
are **not** applied to AC1/AC2; only the numeric band and its membership probability
are reported. A wide confidence interval — from a small sample or genuine
disagreement — pulls the assignment down to a lower band, so thin estimates cannot
masquerade as settled high reliability.

## Reproducibility versus validity

CCR makes a reproducibility claim and nothing more. This is a deliberate scoping
commitment (CCR Method Specification §5.6, §6): inter-rater reliability is a
necessary but not sufficient condition for validity, and no statistical accuracy
rate exists for many judgment-heavy forensic activities (McKemmish, 2008; Dror,
2020). Where ground truth is unavailable, reproducibility is the achievable and
honest property to report.

When a defensible reference standard becomes available, validity testing is added
**beside** the reliability figure in the distinct `validity` field — never merged
into it.

## CLI usage

```bash
trace irr-import  --case-id CASE-001 --coder-2-file ./coder2_classified_transcript.json --root ./trace-workspace
trace irr-compute --case-id CASE-001 --root ./trace-workspace
```

`irr-compute` prints every metric and writes `irr_statistics.json` into the case
directory. The file is carried into the exported evidence package unchanged.

## Scope of the TRACE implementation

TRACE implements the **Coefficient Engine** of the CCR Implementation Specification:
the AC1/AC2 computation, standard error, confidence interval, and probabilistic
benchmark. The remaining components of the full CCR instrument — the Overlap Surface
Registry, Codebook Lifecycle Manager, Blind Coding Harness, Standing Reliability
Ledger, and cryptographic Attestation Record — are out of scope for TRACE and are
not provided here.

## References

The method's load-bearing sources are recorded in the Cross-Competence Reliability:
Research Literature Synthesis v1.0. The sources directly relevant to this
implementation are:

- Gwet, K. L. (2008). Computing inter-rater reliability and its variance in the
  presence of high agreement. *British Journal of Mathematical and Statistical
  Psychology*, 61(1), 29–48.
- Gwet, K. L. (2014). *Handbook of Inter-Rater Reliability* (4th ed.).
- Feinstein, A. R., and Cicchetti, D. V. (1990). High agreement but low kappa.
  *Journal of Clinical Epidemiology*, 43(6), 543–549.
- Wongpakaran, N., et al. (2013). A comparison of Cohen's kappa and Gwet's AC1.
  *BMC Medical Research Methodology*, 13, 61.
- Wong, K., Paritosh, P., and Aroyo, L. (2021). Cross-replication reliability.
- Mobley, D. D. (2026). Cross-Competence Reliability: Method Specification v1.0.
  Heart AI Foundation.
