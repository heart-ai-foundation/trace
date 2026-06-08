from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Callable, Iterable

from trace_forensics.storage import append_jsonl, read_json, utc_now_iso, write_json

# Cross-Competence Reliability (CCR) coefficient engine.
#
# Implements Gwet's AC1 (nominal) and AC2 (ordinal) chance-corrected agreement
# coefficients with the linearization variance from Gwet (2008, 2014), 95%
# confidence intervals, and probabilistic benchmarking. These are the CCR
# primary coefficients: under the skewed marginals typical of rare-event
# forensic judgment, Cohen's kappa and Krippendorff's alpha exhibit the
# prevalence paradox, whereas AC1/AC2 stay stable under imbalance.
#
# Reference: Cross-Competence Reliability: Method Specification v1.0 (§5.1, §5.2,
# §5.5) and Implementation Specification v1.0 (Coefficient Engine, Slice 1).
# Per Method Spec §5.1, Landis-Koch verbal labels are not applied to AC1/AC2;
# the benchmark reports a numeric band and its membership probability only.

CCR_METHOD = "Gwet AC1/AC2"
CCR_METHOD_SPECIFICATION = "Cross-Competence Reliability: Method Specification v1.0"

# Benchmark band edges (high to low). Reported as numeric ranges, not labels.
_BENCHMARK_BANDS = ((0.8, 1.0), (0.6, 0.8), (0.4, 0.6), (0.2, 0.4), (0.0, 0.2))
_BENCHMARK_THRESHOLD = 0.95


def _norm_cdf(z: float) -> float:
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def _probabilistic_benchmark(coefficient: float, standard_error: float) -> dict:
    # Method Spec §5.2: retain the highest band whose cumulative probability that
    # the true coefficient sits at or above the band's lower edge exceeds 0.95.
    for lower, upper in _BENCHMARK_BANDS:
        if standard_error <= 0:
            cumulative = 1.0 if coefficient >= lower else 0.0
        else:
            cumulative = 1.0 - _norm_cdf((lower - coefficient) / standard_error)
        if cumulative >= _BENCHMARK_THRESHOLD:
            return {
                "range": [lower, upper],
                "cumulative_probability": round(cumulative, 4),
                "threshold": _BENCHMARK_THRESHOLD,
            }
    return {"range": None, "cumulative_probability": None, "threshold": _BENCHMARK_THRESHOLD}


def _gwet_coefficient(
    values_a: list,
    values_b: list,
    categories: list,
    weight: Callable[[object, object], float],
    coefficient_type: str,
) -> dict:
    n = len(values_a)
    if n == 0:
        return {
            "coefficient": 1.0,
            "standard_error": 0.0,
            "ci_95": [1.0, 1.0],
            "n": 0,
            "coefficient_type": coefficient_type,
            "benchmark": _probabilistic_benchmark(1.0, 0.0),
        }

    q = len(categories)
    index = {category: position for position, category in enumerate(categories)}
    weights = [[weight(categories[i], categories[j]) for j in range(q)] for i in range(q)]
    total_weight = sum(weights[i][j] for i in range(q) for j in range(q))

    # Mean category proportion across the two raters (Gwet's pi_k).
    pi = [0.0] * q
    for left, right in zip(values_a, values_b, strict=True):
        pi[index[left]] += 0.5
        pi[index[right]] += 0.5
    pi = [value / n for value in pi]

    observed = sum(weights[index[left]][index[right]] for left, right in zip(values_a, values_b, strict=True)) / n

    # A single category means both raters always pick it: perfect, error-free.
    if q <= 1:
        return {
            "coefficient": 1.0,
            "standard_error": 0.0,
            "ci_95": [1.0, 1.0],
            "n": n,
            "coefficient_type": coefficient_type,
            "benchmark": _probabilistic_benchmark(1.0, 0.0),
        }

    expected = (total_weight / (q * (q - 1))) * sum(p * (1 - p) for p in pi)
    coefficient = 1.0 if expected >= 1.0 else (observed - expected) / (1 - expected)

    if n < 2 or expected >= 1.0:
        standard_error = 0.0
    else:
        denominator = 1 - expected
        per_subject = []
        for left, right in zip(values_a, values_b, strict=True):
            agreement = weights[index[left]][index[right]]
            expected_i = (total_weight / (q * (q - 1))) * (
                0.5 * (1 - pi[index[left]]) + 0.5 * (1 - pi[index[right]])
            )
            linearized = (agreement - expected) / denominator - 2 * (1 - coefficient) * (expected_i - expected) / denominator
            per_subject.append(linearized)
        variance = sum((value - coefficient) ** 2 for value in per_subject) / (n * (n - 1))
        standard_error = math.sqrt(variance) if variance > 0 else 0.0

    return {
        "coefficient": round(coefficient, 4),
        "standard_error": round(standard_error, 4),
        "ci_95": [round(coefficient - 1.96 * standard_error, 4), round(coefficient + 1.96 * standard_error, 4)],
        "n": n,
        "coefficient_type": coefficient_type,
        "benchmark": _probabilistic_benchmark(coefficient, standard_error),
    }


def gwet_ac1(values_a: list[str], values_b: list[str]) -> dict:
    if len(values_a) != len(values_b):
        raise ValueError("Gwet AC1 requires equal-length input")
    categories = sorted(set(values_a) | set(values_b))
    return _gwet_coefficient(values_a, values_b, categories, lambda k, l: 1.0 if k == l else 0.0, "AC1")


def gwet_ac2(values_a: list[int], values_b: list[int]) -> dict:
    if len(values_a) != len(values_b):
        raise ValueError("Gwet AC2 requires equal-length input")
    categories = sorted(set(values_a) | set(values_b))
    value_range = (categories[-1] - categories[0]) if len(categories) > 1 else 0

    def weight(k: int, l: int) -> float:
        if value_range == 0:
            return 1.0
        return 1.0 - ((k - l) / value_range) ** 2

    return _gwet_coefficient(values_a, values_b, categories, weight, "AC2")


def cohen_kappa(values_a: list[str], values_b: list[str]) -> float:
    if len(values_a) != len(values_b):
        raise ValueError("Cohen's kappa requires equal-length input")
    if not values_a:
        return 1.0
    observed = sum(1 for left, right in zip(values_a, values_b, strict=True) if left == right) / len(values_a)
    counts_a = Counter(values_a)
    counts_b = Counter(values_b)
    categories = set(counts_a) | set(counts_b)
    expected = sum((counts_a[c] / len(values_a)) * (counts_b[c] / len(values_b)) for c in categories)
    if expected == 1.0:
        return 1.0
    return (observed - expected) / (1 - expected)


def _distance(a: int, b: int, value_range: int) -> float:
    if value_range <= 0:
        return 0.0
    return ((a - b) / value_range) ** 2


def krippendorff_alpha_nominal(values_a: list[str], values_b: list[str]) -> float:
    if len(values_a) != len(values_b):
        raise ValueError("Krippendorff alpha requires equal-length input")
    n = len(values_a)
    if n == 0:
        return 1.0
    observed = sum(0 if left == right else 1 for left, right in zip(values_a, values_b, strict=True)) / n
    pooled = values_a + values_b
    counts = Counter(pooled)
    total = len(pooled)
    expected = 1 - sum((count / total) ** 2 for count in counts.values())
    if expected == 0:
        return 1.0
    return 1 - (observed / expected)


def krippendorff_alpha_ordinal(values_a: list[int], values_b: list[int]) -> float:
    if len(values_a) != len(values_b):
        raise ValueError("Krippendorff alpha requires equal-length input")
    if not values_a:
        return 1.0
    min_value = min(values_a + values_b)
    max_value = max(values_a + values_b)
    value_range = max_value - min_value
    observed = sum(_distance(left, right, value_range) for left, right in zip(values_a, values_b, strict=True)) / len(values_a)

    pooled = values_a + values_b
    total_pairs = 0
    total_distance = 0.0
    for left in pooled:
        for right in pooled:
            total_distance += _distance(left, right, value_range)
            total_pairs += 1
    expected = total_distance / total_pairs if total_pairs else 0.0
    if expected == 0:
        return 1.0
    return 1 - (observed / expected)


def import_second_coder(case_dir: Path, coder_file: Path) -> Path:
    data = read_json(coder_file)
    output_path = case_dir / "coder2_classified_transcript.json"
    write_json(output_path, data)
    append_jsonl(
        case_dir / "audit_log.jsonl",
        {
            "timestamp": utc_now_iso(),
            "event": "irr_import",
            "coder_file": str(coder_file),
            "stored_as": str(output_path),
        },
    )
    return output_path


def _collect_metrics(transcript: Iterable[dict], transcript2: Iterable[dict]) -> tuple[list[str], list[str], list[str], list[str], list[int], list[int]]:
    behavior_1: list[str] = []
    behavior_2: list[str] = []
    roles_1: list[str] = []
    roles_2: list[str] = []
    vuln_1: list[int] = []
    vuln_2: list[int] = []

    for left, right in zip(transcript, transcript2, strict=True):
        if left["speaker"] != right["speaker"]:
            raise ValueError("Transcript mismatch between coders")
        if left["speaker"] == "system":
            behavior_1.append(left["classification"]["behavioral_category"])
            behavior_2.append(right["classification"]["behavioral_category"])
            roles_1.append(left["classification"]["ai_role"])
            roles_2.append(right["classification"]["ai_role"])
        else:
            vuln_1.append(int(left["classification"]["vulnerability_level"]))
            vuln_2.append(int(right["classification"]["vulnerability_level"]))
    return behavior_1, behavior_2, roles_1, roles_2, vuln_1, vuln_2


def compute_irr(case_dir: Path) -> dict:
    coder1 = read_json(case_dir / "classified_transcript.json")
    coder2 = read_json(case_dir / "coder2_classified_transcript.json")
    behavior_1, behavior_2, roles_1, roles_2, vuln_1, vuln_2 = _collect_metrics(
        coder1["transcript"], coder2["transcript"]
    )
    stats = {
        "cross_competence_reliability": {
            "method": CCR_METHOD,
            "method_specification": CCR_METHOD_SPECIFICATION,
            "interpretation": "reproducibility",
            "validity": None,
            "surfaces": {
                "behavioral_category": gwet_ac1(behavior_1, behavior_2),
                "ai_role": gwet_ac1(roles_1, roles_2),
                "vulnerability_level": gwet_ac2(vuln_1, vuln_2),
            },
        },
        "krippendorff_alpha_behavioral": round(krippendorff_alpha_nominal(behavior_1, behavior_2), 4),
        "krippendorff_alpha_vulnerability": round(krippendorff_alpha_ordinal(vuln_1, vuln_2), 4),
        "cohen_kappa_behavioral": round(cohen_kappa(behavior_1, behavior_2), 4),
        "cohen_kappa_ai_roles": round(cohen_kappa(roles_1, roles_2), 4),
    }
    write_json(case_dir / "irr_statistics.json", stats)
    append_jsonl(
        case_dir / "audit_log.jsonl",
        {
            "timestamp": utc_now_iso(),
            "event": "irr_computed",
            "statistics": stats,
        },
    )
    return stats
