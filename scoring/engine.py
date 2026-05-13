from dataclasses import dataclass
from typing import List, Optional

from parser.normalizer import CheckResult, DETECTED, NOT_DETECTED

# Risk thresholds map a global transparency score to a risk label.
# A lower score means the environment is more detectable = higher risk.
_RISK_THRESHOLDS = [
    (0.85, "LOW"),
    (0.65, "MEDIUM"),
    (0.40, "HIGH"),
    (0.00, "CRITICAL"),
]


def compute_risk_level(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    for threshold, label in _RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "CRITICAL"


@dataclass
class CategoryScore:
    category_id: str
    name: str
    weight: float
    score: Optional[float]      # None if all checks errored/unsupported
    checks_count: int
    detected_count: int
    not_detected_count: int
    error_count: int


@dataclass
class ScoreReport:
    global_score: Optional[float]
    risk_level: str             # LOW / MEDIUM / HIGH / CRITICAL / UNKNOWN
    detection_rate: float       # detected / (detected + not_detected), 0–1
    category_scores: List[CategoryScore]
    total_checks: int
    detected_count: int
    not_detected_count: int
    error_count: int


class ScoringEngine:
    def __init__(self, config: dict):
        self.detected_value = float(config.get("detected_value", 0.0))
        self.not_detected_value = float(config.get("not_detected_value", 1.0))
        self.error_behavior = config.get("error_behavior", "exclude")

    def _check_value(self, normalized: str) -> Optional[float]:
        if normalized == DETECTED:
            return self.detected_value
        if normalized == NOT_DETECTED:
            return self.not_detected_value
        return None

    def score(self, check_results: List[CheckResult], categories: list) -> ScoreReport:
        cat_map = {c["id"]: c for c in categories}

        buckets: dict = {}
        for r in check_results:
            buckets.setdefault(r.category_id, []).append(r)

        category_scores: List[CategoryScore] = []
        weighted_sum = 0.0
        total_weight = 0.0

        for cat_id, checks in buckets.items():
            cat_cfg = cat_map.get(cat_id, {"name": cat_id, "weight": 0.0})
            weight = float(cat_cfg.get("weight", 0.0))

            values = [self._check_value(c.normalized) for c in checks]
            valid_values = [v for v in values if v is not None]

            detected = sum(1 for c in checks if c.normalized == DETECTED)
            not_detected = sum(1 for c in checks if c.normalized == NOT_DETECTED)
            errors = len(checks) - detected - not_detected

            cat_score = (sum(valid_values) / len(valid_values)) if valid_values else None

            category_scores.append(CategoryScore(
                category_id=cat_id,
                name=cat_cfg.get("name", cat_id),
                weight=weight,
                score=cat_score,
                checks_count=len(checks),
                detected_count=detected,
                not_detected_count=not_detected,
                error_count=errors,
            ))

            if cat_score is not None and weight > 0:
                weighted_sum += cat_score * weight
                total_weight += weight

        global_score = round(weighted_sum / total_weight, 4) if total_weight > 0 else None

        total = len(check_results)
        detected_total = sum(1 for r in check_results if r.normalized == DETECTED)
        not_detected_total = sum(1 for r in check_results if r.normalized == NOT_DETECTED)
        error_total = total - detected_total - not_detected_total

        # Detection rate is computed only over scored categories (weight > 0).
        # Including uncategorized checks would dilute the metric with results
        # that have no bearing on the scenario's transparency score.
        scored_cats = [c for c in category_scores if c.weight > 0]
        scored_detected = sum(c.detected_count for c in scored_cats)
        scored_total = sum(c.checks_count for c in scored_cats)
        detection_rate = round(scored_detected / scored_total, 4) if scored_total > 0 else 0.0

        return ScoreReport(
            global_score=global_score,
            risk_level=compute_risk_level(global_score),
            detection_rate=detection_rate,
            category_scores=sorted(category_scores, key=lambda c: -c.weight),
            total_checks=total,
            detected_count=detected_total,
            not_detected_count=not_detected_total,
            error_count=error_total,
        )
