import dataclasses
from dataclasses import dataclass
from typing import Dict, List, Optional

from parser.normalizer import CheckResult, DETECTED, NOT_DETECTED

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
    category_id:       str
    name:              str
    weight:            float
    score:             Optional[float]
    checks_count:      int
    detected_count:    int
    not_detected_count:int
    error_count:       int
    dedup_count:       int = 0   # checks that were merged from multiple tools


@dataclass
class ScoreReport:
    global_score:       Optional[float]
    risk_level:         str
    detection_rate:     float
    category_scores:    List[CategoryScore]
    total_checks:       int
    detected_count:     int
    not_detected_count: int
    error_count:        int
    dedup_count:        int = 0  # total checks merged across all categories


def deduplicate_checks(checks: List[CheckResult]) -> List[CheckResult]:
    """
    Within each (category_id, check_id) group, merge results from multiple tools.

    Merging policy (conservative):
      - If any tool reports "detected", the merged result is "detected".
      - If all tools agree on "not_detected", the result is "not_detected".
      - The tool field becomes "al-khaser+pafish" (sorted, deduplicated).
      - deduplicated=True marks the merged entry.

    This prevents double-counting the same logical check when both al-khaser
    and pafish cover it, while ensuring a detection by either tool is surfaced.
    """
    seen: Dict[tuple, CheckResult] = {}

    for check in checks:
        key = (check.category_id, check.check_id)

        if key not in seen:
            seen[key] = dataclasses.replace(check)
            continue

        existing = seen[key]
        tools = sorted(set(existing.tool.split("+") + check.tool.split("+")))
        merged_tool = "+".join(tools)

        if check.normalized == DETECTED and existing.normalized != DETECTED:
            # Upgrade to detected — one tool found it
            seen[key] = dataclasses.replace(
                existing,
                raw_value    = f"{existing.raw_value}/{check.raw_value}",
                normalized   = DETECTED,
                tool         = merged_tool,
                deduplicated = True,
            )
        else:
            # Same outcome from both — just record the multi-tool provenance
            seen[key] = dataclasses.replace(
                existing,
                tool         = merged_tool,
                deduplicated = True,
            )

    return list(seen.values())


class ScoringEngine:
    def __init__(self, config: dict):
        self.detected_value     = float(config.get("detected_value",     0.0))
        self.not_detected_value = float(config.get("not_detected_value", 1.0))
        self.error_behavior     = config.get("error_behavior", "exclude")

    def _check_value(self, normalized: str) -> Optional[float]:
        if normalized == DETECTED:     return self.detected_value
        if normalized == NOT_DETECTED: return self.not_detected_value
        return None

    def score(self, check_results: List[CheckResult], categories: list) -> ScoreReport:
        cat_map = {c["id"]: c for c in categories}

        buckets: Dict[str, List[CheckResult]] = {}
        for r in check_results:
            buckets.setdefault(r.category_id, []).append(r)

        category_scores: List[CategoryScore] = []
        weighted_sum  = 0.0
        total_weight  = 0.0

        for cat_id, checks in buckets.items():
            cat_cfg = cat_map.get(cat_id, {"name": cat_id, "weight": 0.0})
            weight  = float(cat_cfg.get("weight", 0.0))

            values       = [self._check_value(c.normalized) for c in checks]
            valid_values = [v for v in values if v is not None]

            detected     = sum(1 for c in checks if c.normalized == DETECTED)
            not_detected = sum(1 for c in checks if c.normalized == NOT_DETECTED)
            errors       = len(checks) - detected - not_detected
            dedup        = sum(1 for c in checks if c.deduplicated)

            cat_score = (sum(valid_values) / len(valid_values)) if valid_values else None

            category_scores.append(CategoryScore(
                category_id        = cat_id,
                name               = cat_cfg.get("name", cat_id),
                weight             = weight,
                score              = cat_score,
                checks_count       = len(checks),
                detected_count     = detected,
                not_detected_count = not_detected,
                error_count        = errors,
                dedup_count        = dedup,
            ))

            if cat_score is not None and weight > 0:
                weighted_sum += cat_score * weight
                total_weight += weight

        global_score = round(weighted_sum / total_weight, 4) if total_weight > 0 else None

        total            = len(check_results)
        detected_total   = sum(1 for r in check_results if r.normalized == DETECTED)
        not_det_total    = sum(1 for r in check_results if r.normalized == NOT_DETECTED)
        error_total      = total - detected_total - not_det_total
        dedup_total      = sum(1 for r in check_results if r.deduplicated)

        scored_cats      = [c for c in category_scores if c.weight > 0]
        scored_detected  = sum(c.detected_count  for c in scored_cats)
        scored_total     = sum(c.checks_count    for c in scored_cats)
        detection_rate   = round(scored_detected / scored_total, 4) if scored_total > 0 else 0.0

        return ScoreReport(
            global_score       = global_score,
            risk_level         = compute_risk_level(global_score),
            detection_rate     = detection_rate,
            category_scores    = sorted(category_scores, key=lambda c: -c.weight),
            total_checks       = total,
            detected_count     = detected_total,
            not_detected_count = not_det_total,
            error_count        = error_total,
            dedup_count        = dedup_total,
        )
