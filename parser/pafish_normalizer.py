import re
from typing import List, Tuple

from parser.normalizer import (
    CheckResult, DETECTED, NOT_DETECTED,
    _assign_category, _slugify,
)
from runner.executor import ExecutionResult

_VERSION_RE = re.compile(r"\[-\]\s+pafish\s+v?(?P<ver>[\d.]+)", re.IGNORECASE)

# [*] <label> ... OK          → not detected (transparent)
# [*] <label> ... traced!     → detected
_RESULT_RE = re.compile(
    r"^\[\*\]\s+(?P<label>.+?)\s+\.\.\.\s+(?P<value>OK|traced!)$",
    re.IGNORECASE,
)


def extract_pafish_version(stdout: str) -> str:
    m = _VERSION_RE.search(stdout)
    return m.group("ver") if m else "unknown"


def _extract_pairs(text: str) -> List[Tuple[str, str]]:
    pairs = []
    for line in text.splitlines():
        m = _RESULT_RE.match(line.rstrip())
        if m:
            pairs.append((m.group("label").strip(), m.group("value").lower()))
    return pairs


class PafishParser:
    def __init__(self, categories: list):
        self.categories = categories

    def parse(self, exec_result: ExecutionResult) -> List[CheckResult]:
        if not exec_result.stdout:
            return []

        results = []
        for label, raw_value in _extract_pairs(exec_result.stdout):
            cat_id, cat_name = _assign_category(label.lower(), self.categories)
            normalized = NOT_DETECTED if raw_value == "ok" else DETECTED

            results.append(CheckResult(
                check_id=_slugify(label),
                label=label,
                category_id=cat_id,
                category_name=cat_name,
                raw_value=raw_value,
                normalized=normalized,
                timestamp=exec_result.timestamp,
                environment_label=exec_result.environment_label,
                runtime_seconds=exec_result.runtime_seconds,
                tool="pafish",
            ))

        return results
