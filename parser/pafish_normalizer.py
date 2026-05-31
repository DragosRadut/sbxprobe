import re
from typing import Dict, List, Optional, Tuple

from parser.normalizer import CheckResult, DETECTED, NOT_DETECTED, _slugify
from runner.executor import ExecutionResult

_VERSION_RE = re.compile(r"\[-\]\s+pafish\s+v?(?P<ver>[\d.]+)", re.IGNORECASE)

# [*] <label> ... OK       → not detected
# [*] <label> ... traced!  → detected
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
    """
    Parses pafish output and classifies each check into a category using
    pafish_keywords — a small, ordered mapping of {category_id: [keyword, ...]}.

    Classification is first-match: categories are checked in the order they
    appear in pafish_keywords.  Checks that match no keyword are discarded
    (pafish covers fewer techniques than al-khaser; uncategorised results have
    no place in the scoring taxonomy).
    """

    def __init__(self, categories: list, pafish_keywords: Dict[str, List[str]]):
        # Build a name lookup so we can fill category_name on each result.
        self.cat_map        = {c["id"]: c["name"] for c in categories}
        self.pafish_keywords = pafish_keywords   # ordered dict: category → keywords

    def parse(self, exec_result: ExecutionResult) -> List[CheckResult]:
        if not exec_result.stdout:
            return []

        results = []
        for label, raw_value in _extract_pairs(exec_result.stdout):
            cat_id, cat_name = self._classify(label)
            if cat_id is None:
                continue   # no matching category — discard

            normalized = NOT_DETECTED if raw_value == "ok" else DETECTED
            results.append(CheckResult(
                check_id          = _slugify(label),
                label             = label,
                category_id       = cat_id,
                category_name     = cat_name,
                raw_value         = raw_value,
                normalized        = normalized,
                timestamp         = exec_result.timestamp,
                environment_label = exec_result.environment_label,
                runtime_seconds   = exec_result.runtime_seconds,
                tool              = "pafish",
            ))
        return results

    def _classify(self, label: str) -> Tuple[Optional[str], Optional[str]]:
        label_lower = label.lower()
        for cat_id, keywords in self.pafish_keywords.items():
            if cat_id not in self.cat_map:
                continue
            for kw in keywords:
                if kw.lower() in label_lower:
                    return cat_id, self.cat_map[cat_id]
        return None, None
