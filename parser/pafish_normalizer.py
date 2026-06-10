import re
from typing import Dict, List, Optional

from parser.normalizer import CheckResult, DETECTED, NOT_DETECTED, _slugify
from runner.executor import ExecutionResult

# pafish v0.6.1 does not print a numeric version to stdout — "unknown" is expected.
_VERSION_RE = re.compile(r"pafish\s+v?(?P<ver>[\d.]+)", re.IGNORECASE)

# [-] Section name        — printed before every group of checks
_SECTION_RE = re.compile(r"^\[-\]\s+(?P<section>.+?)\s*$")

# [*] <label> ... OK / traced!
_RESULT_RE = re.compile(
    r"^\[\*\]\s+(?P<label>.+?)\s+\.\.\.\s+(?P<value>OK|traced!)$",
    re.IGNORECASE,
)


def extract_pafish_version(stdout: str) -> str:
    m = _VERSION_RE.search(stdout)
    return m.group("ver") if m else "unknown"


class PafishParser:
    """
    Parses pafish output using section-header based classification.

    pafish prints section headers before every check group:
        [-] VirtualBox detection
        [*] Scsi port->bus->...  ... traced!

    pafish_sections maps each section header to a category ID (or "exclude").
    pafish_label_overrides maps specific labels to override the section default —
    useful for mixed sections (e.g. the CPU section contains both timing and VM checks).

    Checks whose section or label resolves to "exclude" are silently dropped.
    This is intentional for behavioural false-positive checks (mouse movement,
    dialog confirmation) that always trigger in headless automated environments
    and would pollute the transparency score with irrelevant detections.
    """

    def __init__(
        self,
        categories: list,
        pafish_sections: Dict[str, str],
        pafish_label_overrides: Dict[str, str],
    ):
        self.cat_map         = {c["id"]: c["name"] for c in categories}
        self.section_map     = pafish_sections
        self.label_overrides = pafish_label_overrides

    def parse(self, exec_result: ExecutionResult) -> List[CheckResult]:
        if not exec_result.stdout:
            return []

        results: List[CheckResult] = []
        current_section: Optional[str] = None

        for line in exec_result.stdout.splitlines():
            m = _SECTION_RE.match(line)
            if m:
                current_section = m.group("section").strip()
                continue

            m = _RESULT_RE.match(line.rstrip())
            if not m:
                continue

            label     = m.group("label").strip()
            raw_value = m.group("value").lower()

            # Label override takes precedence over the section default.
            cat_id = self.label_overrides.get(label) or self.section_map.get(current_section)

            if not cat_id or cat_id == "exclude" or cat_id not in self.cat_map:
                continue

            normalized = NOT_DETECTED if raw_value == "ok" else DETECTED
            results.append(CheckResult(
                check_id          = _slugify(label),
                label             = label,
                category_id       = cat_id,
                category_name     = self.cat_map[cat_id],
                raw_value         = raw_value,
                normalized        = normalized,
                timestamp         = exec_result.timestamp,
                environment_label = exec_result.environment_label,
                runtime_seconds   = exec_result.runtime_seconds,
                tool              = "pafish",
            ))

        return results
