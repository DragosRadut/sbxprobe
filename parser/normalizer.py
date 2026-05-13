import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from runner.executor import ExecutionResult

_VERSION_RE = re.compile(r"\[al-khaser version\s+(?P<ver>[\d.]+)\]", re.IGNORECASE)


def extract_alkhaser_version(stdout: str) -> str:
    """Parse the version banner printed at the top of al-khaser output."""
    m = _VERSION_RE.search(stdout)
    return m.group("ver") if m else "unknown"

DETECTED = "detected"
NOT_DETECTED = "not_detected"
ERROR = "error"
UNSUPPORTED = "unsupported"

# Standard case — result on the same line as the label:
#   [*] Checking IsDebuggerPresent API                    [ GOOD ]
#   [*] Checking If Parent Process is explorer.exe        [ BAD  ]
_INLINE_RE = re.compile(
    r"^\s*\[\*\]\s*(?P<label>.+?)\s+\[\s*(?P<value>GOOD|BAD)\s*\]\s*$",
    re.IGNORECASE,
)

# A [*] line whose result has not appeared yet (deferred because al-khaser
# prints [!] diagnostic lines between the label and the result):
#   [*] Walking process memory for hidden modules
#    [!] Running on WoW64 ...
#   [ BAD  ]
_STAR_LINE_RE = re.compile(r"^\s*\[\*\]\s*(?P<label>.+?)\s*$")

# Orphan result — standalone [ GOOD ] or [ BAD  ] with no [*] prefix:
_ORPHAN_RE = re.compile(r"^\s*\[\s*(?P<value>GOOD|BAD)\s*\]\s*$", re.IGNORECASE)


@dataclass
class CheckResult:
    check_id: str
    label: str
    category_id: str
    category_name: str
    raw_value: str       # "GOOD" or "BAD" (al-khaser) / "ok" or "traced!" (pafish)
    normalized: str      # detected / not_detected / error / unsupported
    timestamp: str
    environment_label: str
    runtime_seconds: float
    tool: str = "al-khaser"


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _assign_category(label_lower: str, categories: list) -> Tuple[str, str]:
    for cat in categories:
        for kw in cat["keywords"]:
            if kw.lower() in label_lower:
                return cat["id"], cat["name"]
    return "uncategorized", "Uncategorized"


def _extract_pairs(text: str) -> List[Tuple[str, str]]:
    """
    Walk al-khaser output and return (label, 'GOOD'|'BAD') pairs.

    Handles both the common inline case and the deferred case where
    al-khaser prints [!] diagnostic lines before emitting the result.
    """
    pairs: List[Tuple[str, str]] = []
    pending_label: Optional[str] = None

    for line in text.splitlines():
        # 1. Inline result — most common path
        m = _INLINE_RE.match(line)
        if m:
            pending_label = None
            pairs.append((m.group("label").strip(), m.group("value").upper()))
            continue

        # 2. Orphan result belonging to the previously seen [*] label
        m = _ORPHAN_RE.match(line)
        if m and pending_label is not None:
            pairs.append((pending_label, m.group("value").upper()))
            pending_label = None
            continue

        # 3. A [*] line without an inline result — store as pending.
        #    If there was already a pending label it had no result (info line),
        #    so discard it and replace with the new one.
        m = _STAR_LINE_RE.match(line)
        if m:
            pending_label = m.group("label").strip()
            continue

        # Any other line ([!], section headers, blank) — leave pending alone.

    return pairs


class AlKhaserParser:
    def __init__(self, categories: list):
        self.categories = categories

    def parse(self, exec_result: ExecutionResult) -> List[CheckResult]:
        # Parse whatever stdout is available; a timeout may leave partial output
        # that is still valid.  Only skip if there is genuinely nothing to read.
        if not exec_result.stdout:
            return []

        results = []
        for label, raw_value in _extract_pairs(exec_result.stdout):
            cat_id, cat_name = _assign_category(label.lower(), self.categories)
            # GOOD = no artifact found = not_detected (transparent)
            # BAD  = artifact found    = detected     (visible to probe)
            normalized = NOT_DETECTED if raw_value == "GOOD" else DETECTED

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
            ))

        return results
