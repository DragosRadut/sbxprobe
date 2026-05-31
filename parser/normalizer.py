import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from runner.executor import ExecutionResult

_VERSION_RE = re.compile(r"\[al-khaser version\s+(?P<ver>[\d.]+)\]", re.IGNORECASE)


def extract_alkhaser_version(stdout: str) -> str:
    m = _VERSION_RE.search(stdout)
    return m.group("ver") if m else "unknown"


DETECTED     = "detected"
NOT_DETECTED = "not_detected"
ERROR        = "error"
UNSUPPORTED  = "unsupported"

# Inline result — most common case:
#   [*] Checking IsDebuggerPresent API    [ GOOD ]
_INLINE_RE = re.compile(
    r"^\s*\[\*\]\s*(?P<label>.+?)\s+\[\s*(?P<value>GOOD|BAD)\s*\]\s*$",
    re.IGNORECASE,
)

# A [*] line whose result is deferred (al-khaser emits [!] diagnostics before it):
#   [*] Walking process memory for hidden modules
#    [!] Running on WoW64 ...
#   [ BAD  ]
_STAR_LINE_RE = re.compile(r"^\s*\[\*\]\s*(?P<label>.+?)\s*$")

# Orphan result — standalone [ GOOD ] or [ BAD  ] belonging to the pending label:
_ORPHAN_RE = re.compile(r"^\s*\[\s*(?P<value>GOOD|BAD)\s*\]\s*$", re.IGNORECASE)


@dataclass
class CheckResult:
    check_id:          str
    label:             str
    category_id:       str
    category_name:     str
    raw_value:         str       # "GOOD" / "BAD" (al-khaser)  or  "ok" / "traced!" (pafish)
    normalized:        str       # detected / not_detected / error / unsupported
    timestamp:         str
    environment_label: str
    runtime_seconds:   float
    tool:              str  = "al-khaser"
    deduplicated:      bool = False   # True when merged from multiple tools


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _extract_pairs(text: str) -> List[Tuple[str, str]]:
    """
    Walk al-khaser output and return (label, 'GOOD'|'BAD') pairs.

    Handles both the common inline case and the deferred case where
    al-khaser prints [!] diagnostic lines before emitting the result.
    """
    pairs: List[Tuple[str, str]] = []
    pending_label: Optional[str] = None

    for line in text.splitlines():
        m = _INLINE_RE.match(line)
        if m:
            pending_label = None
            pairs.append((m.group("label").strip(), m.group("value").upper()))
            continue

        m = _ORPHAN_RE.match(line)
        if m and pending_label is not None:
            pairs.append((pending_label, m.group("value").upper()))
            pending_label = None
            continue

        m = _STAR_LINE_RE.match(line)
        if m:
            pending_label = m.group("label").strip()
            continue

    return pairs


class AlKhaserParser:
    """
    Parses al-khaser output and assigns ALL results to a single pre-determined
    category (the one whose flags produced this run).  No keyword matching —
    category assignment is determined by which flags were passed at invocation.
    """

    def __init__(self, category_id: str, category_name: str):
        self.category_id   = category_id
        self.category_name = category_name

    def parse(self, exec_result: ExecutionResult) -> List[CheckResult]:
        if not exec_result.stdout:
            return []

        results = []
        for label, raw_value in _extract_pairs(exec_result.stdout):
            normalized = NOT_DETECTED if raw_value == "GOOD" else DETECTED
            results.append(CheckResult(
                check_id          = _slugify(label),
                label             = label,
                category_id       = self.category_id,
                category_name     = self.category_name,
                raw_value         = raw_value,
                normalized        = normalized,
                timestamp         = exec_result.timestamp,
                environment_label = exec_result.environment_label,
                runtime_seconds   = exec_result.runtime_seconds,
                tool              = "al-khaser",
            ))
        return results
