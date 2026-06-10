import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import yaml

from _paths import bundle_root
from parser.normalizer import CheckResult, DETECTED
from scoring.engine import ScoreReport


def _load_check_mitre() -> dict:
    path = bundle_root() / "configs" / "check_mitre.yaml"
    try:
        with path.open(encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


class ReportGenerator:
    def __init__(
        self,
        scenario: dict,
        environment_label: str,
        run_id: str,
        output_dir: Path,
        run_status: str,
        tool_versions: dict,
    ):
        self.scenario = scenario
        self.env = environment_label
        self.run_id = run_id
        self.out = Path(output_dir)
        self.run_status = run_status
        self.tool_versions = tool_versions

    def _meta(self) -> dict:
        return {
            "scenario_id": self.scenario["scenario_id"],
            "scenario_name": self.scenario["scenario_name"],
            "scenario_version": str(self.scenario.get("version", "?")),
            "environment": self.env,
            "run_id": self.run_id,
            "run_status": self.run_status,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool_versions": self.tool_versions,
        }

    def write_json(self, checks: List[CheckResult], score: ScoreReport):
        check_mitre = _load_check_mitre()

        def _check_entry(r: CheckResult) -> dict:
            entry = {
                "check_id": r.check_id,
                "label": r.label,
                "category_id": r.category_id,
                "category_name": r.category_name,
                "raw_value": r.raw_value,
                "normalized": r.normalized,
                "tool": r.tool,
                "deduplicated": r.deduplicated,
                "timestamp": r.timestamp,
                "environment_label": r.environment_label,
                "runtime_seconds": r.runtime_seconds,
            }
            mapping = check_mitre.get(r.check_id)
            if isinstance(mapping, dict):
                if mapping.get("mitre"):
                    entry["mitre"] = mapping["mitre"]
                if mapping.get("checkpoint"):
                    entry["checkpoint_url"] = mapping["checkpoint"]
            return entry

        data = {
            "meta": self._meta(),
            "score": {
                "global_score": score.global_score,
                "risk_level": score.risk_level,
                "detection_rate": score.detection_rate,
                "total_checks": score.total_checks,
                "detected_count": score.detected_count,
                "not_detected_count": score.not_detected_count,
                "error_count": score.error_count,
                "categories": [
                    {
                        "id": c.category_id,
                        "name": c.name,
                        "weight": c.weight,
                        "score": c.score,
                        "checks_count": c.checks_count,
                        "detected_count": c.detected_count,
                        "not_detected_count": c.not_detected_count,
                        "error_count": c.error_count,
                    }
                    for c in score.category_scores
                ],
            },
            "checks": [_check_entry(r) for r in checks],
        }
        out_file = self.out / "report.json"
        out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"[report] JSON     → {out_file}")

    def write_csv(self, checks: List[CheckResult]):
        out_file = self.out / "checks.csv"
        fieldnames = [
            "check_id", "label", "category_id", "category_name",
            "raw_value", "normalized", "tool", "deduplicated",
            "timestamp", "environment_label", "runtime_seconds",
        ]
        with out_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in checks:
                writer.writerow({
                    "check_id": r.check_id,
                    "label": r.label,
                    "category_id": r.category_id,
                    "category_name": r.category_name,
                    "raw_value": r.raw_value,
                    "normalized": r.normalized,
                    "tool": r.tool,
                    "deduplicated": r.deduplicated,
                    "timestamp": r.timestamp,
                    "environment_label": r.environment_label,
                    "runtime_seconds": r.runtime_seconds,
                })
        print(f"[report] CSV      → {out_file}")

    def write_markdown(self, checks: List[CheckResult], score: ScoreReport):
        s = self.scenario
        tool_str = ", ".join(f"{k} v{v}" for k, v in self.tool_versions.items())
        score_str = f"{score.global_score:.4f}" if score.global_score is not None else "N/A"

        lines = [
            f"# {s['scenario_name']} — {self.env}",
            "",
            f"**Run ID:** {self.run_id}  ",
            f"**Status:** {self.run_status}  ",
            f"**Tools:** {tool_str}",
            "",
            "## Score Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Global Score | {score_str} |",
            f"| Risk Level | {score.risk_level} |",
            f"| Detection Rate | {score.detection_rate * 100:.1f}% |",
            f"| Total Checks | {score.total_checks} |",
            f"| Detected | {score.detected_count} |",
            f"| Not Detected | {score.not_detected_count} |",
            "",
            "## Category Scores",
            "",
            "| Category | Weight | Score | Checks | Detected |",
            "|----------|--------|-------|--------|----------|",
        ]
        for cat in score.category_scores:
            cs = f"{cat.score:.4f}" if cat.score is not None else "N/A"
            lines.append(
                f"| {cat.name} | {cat.weight:.2f} | {cs} | {cat.checks_count} | {cat.detected_count} |"
            )

        detected = [r for r in checks if r.normalized == DETECTED]
        if detected:
            lines += [
                "",
                "## Detected Checks",
                "",
                "| Label | Category | Tool |",
                "|-------|----------|------|",
            ]
            for r in detected:
                lines.append(f"| {r.label} | {r.category_name} | {r.tool} |")

        out_file = self.out / "report.md"
        out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[report] Markdown → {out_file}")
