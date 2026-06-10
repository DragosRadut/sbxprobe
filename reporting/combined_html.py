import html as _html
from dataclasses import dataclass
from pathlib import Path
from typing import List

from scoring.engine import ScoreReport
from reporting.html_generator import RISK_COLORS, _score_color, _e

_MITRE_URL = "https://attack.mitre.org/techniques/"


@dataclass
class ScenarioResult:
    scenario: dict
    checks: list
    score: ScoreReport
    run_status: str
    tool_versions: dict
    report_dir: Path


_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Consolas','Courier New',monospace; background: #0f172a; color: #e2e8f0;
       padding: 24px; font-size: 14px; }
h1 { font-size: 1.3em; color: #f1f5f9; margin-bottom: 6px; }
h2 { font-size: .8em; color: #64748b; text-transform: uppercase; letter-spacing: .1em; margin: 28px 0 12px; }
.meta { color: #64748b; font-size: .85em; margin-bottom: 28px; }
.meta b { color: #94a3b8; }

.avg-card { display: flex; align-items: center; gap: 20px; background: #1e293b;
            border-radius: 8px; padding: 20px 28px; margin-bottom: 8px; }
.avg-label { color: #64748b; font-size: .75em; text-transform: uppercase; letter-spacing: .1em; margin-bottom: 4px; }
.avg-val   { font-size: 2.8em; font-weight: bold; line-height: 1; }

.grid { display: flex; flex-wrap: wrap; gap: 16px; }
.card { background: #1e293b; border-radius: 8px; padding: 18px 20px;
        min-width: 200px; flex: 1 1 200px; }
.card-title { font-size: .95em; margin-bottom: 4px; }
.card-title a { color: #38bdf8; text-decoration: none; }
.card-title a:hover { text-decoration: underline; }
.card-sid   { color: #475569; font-size: .78em; margin-bottom: 12px; }
.card-score { font-size: 2.2em; font-weight: bold; line-height: 1; margin-bottom: 6px; }
.risk-badge { font-size: .8em; font-weight: bold; padding: 2px 9px;
              border-radius: 4px; color: #000; display: inline-block; margin-bottom: 8px; }
.card-stats { color: #64748b; font-size: .8em; line-height: 1.8; }

table { width: 100%; border-collapse: collapse; font-size: .84em; }
th { text-align: left; padding: 6px 10px; background: #1e293b; color: #64748b;
     text-transform: uppercase; letter-spacing: .06em; font-size: .8em; }
td { padding: 6px 10px; border-top: 1px solid #1e293b44; }
tr:hover td { background: #1e293b66; }
.good { color: #4ade80; } .bad { color: #ef4444; }
a { color: #38bdf8; text-decoration: none; }
a:hover { text-decoration: underline; }
.mitre-link { font-size: .75em; color: #38bdf8; opacity: .7; }
.mitre-link:hover { opacity: 1; }
"""


class CombinedHTMLReportGenerator:
    def __init__(self, environment_label: str, run_id: str, output_dir: Path):
        self.env    = environment_label
        self.run_id = run_id
        self.out    = Path(output_dir)

    def write(self, results: List[ScenarioResult]):
        cards = ""
        table_rows = ""
        all_scores = [r.score.global_score for r in results if r.score.global_score is not None]
        avg_score  = sum(all_scores) / len(all_scores) if all_scores else None
        avg_str    = f"{avg_score:.4f}" if avg_score is not None else "N/A"
        avg_color  = _score_color(avg_score)

        for r in results:
            s          = r.scenario
            score_str  = f"{r.score.global_score:.4f}" if r.score.global_score is not None else "N/A"
            sc_color   = _score_color(r.score.global_score)
            risk_color = RISK_COLORS.get(r.score.risk_level, RISK_COLORS["UNKNOWN"])
            rel_link   = f"{_e(s['scenario_id'])}/report.html"

            cards += f"""
<div class="card">
  <div class="card-title"><a href="{rel_link}">{_e(s['scenario_name'])}</a></div>
  <div class="card-sid">{_e(s['scenario_id'])} &nbsp;·&nbsp; {_e(r.run_status)}</div>
  <div class="card-score" style="color:{sc_color}">{score_str}</div>
  <div class="risk-badge" style="background:{risk_color}">{_e(r.score.risk_level)}</div>
  <div class="card-stats">
    Detection &nbsp; {r.score.detection_rate * 100:.1f}%<br>
    {r.score.detected_count} detected / {r.score.total_checks} total
  </div>
</div>"""

            # Build MITRE coverage cell: distinct technique IDs from all categories
            mitre_ids = []
            seen = set()
            for cat in s.get("categories", []):
                mid = cat.get("mitre", "")
                if mid and mid not in seen:
                    seen.add(mid)
                    mitre_ids.append(mid)
            mitre_cell = " ".join(
                "<a class='mitre-link' href='" + _MITRE_URL + mid.replace(".", "/") + "'"
                " target='_blank'>" + _e(mid) + "</a>"
                for mid in mitre_ids
            ) or "—"

            score_str_td = f"<a href='{rel_link}'>{score_str}</a>"
            table_rows += (
                f"<tr>"
                f"<td>{_e(s['scenario_name'])}</td>"
                f"<td>{score_str_td}</td>"
                f"<td><span class='risk-badge' style='background:{risk_color};color:#000;font-size:.78em;padding:1px 7px'>{_e(r.score.risk_level)}</span></td>"
                f"<td>{r.score.detection_rate * 100:.1f}%</td>"
                f"<td>{r.score.detected_count}</td>"
                f"<td>{r.score.total_checks}</td>"
                f"<td>{_e(r.run_status)}</td>"
                f"<td>{mitre_cell}</td>"
                f"</tr>"
            )

        page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>sbxprobe — {_e(self.env)}</title>
<style>{_CSS}</style>
</head>
<body>

<h1>sbxprobe &mdash; {_e(self.env)}</h1>
<div class="meta">
  <b>run</b> {_e(self.run_id)} &nbsp;&nbsp;
  <b>scenarios</b> {len(results)}
</div>

<div class="avg-card">
  <div>
    <div class="avg-label">Average Transparency Score</div>
    <div class="avg-val" style="color:{avg_color}">{avg_str}</div>
  </div>
</div>

<h2>Scenario Cards</h2>
<div class="grid">{cards}</div>

<h2>Summary Table</h2>
<table>
  <thead>
    <tr>
      <th>Scenario</th><th>Score</th><th>Risk</th>
      <th>Detection</th><th>Detected</th><th>Total</th><th>Status</th><th>MITRE ATT&CK</th>
    </tr>
  </thead>
  <tbody>{table_rows}</tbody>
</table>

</body>
</html>"""

        out_file = self.out / "index.html"
        out_file.write_text(page, encoding="utf-8")
        print(f"[report] Combined → {out_file}")
