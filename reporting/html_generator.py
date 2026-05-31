import html as _html
from pathlib import Path
from typing import List

from parser.normalizer import CheckResult
from scoring.engine import ScoreReport

RISK_COLORS = {
    "LOW":      "#4ade80",
    "MEDIUM":   "#facc15",
    "HIGH":     "#f97316",
    "CRITICAL": "#ef4444",
    "UNKNOWN":  "#94a3b8",
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Consolas','Courier New',monospace; background: #0f172a; color: #e2e8f0; padding: 24px; font-size: 14px; }
a { color: #38bdf8; }
h1 { font-size: 1.3em; color: #f1f5f9; margin-bottom: 6px; }
h2 { font-size: .8em; color: #64748b; text-transform: uppercase; letter-spacing: .1em; margin: 28px 0 8px; }
.meta { color: #64748b; font-size: .85em; margin-bottom: 24px; line-height: 1.8; }
.meta b { color: #94a3b8; }

.score-card { display: flex; align-items: center; gap: 28px; background: #1e293b;
              border-radius: 8px; padding: 20px 28px; margin-bottom: 8px; }
.score-val  { font-size: 3.2em; font-weight: bold; line-height: 1; }
.risk-badge { font-size: .85em; font-weight: bold; padding: 3px 10px;
              border-radius: 4px; color: #000; white-space: nowrap; }
.score-stats { color: #94a3b8; font-size: .88em; line-height: 2; }

table { width: 100%; border-collapse: collapse; font-size: .84em; margin-bottom: 4px; }
th { text-align: left; padding: 6px 10px; background: #1e293b; color: #64748b;
     text-transform: uppercase; letter-spacing: .06em; font-size: .8em; }
td { padding: 5px 10px; border-top: 1px solid #1e293b44; vertical-align: middle; }
tr:hover td { background: #1e293b66; }
.val-detected    { color: #ef4444; font-weight: bold; }
.val-not_detected{ color: #4ade80; }
.val-error       { color: #94a3b8; }
.tool-badge { font-size: .72em; background: #334155; color: #94a3b8;
              padding: 1px 6px; border-radius: 3px; white-space: nowrap; }
.tool-badge.corroborated { background: #1e3a5f; color: #38bdf8; }

.filters { margin-bottom: 8px; display: flex; gap: 6px; flex-wrap: wrap; }
.filters button { background: #1e293b; color: #94a3b8; border: 1px solid #334155;
                  padding: 4px 12px; border-radius: 4px; cursor: pointer;
                  font-family: inherit; font-size: .8em; }
.filters button.active { background: #334155; color: #f1f5f9; border-color: #475569; }
"""

_JS = """
function filterChecks(val) {
  var rows = document.querySelectorAll('#checks-body tr');
  for (var i = 0; i < rows.length; i++) {
    rows[i].style.display = (val === 'all' || rows[i].dataset.status === val) ? '' : 'none';
  }
  var btns = document.querySelectorAll('.filters button');
  for (var j = 0; j < btns.length; j++) {
    btns[j].classList.toggle('active', btns[j].dataset.filter === val);
  }
}
"""


def _score_color(score):
    if score is None:
        return RISK_COLORS["UNKNOWN"]
    if score >= 0.85:
        return RISK_COLORS["LOW"]
    if score >= 0.65:
        return RISK_COLORS["MEDIUM"]
    if score >= 0.40:
        return RISK_COLORS["HIGH"]
    return RISK_COLORS["CRITICAL"]


def _e(s: str) -> str:
    return _html.escape(str(s))


class HTMLReportGenerator:
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

    def write(self, checks: List[CheckResult], score: ScoreReport):
        s = self.scenario
        score_str   = f"{score.global_score:.4f}" if score.global_score is not None else "N/A"
        sc_color    = _score_color(score.global_score)
        risk_color  = RISK_COLORS.get(score.risk_level, RISK_COLORS["UNKNOWN"])
        tool_str    = ", ".join(f"{k} v{v}" for k, v in self.tool_versions.items())

        # ── category table rows ───────────────────────────────────────────────
        cat_rows = ""
        for cat in score.category_scores:
            cs         = f"{cat.score:.4f}" if cat.score is not None else "N/A"
            dedup_cell = (f"<span style='color:#38bdf8'>{cat.dedup_count}</span>"
                          if cat.dedup_count else "—")
            cat_rows += (
                f"<tr>"
                f"<td>{_e(cat.name)}</td>"
                f"<td>{cat.weight:.2f}</td>"
                f"<td>{cs}</td>"
                f"<td>{cat.checks_count}</td>"
                f"<td class='val-detected'>{cat.detected_count}</td>"
                f"<td class='val-not_detected'>{cat.not_detected_count}</td>"
                f"<td>{dedup_cell}</td>"
                f"</tr>"
            )

        # ── checks table rows ─────────────────────────────────────────────────
        check_rows = ""
        for r in checks:
            cls        = f"val-{r.normalized}" if r.normalized in ("detected", "not_detected") else "val-error"
            badge_cls  = "tool-badge corroborated" if r.deduplicated else "tool-badge"
            check_rows += (
                f"<tr data-status='{_e(r.normalized)}'>"
                f"<td class='{cls}'>{_e(r.raw_value)}</td>"
                f"<td>{_e(r.label)}</td>"
                f"<td>{_e(r.category_name)}</td>"
                f"<td><span class='{badge_cls}'>{_e(r.tool)}</span></td>"
                f"</tr>"
            )

        total        = score.total_checks
        detected     = score.detected_count
        not_detected = score.not_detected_count
        dedup_total  = score.dedup_count

        page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>sbxprobe — {_e(s['scenario_name'])}</title>
<style>{_CSS}</style>
</head>
<body>

<h1>{_e(s['scenario_name'])}</h1>
<div class="meta">
  <b>env</b> {_e(self.env)} &nbsp;&nbsp;
  <b>run</b> {_e(self.run_id)} &nbsp;&nbsp;
  <b>status</b> {_e(self.run_status)} &nbsp;&nbsp;
  <b>tools</b> {_e(tool_str)}
</div>

<div class="score-card">
  <div class="score-val" style="color:{sc_color}">{score_str}</div>
  <div class="risk-badge" style="background:{risk_color}">{_e(score.risk_level)}</div>
  <div class="score-stats">
    Detection rate &nbsp; {score.detection_rate * 100:.1f}%<br>
    Detected &nbsp; {detected} &nbsp;/&nbsp; {total}<br>
    Not detected &nbsp; {not_detected}<br>
    {f'Corroborated by both tools &nbsp; <span style="color:#38bdf8">{dedup_total}</span>' if dedup_total else ''}
  </div>
</div>

<h2>Category Scores</h2>
<table>
  <thead>
    <tr>
      <th>Category</th><th>Weight</th><th>Score</th>
      <th>Checks</th><th>Detected</th><th>Clean</th><th title="Checks covered by both tools">Corroborated</th>
    </tr>
  </thead>
  <tbody>{cat_rows}</tbody>
</table>

<h2>Checks</h2>
<div class="filters">
  <button data-filter="all"          class="active" onclick="filterChecks('all')">All ({total})</button>
  <button data-filter="detected"     onclick="filterChecks('detected')">Detected ({detected})</button>
  <button data-filter="not_detected" onclick="filterChecks('not_detected')">Clean ({not_detected})</button>
</div>
<table>
  <thead>
    <tr><th>Result</th><th>Check</th><th>Category</th><th>Tool</th></tr>
  </thead>
  <tbody id="checks-body">{check_rows}</tbody>
</table>

<script>{_JS}</script>
</body>
</html>"""

        out_file = self.out / "report.html"
        out_file.write_text(page, encoding="utf-8")
        print(f"[report] HTML     → {out_file}")
