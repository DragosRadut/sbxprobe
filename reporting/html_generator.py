import html as _html
from pathlib import Path
from typing import List

import yaml

from _paths import bundle_root
from parser.normalizer import CheckResult, DETECTED
from scoring.engine import ScoreReport

RISK_COLORS = {
    "LOW":      "#4ade80",
    "MEDIUM":   "#facc15",
    "HIGH":     "#f97316",
    "CRITICAL": "#ef4444",
    "UNKNOWN":  "#94a3b8",
}

# MITRE ATT&CK technique URLs (append technique ID)
_MITRE_URL = "https://attack.mitre.org/techniques/"

def _load_check_mitre() -> dict:
    """Load configs/check_mitre.yaml. Returns {} gracefully if file is missing."""
    path = bundle_root() / "configs" / "check_mitre.yaml"
    try:
        with path.open(encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


_CHECK_MITRE = _load_check_mitre()

# Extract description strings for backward-compatible lookup in the report.
_CHECK_DESCRIPTIONS = {
    slug: entry.get("description", "").strip()
    for slug, entry in _CHECK_MITRE.items()
    if isinstance(entry, dict) and entry.get("description")
}


def _score_color(score) -> str:
    if score is None:
        return RISK_COLORS["UNKNOWN"]
    if score >= 0.85: return RISK_COLORS["LOW"]
    if score >= 0.65: return RISK_COLORS["MEDIUM"]
    if score >= 0.40: return RISK_COLORS["HIGH"]
    return RISK_COLORS["CRITICAL"]


def _e(s) -> str:
    return _html.escape(str(s))


_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Consolas','Courier New',monospace; background: #0f172a;
       color: #e2e8f0; padding: 24px; font-size: 14px; }
a { color: #38bdf8; text-decoration: none; }
a:hover { text-decoration: underline; }
h1 { font-size: 1.3em; color: #f1f5f9; margin-bottom: 6px; }
h2 { font-size: .78em; color: #64748b; text-transform: uppercase;
     letter-spacing: .1em; margin: 28px 0 8px; }
.meta { color: #64748b; font-size: .85em; margin-bottom: 20px; line-height: 1.8; }
.meta b { color: #94a3b8; }

/* ── Score card ── */
.score-card { display: flex; align-items: flex-start; gap: 28px; background: #1e293b;
              border-radius: 8px; padding: 20px 28px; margin-bottom: 8px; }
.score-val  { font-size: 3.2em; font-weight: bold; line-height: 1; }
.risk-badge { font-size: .85em; font-weight: bold; padding: 3px 10px;
              border-radius: 4px; color: #000; white-space: nowrap; }
.score-stats { color: #94a3b8; font-size: .88em; line-height: 2.1; }
.score-tools { color: #475569; font-size: .78em; margin-top: 6px; }

/* ── Detected summary card ── */
.detected-summary { background: #1e293b; border-left: 3px solid #ef4444;
                    border-radius: 0 8px 8px 0; padding: 14px 18px; margin-bottom: 8px; }
.detected-summary h3 { font-size: .78em; color: #ef4444; text-transform: uppercase;
                        letter-spacing: .1em; margin-bottom: 10px; }
.artifact { margin-bottom: 8px; }
.artifact-label { color: #fca5a5; font-size: .88em; }
.artifact-desc  { color: #64748b; font-size: .8em; margin-top: 2px; line-height: 1.5; }
.artifact-tool  { font-size: .72em; color: #475569; margin-top: 2px; }

/* ── Tables ── */
table { width: 100%; border-collapse: collapse; font-size: .84em; margin-bottom: 4px; }
th { text-align: left; padding: 6px 10px; background: #1e293b; color: #64748b;
     text-transform: uppercase; letter-spacing: .06em; font-size: .78em; }
td { padding: 5px 10px; border-top: 1px solid #1e293b44; vertical-align: middle; }
tr:hover td { background: #1e293b66; }
.val-detected    { color: #ef4444; font-weight: bold; }
.val-not_detected{ color: #4ade80; }
.val-error       { color: #94a3b8; }
.tool-badge { font-size: .72em; background: #334155; color: #94a3b8;
              padding: 1px 6px; border-radius: 3px; white-space: nowrap; }
.tool-badge.corroborated { background: #1e3a5f; color: #38bdf8; }
.mitre-link { font-size: .75em; color: #38bdf8; opacity: .7; }
.mitre-link:hover { opacity: 1; }

/* ── Filters ── */
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


class HTMLReportGenerator:
    def __init__(
        self,
        scenario:          dict,
        environment_label: str,
        run_id:            str,
        output_dir:        Path,
        run_status:        str,
        tool_versions:     dict,
    ):
        self.scenario      = scenario
        self.env           = environment_label
        self.run_id        = run_id
        self.out           = Path(output_dir)
        self.run_status    = run_status
        self.tool_versions = tool_versions

    def write(self, checks: List[CheckResult], score: ScoreReport):
        s           = self.scenario
        score_str   = f"{score.global_score:.4f}" if score.global_score is not None else "N/A"
        sc_color    = _score_color(score.global_score)
        risk_color  = RISK_COLORS.get(score.risk_level, RISK_COLORS["UNKNOWN"])
        tool_str    = ", ".join(f"{k} v{v}" for k, v in self.tool_versions.items())
        dedup_total = score.dedup_count

        # ── Tool contribution breakdown ───────────────────────────────────────
        ak_count  = sum(1 for c in checks if "al-khaser" in c.tool and not c.deduplicated)
        pf_count  = sum(1 for c in checks if c.tool == "pafish" and not c.deduplicated)
        cor_count = dedup_total
        tool_breakdown = (
            f"al-khaser: {ak_count + cor_count} · pafish: {pf_count + cor_count}"
            + (f" · {cor_count} corroborated" if cor_count else "")
        )

        # ── Category table ────────────────────────────────────────────────────
        cat_mitre_map = {c["id"]: c.get("mitre", "") for c in s.get("categories", [])}
        cat_rows = ""
        for cat in score.category_scores:
            cs         = f"{cat.score:.4f}" if cat.score is not None else "N/A"
            dedup_cell = (f"<span style='color:#38bdf8'>{cat.dedup_count}</span>"
                          if cat.dedup_count else "—")
            mitre_id   = cat_mitre_map.get(cat.category_id, "")
            mitre_cell = (f"<a class='mitre-link' href='{_MITRE_URL}{mitre_id.replace('.','/')}"
                          f"' target='_blank'>{_e(mitre_id)}</a>") if mitre_id else "—"
            cat_rows += (
                f"<tr>"
                f"<td>{_e(cat.name)}</td>"
                f"<td>{cat.weight:.2f}</td>"
                f"<td>{cs}</td>"
                f"<td>{cat.checks_count}</td>"
                f"<td class='val-detected'>{cat.detected_count}</td>"
                f"<td class='val-not_detected'>{cat.not_detected_count}</td>"
                f"<td>{dedup_cell}</td>"
                f"<td>{mitre_cell}</td>"
                f"</tr>"
            )

        # ── Detected artifacts summary ────────────────────────────────────────
        detected_checks = [c for c in checks if c.normalized == DETECTED]
        detected_html = ""
        if detected_checks:
            items = ""
            for r in detected_checks:
                desc     = _CHECK_DESCRIPTIONS.get(r.check_id, "")
                tool_cls = "tool-badge corroborated" if r.deduplicated else "tool-badge"
                mitre_entry  = _CHECK_MITRE.get(r.check_id, {})
                mitre_id     = mitre_entry.get("mitre", "") if isinstance(mitre_entry, dict) else ""
                mitre_badge  = (
                    f" &nbsp; <a class='mitre-link' href='{_MITRE_URL}{mitre_id.replace('.','/')}'"
                    f" target='_blank'>{_e(mitre_id)}</a>"
                ) if mitre_id else ""
                items += (
                    f"<div class='artifact'>"
                    f"<div class='artifact-label'>{_e(r.label)}</div>"
                    + (f"<div class='artifact-desc'>{_e(desc)}</div>" if desc else "")
                    + f"<div class='artifact-tool'><span class='{tool_cls}'>{_e(r.tool)}</span>"
                    f"{mitre_badge} &nbsp; {_e(r.category_name)}</div>"
                    f"</div>"
                )
            detected_html = f"""
<div class="detected-summary">
  <h3>Detected Artifacts ({len(detected_checks)})</h3>
  {items}
</div>"""

        # ── Checks table ─────────────────────────────────────────────────────
        total        = score.total_checks
        detected     = score.detected_count
        not_detected = score.not_detected_count

        check_rows = ""
        for r in checks:
            cls       = f"val-{r.normalized}" if r.normalized in ("detected", "not_detected") else "val-error"
            badge_cls = "tool-badge corroborated" if r.deduplicated else "tool-badge"
            check_rows += (
                f"<tr data-status='{_e(r.normalized)}'>"
                f"<td class='{cls}'>{_e(r.raw_value)}</td>"
                f"<td>{_e(r.label)}</td>"
                f"<td>{_e(r.category_name)}</td>"
                f"<td><span class='{badge_cls}'>{_e(r.tool)}</span></td>"
                f"</tr>"
            )

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
  <div>
    <div class="score-val" style="color:{sc_color}">{score_str}</div>
  </div>
  <div class="risk-badge" style="background:{risk_color}">{_e(score.risk_level)}</div>
  <div>
    <div class="score-stats">
      Detection rate &nbsp; {score.detection_rate * 100:.1f}%<br>
      Detected &nbsp; {detected} &nbsp;/&nbsp; {total}<br>
      Not detected &nbsp; {not_detected}
      {f"<br>Corroborated by both tools &nbsp; <span style='color:#38bdf8'>{dedup_total}</span>" if dedup_total else ""}
    </div>
    <div class="score-tools">{_e(tool_breakdown)}</div>
  </div>
</div>

{detected_html}

<h2>Category Scores</h2>
<table>
  <thead>
    <tr>
      <th>Category</th><th>Weight</th><th>Score</th>
      <th>Checks</th><th>Detected</th><th>Clean</th>
      <th title="Checks covered by both tools">Corroborated</th>
      <th>MITRE ATT&CK</th>
    </tr>
  </thead>
  <tbody>{cat_rows}</tbody>
</table>

<h2>All Checks</h2>
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
