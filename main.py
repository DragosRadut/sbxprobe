import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


class _Tee:
    """Duplicates writes to an original stream and a log file simultaneously.

    Plugged into sys.stdout / sys.stderr so every print() and every error
    message appears on the console AND in run.log without any changes to the
    rest of the code.
    """

    def __init__(self, stream, logfile):
        self._stream  = stream
        self._logfile = logfile

    def write(self, data: str) -> int:
        n = self._stream.write(data)
        self._logfile.write(data)
        return n

    def flush(self):
        self._stream.flush()
        self._logfile.flush()

    def fileno(self):
        return self._stream.fileno()

    def isatty(self) -> bool:
        return False

from _paths import output_root
from config_loader import resolve_scenarios, DEFAULT_TOOLS_PATH
from runner.adapters.alkhaser import AlKhaserAdapter
from runner.adapters.pafish import PafishAdapter
from parser.normalizer import AlKhaserParser, CheckResult, extract_alkhaser_version
from parser.pafish_normalizer import PafishParser, extract_pafish_version
from scoring.engine import ScoringEngine, deduplicate_checks
from reporting.generator import ReportGenerator
from reporting.html_generator import HTMLReportGenerator
from reporting.combined_html import CombinedHTMLReportGenerator, ScenarioResult


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sbxprobe",
        description="Sandbox Transparency Evaluation Framework",
    )
    p.add_argument(
        "--scenario", nargs="+", required=True, metavar="NAME",
        help="Scenario name(s) to run, or 'all'.",
    )
    p.add_argument(
        "--env", required=True,
        help="Environment label for this run (e.g. virtualbox_default)",
    )
    p.add_argument(
        "--tools-config", default=DEFAULT_TOOLS_PATH, metavar="PATH",
        help=f"Path to tools.yaml (default: {DEFAULT_TOOLS_PATH})",
    )
    p.add_argument(
        "--output-dir", default=None,
        help="Root directory for report output. Defaults to reports/ next to the executable.",
    )
    p.add_argument(
        "--categories", nargs="*", metavar="CAT_ID",
        help="Score only these category IDs (default: all in scenario)",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Validate config and print execution plan without running.",
    )
    return p.parse_args()


# ── Per-tool runners ──────────────────────────────────────────────────────────

def _run_alkhaser_for_category(
    cat: dict,
    alkhaser_cfg: dict,
    env: str,
    log_dir: Path,
) -> tuple:
    """Run al-khaser with the flags belonging to *cat* and parse all output
    directly into that category.  Returns (version_dict, checks, status)."""

    tool_cfg = {**alkhaser_cfg, "checks": cat["alkhaser_flags"]}
    adapter  = AlKhaserAdapter(tool_cfg)

    flags_str = " ".join(cat["alkhaser_flags"])
    print(f"\n[runner] al-khaser  → {cat['name']}")
    print(f"[runner] Flags      : {flags_str}")
    print(f"[runner] Sleep      : {alkhaser_cfg.get('sleep', 10)}s  "
          f"Timeout : {alkhaser_cfg.get('timeout', 120)}s")
    print(f"[runner] Launching ...")

    exec_result = adapter.run(environment_label=env)

    raw_log  = exec_result.stdout + (
        "\n--- STDERR ---\n" + exec_result.stderr if exec_result.stderr else ""
    )
    log_file = log_dir / f"alkhaser_{cat['id']}_raw.txt"
    log_file.write_text(raw_log, encoding="utf-8")

    print(f"[runner] Exit code  : {exec_result.return_code}  "
          f"Runtime : {exec_result.runtime_seconds:.2f}s")
    print(f"[runner] Raw log    : {log_file}")

    version  = extract_alkhaser_version(exec_result.stdout)
    expected = alkhaser_cfg.get("version", "unknown")
    print(f"[runner] Version    : v{version}", end="")
    if version != expected and version != "unknown":
        print(f"  WARNING: expected v{expected} (check configs/tools.yaml)", end="")
    print()

    if exec_result.error:
        if not exec_result.stdout:
            print(f"[runner] FATAL: {exec_result.error}", file=sys.stderr)
            return {"al-khaser": version}, [], "fatal"
        print(f"[runner] WARNING: {exec_result.error} — partial output captured")
        status = "partial"
    else:
        status = "complete"

    parsed = AlKhaserParser(
        category_id   = cat["id"],
        category_name = cat["name"],
    ).parse(exec_result)

    print(f"[runner] Parsed     : {len(parsed)} checks")
    return {"al-khaser": version}, parsed, status


def _run_pafish_once(
    pafish_cfg:            dict,
    categories:            list,
    pafish_sections:       dict,
    pafish_label_overrides:dict,
    env:                   str,
    log_dir:               Path,
) -> tuple:
    """Run pafish once and classify checks using section headers + label overrides.
    Returns (version_dict, checks, status)."""

    adapter = PafishAdapter(pafish_cfg)
    print(f"\n[runner] pafish     → multi-category")
    print(f"[runner] Timeout    : {pafish_cfg.get('timeout', 60)}s")
    print(f"[runner] Launching ...")

    exec_result = adapter.run(environment_label=env)

    raw_log  = exec_result.stdout + (
        "\n--- STDERR ---\n" + exec_result.stderr if exec_result.stderr else ""
    )
    log_file = log_dir / "pafish_raw.txt"
    log_file.write_text(raw_log, encoding="utf-8")

    print(f"[runner] Exit code  : {exec_result.return_code}  "
          f"Runtime : {exec_result.runtime_seconds:.2f}s")
    print(f"[runner] Raw log    : {log_file}")

    version  = extract_pafish_version(exec_result.stdout)
    expected = pafish_cfg.get("version", "unknown")
    print(f"[runner] Version    : v{version}", end="")
    if version != expected and version != "unknown":
        print(f"  WARNING: expected v{expected} (check configs/tools.yaml)", end="")
    print()

    if exec_result.error:
        if not exec_result.stdout:
            print(f"[runner] FATAL: {exec_result.error}", file=sys.stderr)
            return {"pafish": version}, [], "fatal"
        print(f"[runner] WARNING: {exec_result.error} — partial output captured")
        status = "partial"
    else:
        status = "complete"

    parsed = PafishParser(
        categories             = categories,
        pafish_sections        = pafish_sections,
        pafish_label_overrides = pafish_label_overrides,
    ).parse(exec_result)

    by_cat: Dict[str, int] = {}
    for r in parsed:
        by_cat[r.category_id] = by_cat.get(r.category_id, 0) + 1
    for cat_id, n in sorted(by_cat.items()):
        print(f"[runner] Parsed     : {n} checks → {cat_id}")
    if not parsed:
        print("[runner] Parsed     : 0 checks (no section matched a category)")

    return {"pafish": version}, parsed, status


# ── Scenario orchestration ────────────────────────────────────────────────────

def _run_scenario(
    scenario:        dict,
    category_filter: Optional[List[str]],
    env:             str,
    run_id:          str,
    output_dir:      Path,
    log_dir:         Path,
) -> Optional[ScenarioResult]:

    categories = scenario["categories"]
    if category_filter:
        categories = [c for c in categories if c["id"] in category_filter]
        if not categories:
            print(
                f"[sbxprobe] WARNING: none of the requested categories "
                f"{category_filter} exist in {scenario['scenario_id']} — skipping.",
                file=sys.stderr,
            )
            return None

    output_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    alkhaser_cfg           = scenario.get("tools", {}).get("alkhaser", {})
    pafish_cfg             = scenario.get("tools", {}).get("pafish")
    pafish_sections        = scenario.get("pafish_sections", {})
    pafish_label_overrides = scenario.get("pafish_label_overrides", {})

    all_checks:   List[CheckResult] = []
    tool_versions: dict             = {}
    worst_status                    = "complete"

    # ── Run al-khaser once per category ───────────────────────────────────────
    for cat in categories:
        if not cat.get("alkhaser_flags"):
            continue
        # Per-category sleep override: alkhaser_sleep on the category takes
        # precedence over the global sleep in tools.alkhaser.
        cat_cfg = dict(alkhaser_cfg)
        if "alkhaser_sleep" in cat:
            cat_cfg["sleep"] = cat["alkhaser_sleep"]
        tv, parsed, status = _run_alkhaser_for_category(
            cat, cat_cfg, env, log_dir
        )
        tool_versions.update(tv)
        all_checks.extend(parsed)
        if status == "partial" and worst_status == "complete":
            worst_status = "partial"
        elif status == "fatal":
            worst_status = "fatal"

    # ── Run pafish once if any category requests it ───────────────────────────
    pafish_cats = [c for c in categories if c.get("pafish", False)]
    if pafish_cats and pafish_cfg and pafish_sections:
        tv, parsed, status = _run_pafish_once(
            pafish_cfg, categories, pafish_sections, pafish_label_overrides, env, log_dir
        )
        tool_versions.update(tv)
        all_checks.extend(parsed)
        if status == "partial" and worst_status == "complete":
            worst_status = "partial"
        elif status == "fatal":
            worst_status = "fatal"

    if worst_status == "fatal" and not all_checks:
        print("[sbxprobe] FATAL: all tools failed to produce output.", file=sys.stderr)
        return None

    # ── Deduplicate overlapping checks ────────────────────────────────────────
    raw_count    = len(all_checks)
    all_checks   = deduplicate_checks(all_checks)
    dedup_merged = raw_count - len(all_checks)

    check_results = [r for r in all_checks if r.category_id]
    run_status    = "partial" if worst_status in ("partial", "fatal") else "complete"

    print(f"\n[parser] Total checks : {len(check_results)}", end="")
    if dedup_merged:
        print(f"  ({dedup_merged} duplicate(s) merged — same check covered by both tools)", end="")
    print()

    if not check_results:
        print(
            "[parser] WARNING: no results. Verify probe binaries ran and "
            "scenario flags are valid.",
            file=sys.stderr,
        )

    # ── Score ─────────────────────────────────────────────────────────────────
    engine       = ScoringEngine(scenario.get("scoring", {}))
    score_report = engine.score(check_results, categories)

    score_str = f"{score_report.global_score:.4f}" if score_report.global_score is not None else "N/A"
    print(f"\n[scoring] Score: {score_str}  Risk: {score_report.risk_level}  "
          f"Detection rate: {score_report.detection_rate * 100:.1f}%")
    for cat in score_report.category_scores:
        if cat.weight == 0:
            continue
        cs = f"{cat.score:.4f}" if cat.score is not None else "N/A"
        dedup_note = f"  [{cat.dedup_count} corroborated]" if cat.dedup_count else ""
        print(f"  {cat.name:<30} {cs}  "
              f"({cat.checks_count} checks, {cat.detected_count} detected{dedup_note})")

    # ── Reports ───────────────────────────────────────────────────────────────
    reporter = ReportGenerator(
        scenario=scenario, environment_label=env, run_id=run_id,
        output_dir=output_dir, run_status=run_status, tool_versions=tool_versions,
    )
    html_reporter = HTMLReportGenerator(
        scenario=scenario, environment_label=env, run_id=run_id,
        output_dir=output_dir, run_status=run_status, tool_versions=tool_versions,
    )
    print()
    reporter.write_json(check_results, score_report)
    reporter.write_csv(check_results)
    reporter.write_markdown(check_results, score_report)
    html_reporter.write(check_results, score_report)

    return ScenarioResult(
        scenario=scenario, checks=check_results, score=score_report,
        run_status=run_status, tool_versions=tool_versions, report_dir=output_dir,
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()

    if args.output_dir is not None:
        out_base = (Path(args.output_dir) if Path(args.output_dir).is_absolute()
                    else output_root() / args.output_dir)
    else:
        out_base = output_root() / "reports"
    log_base = output_root() / "logs"

    print(f"[sbxprobe] Resolving scenarios : {args.scenario}")
    print(f"[sbxprobe] Tools config        : {args.tools_config}")
    try:
        scenarios = resolve_scenarios(args.scenario, args.tools_config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[sbxprobe] ERROR: {exc}", file=sys.stderr)
        return 1

    is_multi = len(scenarios) > 1

    if args.dry_run:
        for scenario in scenarios:
            cats = scenario["categories"]
            if args.categories:
                cats = [c for c in cats if c["id"] in args.categories]
            print(f"\n[dry-run] Scenario   : {scenario['scenario_name']} "
                  f"(v{scenario.get('version', '?')})")
            for cat in cats:
                flags  = cat.get("alkhaser_flags", [])
                pafish = cat.get("pafish", False)
                tools  = (["al-khaser"] if flags else []) + (["pafish"] if pafish else [])
                print(f"[dry-run]   {cat['id']:<20} weight={cat['weight']:.2f}  "
                      f"tools={tools}  flags={flags}")
            ps = scenario.get("pafish_sections", {})
            if ps:
                print(f"[dry-run] pafish_sections: "
                      f"{sum(1 for v in ps.values() if v != 'exclude')} active, "
                      f"{sum(1 for v in ps.values() if v == 'exclude')} excluded")
        return 0

    run_id      = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base_output = out_base  / args.env / run_id
    base_log    = log_base  / args.env / run_id

    # ── Set up run.log before any further output ──────────────────────────────
    base_output.mkdir(parents=True, exist_ok=True)
    run_log_path = base_output / "run.log"
    _logfile     = run_log_path.open("w", encoding="utf-8", buffering=1)
    _orig_stdout, _orig_stderr = sys.stdout, sys.stderr
    sys.stdout = _Tee(_orig_stdout, _logfile)
    sys.stderr = _Tee(_orig_stderr, _logfile)

    exit_code = 1
    try:
        print(f"[sbxprobe] Env       : {args.env}")
        print(f"[sbxprobe] Run ID    : {run_id}")
        print(f"[sbxprobe] Mode      : {'multi-scenario' if is_multi else 'single-scenario'} "
              f"({len(scenarios)} scenario{'s' if len(scenarios) != 1 else ''})")
        print(f"[sbxprobe] Output    : {base_output}")
        print(f"[sbxprobe] Log       : {run_log_path}")

        scenario_results: List[ScenarioResult] = []

        for scenario in scenarios:
            sid   = scenario["scenario_id"]
            sname = scenario["scenario_name"]

            output_dir = (base_output / sid) if is_multi else base_output
            log_dir    = (base_log    / sid) if is_multi else base_log

            print(f"\n{'='*60}")
            print(f"[sbxprobe] Running : {sname}")
            print(f"[sbxprobe] Output  : {output_dir}")
            print(f"{'='*60}")

            result = _run_scenario(
                scenario        = scenario,
                category_filter = args.categories,
                env             = args.env,
                run_id          = run_id,
                output_dir      = output_dir,
                log_dir         = log_dir,
            )
            if result is not None:
                scenario_results.append(result)

        if is_multi and scenario_results:
            print(f"\n{'='*60}")
            print(f"[sbxprobe] Generating combined report")
            print(f"{'='*60}")
            CombinedHTMLReportGenerator(
                environment_label=args.env,
                run_id=run_id,
                output_dir=base_output,
            ).write(scenario_results)

        print(f"\n[sbxprobe] Done.")
        exit_code = 0 if scenario_results else 1

    finally:
        sys.stdout = _orig_stdout
        sys.stderr = _orig_stderr
        _logfile.close()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
