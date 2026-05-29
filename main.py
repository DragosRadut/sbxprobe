import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from _paths import output_root
from config_loader import resolve_scenarios, DEFAULT_TOOLS_PATH
from runner.adapters.alkhaser import AlKhaserAdapter
from runner.adapters.pafish import PafishAdapter
from parser.normalizer import AlKhaserParser, extract_alkhaser_version
from parser.pafish_normalizer import PafishParser, extract_pafish_version
from scoring.engine import ScoringEngine
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
        help=(
            "Scenario name(s) to run (e.g. vm_checks anti_debug), "
            "or 'all' to run every scenario in configs/scenarios/."
        ),
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
        help=(
            "Root directory for report output. "
            "Defaults to 'reports/' next to the executable."
        ),
    )
    p.add_argument(
        "--categories", nargs="*", metavar="CAT_ID",
        help="Score only these category IDs (default: all defined in scenario)",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Validate config and print execution plan without running anything",
    )
    return p.parse_args()


def _run_tool(
    tool_name: str,
    tool_cfg: dict,
    categories: list,
    env: str,
    log_dir: Path,
) -> tuple:
    """
    Run a single probe tool and return (tool_versions_entry, parsed_checks, run_status).

    tool_versions_entry : dict with one key e.g. {"al-khaser": "0.81"}
    parsed_checks       : list[CheckResult]
    run_status          : "complete" | "partial" | "fatal"
    """
    if tool_name == "alkhaser":
        adapter = AlKhaserAdapter(tool_cfg)
        display = f"al-khaser v{tool_cfg.get('version', '?')} (expected)"
        checks_str = " ".join(tool_cfg.get("checks", []))
        print(f"[runner] Tool      : {display}")
        print(f"[runner] Checks    : {checks_str}")
        print(f"[runner] Sleep     : {tool_cfg.get('sleep', 10)}s  Timeout: {tool_cfg.get('timeout', 120)}s")
        print(f"[runner] Launching ...")
        exec_result = adapter.run(environment_label=env)

        raw_log = exec_result.stdout + (
            "\n--- STDERR ---\n" + exec_result.stderr if exec_result.stderr else ""
        )
        log_file = log_dir / "alkhaser_raw.txt"
        log_file.write_text(raw_log, encoding="utf-8")
        print(f"[runner] Exit code : {exec_result.return_code}  Runtime: {exec_result.runtime_seconds:.2f}s")
        print(f"[runner] Raw log   : {log_file}")

        version = extract_alkhaser_version(exec_result.stdout)
        expected = tool_cfg.get("version", "unknown")
        print(f"[runner] Version   : v{version}", end="")
        if version != expected and version != "unknown":
            print(f"  WARNING: expected v{expected} (check configs/tools.yaml)", end="")
        print()

        if exec_result.error:
            if not exec_result.stdout:
                print(f"[runner] FATAL: {exec_result.error}", file=sys.stderr)
                return {"al-khaser": version}, [], "fatal"
            print(f"[runner] WARNING: {exec_result.error}")
            print(f"[runner] Partial output captured — continuing with available results")
            status = "partial"
        else:
            status = "complete"

        parsed = AlKhaserParser(categories=categories).parse(exec_result)
        return {"al-khaser": version}, parsed, status

    elif tool_name == "pafish":
        adapter = PafishAdapter(tool_cfg)
        print(f"[runner] Tool      : pafish v{tool_cfg.get('version', '?')} (expected)")
        print(f"[runner] Timeout   : {tool_cfg.get('timeout', 60)}s")
        print(f"[runner] Launching ...")
        exec_result = adapter.run(environment_label=env)

        raw_log = exec_result.stdout + (
            "\n--- STDERR ---\n" + exec_result.stderr if exec_result.stderr else ""
        )
        log_file = log_dir / "pafish_raw.txt"
        log_file.write_text(raw_log, encoding="utf-8")
        print(f"[runner] Exit code : {exec_result.return_code}  Runtime: {exec_result.runtime_seconds:.2f}s")
        print(f"[runner] Raw log   : {log_file}")

        version = extract_pafish_version(exec_result.stdout)
        expected = tool_cfg.get("version", "unknown")
        print(f"[runner] Version   : v{version}", end="")
        if version != expected and version != "unknown":
            print(f"  WARNING: expected v{expected} (check configs/tools.yaml)", end="")
        print()

        if exec_result.error:
            if not exec_result.stdout:
                print(f"[runner] FATAL: {exec_result.error}", file=sys.stderr)
                return {"pafish": version}, [], "fatal"
            print(f"[runner] WARNING: {exec_result.error}")
            print(f"[runner] Partial output captured — continuing with available results")
            status = "partial"
        else:
            status = "complete"

        parsed = PafishParser(categories=categories).parse(exec_result)
        return {"pafish": version}, parsed, status

    else:
        print(f"[runner] WARNING: unknown tool '{tool_name}' — skipping", file=sys.stderr)
        return {}, [], "complete"


def _run_scenario(
    scenario: dict,
    category_filter: Optional[List[str]],
    env: str,
    run_id: str,
    output_dir: Path,
    log_dir: Path,
) -> Optional[ScenarioResult]:
    """
    Execute one scenario end-to-end, running every configured probe tool.

    Returns a ScenarioResult on success (even partial), or None only if every
    configured tool failed to produce any output.
    """
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

    all_parsed: list = []
    tool_versions: dict = {}
    worst_status = "complete"

    for tool_name, tool_cfg in scenario["tools"].items():
        print()
        tv, parsed, status = _run_tool(tool_name, tool_cfg, categories, env, log_dir)
        tool_versions.update(tv)
        all_parsed.extend(parsed)
        if status == "partial" and worst_status == "complete":
            worst_status = "partial"
        elif status == "fatal":
            worst_status = "fatal"

    check_results = [r for r in all_parsed if r.category_id != "uncategorized"]
    ignored = len(all_parsed) - len(check_results)

    if worst_status == "fatal" and not check_results:
        print("[sbxprobe] FATAL: all tools failed to produce output.", file=sys.stderr)
        return None

    run_status = "partial" if worst_status in ("partial", "fatal") else "complete"

    print(f"\n[parser] Total checks : {len(check_results)}"
          + (f"  ({ignored} ignored — no keyword match)" if ignored else "")
          + (f"  [from {len(scenario['tools'])} tool(s)]" if len(scenario["tools"]) > 1 else ""))

    if not check_results:
        print(
            "[parser] WARNING: no results parsed. Verify binaries produced output "
            "and that scenario keywords match the tool output format.",
            file=sys.stderr,
        )

    engine = ScoringEngine(scenario.get("scoring", {}))
    score_report = engine.score(check_results, categories)

    score_str = f"{score_report.global_score:.4f}" if score_report.global_score is not None else "N/A"
    print(f"\n[scoring] Score: {score_str}  Risk: {score_report.risk_level}  "
          f"Detection rate: {score_report.detection_rate * 100:.1f}%")
    for cat in score_report.category_scores:
        if cat.weight == 0:
            continue
        cs = f"{cat.score:.4f}" if cat.score is not None else "N/A"
        print(f"  {cat.name:<30} {cs}  "
              f"({cat.checks_count} checks, {cat.detected_count} detected)")

    reporter = ReportGenerator(
        scenario=scenario,
        environment_label=env,
        run_id=run_id,
        output_dir=output_dir,
        run_status=run_status,
        tool_versions=tool_versions,
    )
    html_reporter = HTMLReportGenerator(
        scenario=scenario,
        environment_label=env,
        run_id=run_id,
        output_dir=output_dir,
        run_status=run_status,
        tool_versions=tool_versions,
    )
    print()
    reporter.write_json(check_results, score_report)
    reporter.write_csv(check_results)
    reporter.write_markdown(check_results, score_report)
    html_reporter.write(check_results, score_report)

    return ScenarioResult(
        scenario=scenario,
        checks=check_results,
        score=score_report,
        run_status=run_status,
        tool_versions=tool_versions,
        report_dir=output_dir,
    )


def main() -> int:
    args = parse_args()

    # Resolve output root: explicit arg → use as-is if absolute, else relative to
    # output_root(). Default (no arg) → output_root()/reports.
    if args.output_dir is not None:
        out_base = Path(args.output_dir) if Path(args.output_dir).is_absolute() \
                   else output_root() / args.output_dir
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
            print(f"\n[dry-run] Scenario   : {scenario['scenario_name']} (v{scenario.get('version', '?')})")
            for tool_name, tool_cfg in scenario["tools"].items():
                print(f"[dry-run] Tool       : {tool_name} v{tool_cfg.get('version', '?')} @ {tool_cfg['executable']}")
                if tool_name == "alkhaser":
                    print(f"[dry-run]   Checks   : {tool_cfg.get('checks', [])}")
                    print(f"[dry-run]   Sleep    : {tool_cfg.get('sleep', 10)}s")
                print(f"[dry-run]   Timeout  : {tool_cfg.get('timeout', 120)}s")
            print(f"[dry-run] Categories : {[c['id'] for c in cats]}")
            print(f"[dry-run] Weights    : { {c['id']: c['weight'] for c in cats} }")
        return 0

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base_output = out_base / args.env / run_id
    base_log    = log_base / args.env / run_id

    print(f"[sbxprobe] Env       : {args.env}")
    print(f"[sbxprobe] Run ID    : {run_id}")
    print(f"[sbxprobe] Mode      : {'multi-scenario' if is_multi else 'single-scenario'} "
          f"({len(scenarios)} scenario{'s' if len(scenarios) != 1 else ''})")
    print(f"[sbxprobe] Output    : {base_output}")

    scenario_results: List[ScenarioResult] = []

    for scenario in scenarios:
        sid = scenario["scenario_id"]
        sname = scenario["scenario_name"]

        if is_multi:
            output_dir = base_output / sid
            log_dir    = base_log    / sid
        else:
            output_dir = base_output
            log_dir    = base_log

        print(f"\n{'='*60}")
        print(f"[sbxprobe] Running scenario : {sname}")
        print(f"[sbxprobe] Output           : {output_dir}")
        print(f"{'='*60}")

        result = _run_scenario(
            scenario=scenario,
            category_filter=args.categories,
            env=args.env,
            run_id=run_id,
            output_dir=output_dir,
            log_dir=log_dir,
        )
        if result is not None:
            scenario_results.append(result)

    if is_multi and scenario_results:
        print(f"\n{'='*60}")
        print(f"[sbxprobe] Generating combined report")
        print(f"{'='*60}")
        combined = CombinedHTMLReportGenerator(
            environment_label=args.env,
            run_id=run_id,
            output_dir=base_output,
        )
        combined.write(scenario_results)

    print(f"\n[sbxprobe] Done.")
    return 0 if scenario_results else 1


if __name__ == "__main__":
    sys.exit(main())
