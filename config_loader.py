import yaml
from pathlib import Path

from runner.adapters.alkhaser import VALID_CHECKS

DEFAULT_TOOLS_PATH = "configs/tools.yaml"
SCENARIOS_DIR = Path("configs/scenarios")


def resolve_scenarios(names: list, tools_path: str = DEFAULT_TOOLS_PATH) -> list:
    """
    Resolve one or more scenario names to loaded scenario dicts.

    Accepted forms:
      - "all"                       → every *.yaml in configs/scenarios/
      - "vm_checks"                 → configs/scenarios/vm_checks.yaml
      - "configs/scenarios/foo.yaml"→ explicit path (backward compat)
    Returns a list of loaded+merged scenario dicts, in discovery order.
    """
    if names == ["all"]:
        paths = sorted(SCENARIOS_DIR.glob("*.yaml"))
        if not paths:
            raise ValueError(f"No scenario YAML files found in {SCENARIOS_DIR}")
    else:
        paths = []
        for name in names:
            p = Path(name)
            if p.exists():
                paths.append(p)
            elif (SCENARIOS_DIR / f"{name}.yaml").exists():
                paths.append(SCENARIOS_DIR / f"{name}.yaml")
            else:
                raise ValueError(
                    f"Scenario '{name}' not found. "
                    f"Provide a file path or a name matching a file in {SCENARIOS_DIR}/."
                )

    return [load_scenario(str(p), tools_path) for p in paths]


def load_scenario(scenario_path: str, tools_path: str = DEFAULT_TOOLS_PATH) -> dict:
    scenario = _load_yaml(scenario_path)
    tools_cfg = _load_yaml(tools_path)
    _merge_tools(scenario, tools_cfg)
    _validate(scenario)
    return scenario


# ── Internal helpers ──────────────────────────────────────────────────────────

def _load_yaml(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with p.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _merge_tools(scenario: dict, tools_cfg: dict):
    """
    Inject global tool defaults into each tool block in the scenario.

    Resolution order (highest → lowest priority):
      scenario value  >  tools.yaml default  >  hardcoded fallback

    The executable and version always come from tools.yaml and cannot
    be overridden per scenario — they are managed in one place only.
    """
    for tool_name, scenario_tool in scenario.get("tools", {}).items():
        global_tool = tools_cfg.get(tool_name)
        if not global_tool:
            raise ValueError(
                f"Tool '{tool_name}' referenced in scenario but not found in tools.yaml. "
                f"Add it to configs/tools.yaml before using it."
            )

        # executable and version: always from tools.yaml, not overridable per-scenario
        scenario_tool["executable"] = global_tool["executable"]
        scenario_tool["version"]    = global_tool.get("version", "unknown")

        # timeout and sleep: scenario can override, otherwise fall back to tool defaults
        if "timeout" not in scenario_tool:
            scenario_tool["timeout"] = global_tool.get("default_timeout", 120)
        if "sleep" not in scenario_tool:
            scenario_tool["sleep"] = global_tool.get("default_sleep", 10)


def _validate(scenario: dict):
    required_top = ["scenario_id", "scenario_name", "tools", "categories", "scoring"]
    for field in required_top:
        if field not in scenario:
            raise ValueError(f"Scenario missing required field: '{field}'")

    tools = scenario["tools"]
    if not tools:
        raise ValueError("Scenario must define at least one tool under 'tools:'")

    # Validate al-khaser check names if the tool is present
    ak = tools.get("alkhaser")
    if ak is not None:
        if "checks" not in ak or not ak["checks"]:
            raise ValueError(
                "tools.alkhaser must define 'checks' — a list of al-khaser --check flags. "
                f"Valid: {sorted(VALID_CHECKS)}"
            )
        unknown = [c for c in ak["checks"] if c.upper() not in VALID_CHECKS]
        if unknown:
            raise ValueError(
                f"Unknown al-khaser check type(s): {unknown}. Valid: {sorted(VALID_CHECKS)}"
            )

    known_tools = {"alkhaser", "pafish"}
    for tool_name in tools:
        if tool_name not in known_tools:
            raise ValueError(
                f"Unknown tool '{tool_name}' in scenario. Known tools: {sorted(known_tools)}"
            )

    required_cat = ["id", "name", "weight", "keywords"]
    for cat in scenario["categories"]:
        for field in required_cat:
            if field not in cat:
                raise ValueError(f"Category '{cat.get('id', '?')}' missing field: '{field}'")

    total_weight = sum(c["weight"] for c in scenario["categories"])
    if not (0.99 <= total_weight <= 1.01):
        raise ValueError(
            f"Category weights must sum to 1.0 (got {total_weight:.3f})."
        )
