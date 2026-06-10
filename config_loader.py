import yaml
from pathlib import Path

from _paths import bundle_root
from runner.adapters.alkhaser import VALID_CHECKS

DEFAULT_TOOLS_PATH = str(bundle_root() / "configs" / "tools.yaml")
SCENARIOS_DIR      = bundle_root() / "configs" / "scenarios"


def resolve_scenarios(names: list, tools_path: str = None) -> list:
    """
    Resolve one or more scenario names to loaded scenario dicts.

    Accepted forms:
      - "all"                        → every *.yaml in configs/scenarios/
      - "vm_checks"                  → configs/scenarios/vm_checks.yaml
      - "configs/scenarios/foo.yaml" → explicit path
    """
    if tools_path is None:
        tools_path = DEFAULT_TOOLS_PATH

    scenarios_dir = bundle_root() / "configs" / "scenarios"

    if names == ["all"]:
        paths = sorted(scenarios_dir.glob("*.yaml"))
        if not paths:
            raise ValueError(f"No scenario YAML files found in {scenarios_dir}")
    else:
        paths = []
        for name in names:
            p = Path(name)
            if p.exists():
                paths.append(p)
            elif (scenarios_dir / f"{name}.yaml").exists():
                paths.append(scenarios_dir / f"{name}.yaml")
            else:
                raise ValueError(
                    f"Scenario '{name}' not found. "
                    f"Provide a file path or a name matching a file in {scenarios_dir}/."
                )

    return [load_scenario(str(p), tools_path) for p in paths]


def load_scenario(scenario_path: str, tools_path: str = None) -> dict:
    if tools_path is None:
        tools_path = DEFAULT_TOOLS_PATH
    scenario  = _load_yaml(scenario_path)
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
    Inject global tool defaults (executable path, version, default timeouts)
    into each tool block present in the scenario.

    The executable and version always come from tools.yaml and cannot be
    overridden per-scenario.  Timeouts and sleep may be overridden.

    Paths are resolved relative to bundle_root() so the code works identically
    in dev mode and inside a frozen PyInstaller bundle.
    """
    root = bundle_root()
    for tool_name, scenario_tool in scenario.get("tools", {}).items():
        global_tool = tools_cfg.get(tool_name)
        if not global_tool:
            raise ValueError(
                f"Tool '{tool_name}' referenced in scenario but not in tools.yaml. "
                f"Add it to configs/tools.yaml first."
            )

        raw_exe = global_tool["executable"]
        scenario_tool["executable"] = str(root / Path(raw_exe))
        scenario_tool["version"]    = global_tool.get("version", "unknown")

        if "timeout" not in scenario_tool:
            scenario_tool["timeout"] = global_tool.get("default_timeout", 120)
        if "sleep" not in scenario_tool:
            scenario_tool["sleep"] = global_tool.get("default_sleep", 10)


def _validate(scenario: dict):
    for field in ["scenario_id", "scenario_name", "categories", "scoring"]:
        if field not in scenario:
            raise ValueError(f"Scenario missing required field: '{field}'")

    # ── tools block: optional but if present must reference known tools ────────
    known_tools = {"alkhaser", "pafish"}
    for tool_name in scenario.get("tools", {}):
        if tool_name not in known_tools:
            raise ValueError(
                f"Unknown tool '{tool_name}' in scenario. Known: {sorted(known_tools)}"
            )

    # ── categories ────────────────────────────────────────────────────────────
    categories = scenario["categories"]
    if not categories:
        raise ValueError("Scenario must define at least one category.")

    for cat in categories:
        for f in ["id", "name", "weight"]:
            if f not in cat:
                raise ValueError(f"Category '{cat.get('id', '?')}' missing field: '{f}'")

        flags   = cat.get("alkhaser_flags", [])
        pafish  = cat.get("pafish", False)

        if not flags and not pafish:
            raise ValueError(
                f"Category '{cat['id']}' has no data source. "
                f"Set alkhaser_flags and/or pafish: true."
            )

        if flags:
            unknown = [f for f in flags if f.upper() not in VALID_CHECKS]
            if unknown:
                raise ValueError(
                    f"Category '{cat['id']}': unknown al-khaser flag(s) {unknown}. "
                    f"Valid: {sorted(VALID_CHECKS)}"
                )

    # ── pafish config: if any category enables pafish, section map must exist ─
    pafish_cats = [c for c in categories if c.get("pafish", False)]
    if pafish_cats:
        ps = scenario.get("pafish_sections", {})
        if not ps:
            raise ValueError(
                "At least one category has pafish: true but 'pafish_sections' "
                "is missing from the scenario. Add a pafish_sections mapping."
            )
        valid_targets = {c["id"] for c in categories} | {"exclude"}
        for section, cat_id in ps.items():
            if cat_id not in valid_targets:
                raise ValueError(
                    f"pafish_sections: section '{section}' maps to unknown "
                    f"category '{cat_id}'. Valid: {sorted(valid_targets)}"
                )
        for label, cat_id in scenario.get("pafish_label_overrides", {}).items():
            if cat_id not in valid_targets:
                raise ValueError(
                    f"pafish_label_overrides: label '{label}' maps to unknown "
                    f"category '{cat_id}'. Valid: {sorted(valid_targets)}"
                )

    # ── weights ────────────────────────────────────────────────────────────────
    total_weight = sum(c["weight"] for c in categories)
    if not (0.99 <= total_weight <= 1.01):
        raise ValueError(
            f"Category weights must sum to 1.0 (got {total_weight:.3f})."
        )
