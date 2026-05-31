"""
Smoke test: validate that the vm_checks scenario loads and parses correctly
with the new flag-based architecture.

Run with:  python -m pytest tests/test_vm_checks_scenario.py -v
       or: python tests/test_vm_checks_scenario.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import yaml
from datetime import datetime, timezone

from parser.normalizer import AlKhaserParser, DETECTED, NOT_DETECTED
from scoring.engine import ScoringEngine, deduplicate_checks
from runner.executor import ExecutionResult

# Subset of real al-khaser v0.82 output for the VBOX + GEN_SANDBOX flags
SAMPLE_OUTPUT = """
[al-khaser version 0.82]
-------------------------[Generic Sandbox/VM Detection]-------------------------
[*] Checking if process loaded modules contains: avghookx.dll                  [ GOOD ]
[*] Checking if process loaded modules contains: sbiedll.dll                   [ GOOD ]
[*] Checking if process file name contains: sample.exe                         [ GOOD ]
[*] Checking if username matches : Sandbox                                     [ GOOD ]
[*] Checking if hostname matches : SANDBOX                                     [ GOOD ]
[*] Checking Number of processors in machine                                   [ GOOD ]

-------------------------[VirtualBox Detection]-------------------------
[*] Checking reg key HARDWARE\\ACPI\\DSDT\\VBOX__                               [ BAD  ]
[*] Checking reg key HARDWARE\\ACPI\\FADT\\VBOX__                               [ BAD  ]
[*] Checking reg key HARDWARE\\ACPI\\RSDT\\VBOX__                               [ BAD  ]
[*] Checking if CPU hypervisor field is set using cpuid(0x1)                   [ BAD  ]
[*] Checking hypervisor vendor using cpuid(0x40000000)                        [ BAD  ]
[*] Checking ACPI table strings                                                [ BAD  ]
[*] Checking VirtualBox Guest Additions directory                              [ GOOD ]
[*] Checking file C:\\Windows\\System32\\drivers\\VBoxMouse.sys                 [ GOOD ]
[*] Checking VirtualBox process vboxservice.exe                                [ GOOD ]
"""


def _load_scenario():
    path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "configs", "scenarios", "vm_checks.yaml"
    )
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _make_exec_result(stdout: str) -> ExecutionResult:
    return ExecutionResult(
        check_id="test", tool="al-khaser_x86.exe", return_code=0,
        stdout=stdout, stderr="", runtime_seconds=1.0,
        timestamp=datetime.now(timezone.utc).isoformat(),
        environment_label="test_env",
    )


def test_scenario_loads():
    scenario = _load_scenario()
    assert scenario["scenario_id"] == "vm_checks_001"
    cats = scenario["categories"]
    assert len(cats) == 1
    assert cats[0]["id"] == "vm_checks"
    assert cats[0].get("alkhaser_flags"), "vm_checks category must have alkhaser_flags"
    print(f"  alkhaser_flags: {cats[0]['alkhaser_flags']}")


def test_all_checks_assigned_to_vm_checks():
    """With flag-based assignment, every parsed check goes to vm_checks."""
    scenario = _load_scenario()
    cat      = scenario["categories"][0]
    parser   = AlKhaserParser(category_id=cat["id"], category_name=cat["name"])
    results  = parser.parse(_make_exec_result(SAMPLE_OUTPUT))

    assert results, "No results parsed"
    assert all(r.category_id == "vm_checks" for r in results), \
        "All results must be assigned to vm_checks"
    print(f"  Parsed {len(results)} checks, all → vm_checks")


def test_detected_and_not_detected_present():
    scenario = _load_scenario()
    cat      = scenario["categories"][0]
    parser   = AlKhaserParser(category_id=cat["id"], category_name=cat["name"])
    results  = parser.parse(_make_exec_result(SAMPLE_OUTPUT))

    detected     = [r for r in results if r.normalized == DETECTED]
    not_detected = [r for r in results if r.normalized == NOT_DETECTED]

    assert detected,     "No detected checks found in VirtualBox sample"
    assert not_detected, "No not-detected checks found in sample"
    print(f"  detected={len(detected)}  not_detected={len(not_detected)}")


def test_score_in_range():
    scenario = _load_scenario()
    cat      = scenario["categories"][0]
    parser   = AlKhaserParser(category_id=cat["id"], category_name=cat["name"])
    results  = parser.parse(_make_exec_result(SAMPLE_OUTPUT))

    engine = ScoringEngine(scenario["scoring"])
    report = engine.score(results, scenario["categories"])

    assert report.global_score is not None, "Score must not be None"
    assert 0.0 <= report.global_score <= 1.0
    print(f"  Score={report.global_score:.4f}  Risk={report.risk_level}  "
          f"Detected={report.detected_count}/{report.total_checks}")


def test_deduplication_does_not_affect_single_tool():
    """Deduplication on single-tool results must leave count unchanged."""
    scenario = _load_scenario()
    cat      = scenario["categories"][0]
    parser   = AlKhaserParser(category_id=cat["id"], category_name=cat["name"])
    results  = parser.parse(_make_exec_result(SAMPLE_OUTPUT))

    deduped = deduplicate_checks(results)
    assert len(deduped) == len(results), \
        "Single-tool results should not be reduced by deduplication"
    assert not any(r.deduplicated for r in deduped), \
        "No check should be marked deduplicated when only one tool ran"


if __name__ == "__main__":
    tests = [
        test_scenario_loads,
        test_all_checks_assigned_to_vm_checks,
        test_detected_and_not_detected_present,
        test_score_in_range,
        test_deduplication_does_not_affect_single_tool,
    ]
    for t in tests:
        print(f"-- {t.__name__}")
        t()
    print("\nAll tests passed.")
