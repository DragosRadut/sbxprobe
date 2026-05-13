"""
Offline parser validation — paste al-khaser output into SAMPLE_OUTPUT and run:
    python -m pytest tests/test_parser.py -v
or:
    python tests/test_parser.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from parser.normalizer import _extract_pairs, AlKhaserParser, DETECTED, NOT_DETECTED
from runner.executor import ExecutionResult
from datetime import datetime, timezone

SAMPLE_OUTPUT = """
[al-khaser version 0.81]
-------------------------[Initialisation]-------------------------

[*] You are running: Microsoft Windows 10  (build 19045) 64-bit
[*] All APIs present and accounted for.
Process is running under WOW64


-------------------------[TLS Callbacks]-------------------------
[*] TLS process attach callback                                                                    [ GOOD ]
[*] TLS thread attach callback                                                                     [ GOOD ]

-------------------------[Debugger Detection]-------------------------
[*] Checking IsDebuggerPresent API                                                                 [ GOOD ]
[*] Checking PEB.BeingDebugged                                                                     [ GOOD ]
[*] Checking CheckRemoteDebuggerPresent API                                                        [ GOOD ]
[*] Checking PEB.NtGlobalFlag                                                                      [ GOOD ]
[*] Checking ProcessHeap.Flags                                                                     [ GOOD ]
[*] Checking ProcessHeap.ForceFlags                                                                [ GOOD ]
[*] Checking Low Fragmentation Heap                                                                [ GOOD ]
[*] Checking NtQueryInformationProcess with ProcessDebugPort                                       [ GOOD ]
[*] Checking NtQueryInformationProcess with ProcessDebugFlags                                      [ GOOD ]
[*] Checking NtQueryInformationProcess with ProcessDebugObject                                     [ GOOD ]
[*] Checking WudfIsAnyDebuggerPresent API                                                          [ GOOD ]
[*] Checking WudfIsKernelDebuggerPresent API                                                       [ GOOD ]
[*] Checking WudfIsUserDebuggerPresent API                                                         [ GOOD ]
[*] Checking NtSetInformationThread with ThreadHideFromDebugger                                    [ GOOD ]
[*] Checking CloseHandle with an invalide handle                                                   [ GOOD ]
[*] Checking NtSystemDebugControl                                                                  [ GOOD ]
[*] Checking UnhandledExcepFilterTest                                                              [ GOOD ]
[*] Checking OutputDebugString                                                                     [ GOOD ]
[*] Checking Hardware Breakpoints                                                                  [ GOOD ]
[*] Checking Software Breakpoints                                                                  [ GOOD ]
[*] Checking Interupt 0x2d                                                                         [ GOOD ]
[*] Checking Interupt 1                                                                            [ GOOD ]
[*] Checking trap flag                                                                             [ GOOD ]
[*] Checking Memory Breakpoints PAGE GUARD                                                         [ GOOD ]
[*] Checking If Parent Process is explorer.exe                                                     [ BAD  ]
[*] Checking SeDebugPrivilege                                                                      [ GOOD ]
[*] Checking NtQueryObject with ObjectTypeInformation                                              [ GOOD ]
[*] Checking NtQueryObject with ObjectAllTypesInformation                                          [ GOOD ]
[*] Checking NtYieldExecution                                                                      [ GOOD ]
[*] Checking CloseHandle protected handle trick                                                    [ GOOD ]
[*] Checking NtQuerySystemInformation with SystemKernelDebuggerInformation                         [ GOOD ]
[*] Checking SharedUserData->KdDebuggerEnabled                                                     [ GOOD ]
[*] Checking if process is in a job                                                                [ BAD  ]
[*] Checking VirtualAlloc write watch (buffer only)                                                [ GOOD ]
[*] Checking VirtualAlloc write watch (API calls)                                                  [ GOOD ]
[*] Checking VirtualAlloc write watch (IsDebuggerPresent)                                          [ GOOD ]
[*] Checking VirtualAlloc write watch (code write)                                                 [ GOOD ]
[*] Checking for page exception breakpoints                                                        [ GOOD ]
[*] Checking for API hooks outside module bounds                                                   [ GOOD ]

-------------------------[DLL Injection Detection]-------------------------
[*] Enumerating modules with EnumProcessModulesEx [32-bit]                                         [ GOOD ]
[*] Enumerating modules with EnumProcessModulesEx [64-bit]                                         [ GOOD ]
[*] Enumerating modules with EnumProcessModulesEx [ALL]                                            [ GOOD ]
[*] Enumerating modules with ToolHelp32                                                            [ GOOD ]
[*] Enumerating the process LDR via LdrEnumerateLoadedModules                                      [ GOOD ]
[*] Enumerating the process LDR directly                                                           [ GOOD ]
[*] Walking process memory with GetModuleInformation                                               [ GOOD ]
[*] Walking process memory for hidden modules

 [!] Running on WoW64, there will be false positives due to wow64 DLLs.
 [!] Executable at 77CB0000
[ BAD  ]
[*] Walking process memory for .NET module structures                                              [ GOOD ]

-------------------------[Generic Sandboxe/VM Detection]-------------------------
[*] Checking if process loaded modules contains: avghookx.dll                                      [ GOOD ]
[*] Checking if process loaded modules contains: sbiedll.dll                                       [ GOOD ]
[*] Checking if process loaded modules contains: vmcheck.dll                                       [ GOOD ]
[*] Checking if process file name contains: sample.exe                                             [ GOOD ]
[*] Checking if username matches : CurrentUser                                                     [ GOOD ]
[*] Checking if username matches : Sandbox                                                         [ GOOD ]
[*] Checking if hostname matches : SANDBOX                                                         [ GOOD ]
[*] Checking whether username is 'Wilber' and NetBIOS name starts with 'SC' or 'SW'                [ GOOD ]
[*] Checking whether four known sandbox 'email' file paths exist                                   [ GOOD ]
[*] Checking processes looking-glass-host.exe                                                      [ GOOD ]
[*] Checking Number of processors in machine                                                       [ GOOD ]
[*] Checking Interupt Descriptor Table location                                                    [ GOOD ]
[*] Checking Local Descriptor Table location                                                       [ GOOD ]
"""


def make_exec_result(stdout: str) -> ExecutionResult:
    return ExecutionResult(
        check_id="test",
        tool="al-khaser_x86.exe",
        return_code=0,
        stdout=stdout,
        stderr="",
        runtime_seconds=1.0,
        timestamp=datetime.now(timezone.utc).isoformat(),
        environment_label="test_env",
    )


def test_extract_pairs_count():
    pairs = _extract_pairs(SAMPLE_OUTPUT)
    # Info lines ([*] You are running, [*] All APIs present) must NOT be captured
    # because they have no trailing [ GOOD ] / [ BAD  ]
    assert len(pairs) > 0, "No pairs extracted"
    print(f"  Extracted {len(pairs)} pairs")


def test_deferred_result_captured():
    pairs = _extract_pairs(SAMPLE_OUTPUT)
    labels = [label for label, _ in pairs]
    assert any("hidden modules" in l.lower() for l in labels), (
        "Deferred-result line 'Walking process memory for hidden modules' was not captured"
    )


def test_good_maps_to_not_detected():
    pairs = _extract_pairs(SAMPLE_OUTPUT)
    good_pairs = [p for p in pairs if p[1] == "GOOD"]
    assert good_pairs, "No GOOD results found"
    # Verify normalization direction
    import yaml
    with open("configs/scenarios/baseline.yaml", encoding="utf-8") as f:
        scenario = yaml.safe_load(f)
    parser = AlKhaserParser(categories=scenario["categories"])
    results = parser.parse(make_exec_result(SAMPLE_OUTPUT))
    good_results = [r for r in results if r.raw_value == "GOOD"]
    assert all(r.normalized == NOT_DETECTED for r in good_results)


def test_bad_maps_to_detected():
    import yaml
    with open("configs/scenarios/baseline.yaml", encoding="utf-8") as f:
        scenario = yaml.safe_load(f)
    parser = AlKhaserParser(categories=scenario["categories"])
    results = parser.parse(make_exec_result(SAMPLE_OUTPUT))
    bad_results = [r for r in results if r.raw_value == "BAD"]
    assert bad_results, "No BAD results found — check sample output contains [ BAD  ] lines"
    assert all(r.normalized == DETECTED for r in bad_results)


def test_category_assignment():
    import yaml
    with open("configs/scenarios/baseline.yaml", encoding="utf-8") as f:
        scenario = yaml.safe_load(f)
    parser = AlKhaserParser(categories=scenario["categories"])
    results = parser.parse(make_exec_result(SAMPLE_OUTPUT))

    by_cat = {}
    for r in results:
        by_cat.setdefault(r.category_id, []).append(r.label)

    print("\n  Category breakdown:")
    for cat_id, labels in sorted(by_cat.items()):
        print(f"    {cat_id} ({len(labels)})")
        for l in labels:
            print(f"      - {l}")

    uncategorized = by_cat.get("uncategorized", [])
    if uncategorized:
        print(f"\n  WARNING — {len(uncategorized)} uncategorized checks:")
        for l in uncategorized:
            print(f"    - {l}")


if __name__ == "__main__":
    print("-- test_extract_pairs_count")
    test_extract_pairs_count()
    print("-- test_deferred_result_captured")
    test_deferred_result_captured()
    print("-- test_good_maps_to_not_detected")
    test_good_maps_to_not_detected()
    print("-- test_bad_maps_to_detected")
    test_bad_maps_to_detected()
    print("-- test_category_assignment")
    test_category_assignment()
    print("\nAll tests passed.")
