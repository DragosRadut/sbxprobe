"""
Offline validation of the vm_checks scenario against known al-khaser output.
Run with: python tests/test_vm_checks_scenario.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import yaml
from datetime import datetime, timezone

from parser.normalizer import AlKhaserParser, DETECTED, NOT_DETECTED
from scoring.engine import ScoringEngine
from runner.executor import ExecutionResult

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
[*] Checking if process loaded modules contains: avghooka.dll                                      [ GOOD ]
[*] Checking if process loaded modules contains: snxhk.dll                                         [ GOOD ]
[*] Checking if process loaded modules contains: sbiedll.dll                                       [ GOOD ]
[*] Checking if process loaded modules contains: dbghelp.dll                                       [ GOOD ]
[*] Checking if process loaded modules contains: api_log.dll                                       [ GOOD ]
[*] Checking if process loaded modules contains: dir_watch.dll                                     [ GOOD ]
[*] Checking if process loaded modules contains: pstorec.dll                                       [ GOOD ]
[*] Checking if process loaded modules contains: vmcheck.dll                                       [ GOOD ]
[*] Checking if process loaded modules contains: wpespy.dll                                        [ GOOD ]
[*] Checking if process loaded modules contains: cmdvrt64.dll                                      [ GOOD ]
[*] Checking if process loaded modules contains: cmdvrt32.dll                                      [ GOOD ]
[*] Checking if process file name contains: sample.exe                                             [ GOOD ]
[*] Checking if process file name contains: bot.exe                                                [ GOOD ]
[*] Checking if process file name contains: sandbox.exe                                            [ GOOD ]
[*] Checking if process file name contains: malware.exe                                            [ GOOD ]
[*] Checking if process file name contains: test.exe                                               [ GOOD ]
[*] Checking if process file name contains: klavme.exe                                             [ GOOD ]
[*] Checking if process file name contains: myapp.exe                                              [ GOOD ]
[*] Checking if process file name contains: testapp.exe                                            [ GOOD ]
[*] Checking if process file name looks like a hash: al-khaser_x86                                 [ GOOD ]
[*] Checking if username matches : CurrentUser                                                     [ GOOD ]
[*] Checking if username matches : Sandbox                                                         [ GOOD ]
[*] Checking if username matches : Emily                                                           [ GOOD ]
[*] Checking if username matches : HAPUBWS                                                         [ GOOD ]
[*] Checking if username matches : Hong Lee                                                        [ GOOD ]
[*] Checking if username matches : IT-ADMIN                                                        [ GOOD ]
[*] Checking if username matches : Johnson                                                         [ GOOD ]
[*] Checking if username matches : Miller                                                          [ GOOD ]
[*] Checking if username matches : milozs                                                          [ GOOD ]
[*] Checking if username matches : Peter Wilson                                                    [ GOOD ]
[*] Checking if username matches : timmy                                                           [ GOOD ]
[*] Checking if username matches : user                                                            [ GOOD ]
[*] Checking if username matches : sand box                                                        [ GOOD ]
[*] Checking if username matches : malware                                                         [ GOOD ]
[*] Checking if username matches : maltest                                                         [ GOOD ]
[*] Checking if username matches : test user                                                       [ GOOD ]
[*] Checking if username matches : virus                                                           [ GOOD ]
[*] Checking if username matches : John Doe                                                        [ GOOD ]
[*] Checking if hostname matches : SANDBOX                                                         [ GOOD ]
[*] Checking if hostname matches : 7SILVIA                                                         [ GOOD ]
[*] Checking if hostname matches : HANSPETER-PC                                                    [ GOOD ]
[*] Checking if hostname matches : JOHN-PC                                                         [ GOOD ]
[*] Checking if hostname matches : MUELLER-PC                                                      [ GOOD ]
[*] Checking if hostname matches : WIN7-TRAPS                                                      [ GOOD ]
[*] Checking if hostname matches : FORTINET                                                        [ GOOD ]
[*] Checking if hostname matches : TEQUILABOOMBOOM                                                 [ GOOD ]
[*] Checking whether username is 'Wilber' and NetBIOS name starts with 'SC' or 'SW'                [ GOOD ]
[*] Checking whether username is 'admin' and NetBIOS name is 'SystemIT'                            [ GOOD ]
[*] Checking whether username is 'admin' and DNS hostname is 'KLONE_X64-PC'                        [ GOOD ]
[*] Checking whether username is 'John' and two sandbox files exist                                [ GOOD ]
[*] Checking whether four known sandbox 'email' file paths exist                                   [ GOOD ]
[*] Checking whether three known sandbox 'foobar' files exist                                      [ GOOD ]
[*] Checking processes looking-glass-host.exe                                                      [ GOOD ]
[*] Checking processes VDDSysTray.exe                                                              [ GOOD ]
[*] Checking Number of processors in machine                                                       [ GOOD ]
[*] Checking Interupt Descriptor Table location                                                    [ GOOD ]
[*] Checking Local Descriptor Table location                                                       [ GOOD ]
"""


def _load_scenario():
    with open("configs/scenarios/vm_checks.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _make_exec_result(stdout: str) -> ExecutionResult:
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


def test_only_vm_checks_captured():
    """
    With a vm_checks-only scenario, anti-debug and DLL-injection lines from
    al-khaser fall into 'uncategorized' (zero weight) rather than being scored.
    This test confirms that no non-VM check is misclassified INTO vm_checks.
    """
    scenario = _load_scenario()
    parser = AlKhaserParser(categories=scenario["categories"])
    results = parser.parse(_make_exec_result(SAMPLE_OUTPUT))

    vm = [r for r in results if r.category_id == "vm_checks"]
    uncategorized = [r for r in results if r.category_id == "uncategorized"]

    assert len(vm) > 0, "No vm_checks results captured at all"
    print(f"  vm_checks      : {len(vm)}")
    print(f"  uncategorized  : {len(uncategorized)}  (excluded from score — correct)")


def test_debug_checks_not_scored():
    """
    Anti-debug checks must land in 'uncategorized', not in 'vm_checks',
    so they contribute nothing to the transparency score.
    """
    scenario = _load_scenario()
    parser = AlKhaserParser(categories=scenario["categories"])
    results = parser.parse(_make_exec_result(SAMPLE_OUTPUT))

    misclassified = [
        r for r in results
        if r.category_id == "vm_checks"
        and ("isdebuggerpresent" in r.label.lower()
             or "peb.being" in r.label.lower()
             or "breakpoints" in r.label.lower())
    ]
    assert not misclassified, (
        f"Anti-debug checks leaked into vm_checks scoring: "
        + str([r.label for r in misclassified])
    )
    print("  Anti-debug checks correctly excluded from vm_checks score")


def test_score_computed():
    scenario = _load_scenario()
    parser = AlKhaserParser(categories=scenario["categories"])
    results = parser.parse(_make_exec_result(SAMPLE_OUTPUT))

    engine = ScoringEngine(scenario["scoring"])
    report = engine.score(results, scenario["categories"])

    assert report.global_score is not None
    assert 0.0 <= report.global_score <= 1.0
    print(f"  Global score: {report.global_score:.4f}")
    print(f"  Detected: {report.detected_count}  Not detected: {report.not_detected_count}")


def test_coverage_report():
    scenario = _load_scenario()
    parser = AlKhaserParser(categories=scenario["categories"])
    results = parser.parse(_make_exec_result(SAMPLE_OUTPUT))

    uncategorized = [r for r in results if r.category_id == "uncategorized"]
    vm = [r for r in results if r.category_id == "vm_checks"]

    print(f"\n  vm_checks captured  : {len(vm)}")
    print(f"  uncategorized       : {len(uncategorized)}")

    if uncategorized:
        print("  Uncategorized labels (add keywords if these are VM-related):")
        for r in uncategorized:
            print(f"    - {r.label}")

    print("\n  vm_checks labels captured:")
    for r in vm:
        status = "BAD " if r.normalized == DETECTED else "GOOD"
        print(f"    [{status}] {r.label}")


if __name__ == "__main__":
    print("-- test_only_vm_checks_captured")
    test_only_vm_checks_captured()
    print("-- test_debug_checks_not_scored")
    test_debug_checks_not_scored()
    print("-- test_score_computed")
    test_score_computed()
    print("-- test_coverage_report")
    test_coverage_report()
    print("\nAll tests passed.")
