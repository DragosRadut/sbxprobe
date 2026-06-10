"""
Offline parser validation — tests the al-khaser output parser and the
deduplication logic without requiring the probe binaries to be present.

Run with:  python -m pytest tests/test_parser.py -v
       or: python tests/test_parser.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import datetime, timezone

from parser.normalizer import _extract_pairs, AlKhaserParser, DETECTED, NOT_DETECTED
from parser.pafish_normalizer import PafishParser
from runner.executor import ExecutionResult
from scoring.engine import deduplicate_checks

ALKHASER_SAMPLE = """
[al-khaser version 0.82]
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
[*] Checking If Parent Process is explorer.exe                                                     [ BAD  ]
[*] Checking if process is in a job                                                                [ GOOD ]

[*] Walking process memory for hidden modules

 [!] Running on WoW64, there will be false positives due to wow64 DLLs.
 [!] Executable at 77CB0000
[ BAD  ]
[*] Walking process memory for .NET module structures                                              [ GOOD ]
"""

PAFISH_SAMPLE = """
* Pafish (Paranoid Fish) *

[-] Windows version: 6.2 build 9200
[-] Running in WoW64: True

[-] Debuggers detection
[*] Using IsDebuggerPresent() ... OK
[*] Using BeingDebugged via PEB access ... OK

[-] CPU information based detections
[*] Checking the difference between CPU timestamp counters (rdtsc) ... OK
[*] Checking the difference between CPU timestamp counters (rdtsc) forcing VM exit ... traced!
[*] Checking hypervisor bit in cpuid feature bits ... traced!
[*] Checking cpuid hypervisor vendor for known VM vendors ... traced!

[-] Generic reverse turing tests
[*] Checking mouse movement ... traced!
[*] Checking dialog confirmation ... traced!

[-] Generic sandbox detection
[*] Checking if disk size <= 60GB via GetDiskFreeSpaceExA() ... traced!
[*] Checking if Sleep() is patched using GetTickCount() ... OK

[-] VirtualBox detection
[*] Reg key (HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__) ... traced!
[*] Reg key (HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions) ... OK
[*] Looking for a MAC address starting with 08:00:27 ... traced!

[-] VMware detection
[*] Reg key (HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools) ... OK

[-] Cuckoo detection
[*] Looking in the TLS for the hooks information structure ... OK
"""


def _make_ak_result(stdout: str) -> ExecutionResult:
    return ExecutionResult(
        check_id="test", tool="al-khaser_x86.exe", return_code=0,
        stdout=stdout, stderr="", runtime_seconds=1.0,
        timestamp=datetime.now(timezone.utc).isoformat(),
        environment_label="test_env",
    )


def _make_pf_result(stdout: str) -> ExecutionResult:
    return ExecutionResult(
        check_id="test", tool="pafish.exe", return_code=0,
        stdout=stdout, stderr="", runtime_seconds=1.0,
        timestamp=datetime.now(timezone.utc).isoformat(),
        environment_label="test_env",
    )


# ── AlKhaser parser tests ──────────────────────────────────────────────────────

def test_extract_pairs_count():
    pairs = _extract_pairs(ALKHASER_SAMPLE)
    assert len(pairs) > 0, "No pairs extracted"
    print(f"  Extracted {len(pairs)} pairs")


def test_deferred_result_captured():
    """The deferred-result case ([*] line + [!] diagnostic + orphan [ BAD ]) must be captured."""
    pairs = _extract_pairs(ALKHASER_SAMPLE)
    labels = [label for label, _ in pairs]
    assert any("hidden modules" in l.lower() for l in labels), (
        "Deferred result 'Walking process memory for hidden modules' was not captured"
    )


def test_good_maps_to_not_detected():
    parser  = AlKhaserParser(category_id="anti_debug", category_name="Anti-Debug Checks")
    results = parser.parse(_make_ak_result(ALKHASER_SAMPLE))
    good    = [r for r in results if r.raw_value == "GOOD"]
    assert good, "No GOOD results found in sample"
    assert all(r.normalized == NOT_DETECTED for r in good), \
        "GOOD should map to not_detected"


def test_bad_maps_to_detected():
    parser  = AlKhaserParser(category_id="anti_debug", category_name="Anti-Debug Checks")
    results = parser.parse(_make_ak_result(ALKHASER_SAMPLE))
    bad     = [r for r in results if r.raw_value == "BAD"]
    assert bad, "No BAD results found — check sample output"
    assert all(r.normalized == DETECTED for r in bad), \
        "BAD should map to detected"


def test_all_results_assigned_to_given_category():
    """Flag-based design: ALL results from a run go to the specified category."""
    parser  = AlKhaserParser(category_id="vm_checks", category_name="VM Detection Checks")
    results = parser.parse(_make_ak_result(ALKHASER_SAMPLE))
    assert all(r.category_id == "vm_checks" for r in results), \
        "All results must be assigned to the category supplied at parser construction"


# ── Pafish parser tests ────────────────────────────────────────────────────────

def test_pafish_ok_maps_to_not_detected():
    categories      = [
        {"id": "vm_checks",     "name": "VM Detection Checks"},
        {"id": "anti_debug",    "name": "Anti-Debug Checks"},
        {"id": "timing_attacks","name": "Timing Attacks"},
    ]
    pafish_sections = {
        "Debuggers detection":              "anti_debug",
        "CPU information based detections": "vm_checks",
        "Generic sandbox detection":        "vm_checks",
        "VirtualBox detection":             "vm_checks",
        "VMware detection":                 "vm_checks",
    }
    pafish_label_overrides = {
        "Checking the difference between CPU timestamp counters (rdtsc)":                "timing_attacks",
        "Checking the difference between CPU timestamp counters (rdtsc) forcing VM exit":"timing_attacks",
    }
    parser  = PafishParser(categories=categories,
                           pafish_sections=pafish_sections,
                           pafish_label_overrides=pafish_label_overrides)
    results = parser.parse(_make_pf_result(PAFISH_SAMPLE))

    ok = [r for r in results if r.raw_value == "ok"]
    assert ok, "No OK results found"
    assert all(r.normalized == NOT_DETECTED for r in ok)


def test_pafish_traced_maps_to_detected():
    categories      = [
        {"id": "vm_checks",     "name": "VM Detection Checks"},
        {"id": "anti_debug",    "name": "Anti-Debug Checks"},
        {"id": "timing_attacks","name": "Timing Attacks"},
    ]
    pafish_sections = {
        "Debuggers detection":              "anti_debug",
        "CPU information based detections": "vm_checks",
        "Generic sandbox detection":        "vm_checks",
        "VirtualBox detection":             "vm_checks",
        "VMware detection":                 "vm_checks",
    }
    pafish_label_overrides = {
        "Checking the difference between CPU timestamp counters (rdtsc)":                "timing_attacks",
        "Checking the difference between CPU timestamp counters (rdtsc) forcing VM exit":"timing_attacks",
    }
    parser  = PafishParser(categories=categories,
                           pafish_sections=pafish_sections,
                           pafish_label_overrides=pafish_label_overrides)
    results = parser.parse(_make_pf_result(PAFISH_SAMPLE))

    traced = [r for r in results if r.raw_value == "traced!"]
    assert traced, "No traced! results found"
    assert all(r.normalized == DETECTED for r in traced)


def test_pafish_rdtsc_goes_to_timing_attacks():
    """RDTSC label override must route to timing_attacks even though section is vm_checks."""
    categories      = [
        {"id": "vm_checks",     "name": "VM Detection Checks"},
        {"id": "timing_attacks","name": "Timing Attacks"},
    ]
    pafish_sections = {
        "CPU information based detections": "vm_checks",
    }
    pafish_label_overrides = {
        "Checking the difference between CPU timestamp counters (rdtsc)":                "timing_attacks",
        "Checking the difference between CPU timestamp counters (rdtsc) forcing VM exit":"timing_attacks",
    }
    parser  = PafishParser(categories=categories,
                           pafish_sections=pafish_sections,
                           pafish_label_overrides=pafish_label_overrides)
    results = parser.parse(_make_pf_result(PAFISH_SAMPLE))

    rdtsc = [r for r in results if "rdtsc" in r.label.lower()]
    assert rdtsc, "No RDTSC results found"
    assert all(r.category_id == "timing_attacks" for r in rdtsc), \
        f"RDTSC checks must go to timing_attacks, got: {[r.category_id for r in rdtsc]}"


# ── Deduplication tests ────────────────────────────────────────────────────────

def test_deduplication_merges_same_check():
    """Same (category_id, check_id) from two tools → one merged result."""
    ak_parser = AlKhaserParser(category_id="anti_debug", category_name="Anti-Debug Checks")
    ak_results = ak_parser.parse(_make_ak_result(
        "[al-khaser version 0.82]\n"
        "[*] Checking IsDebuggerPresent API                          [ GOOD ]\n"
    ))

    pf_categories = [{"id": "anti_debug", "name": "Anti-Debug Checks"}]
    pf_parser     = PafishParser(
        categories=pf_categories,
        pafish_sections={"Debuggers detection": "anti_debug"},
        pafish_label_overrides={},
    )
    # Pafish label "Debugger - IsDebuggerPresent" → slug "debugger_isdebuggerpr..."
    # Different slug from al-khaser → no dedup expected here; but same slug case:
    pf_results = pf_parser.parse(_make_pf_result(
        "[*] Checking IsDebuggerPresent API ... OK\n"  # same label as al-khaser!
    ))
    # Note: pafish uses different format ("... OK"), so PafishParser won't parse
    # al-khaser format. Use a manually crafted duplicate for the test:
    import dataclasses
    duplicate = dataclasses.replace(ak_results[0], tool="pafish")

    combined = ak_results + [duplicate]
    deduped  = deduplicate_checks(combined)

    assert len(deduped) == len(ak_results), \
        "Duplicate check from second tool should be merged, not added"
    merged = [r for r in deduped if r.deduplicated]
    assert merged, "Merged check should have deduplicated=True"
    assert all("pafish" in r.tool for r in merged), \
        "Merged tool field should reference both tools"


def test_deduplication_detected_beats_not_detected():
    """If al-khaser says GOOD but pafish says traced!, result must be detected."""
    ak_parser  = AlKhaserParser(category_id="vm_checks", category_name="VM Detection Checks")
    ak_results = ak_parser.parse(_make_ak_result(
        "[al-khaser version 0.82]\n"
        "[*] Checking cpuid hypervisor bit                           [ GOOD ]\n"
    ))

    import dataclasses
    pafish_detection = dataclasses.replace(
        ak_results[0],
        tool="pafish",
        raw_value="traced!",
        normalized=DETECTED,
    )

    deduped = deduplicate_checks(ak_results + [pafish_detection])
    assert len(deduped) == 1
    assert deduped[0].normalized == DETECTED, \
        "detected from pafish must override not_detected from al-khaser"


if __name__ == "__main__":
    tests = [
        test_extract_pairs_count,
        test_deferred_result_captured,
        test_good_maps_to_not_detected,
        test_bad_maps_to_detected,
        test_all_results_assigned_to_given_category,
        test_pafish_ok_maps_to_not_detected,
        test_pafish_traced_maps_to_detected,
        test_pafish_rdtsc_goes_to_timing_attacks,
        test_deduplication_merges_same_check,
        test_deduplication_detected_beats_not_detected,
    ]
    for t in tests:
        print(f"-- {t.__name__}")
        t()
    print("\nAll tests passed.")
