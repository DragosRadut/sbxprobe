# sbxprobe

**Sandbox Transparency Evaluation Framework**

sbxprobe orchestrates anti-analysis probes against a target environment, parses their output, scores the environment's transparency, and produces structured reports. It is designed as a research tool for the systematic evaluation of sandbox and malware-analysis environment hardening, and is the practical component of a master's thesis on sandbox transparency.

---

## How It Works

```
Scenario YAML
     │
     ▼
config_loader  ──►  tools.yaml (binary paths, versions)
     │
     ▼
AlKhaserAdapter  ──►  al-khaser.exe --check X --sleep N
     │
     ▼
AlKhaserParser   ──►  keyword → category assignment
     │
     ▼
ScoringEngine    ──►  weighted category scores, global transparency score
     │
     ▼
Reports          ──►  JSON · CSV · Markdown · HTML (per-scenario + combined)
```

Each **scenario** defines which al-khaser check modules to run, which output keywords map to which scoring categories, and the weight of each category in the global score. Checks whose output does not match any keyword are silently discarded — only checks explicitly defined by the scenario contribute to scoring.

### Transparency Score

| Score | Meaning |
|-------|---------|
| `1.0` | Fully transparent — no artifacts detected |
| `0.0` | Fully detected — all checks triggered |

Risk levels: **LOW** ≥ 0.85 · **MEDIUM** ≥ 0.65 · **HIGH** ≥ 0.40 · **CRITICAL** < 0.40

---

## Project Structure

```
sbxprobe/
├── main.py                        # Entry point — multi-scenario orchestration
├── config_loader.py               # Scenario resolution and YAML merging
│
├── configs/
│   ├── tools.yaml                 # Global tool registry (binary path, version)
│   └── scenarios/
│       ├── vm_checks.yaml         # VM / hypervisor fingerprinting
│       ├── anti_debug.yaml        # Anti-debugging probes
│       ├── timing_attacks.yaml    # Timing-based anti-sandbox checks
│       ├── analysis_tools.yaml    # Analysis tool process detection
│       └── baseline.yaml          # Multi-category baseline (all techniques)
│
├── runner/
│   ├── executor.py                # subprocess wrapper — captures partial output on timeout
│   └── adapters/
│       ├── alkhaser.py            # Builds --check / --sleep CLI args for al-khaser
│       └── pafish.py              # Runs pafish with no args (executes all checks)
│
├── parser/
│   ├── normalizer.py              # Parses GOOD/BAD lines (inline + deferred orphan)
│   └── pafish_normalizer.py       # Parses OK/traced! lines from pafish output
│
├── scoring/
│   └── engine.py                  # Weighted category scores → global score + risk level
│
├── reports/
│   ├── generator.py               # JSON, CSV, Markdown writers
│   ├── html_generator.py          # Self-contained per-scenario HTML report
│   └── combined_html.py           # Combined overview HTML for multi-scenario runs
│
├── probes/                        # Third-party probe binaries (not tracked in git)
│   ├── al-khaser/
│   │   └── al-khaser_x86.exe
│   └── pafish/
│       └── pafish.exe
│
├── logs/                          # Raw probe output, one dir per run
└── reports/                       # Generated reports, one dir per run
```

---

## Scenarios

| File | ID | al-khaser Flags | Coverage |
|------|----|-----------------|----------|
| `vm_checks.yaml` | `vm_checks_001` | GEN_SANDBOX VBOX VMWARE VPC QEMU KVM XEN WINE PARALLELS HYPERV | Registry keys, file artifacts, processes, MAC addresses, CPUID vendor strings, WMI hardware sensors, descriptor tables, SMBIOS/ACPI tables |
| `anti_debug.yaml` | `anti_debug_001` | DEBUG TLS | IsDebuggerPresent, PEB flags, heap tricks, NtQueryInformationProcess, handle tricks, breakpoints (HW/SW/memory), interrupts, kernel debugger, write-watch, job object, API hooks, TLS callbacks |
| `timing_attacks.yaml` | `timing_attacks_001` | TIMING_ATTACKS | RDTSC (plain + Locky), Sleep/SleepEx/NtDelayExecution, GetTickCount acceleration, SetTimer, timeSetEvent, WaitForSingleObject, WaitForMultipleObjects, IcmpSendEcho, CreateWaitableTimer, CreateTimerQueueTimer |
| `analysis_tools.yaml` | `analysis_tools_001` | ANALYSIS_TOOLS ANTI_DISASSM | OllyDbg, WinDbg, x64dbg, IDA Pro, Immunity, Process Explorer/Monitor, Wireshark, Fiddler, Frida, ProcessHacker, PE tools, JoeBox, anti-disassembly tricks |
| `baseline.yaml` | `baseline_001` | TLS DEBUG GEN_SANDBOX VBOX VMWARE VPC QEMU KVM XEN WINE PARALLELS HYPERV TIMING_ATTACKS ANALYSIS_TOOLS | All of the above in a single weighted run (vm 35%, anti-debug 30%, timing 20%, resource 15%) |

---

## Requirements

- Python 3.9+
- `pyyaml` (`pip install pyyaml`)
- `al-khaser_x86.exe` v0.81 placed at `probes\al-khaser\al-khaser_x86.exe`
- `pafish.exe` v0.6.1 placed at `probes\pafish\pafish.exe`
- Windows host (al-khaser is a Windows binary)

---

## Usage

### Run a single scenario

```
python main.py --scenario vm_checks --env virtualbox_default
python main.py --scenario anti_debug --env virtualbox_default
python main.py --scenario timing_attacks --env cuckoo_default
python main.py --scenario analysis_tools --env anyrun
```

### Run multiple specific scenarios

```
python main.py --scenario vm_checks anti_debug --env virtualbox_default
```

### Run all scenarios

```
python main.py --scenario all --env virtualbox_default
```

Multi-scenario runs write each scenario's reports into `reports/{env}/{run_id}/{scenario_id}/` and generate a combined `index.html` at `reports/{env}/{run_id}/`.

### Dry run (validate config without executing)

```
python main.py --scenario all --env test --dry-run
```

### Filter to specific categories

```
python main.py --scenario baseline --env myenv --categories vm_checks anti_debug
```

### Use a non-default tools config

```
python main.py --scenario vm_checks --env myenv --tools-config configs/tools_lab.yaml
```

---

## Output Structure

**Single scenario:**
```
reports/{env}/{run_id}/
    report.json      # Full structured output (scores, checks, metadata)
    checks.csv       # Per-check flat table
    report.md        # Markdown summary
    report.html      # Self-contained HTML report

logs/{env}/{run_id}/
    alkhaser_raw.txt # Raw stdout + stderr from al-khaser
```

**Multi-scenario (`--scenario all` or multiple names):**
```
reports/{env}/{run_id}/
    index.html                     # Combined overview with per-scenario cards
    {scenario_id}/
        report.json
        checks.csv
        report.md
        report.html
```

---

## Configuration

### `configs/tools.yaml` — global tool registry

```yaml
alkhaser:
  executable: "probes\\al-khaser\\al-khaser_x86.exe"
  version: "0.81"
  default_timeout: 120
  default_sleep: 10

pafish:
  executable: "probes\\pafish\\pafish.exe"
  version: "0.6.1"
  default_timeout: 60
  default_sleep: 0
```

The `executable` and `version` fields are **managed here only** — scenarios cannot override them. Scenarios may override `timeout` and `sleep`.

### Scenario YAML structure

```yaml
scenario_id: vm_checks_001
scenario_name: VM Detection Checks
version: "1.0"

tools:
  alkhaser:
    timeout: 300      # override global default
    sleep: 5
    checks:
      - VBOX
      - VMWARE

categories:
  - id: vm_checks
    name: VM Detection Checks
    weight: 1.0       # weights must sum to 1.0
    keywords:
      - virtualbox
      - vmware
      - vbox

scoring:
  detected_value: 0.0       # score contribution of a detected check
  not_detected_value: 1.0   # score contribution of a clean check
  error_behavior: exclude   # ignore errored checks in score calculation
```

---

## How Scoring Works

1. Each parsed check line is matched against category keywords (substring match, case-insensitive). If no keyword matches, the check is discarded.
2. Each category receives a score: average of its checks' values (`0.0` for detected, `1.0` for not-detected).
3. The global transparency score is the weighted average of category scores.
4. Detection rate = detected checks / total scored checks.
5. Risk level is derived from the global score against fixed thresholds.

---

## MITRE ATT&CK Mapping

| Scenario | Technique |
|----------|-----------|
| VM Detection | T1497 — Virtualization/Sandbox Evasion |
| Anti-Debug | T1622 — Debugger Evasion |
| Timing Attacks | T1497.003 — Time Based Evasion |
| Analysis Tools | T1518.001 — Security Software Discovery |
| Resource Profiling | T1497.001 — System Checks |

---

## Next Steps

### Immediate — data collection and keyword verification

- **Run anti_debug, timing_attacks, analysis_tools against the target environment** and inspect the raw logs to verify keyword coverage, the same way vm_checks was verified (all 227 checks matched).
- **Run `--scenario all` on each environment under evaluation** (VirtualBox default, VirtualBox hardened, Cuckoo, any analysis service) to build the dataset for the thesis results chapter.

### Cross-environment comparison report

A script (`compare.py`) that reads `report.json` files from multiple runs of the same scenario across different environments and produces a side-by-side HTML + CSV comparison table. This is the primary thesis deliverable — it shows e.g. "VirtualBox default vs hardened vs Cuckoo" on the same transparency axis.

```
python compare.py --scenario vm_checks \
    --runs reports/virtualbox_default reports/virtualbox_hardened reports/cuckoo
```

### Remaining al-khaser scenarios

Three al-khaser flag groups are not yet covered by a focused scenario:

| Scenario to create | Flags | Coverage |
|--------------------|-------|----------|
| `injection.yaml` | `INJECTION` | EnumProcessModulesEx, ToolHelp32, LdrEnumerateLoadedModules, hidden module walk |
| `code_injections.yaml` | `CODE_INJECTIONS` | CreateRemoteThread, SetWindowsHooksEx, NtCreateThreadEx, RtlCreateUserThread, APC, RunPE |
| `dumping.yaml` | `DUMPING_CHECK` | PE header erasure from memory, SizeOfImage manipulation |

### Additional probe tools

The tool registry (`configs/tools.yaml`) is designed to support multiple probe backends. Candidate tools to integrate alongside al-khaser:

- **[pafish](https://github.com/a0rtega/pafish)** — alternative VM/sandbox detection suite, useful for cross-tool result comparison
- **[vmde](https://github.com/hfiref0x/VMDE)** — kernel-level VM detection

Adding a new tool requires: an adapter in `runner/adapters/`, an entry in `configs/tools.yaml`, and a parser in `parser/` if its output format differs from al-khaser's `[ GOOD ]/[ BAD ]` lines.

### Delta / regression report

Compare two runs of the same scenario on the same environment to quantify the effect of a hardening change. Output would show which checks flipped (detected → clean or vice versa) and the score delta. Useful for the "before / after hardening" section of the thesis.

### Hardening validation workflow

```
1. python main.py --scenario all --env vbox_default     # baseline
2. apply hardening (mask CPUID, rename processes, etc.)
3. python main.py --scenario all --env vbox_hardened    # after
4. python compare.py ...                                # delta report
```
