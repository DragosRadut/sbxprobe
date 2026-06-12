# Implementation

## 3.1 Overview and Design Goals

sbxprobe is a sandbox transparency evaluation framework designed to quantify how detectable
a Windows analysis environment is to adversarial code. The core design goal is scientific
reproducibility: every run must produce a deterministic, structured output that can be
compared across environments and over time without manual interpretation.

The framework operates by orchestrating existing open-source sandbox evasion probes
(al-khaser v0.82 and pafish v0.6.1), parsing their output into a unified data model,
scoring the result against a weighted category schema, and generating four report formats.
The entire logic from invocation to HTML report is approximately 1,200 lines of Python,
with an additional 371-entry YAML knowledge base mapping every check to its MITRE ATT&CK
technique and Checkpoint Evasions Encyclopedia reference.

The three principal design constraints that shaped every implementation decision were:

1. **Zero dropped checks.** All probe output must be captured and classified. No check
   result may be silently discarded due to a category mismatch or parser failure.

2. **No hardcoded category assignment.** Categories are determined by configuration, not
   by keyword-matching probe labels. This prevents silent reclassification as probes
   evolve their output text.

3. **Deployability as a standalone executable.** The framework must run on a clean Windows
   guest without Python, package managers, or external network access. All data files are
   bundled with the executable.

---

## 3.2 System Architecture

The framework is organised into five layers that form a unidirectional processing pipeline.
Each layer depends only on the layer below it, and no layer reaches upward.

```
┌─────────────────────────────────────────────────────────┐
│  CLI / Orchestration  (main.py)                         │
│  - Argument parsing, scenario resolution, run-ID gen    │
│  - Log tee-ing (stdout → console + run.log)             │
│  - Multi-scenario loop, combined-report generation      │
├─────────────────────────────────────────────────────────┤
│  Configuration Layer  (config_loader.py, _paths.py)     │
│  - YAML loading: tools.yaml, scenarios/*.yaml           │
│  - Path resolution: dev mode vs PyInstaller bundle      │
│  - Schema validation: weights, required fields, flags   │
├─────────────────────────────────────────────────────────┤
│  Runner Layer  (runner/)                                │
│  - AlKhaserAdapter: builds --check / --sleep args       │
│  - PafishAdapter: invokes with no arguments             │
│  - executor.py: subprocess management, timeout, decode  │
├─────────────────────────────────────────────────────────┤
│  Parser Layer  (parser/)                                │
│  - AlKhaserParser: [*]/[ GOOD/BAD ] + deferred cases   │
│  - PafishParser: section-header classification          │
│  - Deduplication: cross-tool merge with corroboration   │
├─────────────────────────────────────────────────────────┤
│  Scoring + Reporting  (scoring/, reporting/)            │
│  - ScoringEngine: per-category mean → weighted global   │
│  - ReportGenerator: JSON, CSV, Markdown                 │
│  - HTMLReportGenerator: per-scenario interactive HTML   │
│  - CombinedHTMLReportGenerator: multi-scenario index    │
└─────────────────────────────────────────────────────────┘
```

Data flows strictly downward. The CLI instantiates configuration objects and passes them
to the runner; the runner returns `ExecutionResult` objects to the parsers; the parsers
return `CheckResult` lists to the scoring engine; the scoring engine returns a `ScoreReport`
to the report generators. None of the lower layers import from the CLI or the reporter.

---

## 3.3 Configuration System

### 3.3.1 Two-File Configuration Model

The configuration system is divided into two files with distinct responsibilities:

**`configs/tools.yaml`** is the global tool registry. It records the executable path,
expected version, default timeout, and default sleep delay for each probe. These values
are authoritative and cannot be overridden per-scenario:

```yaml
alkhaser:
  executable: "probes\\al-khaser\\al-khaser_x86.exe"
  version: "0.82"
  default_timeout: 120
  default_sleep: 2

pafish:
  executable: "probes\\pafish\\pafish.exe"
  version: "0.6.1"
  default_timeout: 60
  default_sleep: 0
```

The separation of executable path from scenario configuration is a deliberate design
choice: it means moving the probes to a different directory requires editing exactly
one file, not every scenario.

**`configs/scenarios/*.yaml`** defines the evaluation structure. Each scenario specifies
which categories to score, the weight each carries, which al-khaser flag groups belong
to each category, whether pafish participates, and how pafish sections are classified.
Timeouts and sleep values may be overridden at the scenario level.

### 3.3.2 Configuration Merging and Validation

`config_loader.py` performs a two-step load. First, it reads the scenario YAML and the
tools YAML independently. Then `_merge_tools()` injects the executable path and version
from the tools registry into each tool block in the scenario. Path resolution is delegated
to `bundle_root()` so the same path strings work in both development and bundled mode:

```python
raw_exe = global_tool["executable"]
scenario_tool["executable"] = str(root / Path(raw_exe))
scenario_tool["version"]    = global_tool.get("version", "unknown")
```

After merging, `_validate()` enforces structural invariants before any execution begins:

- All required fields (`scenario_id`, `scenario_name`, `categories`, `scoring`) are present.
- Every al-khaser flag referenced in a category is in the known set (`VALID_CHECKS`).
- Every category has at least one data source (`alkhaser_flags` or `pafish: true`).
- If any category enables pafish, a `pafish_sections` mapping must exist.
- Category weights sum to exactly 1.0 (±0.01 tolerance for floating-point rounding).

Validation failures raise `ValueError` before any probe is launched, which prevents
partial runs that would produce incomplete and misleading scores.

### 3.3.3 Scenario Structure — The Baseline Scenario

The baseline scenario (`baseline.yaml`) evaluates all four transparency categories in
a single run. It is the primary evaluation scenario used in this thesis:

```yaml
scenario_id: baseline_001
scenario_name: Baseline Transparency Evaluation
version: "2.0"

categories:
  - id: vm_checks
    name: VM Detection Checks
    weight: 0.30
    mitre: "T1497"
    alkhaser_flags: [GEN_SANDBOX, VBOX, VMWARE, VPC, QEMU, KVM, XEN, WINE, PARALLELS, HYPERV]
    pafish: true

  - id: anti_debug
    name: Anti-Debug Checks
    weight: 0.10
    mitre: "T1622"
    alkhaser_flags: [TLS, DEBUG]
    pafish: true

  - id: timing_attacks
    name: Timing Attacks
    weight: 0.25
    mitre: "T1497.003"
    alkhaser_flags: [TIMING_ATTACKS]
    alkhaser_sleep: 2
    pafish: true

  - id: analysis_tools
    name: Analysis Tool Detection
    weight: 0.35
    mitre: "T1518.001"
    alkhaser_flags: [ANALYSIS_TOOLS, ANTI_DISASSM]
    pafish: false
```

The weight ordering reflects the discriminating power of each category for identifying
active sandbox environments, not merely virtual machines:

- **Analysis Tool Detection (0.35)** carries the highest weight because the presence of
  process monitors, disassemblers, or debuggers is the most direct indicator of an active
  analysis session. A virtual machine without any analysis tools does not constitute a
  sandbox in the adversarial sense.

- **VM Detection Checks (0.30)** identifies hypervisor artifacts. Detection here indicates
  virtualisation but is insufficient alone to conclude a sandbox is present.

- **Timing Attacks (0.25)** detects sleep-skipping and RDTSC anomalies. Sleep acceleration
  is a deliberate sandbox instrumentation that malware actively exploits to detect automated
  analysis; it is absent from pure VMs.

- **Anti-Debug Checks (0.10)** carries the lowest weight because automated sandboxes
  typically do not attach a userspace debugger to the target process; anti-debug detection
  has high false-positive rates from execution context (e.g., non-explorer parent processes).

### 3.3.4 Pafish Section Classification

Unlike al-khaser, pafish does not accept command-line flags to select check categories.
It runs all checks unconditionally and prints section headers (`[-] Section name`) before
each group. The scenario YAML maps each header to a category ID:

```yaml
pafish_sections:
  "Debuggers detection":             anti_debug
  "CPU information based detections": vm_checks
  "Generic reverse turing tests":    exclude
  "Generic sandbox detection":       vm_checks
  "Hooks detection":                 anti_debug
  "VirtualBox detection":            vm_checks
  "VMware detection":                vm_checks
  "Cuckoo detection":                anti_debug

pafish_label_overrides:
  "Checking the difference between CPU timestamp counters (rdtsc)":              timing_attacks
  "Checking the difference between CPU timestamp counters (rdtsc) forcing VM exit": timing_attacks
  "Checking if Sleep() is patched using GetTickCount()":                         timing_attacks
  "Checking mouse movement":         exclude
  "Checking mouse speed":            exclude
  "Checking dialog confirmation":    exclude
```

The `exclude` target silently drops checks that always produce false positives in headless
automated environments regardless of VM hardening. The mouse movement, mouse speed, and
dialog confirmation checks require human interaction; they will always return `traced!`
in any unattended run. Including them would artificially inflate the detection count and
depress the transparency score without conveying meaningful information about the
environment. Their exclusion is therefore justified as a deliberate measurement design
decision, not a data suppression choice.

Per-label overrides (`pafish_label_overrides`) take precedence over section defaults.
The RDTSC checks appear inside the "CPU information based detections" section (which maps
to `vm_checks`) but are timing measurements, not VM artifact inspections. The override
routes them to `timing_attacks`, matching their semantic meaning.

### 3.3.5 Path Resolution and Bundle Compatibility

The framework is distributed as a PyInstaller-frozen executable (`sbxprobe.exe`). When
frozen, PyInstaller extracts bundled read-only files to a temporary directory
(`sys._MEIPASS`), which differs from the executable's location. Writable output
(reports, logs) must be written next to the executable, never to `sys._MEIPASS`.

`_paths.py` provides two functions that abstract this distinction:

```python
def bundle_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    return Path(__file__).parent

def output_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent
```

All config reads go through `bundle_root()`. All output writes go through `output_root()`.
The rest of the codebase is entirely unaware of whether it is running in development or
bundled mode.

---

## 3.4 Runner Layer

### 3.4.1 Subprocess Execution

`runner/executor.py` provides a single function, `run_subprocess()`, that handles all
probe invocations. It manages three failure modes:

1. **Timeout**: The subprocess is killed, and whatever partial stdout has been written
   to the pipe buffer is returned alongside an `error` field. The partial output is still
   parsed and scored; the run is marked `partial` rather than `fatal`.

2. **FileNotFoundError**: The executable path is wrong or the binary is absent. The
   result carries an empty stdout and `error` set. Logged as a fatal error; the category
   is skipped.

3. **General exception**: Any other OS-level error is caught and reported in the `error`
   field, preventing the entire run from crashing.

Output encoding is handled explicitly. Both probes run as native Windows PE executables
and may emit text in the system's OEM code page. The output is decoded as UTF-8 with
`errors='replace'` to prevent truncation when non-ASCII characters (BIOS vendor strings,
WMI property values) appear in the output:

```python
stdout=stdout_b.decode("utf-8", errors="replace"),
```

`stdin` is set to `subprocess.DEVNULL` to prevent al-khaser's `system("pause")` call at
the end of its output from blocking indefinitely when stdout is redirected to a pipe.

### 3.4.2 al-khaser Adapter

al-khaser accepts check selection via `--check <FLAG>` and controls the sleep duration
between timing checks via `--sleep <seconds>`. `AlKhaserAdapter` builds this argument
list from the scenario configuration:

```python
def build_args(checks: list, sleep: int) -> list:
    args = []
    for c in checks:
        args += ["--check", c.upper()]
    args += ["--sleep", str(sleep)]
    return args
```

An important design choice is that al-khaser is invoked **once per category**, not once
for all flags combined. This is necessary because the category assignment of results is
determined by which flags produced them. If VBOX and ANALYSIS_TOOLS were passed in the
same invocation, all results would appear in the same stdout stream with no way to
attribute each check to its correct category. Running once per category preserves the
invariant that `AlKhaserParser` can assign the correct `category_id` to every result
without any label-based heuristics.

### 3.4.3 Pafish Adapter

pafish does not accept check-selection flags. `PafishAdapter` invokes the executable with
an empty argument list. The classification of its output is handled entirely in the parser
layer using section headers.

---

## 3.5 Parser Layer

### 3.5.1 al-khaser Output Parser

al-khaser output follows two patterns. The common case is an inline result on a single line:

```
[*] Checking IsDebuggerPresent API                    [ GOOD ]
[*] Checking VirtualBox registry keys                 [ BAD  ]
```

The deferred case occurs when al-khaser emits `[!]` diagnostic lines between the check
label and its result:

```
[*] Walking process memory for hidden modules
 [!] Running on WoW64, there will be false positives due to wow64 DLLs.
 [!] Executable at 77CB0000
[ BAD  ]
```

`_extract_pairs()` handles both cases with a small state machine. It maintains a
`pending_label` variable that is set when a `[*]` line is seen without an inline result.
If a subsequent `[ GOOD ]` or `[ BAD  ]` orphan line is encountered while `pending_label`
is set, it is attributed to that label and the pending state is cleared:

```python
pending_label: Optional[str] = None

for line in text.splitlines():
    m = _INLINE_RE.match(line)
    if m:
        pending_label = None
        pairs.append((m.group("label").strip(), m.group("value").upper()))
        continue

    m = _ORPHAN_RE.match(line)
    if m and pending_label is not None:
        pairs.append((pending_label, m.group("value").upper()))
        pending_label = None
        continue

    m = _STAR_LINE_RE.match(line)
    if m:
        pending_label = m.group("label").strip()
        continue
```

The normalisation of al-khaser results is straightforward: `GOOD` maps to `not_detected`
and `BAD` maps to `detected`. This inversion of the natural reading ("GOOD" means the
check found nothing suspicious, which is good from a transparency perspective) is
consistent with al-khaser's design.

### 3.5.2 Check ID Generation — Slug Algorithm

Every check result is assigned a canonical `check_id` by slugifying its label text:

```python
def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
```

This converts `"Checking IsDebuggerPresent API"` to `"checking_isdebuggerpresent_api"`.
The slug serves as the stable identifier used to look up MITRE mappings in
`check_mitre.yaml` and as the key for cross-tool deduplication. The algorithm must be
applied consistently to both al-khaser and pafish labels for deduplication to work:
two checks from different tools describing the same technique will only be merged if their
slugified labels produce the same string.

A practical implication: `check_mitre.yaml` keys must exactly match what the slugifier
produces for the corresponding al-khaser or pafish label text. A capital letter in a YAML
key that the slugifier would lowercase will silently cause a MITRE mapping miss. This was
discovered and corrected during testing: the initial key `using_isdebuggerPresent` had a
capital `P` that the slugifier lowercases, so the entry was unreachable until renamed to
`using_isdebuggerpresent`.

### 3.5.3 pafish Output Parser

`PafishParser` processes pafish output in a single pass using a two-state machine. The
current section is tracked by matching `[-]` section header lines. Each subsequent
`[*] ... ... OK/traced!` line is classified according to the current section's mapping,
with label overrides applied first:

```python
for line in exec_result.stdout.splitlines():
    m = _SECTION_RE.match(line)
    if m:
        current_section = m.group("section").strip()
        continue

    m = _RESULT_RE.match(line.rstrip())
    if not m:
        continue

    label   = m.group("label").strip()
    raw_value = m.group("value").lower()

    cat_id = self.label_overrides.get(label) or self.section_map.get(current_section)
    if not cat_id or cat_id == "exclude" or cat_id not in self.cat_map:
        continue

    normalized = NOT_DETECTED if raw_value == "ok" else DETECTED
```

pafish uses `OK` for a clean check and `traced!` for a detection. The normalisation
maps these to `not_detected` and `detected` respectively, matching the al-khaser
convention.

### 3.5.4 Cross-Tool Deduplication

After all tools have run for a scenario, `deduplicate_checks()` merges results that share
the same `(category_id, check_id)` key. The function distinguishes two cases:

**Same-tool collapse**: If the same check appears twice under the same tool — which
happens when two al-khaser flag groups both exercise the same underlying check — the
second occurrence is silently absorbed into the first. `deduplicated` is not set to `True`
because this is not cross-tool corroboration; it is a data normalisation step.

**Cross-tool corroboration**: If the same check appears from two different tools (e.g.,
`al-khaser` and `pafish` both check for the VirtualBox CPUID vendor string), the results
are merged and `deduplicated=True` is set. This flag signals to the report generator that
the detection was independently confirmed by two distinct tools, which carries stronger
evidentiary weight.

The merge policy for conflicting results is conservative: if any tool reports `detected`,
the merged result is `detected`. The rational is that a single positive from any tool is
sufficient to conclude the check fired; requiring all tools to agree would suppress real
detections.

```python
if not added_tools:
    # Same-tool duplicate — collapse silently, no corroboration mark.
    if check.normalized == DETECTED and existing.normalized != DETECTED:
        seen[key] = dataclasses.replace(existing, normalized=DETECTED, ...)
    continue

# Different tools — genuine cross-tool corroboration.
merged_tool = "+".join(sorted(existing_tools | new_tools))
seen[key] = dataclasses.replace(existing, tool=merged_tool, deduplicated=True)
```

This conservative definition ensures that the `deduplicated=True` flag in the output
JSON is a trustworthy indicator: it means exactly "two distinct tools independently
confirmed this check", not "the same tool was invoked twice with different flags".

---

## 3.6 Data Model

All inter-layer communication uses two dataclasses defined in `parser/normalizer.py`
and `scoring/engine.py`. Using frozen-equivalent dataclasses (with `dataclasses.replace()`
for immutable updates) ensures that parser results are not mutated after creation.

**`CheckResult`** represents a single probe check result:

| Field | Type | Description |
|---|---|---|
| `check_id` | `str` | Slugified label — stable lookup key |
| `label` | `str` | Original human-readable label text |
| `category_id` | `str` | Scenario category this check belongs to |
| `category_name` | `str` | Human-readable category name |
| `raw_value` | `str` | Original probe output ("GOOD"/"BAD"/"ok"/"traced!") |
| `normalized` | `str` | Canonical status: `detected`/`not_detected`/`error` |
| `tool` | `str` | Source tool ("al-khaser", "pafish", "al-khaser+pafish") |
| `deduplicated` | `bool` | True only when confirmed by two distinct tools |
| `timestamp` | `str` | ISO-8601 UTC timestamp of probe execution |
| `runtime_seconds` | `float` | Wall-clock time for the probe execution |

**`ScoreReport`** is the output of the scoring engine:

| Field | Type | Description |
|---|---|---|
| `global_score` | `float` | Weighted transparency score in [0, 1] |
| `risk_level` | `str` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `detection_rate` | `float` | Fraction of checks that were detected |
| `category_scores` | `List[CategoryScore]` | Per-category breakdown |
| `total_checks` | `int` | Total unique checks after deduplication |
| `detected_count` | `int` | Number of detected checks |
| `dedup_count` | `int` | Number of cross-tool corroborated checks |

---

## 3.7 Scoring Engine

### 3.7.1 Per-Category Score

For each category, the engine computes the arithmetic mean of all valid check values.
Checks are valued at 0.0 (`detected`) or 1.0 (`not_detected`). Checks with an `error`
status are excluded from the denominator when `error_behavior: exclude` is configured,
which prevents error-producing checks from diluting the score:

```python
values       = [self._check_value(c.normalized) for c in checks]
valid_values = [v for v in values if v is not None]
cat_score    = sum(valid_values) / len(valid_values) if valid_values else None
```

A category score of 1.0 means no checks were detected — the environment is fully
transparent with respect to that category. A score of 0.0 means every check was detected.

### 3.7.2 Global Transparency Score

The global score is a weighted mean of the category scores, using only categories with
non-zero weight:

```
global_score = Σ (cat_score_i × weight_i) / Σ weight_i
```

This formulation is robust to scenarios that define a category with `weight: 0.0` (a
category included for data collection but excluded from scoring). The denominator sums
only the weights of participating categories, so the score remains in [0, 1] regardless
of which categories are active.

### 3.7.3 Risk Level Classification

The global score is mapped to a risk level using fixed thresholds:

| Score range | Risk level | Interpretation |
|---|---|---|
| ≥ 0.85 | LOW | Most evasion checks pass; environment is not obviously a sandbox |
| ≥ 0.65 | MEDIUM | Significant detectable artifacts; partial evasion possible |
| ≥ 0.40 | HIGH | Majority of checks fire; actively detectable environment |
| < 0.40 | CRITICAL | Extremely detectable; typical of an un-hardened commercial sandbox |

The thresholds are deliberately asymmetric — the transition from LOW to MEDIUM requires
a 15-point drop, while MEDIUM to HIGH and HIGH to CRITICAL are 25-point steps. This
reflects the practical significance of small improvements near the transparent end of
the scale: improving from 0.84 to 0.86 (crossing LOW) is a more meaningful hardening
achievement than the same delta near 0.50.

---

## 3.8 MITRE ATT&CK Mapping

### 3.8.1 Knowledge Base Structure

`configs/check_mitre.yaml` is a 371-entry YAML dictionary. Every key is a check_id slug.
Every value is a three-field record:

```yaml
checking_if_cpu_hypervisor_field_is_set_using_cpuid_0x1:
  mitre: "T1497.001"
  checkpoint: "https://evasions.checkpoint.com/src/Evasions/techniques/cpu.html"
  description: >
    CPUID leaf 0x1 ECX bit 31 is the hypervisor present bit; set by VirtualBox, VMware,
    KVM, Hyper-V and all major type-2 hypervisors. Cannot be masked without modifying
    the hypervisor itself.
```

The `mitre` field is a MITRE ATT&CK v16 technique ID. The `checkpoint` field is the URL
of the corresponding entry in the Checkpoint Evasions Encyclopedia, an independently
maintained reference cataloguing the same techniques from a defensive perspective. The
`description` field provides a one-sentence technical explanation of what the check
measures and why it fires in virtualised environments.

### 3.8.2 Technique Coverage

The 371 mapped checks cover five MITRE ATT&CK techniques:

| Technique | Name | Scope in sbxprobe |
|---|---|---|
| T1497.001 | System Checks | Registry keys, CPUID, firmware tables, MAC OUI, WMI hardware sensors, disk size, process/module/filename artifacts |
| T1497.002 | User Activity Based Checks | Mouse movement, last-input time |
| T1497.003 | Time Based Evasion | RDTSC delta, CPUID VM-exit overhead, GetTickCount sleep patch |
| T1622 | Debugger Evasion | PEB.BeingDebugged, NtQueryInformationProcess, hardware breakpoints, TLS callbacks |
| T1518.001 | Security Software Discovery | Process enumeration for analysis tools (ProcMon, x64dbg, Wireshark, etc.) |

T1497.001 accounts for the majority of mapped checks (~82%) because hypervisor-specific
static artifacts (registry keys, firmware strings, hardware fingerprints) are the most
numerous and most reliably enumerated category of sandbox evasion techniques.

### 3.8.3 Mapping Lookup at Report Time

The `check_mitre.yaml` is loaded once per report generation pass. The loaded dictionary
is stored at module level (`_CHECK_MITRE`) so file I/O occurs exactly once regardless
of the number of checks in the report. The lookup is a simple dictionary key access:

```python
mapping = check_mitre.get(r.check_id)
if isinstance(mapping, dict):
    if mapping.get("mitre"):
        entry["mitre"] = mapping["mitre"]
    if mapping.get("checkpoint"):
        entry["checkpoint_url"] = mapping["checkpoint"]
```

The `isinstance(mapping, dict)` guard handles the degenerate case where a YAML key has
a scalar value rather than a mapping, which would cause a `AttributeError` on `.get()`.

---

## 3.9 Reporting System

The framework produces four output formats from a single run. All four are written to
the same output directory (`reports/<env>/<run_id>/`).

### 3.9.1 JSON Report

`report.json` is the machine-readable canonical output. It contains three top-level keys:

- **`meta`**: Run metadata — scenario ID and version, environment label, run ID, status,
  UTC timestamp, and tool versions as a dictionary.

- **`score`**: The full `ScoreReport` serialised as nested dicts, including the per-category
  breakdown and the global score and risk level.

- **`checks`**: An array of all `CheckResult` records, each enriched with `mitre` and
  `checkpoint_url` fields where a mapping exists in `check_mitre.yaml`.

The JSON report is designed for downstream analysis: a second-pass script can load it to
compute cross-environment comparisons, track score evolution over time, or extract all
checks for a specific MITRE technique.

### 3.9.2 CSV Report

`checks.csv` provides a flat tabular view of all check results. The eleven columns
(`check_id`, `label`, `category_id`, `category_name`, `raw_value`, `normalized`, `tool`,
`deduplicated`, `timestamp`, `environment_label`, `runtime_seconds`) map directly to
the `CheckResult` dataclass fields. This format is included for compatibility with
spreadsheet tools and statistical software.

### 3.9.3 Markdown Report

`report.md` provides a human-readable summary structured as a GitHub Flavored Markdown
document: score summary table, per-category breakdown table, and a detected checks
table. It is intended as a quick-reference format that renders correctly in most
documentation systems.

### 3.9.4 HTML Report

`report.html` is the primary interactive report format. It is a self-contained single-file
HTML document with all CSS and JavaScript inline (no external dependencies), making it
viewable on an isolated analysis machine.

**Score card**: Displays the global score in a colour-coded value (green for LOW, yellow
for MEDIUM, orange for HIGH, red for CRITICAL), the risk level badge, detection rate,
and detected/total counts.

**Detected artifacts panel**: Lists only the checks that returned `detected`, with each
artifact showing its label, a one-sentence description from `check_mitre.yaml`, the
source tool, a linked MITRE ATT&CK technique badge, and — where available — a linked
Checkpoint Evasions Encyclopedia (CPR) badge. The panel includes filter buttons generated
dynamically from the categories present in the detected set, allowing the user to isolate
vm_checks, anti_debug, timing_attacks, or analysis_tools artifacts:

```python
filter_btns = f"<button class='af-btn active' data-cat='all' ...>All ({len(detected_checks)})</button>"
for cat_id, (cat_name, cnt) in cat_counts.items():
    filter_btns += f"<button class='af-btn' data-cat='{cat_id}' ...>{cat_name} ({cnt})</button>"
```

The JavaScript filter function operates entirely on `data-cat` attributes without
any server communication:

```javascript
function filterArtifacts(btn) {
  var cat = btn.dataset.cat;
  var items = document.querySelectorAll('#artifacts-list .artifact');
  for (var i = 0; i < items.length; i++) {
    items[i].style.display = (cat === 'all' || items[i].dataset.cat === cat) ? '' : 'none';
  }
}
```

**Category score table**: Tabular breakdown of each category with weight, score, check
counts (total / detected / clean / corroborated), and a linked MITRE ATT&CK technique badge.

**All checks table**: Complete list of all checks with result status colour-coding
(red for detected, green for not_detected) and filter buttons for detected-only and
clean-only views.

### 3.9.5 Combined HTML Report

When multiple scenarios are run in a single invocation (`--scenario all` or multiple
named scenarios), `combined_html.py` generates an `index.html` summary page that aggregates
all scenario results. It displays scenario cards with per-scenario scores and risk badges,
an average transparency score across all scenarios, and a summary table with per-scenario
MITRE ATT&CK technique badges drawn from the scenario YAML `mitre` fields.

The combined report is linked to individual scenario reports via relative paths, allowing
the entire output directory to be archived and browsed without a web server.

---

## 3.10 Orchestration and Execution Flow

### 3.10.1 Run ID and Output Structure

Each invocation generates a unique run ID from the current UTC timestamp in ISO-8601
compact form (`20260612T143022Z`). Output is written to
`reports/<env>/<run_id>/<scenario_id>/` for multi-scenario runs, or
`reports/<env>/<run_id>/` for single-scenario runs. This structure allows multiple
runs against the same environment to coexist without overwriting each other.

### 3.10.2 Console Log Tee-ing

All console output is simultaneously written to `run.log` via a `_Tee` class that
intercepts `sys.stdout` and `sys.stderr`:

```python
class _Tee:
    def write(self, data: str) -> int:
        n = self._stream.write(data)
        self._logfile.write(data)
        return n
```

This is plugged in before any processing begins and restored after. The `_Tee` is
transparent to the rest of the codebase — all `print()` calls and `sys.stderr.write()`
calls continue to work without modification, and the log file receives an exact copy
of everything displayed on screen.

### 3.10.3 Dry-Run Mode

The `--dry-run` flag validates the configuration and prints the execution plan
(which categories would run, with which flags and which tools) without launching any
probe. This is useful for verifying a new scenario configuration before committing
time on an analysis VM.

### 3.10.4 Version Verification

After each probe executes, the parsed version is compared against the expected version
from `tools.yaml`. For al-khaser, the version is extracted from the `[al-khaser version
X.X]` banner line. For pafish v0.6.1, which does not print its version to stdout, the
expected version from `tools.yaml` is used directly as a fallback:

```python
version  = extract_pafish_version(exec_result.stdout)
expected = pafish_cfg.get("version", "unknown")
if version == "unknown":
    version = expected  # pafish v0.6.1 does not self-report; use tools.yaml
```

This ensures that the reported version in the output JSON is always a meaningful string
rather than the literal "unknown", while still issuing a warning if a newer pafish
version does begin reporting its version and it differs from the expected value.

---

## 3.11 Test Suite

The test suite in `tests/test_parser.py` validates the parser and deduplication logic
using synthetic probe output, without requiring the probe binaries to be present on the
test machine. Ten test cases cover:

- **`test_extract_pairs_count`**: Confirms that at least one pair is extracted from the
  al-khaser sample.

- **`test_deferred_result_captured`**: Verifies that the deferred-result case (a `[*]`
  line followed by `[!]` diagnostics and an orphan `[ BAD ]`) is correctly attributed.

- **`test_good_maps_to_not_detected`** / **`test_bad_maps_to_detected`**: Verify the
  GOOD/BAD normalisation direction.

- **`test_all_results_assigned_to_given_category`**: Confirms the flag-based design
  invariant — all results from a run go to the category specified at parser construction,
  regardless of label content.

- **`test_pafish_ok_maps_to_not_detected`** / **`test_pafish_traced_maps_to_detected`**:
  Mirror the al-khaser normalisation tests for pafish output.

- **`test_pafish_rdtsc_goes_to_timing_attacks`**: Validates that the label override
  mechanism correctly routes RDTSC checks to `timing_attacks` even when they appear
  inside the `vm_checks` section.

- **`test_deduplication_merges_same_check`**: Confirms that the same check from two
  different tools is collapsed to a single result with `deduplicated=True` and a
  combined tool string.

- **`test_deduplication_detected_beats_not_detected`**: Confirms that if al-khaser
  reports `not_detected` but pafish reports `detected`, the merged result is `detected`.

The test suite can be run both with pytest (`python -m pytest tests/test_parser.py -v`)
and as a standalone script (`python tests/test_parser.py`), the latter for use on
environments where pytest may not be installed.

---

## 3.12 Key Implementation Decisions and Trade-offs

**Probe invocation strategy (once per category vs. once total)**

al-khaser could be invoked once with all flags combined, which would reduce execution time.
This was rejected because the single-invocation output provides no way to attribute each
check to a category without label-based heuristics. Label-based heuristics are fragile:
al-khaser check labels are not guaranteed to remain stable across versions, and some labels
are genuinely ambiguous (a check labelled "Checking CPU information" could belong to either
vm_checks or timing_attacks). Invoking once per category costs a few extra seconds of
execution time but eliminates an entire class of classification errors.

**Section-header classification for pafish vs. label-based classification**

An alternative design would classify pafish checks by matching each label against a
keyword list for each category. This was considered and rejected for the same fragility
reason: keyword lists require maintenance as probe output evolves. The section-header
approach requires only that the pafish `[-]` header text is stable, which is a much
weaker dependency. The label override mechanism handles the small number of cases where
the section default is semantically incorrect (the RDTSC and sleep-skipping checks).

**Conservative deduplication semantics**

Setting `deduplicated=True` only for cross-tool corroboration (not for same-tool flag
group overlaps) preserves the semantic precision of the flag. This choice was validated
by a real-world bug discovered during development: ResourceHacker.exe appeared in both
the `ANALYSIS_TOOLS` and `ANTI_DISASSM` flag groups of al-khaser, which initially caused
it to be marked as corroborated. Fixing the deduplication logic to distinguish same-tool
from cross-tool merges eliminated this false corroboration, producing a more trustworthy
corroboration count in the output.

**Slug-based MITRE lookup vs. runtime label matching**

MITRE mappings are keyed by pre-computed slugs rather than by performing slug computation
at lookup time. This is equivalent in cost but more explicit: the YAML file serves as
documentation of exactly which labels are covered. A missing mapping produces a lookup
miss (no MITRE badge shown) rather than a silent error, making coverage gaps immediately
visible in the report.

**Self-contained HTML reports**

All CSS and JavaScript is inline in each HTML file. This was chosen over linking to
external style sheets because the reports are intended to be archived and shared as
self-contained files, viewable on isolated networks without internet access. The trade-off
is slightly larger file sizes, which is acceptable given that a typical report contains
fewer than 400 check rows.
