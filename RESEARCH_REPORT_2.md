# NATIONAL UNIVERSITY OF SCIENCE AND TECHNOLOGY POLITEHNICA BUCHAREST
## FACULTY OF AUTOMATIC CONTROL AND COMPUTERS
### COMPUTER SCIENCE DEPARTMENT

---

# DIPLOMA PROJECT

## sbxprobe — Sandbox Evasion and Transparency Evaluation Framework

**Dragoș-Andrei Răduț**

**Thesis advisor:** ȘL. Dr. Ing. Flavia Oprea

**BUCHAREST, 2026**

---

## Research Report 2 — Preliminary Prototype and Technology Selection

---

## Table of Contents

- [Notations and Abbreviations](#notations-and-abbreviations)
- [Abstract](#abstract)
- [1. Introduction](#1-introduction)
  - [1.1 Context and Problem Statement](#11-context-and-problem-statement)
  - [1.2 Motivation](#12-motivation)
  - [1.3 Solution Overview](#13-solution-overview)
  - [1.4 Objectives](#14-objectives)
- [2. Summary of Research Report 1](#2-summary-of-research-report-1)
  - [2.1 State of the Art](#21-state-of-the-art)
  - [2.2 Taxonomy of Sandbox Evasion Techniques](#22-taxonomy-of-sandbox-evasion-techniques)
- [3. Technology Selection](#3-technology-selection)
  - [3.1 Probe Tools Evaluated](#31-probe-tools-evaluated)
  - [3.2 Selected Probe Tools and Justification](#32-selected-probe-tools-and-justification)
  - [3.3 Framework Language and Runtime](#33-framework-language-and-runtime)
  - [3.4 Configuration and Data Format Selection](#34-configuration-and-data-format-selection)
  - [3.5 Distribution Strategy](#35-distribution-strategy)
- [4. General Solution Design](#4-general-solution-design)
  - [4.1 Architectural Overview](#41-architectural-overview)
  - [4.2 Component Breakdown](#42-component-breakdown)
  - [4.3 Scenario Model](#43-scenario-model)
  - [4.4 Scoring Model](#44-scoring-model)
  - [4.5 MITRE ATT&CK Integration](#45-mitre-attck-integration)
  - [4.6 Output Formats](#46-output-formats)
- [5. Preliminary Prototype](#5-preliminary-prototype)
  - [5.1 Execution Pipeline](#51-execution-pipeline)
  - [5.2 Al-khaser Integration and Output Parsing](#52-al-khaser-integration-and-output-parsing)
  - [5.3 Pafish Integration and Section-Header Classification](#53-pafish-integration-and-section-header-classification)
  - [5.4 Deduplication and Scoring Engine](#54-deduplication-and-scoring-engine)
  - [5.5 Reporting Layer](#55-reporting-layer)
  - [5.6 CLI Interface and Invocation Examples](#56-cli-interface-and-invocation-examples)
- [6. Problems Encountered and Solutions Found](#6-problems-encountered-and-solutions-found)
  - [6.1 Non-ASCII Characters in Probe Output](#61-non-ascii-characters-in-probe-output)
  - [6.2 Al-khaser Interactive Prompt Blocking Execution](#62-al-khaser-interactive-prompt-blocking-execution)
  - [6.3 Pafish Output Classification Ambiguity](#63-pafish-output-classification-ambiguity)
  - [6.4 Double-Counting Overlapping Checks](#64-double-counting-overlapping-checks)
  - [6.5 Deferred Output Lines in Al-khaser](#65-deferred-output-lines-in-al-khaser)
  - [6.6 Behavioral False Positives in Headless Environments](#66-behavioral-false-positives-in-headless-environments)
  - [6.7 PyInstaller Path Resolution](#67-pyinstaller-path-resolution)
- [7. Preliminary Results](#7-preliminary-results)
  - [7.1 Framework Validation](#71-framework-validation)
  - [7.2 Check Coverage per Category](#72-check-coverage-per-category)
  - [7.3 MITRE ATT&CK Coverage](#73-mitre-attck-coverage)
  - [7.4 Report Generation Quality](#74-report-generation-quality)
- [8. Work Plan for Research 3](#8-work-plan-for-research-3)
  - [8.1 Data Collection Phase](#81-data-collection-phase)
  - [8.2 Cross-Environment Comparative Analysis](#82-cross-environment-comparative-analysis)
  - [8.3 Hardening Validation Workflow](#83-hardening-validation-workflow)
  - [8.4 Remaining Taxonomy Coverage](#84-remaining-taxonomy-coverage)
  - [8.5 Timeline](#85-timeline)
- [9. Demonstration Video](#9-demonstration-video)
- [Bibliography](#bibliography)

---

## Notations and Abbreviations

| Abbreviation | Meaning |
|---|---|
| API | Application Programming Interface |
| IPS | Intrusion Prevention Systems |
| EDR | Endpoint Detection and Response |
| APT | Advanced Persistent Threat |
| C2 | Command and Control |
| ACPI | Advanced Configuration and Power Interface |
| AV | Antivirus |
| VM | Virtual Machine |
| PEB | Process Environment Block |
| DMI | Desktop Management Interface |
| DBI | Dynamic Binary Instrumentation |
| JIT | Just-In-Time (compiler) |
| TEB | Thread Environment Block |
| RDTSC | Read Time-Stamp Counter |
| JSON | JavaScript Object Notation |
| DSDT | Differentiated System Description Table |
| IOCTL | Input/Output Control |
| PE | Portable Executable |
| YAML | YAML Ain't Markup Language |
| CLI | Command-Line Interface |
| PoC | Proof of Concept |
| OUI | Organizationally Unique Identifier |
| WMI | Windows Management Instrumentation |
| PnP | Plug and Play |
| SMBIOS | System Management BIOS |
| IDT | Interrupt Descriptor Table |
| GDT | Global Descriptor Table |
| LDT | Local Descriptor Table |
| TSC | Time Stamp Counter |
| TLS | Thread Local Storage |

---

## Abstract

This report presents the second phase of the sbxprobe research project, a framework designed to evaluate the transparency of sandboxed malware-analysis environments against representative evasion techniques. Building on the taxonomy-driven foundation established in the first research report, this phase focuses on the selection of probe tools and framework technologies, the design of the overall system architecture, and the construction of a functional preliminary prototype. The framework integrates two established anti-analysis tools — al-khaser and pafish — into a modular, scenario-driven pipeline that orchestrates probe execution, parses and normalizes results, deduplicates overlapping checks, computes weighted transparency scores per category and globally, and produces structured reports in JSON, CSV, Markdown, and interactive HTML formats. The prototype has been validated against a dry-run test suite and is ready for controlled execution against target environments. Preliminary results confirm the technical feasibility of the approach, demonstrate coverage of over two hundred individual checks across four anti-analysis categories, and establish a reproducible methodology for comparing sandbox transparency across different environment configurations.

---

## 1. Introduction

### 1.1 Context and Problem Statement

The purpose of this research is to design and implement a unified framework for evaluating the transparency of sandboxed environments against evasive malware techniques. The framework aggregates a set of anti-analysis checks into a modular test suite and uses them to probe whether an analysis environment reveals artifacts that can be detected by malware. The final goal is to support more reliable malware analysis by identifying where current sandbox configurations remain visible to adversarial samples.

The need for such a framework arises from the growing gap between modern malware behavior and traditional analysis environments. Malware increasingly relies on environment-aware evasion, delaying or suppressing malicious behavior when it determines that it is running inside a sandbox, virtual machine, or instrumented lab system. This means that a sandbox is no longer useful merely because it can execute a sample; its value depends on how convincingly it resembles a real victim system from the perspective of the malware being analyzed.

Current defensive practice already includes static analysis, dynamic execution, and detection platforms, but these methods are not sufficient on their own when malware actively avoids observation. Many proof-of-concept tools and academic references cover only a subset of anti-analysis checks, which makes it difficult to compare environments consistently or understand which types of artifacts are still exposed. This project therefore focuses on the problem of sandbox transparency, meaning the degree to which an analysis environment can remain indistinguishable from a real endpoint when tested against known evasion techniques.

### 1.2 Motivation

This objective is motivated by the fact that modern malware increasingly relies on environment-aware behavior before exposing its malicious payload. Instead of executing immediately, evasive samples may first inspect the host for virtualization artifacts, debugger presence, instrumentation traces, timing anomalies, or unrealistic system characteristics. As a result, the effectiveness of a sandbox can no longer be judged only by its ability to execute a suspicious sample, but it must also be judged by the extent to which it avoids revealing characteristics that allow malware to identify the environment as an analysis platform.

From this perspective, the role of the proposed framework is to provide a systematic way of evaluating sandbox transparency by using known anti-analysis techniques as controlled probes. The purpose is not to demonstrate the offensive capability of the testing tool, but to examine how existing analysis environments respond when confronted with representative evasion logic.

Reports from industry sources corroborate this motivation. According to OPSWAT's Threat Report 2025, evasive malware families continue to represent the fastest-growing threat category [1]. ANY.RUN's Malware Trends Overview Report for 2025 identifies sandbox evasion as a dominant capability among actively deployed families [4]. The academic literature similarly confirms the prevalence and sophistication of anti-analysis techniques, with comprehensive surveys by Afianian et al. [2] and Geng et al. [9] documenting hundreds of distinct evasion primitives across multiple operating system layers.

### 1.3 Solution Overview

The proposed solution, named sbxprobe, is a Python-based orchestration framework that wraps established anti-analysis probe tools, parses and normalizes their output, and aggregates results into structured transparency metrics. The framework is scenario-driven: each scenario is a YAML configuration file that specifies which probe modules to execute, how to map their output to scoring categories, and what weight each category contributes to the global transparency score.

The core pipeline consists of five stages. First, a scenario configuration is loaded and validated. Second, probe binaries are executed via subprocess adapters with timeout and partial-output handling. Third, the raw output from each probe is parsed into a normalized list of check results, each labeled with a category identifier, a result value, and metadata. Fourth, overlapping checks from multiple tools are deduplicated using a conservative merge policy. Fifth, a weighted scoring engine computes per-category and global transparency scores, which are then rendered into multiple output formats.

The framework is designed to be extensible: new probe tools can be integrated by adding a subprocess adapter and a parser; new scenarios can be defined in YAML without modifying any Python code; and new output formats can be added as report generators.

### 1.4 Objectives

To support the main research objective, the thesis pursues several specific aims. First, it defines a consolidated taxonomy of sandbox evasion techniques derived from public research, industry references, and proof-of-concept tools. Second, it maps this taxonomy to a modular implementation structure in which tests can be grouped and executed through clearly defined scenarios rather than as a disconnected list of checks. Third, it implements a proof-of-concept runner capable of executing selected techniques in controlled environments and storing the results in a reproducible format. Fourth, it derives category-level and overall transparency indicators from the observed outcomes in order to support comparative assessment. Fifth, it establishes a MITRE ATT&CK-aligned labeling system for all checks, enabling cross-referencing with industry threat intelligence.

The scope of this project is deliberately limited to evaluation. The implementation focuses on a proof-of-concept framework that aggregates existing anti-analysis checks, executes them in a controlled and repeatable way, and analyzes the resulting observations. It does not attempt to create novel malware techniques, persistence mechanisms, or destructive bypass logic against endpoint protection solutions.

---

## 2. Summary of Research Report 1

### 2.1 State of the Art

The first research report conducted a comprehensive survey of sandbox evasion techniques, related work, and existing tools. The survey identified that malware evasion of analysis environments is a well-documented and actively exploited problem, with roots traceable to early virtual machine detection research and contemporary manifestation in sophisticated ransomware, APT toolkits, and commodity malware loaders.

The related work survey examined four categories of prior contribution. The first category comprises academic surveys, most notably the work of Afianian et al. [2] and D'Elia et al. [14], which systematically classify hundreds of evasion primitives and provide empirical measurements of their prevalence in the wild. The second category includes industry frameworks for sandbox evaluation, in particular the AMTSO Sandbox Evaluation Framework [3, 6], which establishes methodological guidelines for testing sandbox effectiveness but does not provide a transparent, open-source implementation for controlled transparency probing. The third category encompasses proof-of-concept tools: al-khaser [10], pafish [11], VMDE [12], InviZzzible [13], and the BluePill project [14, 15], each of which implements a curated set of anti-analysis checks targeting specific evasion families. The fourth category includes Check Point's publicly available Malware Evasion Techniques Encyclopedia [16], which provides per-technique documentation, implementation notes, and sandbox hardening guidance.

The survey concluded that, while the individual components of an evaluation framework are well-represented in the literature and in open-source tooling, no existing solution provides a unified, taxonomy-driven, scenario-configurable framework that aggregates multiple tools, normalizes their output, weights results across categories, and produces structured comparative metrics. This gap is the direct motivation for the sbxprobe project.

### 2.2 Taxonomy of Sandbox Evasion Techniques

The first research report established a comprehensive taxonomy of anti-dynamic analysis techniques, which serves as the conceptual foundation guiding this paper's implementation and structure. This taxonomy consolidates evasion techniques from the BluePill research paper [14, 15], the al-khaser framework [10], and Check Point's evasion encyclopedia [16] into seven main categories.

**Table 2.1: Comprehensive Anti-Sandbox Technique Taxonomy**

| Category | Key Techniques | Implementation Primitives | Sandbox Hardening |
|---|---|---|---|
| Anti-Debug | PEB flags, API checks, breakpoints | IsDebuggerPresent(), PEB BeingDebugged | API hooking |
| Anti-Dump | PE header erasure, memory corruption | VirtualProtect() + checksums | Memory encryption |
| Anti-Instrumentation | DBI/JIT detection | Memory region anomalies | Stealth injection |
| Code Injection | Remote thread execution | CreateRemoteThread() | Behavioral whitelisting |
| VM Checks | Artifacts, CPUID | CPUID hypervisor, VBox files | Artifact spoofing |
| Timing Attacks | Sleep skew, RDTSC | Sleep() + GetTickCount() | Time normalization |
| Resource Profiling | Wear/tear validation | Disk size, hostname, entropy | Realism simulation |

Anti-debugging techniques represent a series of defense mechanisms used to prevent, detect, or actively tamper with the analysis. These techniques target the numerous artifacts debuggers introduce into CPU state (debug registers and flags), OS data structures (PEB/TEB flags, heap configurations), and execution behavior (exception chains, timing anomalies). VM checks target the vendor-specific artifacts introduced by virtualization and emulation solutions. Hypervisors like VMware, VirtualBox, Hyper-V, KVM, Xen, and QEMU can be exposed through CPUID hypervisor bits and vendor strings, specific MAC address prefixes, or firmware anomalies. Timing attacks exploit the temporal constraints and performance characteristics of dynamic analysis environments through two primary strategies: time stalling and runtime measurements. Resource profiling and wear-and-tear assessment techniques represent sophisticated detection mechanisms that distinguish victim systems from analysis environments by evaluating system maturity and usage plausibility rather than virtualization presence.

The implementation phase of this research focuses on the four most mature and reproducible categories: VM checks, anti-debug, timing attacks, and analysis tool detection. These four categories are the most directly supported by both the available proof-of-concept tooling and the academic literature. Anti-instrumentation and code injection are retained in the broader design as future extension points, while anti-dump techniques require low-level memory manipulation that falls outside the scope of the current evaluation-focused approach.

---

## 3. Technology Selection

### 3.1 Probe Tools Evaluated

The selection of probe tools for the sbxprobe framework followed a three-criterion evaluation process. First, a tool must implement a sufficiently large and documented set of anti-analysis checks to justify integration. Second, it must provide machine-parseable output, meaning that its results must be reliably extractable without requiring interactive input or graphical output. Third, it must be representative of the techniques employed by real-world malware, grounding the evaluation in genuinely adversarial behavior rather than synthetic benchmarks.

The following candidate tools were evaluated during the research phase.

**Al-khaser** [10] is an open-source Windows tool by L. Balev that implements over two hundred individual anti-analysis checks across multiple categories, selectable via command-line flags. It produces structured output in the form `[*] label ... [ GOOD ]` or `[*] label ... [ BAD ]`, where GOOD indicates the check was not triggered and BAD indicates a detectable artifact was found. Al-khaser is flag-driven, allowing the framework to select specific check modules without executing the entire suite, which is essential for category-based scenario design.

**Pafish** [11] is a sandbox and VM detection tool by A. Ortega. It runs all checks by default and produces output organized into labeled sections introduced by `[-] Section name` header lines, followed by per-check results in the form `[*] label ... OK` or `[*] label ... traced!`. Pafish does not support flag-based selection, but its section-organized output enables classification of results by category at parse time.

**VMDE** (Virtual Machine Detection Environment) [12] is a kernel-level VM detection tool. While technically thorough, it requires driver installation and elevated privileges that make automated subprocess-based invocation impractical in a general framework. For this reason, VMDE was retained as a reference source for technique documentation but was not selected for integration.

**InviZzzible** [13] is Check Point's virtual environment assessment tool. It provides extensive coverage but its output format is not machine-parseable in a straightforward manner, as it produces Windows dialog boxes rather than console output. Integration would require UI automation, introducing fragility and platform-specific dependencies that would undermine the reproducibility goal.

### 3.2 Selected Probe Tools and Justification

Based on the evaluation, **al-khaser v0.82** and **pafish v0.6.1** were selected as the primary probe tools for the sbxprobe framework.

Al-khaser was selected because it provides the broadest coverage of any parseable tool, with distinct flag groups for VM checks (GEN_SANDBOX, VBOX, VMWARE, VPC, QEMU, KVM, XEN, WINE, PARALLELS, HYPERV), anti-debugging (DEBUG, TLS), timing attacks (TIMING_ATTACKS), and analysis tool detection (ANALYSIS_TOOLS, ANTI_DISASSM). Its structured output format admits reliable parsing without heuristics, and its flag-based invocation allows the framework to run category-specific probes with precise control over what is tested.

Pafish was selected as a complementary tool because it covers overlapping checks from a distinct implementation perspective, which makes it useful for cross-tool corroboration. A check that is triggered by both al-khaser and pafish independently provides stronger evidence of a detectable artifact than a single-tool detection. Additionally, pafish's section-based output structure, once mapped to category identifiers, can be parsed with the same reliability as al-khaser output.

The use of two tools introduces the problem of double-counting: when both tools cover the same logical check, counting both detections would inflate the detection rate and distort the transparency score. This problem is addressed by the deduplication engine described in Section 5.4.

### 3.3 Framework Language and Runtime

**Python 3.9+** was selected as the implementation language for the sbxprobe framework for several reasons. Python's subprocess module provides robust, cross-platform process management with configurable timeouts, stdin/stdout/stderr capture, and graceful timeout handling. The `pathlib` module enables platform-independent path manipulation essential for the PyInstaller bundle compatibility requirements. Python's `dataclasses` module allows clean, typed data structures without the boilerplate of manual `__init__` methods.

The primary alternative considered was Go, which would have produced a single-binary distribution more naturally than Python. However, the richness of Python's YAML parsing ecosystem (`pyyaml`), its suitability for rapid iteration on configuration-heavy code, and the existing familiarity of the research team with Python outweighed the distribution advantage of Go for this project phase.

The framework explicitly does not use any machine learning libraries or numerical computation frameworks. All scoring logic is implemented with standard Python arithmetic, keeping the dependency surface minimal and the scoring algorithm fully transparent and auditable.

### 3.4 Configuration and Data Format Selection

**YAML** was selected as the configuration language for scenarios and tool registry files. YAML's indented block structure is well-suited for expressing the hierarchical scenario model (scenario → categories → per-category flags and weights), and it is human-readable and editable without requiring specialized tooling. The `pyyaml` library provides safe parsing with the `yaml.safe_load()` method, preventing arbitrary code execution via malicious YAML input.

**JSON** was selected for the primary structured output format because it is universally machine-readable, directly importable into data analysis tools (pandas, jq, Excel), and preserves full precision for numeric scores. JSON output includes the complete check table, scoring metadata, tool versions, run timestamps, and MITRE ATT&CK annotations.

**CSV** was selected as a secondary output format for its compatibility with spreadsheet tools. The flat check table exported to CSV enables ad hoc analysis without programming knowledge, which is relevant for the thesis results chapter where score comparisons need to be presented in tabular form.

**HTML** was selected as the primary human-readable report format. The HTML report is self-contained (all CSS and JavaScript is embedded inline), requires no web server, and can be opened directly in any browser. It includes interactive filtering of checks by status, color-coded score cards, MITRE ATT&CK links, and a detected-artifacts summary section.

### 3.5 Distribution Strategy

The framework is distributed as a **PyInstaller** single-file Windows executable (`sbxprobe.exe`). This is necessary because the target environments are Windows VMs, which may not have Python installed. The PyInstaller bundle embeds the Python interpreter, all dependencies, the configuration files under `configs/`, and the probe binaries under `probes/` into a single executable.

A custom `_paths.py` module provides `bundle_root()` and `output_root()` functions that resolve paths correctly both in development mode (relative to the source directory) and inside the frozen bundle (relative to `sys._MEIPASS`). This abstraction is transparent to all other modules, which use `bundle_root()` uniformly without needing to distinguish between the two execution contexts.

UPX compression is disabled in the PyInstaller spec file. The reason for this is that UPX compression of Python executables is frequently flagged by antivirus engines as a generic packer heuristic, which would cause the framework itself to be quarantined when deployed on a Windows environment with active endpoint protection.

---

## 4. General Solution Design

### 4.1 Architectural Overview

The sbxprobe framework is organized as a linear pipeline with a clear separation of concerns between its five stages: configuration, execution, parsing, scoring, and reporting. The pipeline is orchestrated by `main.py`, which serves as the entry point and delegates each stage to specialized modules.

```
Scenario YAML
     │
     ▼
config_loader      ──►  tools.yaml (binary paths, versions, defaults)
     │
     ▼
AlKhaserAdapter    ──►  al-khaser.exe --check X [--check Y ...] --sleep N
PafishAdapter      ──►  pafish.exe
     │
     ▼
AlKhaserParser     ──►  [ GOOD ]/[ BAD ] lines → CheckResult list (category-assigned)
PafishParser       ──►  OK/traced! lines → CheckResult list (section-classified)
     │
     ▼
deduplicate_checks ──►  (category_id, check_id) merge, conservative policy
     │
     ▼
ScoringEngine      ──►  weighted category scores → global transparency score + risk level
     │
     ▼
ReportGenerator    ──►  JSON · CSV · Markdown
HTMLReportGenerator──►  self-contained per-scenario HTML
CombinedHTML       ──►  multi-scenario overview index.html
```

### 4.2 Component Breakdown

The framework consists of eleven Python modules organized into five packages.

**`main.py`** — Entry point. Implements argument parsing, logging (via a `_Tee` stream duplicator that mirrors all output to `run.log`), scenario iteration, and combined report generation. The `_run_alkhaser_for_category()` function runs al-khaser once per category with the flags belonging to that category. The `_run_pafish_once()` function runs pafish once and distributes its output across multiple categories via section headers. The `_run_scenario()` function orchestrates the full pipeline for a single scenario.

**`config_loader.py`** — Scenario resolution and validation. Accepts scenario names as short identifiers (e.g., `vm_checks`) or explicit file paths and loads the corresponding YAML. Merges global tool configuration from `tools.yaml` into each scenario, resolving executable paths relative to `bundle_root()`. Performs comprehensive structural validation including weight sum checking, MITRE field presence, pafish section target validation, and al-khaser flag validity.

**`runner/executor.py`** — Subprocess wrapper. Launches probe binaries with configurable timeout, stdin=DEVNULL (to prevent interactive prompts from blocking), and explicit UTF-8 decoding with error replacement for non-ASCII BIOS strings. Captures partial stdout on timeout. Returns a typed `ExecutionResult` dataclass with all captured output and metadata.

**`runner/adapters/alkhaser.py`** and **`runner/adapters/pafish.py`** — Tool-specific adapters that translate framework configuration into the correct command-line invocation for each tool.

**`parser/normalizer.py`** — Al-khaser output parser. Handles both inline results (`[*] label ... [ GOOD ]`) and deferred results where a `[!]` diagnostic precedes an orphan `[ BAD ]` line. Assigns all checks from a run to the pre-determined category for that run.

**`parser/pafish_normalizer.py`** — Pafish output parser. Uses section-header lines (`[-] Section name`) to track the current section, and maps each `[*] label ... OK/traced!` line to a category ID via the `pafish_sections` dictionary, with per-label overrides applied first.

**`scoring/engine.py`** — Scoring and deduplication. Contains `deduplicate_checks()` and `ScoringEngine.score()`.

**`reporting/generator.py`**, **`reporting/html_generator.py`**, **`reporting/combined_html.py`** — Report generators for the three output format families.

### 4.3 Scenario Model

Each scenario is defined as a YAML file containing the following top-level fields.

| Field | Type | Description |
|---|---|---|
| `scenario_id` | string | Unique identifier (e.g., `baseline_001`) |
| `scenario_name` | string | Human-readable name |
| `version` | string | Scenario schema version |
| `tools` | dict | Per-tool timeout and sleep overrides |
| `categories` | list | Category definitions (see below) |
| `pafish_sections` | dict | Section-header to category-ID mapping |
| `pafish_label_overrides` | dict | Per-label category overrides |
| `scoring` | dict | Score value assignments and error behavior |

Each category within a scenario specifies its unique `id`, human-readable `name`, numerical `weight` (all weights must sum to 1.0), MITRE technique identifier, list of `alkhaser_flags` to pass for this category's run, and a boolean `pafish` flag indicating whether pafish output sections should be routed to this category.

The baseline scenario (`baseline_001`) provides a representative example of the full model. It defines four categories with the following weights: VM Detection Checks at 35%, Anti-Debug Checks at 30%, Timing Attacks at 20%, and Analysis Tool Detection at 15%. This weighting reflects the relative prevalence and severity of each evasion family in the current threat landscape: VM detection artifacts are the most universally present form of sandbox evidence, while analysis tool detection, though important, typically requires the presence of specific running processes that may not always be co-located with the analysis session.

### 4.4 Scoring Model

The transparency score is defined on the interval [0.0, 1.0], where 1.0 represents a fully transparent environment in which no anti-analysis artifact was detected, and 0.0 represents an environment in which every check triggered a detection.

The per-category score is the arithmetic mean of the normalized values of all checks in that category. Each check contributes either 1.0 (not detected, configured by `not_detected_value`) or 0.0 (detected, configured by `detected_value`). Checks that produced an error are excluded from the average by default (controlled by `error_behavior: exclude`).

The global transparency score is the weighted average of category scores:

```
global_score = Σ (category_score_i × weight_i) / Σ weight_i
```

where the sum ranges only over categories that have at least one valid check result and a non-zero weight.

Risk levels are derived from the global score against fixed thresholds:

| Score Range | Risk Level |
|---|---|
| ≥ 0.85 | LOW |
| ≥ 0.65 | MEDIUM |
| ≥ 0.40 | HIGH |
| < 0.40 | CRITICAL |

The detection rate is defined separately as the ratio of detected checks to total scored checks. This metric complements the transparency score by providing an absolute count perspective that is not weighted by category importance.

### 4.5 MITRE ATT&CK Integration

All scenarios and individual checks are annotated with MITRE ATT&CK technique identifiers. Category-level mappings are defined directly in each scenario YAML. Per-check mappings are stored in `configs/check_mitre.yaml`, a separate file containing over two hundred entries keyed by slugified check labels.

The relevant MITRE techniques covered by the framework are:

| Technique ID | Name | Coverage |
|---|---|---|
| T1497 | Virtualization/Sandbox Evasion | Parent technique |
| T1497.001 | System Checks | Registry keys, files, CPUID, MAC, WMI, firmware |
| T1497.002 | User Activity Based Checks | Mouse movement, last input time |
| T1497.003 | Time Based Evasion | RDTSC delta, sleep-skipping detection |
| T1622 | Debugger Evasion | PEB flags, NtQuery*, breakpoints, heap tricks, TLS |
| T1518.001 | Security Software Discovery | Process enumeration for analysis tools |

The MITRE annotations serve two purposes in the context of the thesis. First, they ground the framework's check categories in widely recognized industry threat intelligence, making the evaluation results interpretable to practitioners familiar with the ATT&CK framework. Second, they enable the HTML reports to link directly to the corresponding ATT&CK technique pages at `https://attack.mitre.org`, allowing investigators to cross-reference detected artifacts with documented adversary behavior.

### 4.6 Output Formats

The framework produces the following output per scenario run:

```
reports/{env}/{run_id}/
├── report.json          # Full structured output with scores, checks, MITRE annotations
├── checks.csv           # Flat check table for spreadsheet analysis
├── report.md            # Markdown summary with score tables and detected check list
└── report.html          # Self-contained interactive HTML report

logs/{env}/{run_id}/
├── alkhaser_{cat}_raw.txt   # Raw al-khaser stdout+stderr per category
├── pafish_raw.txt           # Raw pafish stdout+stderr
└── run.log                  # Complete orchestration log (stdout+stderr mirror)
```

For multi-scenario runs (using `--scenario all` or multiple scenario names), an additional `index.html` is generated at the run root, providing a combined overview with per-scenario score cards and a comparative summary table.

---

## 5. Preliminary Prototype

### 5.1 Execution Pipeline

The main execution pipeline in `main.py` orchestrates the complete pipeline for each scenario. The following excerpt illustrates the core orchestration logic of `_run_scenario()`:

```python
# Run al-khaser once per category
for cat in categories:
    if not cat.get("alkhaser_flags"):
        continue
    cat_cfg = dict(alkhaser_cfg)
    if "alkhaser_sleep" in cat:
        cat_cfg["sleep"] = cat["alkhaser_sleep"]
    tv, parsed, status = _run_alkhaser_for_category(cat, cat_cfg, env, log_dir)
    tool_versions.update(tv)
    all_checks.extend(parsed)

# Run pafish once if any category requests it
pafish_cats = [c for c in categories if c.get("pafish", False)]
if pafish_cats and pafish_cfg and pafish_sections:
    tv, parsed, status = _run_pafish_once(
        pafish_cfg, categories, pafish_sections,
        pafish_label_overrides, env, log_dir
    )
    tool_versions.update(tv)
    all_checks.extend(parsed)

# Deduplicate overlapping checks
raw_count  = len(all_checks)
all_checks = deduplicate_checks(all_checks)
dedup_merged = raw_count - len(all_checks)

# Score
engine       = ScoringEngine(scenario.get("scoring", {}))
score_report = engine.score(check_results, categories)
```

The design decision to run al-khaser once per category rather than once for all categories combined is architecturally significant. By running al-khaser with only the flags belonging to a single category, the framework can attribute every line of al-khaser output to that category without keyword matching. This eliminates the possibility of a check being silently discarded because its label did not match any configured keyword, which was a documented source of data loss in earlier prototypes.

### 5.2 Al-khaser Integration and Output Parsing

The al-khaser adapter constructs the command-line invocation from the category's `alkhaser_flags` list:

```python
def build_args(self) -> list:
    args = []
    for check in self.config.get("checks", []):
        args += ["--check", check]
    sleep = self.config.get("sleep", 2)
    args += ["--sleep", str(sleep)]
    return args
```

The subprocess executor captures stdout and stderr with explicit UTF-8 decoding using the `errors='replace'` strategy to handle non-ASCII characters that may appear in BIOS and firmware strings:

```python
stdout = proc.stdout.decode("utf-8", errors="replace")
stderr = proc.stderr.decode("utf-8", errors="replace")
```

The `AlKhaserParser` processes each line of the captured stdout. It handles two output patterns: inline results, where the label and result appear on the same line, and deferred results, where a `[!]` diagnostic line is followed on the next line by an orphan `[ BAD ]` result. The deferred pattern arises when al-khaser's internal logic needs to emit a diagnostic message between the check label and its outcome.

```python
_INLINE_RE  = re.compile(r"^\[\*\]\s+(.+?)\s+\.\.\.\s+\[\s*(GOOD|BAD)\s*\]")
_LABEL_RE   = re.compile(r"^\[\*\]\s+(.+?)\s*\.{2,}\s*$")
_ORPHAN_RE  = re.compile(r"^\[\s*(GOOD|BAD)\s*\]")
```

### 5.3 Pafish Integration and Section-Header Classification

Pafish produces output organized into labeled sections. The `PafishParser` uses a stateful line-by-line scan that tracks the current section and applies category routing based on the section map and per-label overrides:

```python
for line in exec_result.stdout.splitlines():
    m = _SECTION_RE.match(line)
    if m:
        current_section = m.group("section").strip()
        continue

    m = _RESULT_RE.match(line.rstrip())
    if not m:
        continue

    label     = m.group("label").strip()
    raw_value = m.group("value").lower()

    # Label override takes precedence over section default
    cat_id = (self.label_overrides.get(label)
              or self.section_map.get(current_section))

    if not cat_id or cat_id == "exclude" or cat_id not in self.cat_map:
        continue

    normalized = NOT_DETECTED if raw_value == "ok" else DETECTED
```

The section-to-category mapping for the baseline scenario illustrates how pafish's mixed-content sections are handled:

```yaml
pafish_sections:
  "Debuggers detection":              anti_debug
  "CPU information based detections": vm_checks   # overridden per-label below
  "Generic reverse turing tests":     exclude     # always headless false-positive
  "Generic sandbox detection":        vm_checks
  "VirtualBox detection":             vm_checks
  "VMware detection":                 vm_checks
  "Cuckoo detection":                 anti_debug

pafish_label_overrides:
  "Checking the difference between CPU timestamp counters (rdtsc)":
    timing_attacks
  "Checking the difference between CPU timestamp counters (rdtsc) forcing VM exit":
    timing_attacks
  "Checking if Sleep() is patched using GetTickCount()":
    timing_attacks
```

The CPU section illustrates the need for per-label overrides: it contains both CPUID-based hypervisor detection (which belongs in `vm_checks`) and RDTSC-based timing measurement (which belongs in `timing_attacks`). Without label overrides, all CPU section checks would be incorrectly classified as VM checks, distorting the timing category score.

### 5.4 Deduplication and Scoring Engine

The `deduplicate_checks()` function merges entries from multiple tools that share the same `(category_id, check_id)` key. The merge policy is conservative: if either tool reports a detection, the merged result is detected. This prevents under-reporting in the case where one tool's implementation is more sensitive than the other's.

```python
def deduplicate_checks(checks: List[CheckResult]) -> List[CheckResult]:
    seen: Dict[tuple, CheckResult] = {}

    for check in checks:
        key = (check.category_id, check.check_id)
        if key not in seen:
            seen[key] = dataclasses.replace(check)
            continue

        existing = seen[key]
        tools = sorted(set(existing.tool.split("+") + check.tool.split("+")))
        merged_tool = "+".join(tools)

        if check.normalized == DETECTED and existing.normalized != DETECTED:
            seen[key] = dataclasses.replace(
                existing,
                raw_value    = f"{existing.raw_value}/{check.raw_value}",
                normalized   = DETECTED,
                tool         = merged_tool,
                deduplicated = True,
            )
        else:
            seen[key] = dataclasses.replace(
                existing,
                tool         = merged_tool,
                deduplicated = True,
            )

    return list(seen.values())
```

The `ScoringEngine.score()` method computes per-category scores as arithmetic means and aggregates them into a global weighted average:

```python
cat_score = (sum(valid_values) / len(valid_values)) if valid_values else None

if cat_score is not None and weight > 0:
    weighted_sum += cat_score * weight
    total_weight += weight

global_score = round(weighted_sum / total_weight, 4) if total_weight > 0 else None
```

Risk level classification uses a threshold ladder applied to the global score:

```python
_RISK_THRESHOLDS = [
    (0.85, "LOW"),
    (0.65, "MEDIUM"),
    (0.40, "HIGH"),
    (0.00, "CRITICAL"),
]
```

### 5.5 Reporting Layer

The reporting layer produces four formats per scenario run. The JSON report is the most complete, including all check metadata, MITRE annotations, scoring data, tool versions, and run timestamps. A representative JSON check entry with MITRE annotation takes the following form:

```json
{
  "check_id": "checking_if_cpu_hypervisor_field_is_set_using_cpuid_0x1",
  "label": "Checking if CPU hypervisor field is set using cpuid(0x1)",
  "category_id": "vm_checks",
  "raw_value": "BAD",
  "normalized": "detected",
  "tool": "al-khaser",
  "mitre": "T1497.001",
  "checkpoint_url": "https://evasions.checkpoint.com/src/Evasions/techniques/cpu.html",
  "deduplicated": false
}
```

The interactive HTML report embeds score cards, a detected-artifacts summary section, and a full check table with client-side filtering by status (All / Detected / Clean). The score card presents the global transparency score, risk badge, detection rate, and a breakdown of tool contributions. Each detected artifact in the summary section is annotated with its MITRE technique badge and a Checkpoint Evasions link. The full checks table allows analysts to drill into any individual check and see its raw output value, tool provenance, and MITRE classification.

The combined HTML report is generated when multiple scenarios are run in the same invocation. It presents per-scenario score cards and a summary table comparing transparency scores across all scenarios, enabling at-a-glance comparison of how the target environment performs across different evasion families.

### 5.6 CLI Interface and Invocation Examples

The framework is invoked from the command line with the following interface:

```
sbxprobe --scenario <name> [<name2> ...] --env <label> [options]

Options:
  --scenario     One or more scenario names, or 'all'
  --env          Environment label for this run (e.g., virtualbox_default)
  --tools-config Path to tools.yaml (default: configs/tools.yaml)
  --output-dir   Root directory for reports (default: reports/)
  --categories   Filter to specific category IDs
  --dry-run      Validate and print execution plan without executing
```

Representative invocations:

```bash
# Single scenario targeting a VirtualBox environment
python main.py --scenario vm_checks --env virtualbox_default

# Multi-scenario comprehensive evaluation
python main.py --scenario all --env cuckoo_sandbox

# Validate configuration without executing
python main.py --scenario baseline --env test --dry-run

# Category-filtered run
python main.py --scenario baseline --env myenv --categories vm_checks anti_debug
```

The `--dry-run` flag validates the complete scenario configuration, resolves executable paths, and prints the planned execution tree without invoking any probe binaries. This is useful for verifying that a new scenario YAML is structurally correct before deploying to a target environment.

---

## 6. Problems Encountered and Solutions Found

### 6.1 Non-ASCII Characters in Probe Output

**Problem:** When running al-khaser against environments where BIOS and firmware strings contain non-ASCII characters (such as vendor-specific extended characters in SMBIOS tables), Python's default subprocess stdout capture using `text=True` with the system locale encoding raised `UnicodeDecodeError` exceptions on Windows systems configured with non-UTF-8 code pages.

**Solution:** The subprocess invocation was changed to capture output as raw bytes (`text=False`) and explicitly decode with UTF-8 and the `errors='replace'` strategy. This converts any non-decodable byte sequences to the Unicode replacement character (U+FFFD) instead of raising an exception, ensuring that the framework captures complete output even when firmware strings contain vendor-specific byte sequences outside the ASCII range.

```python
stdout = proc.stdout.decode("utf-8", errors="replace")
stderr = proc.stderr.decode("utf-8", errors="replace")
```

### 6.2 Al-khaser Interactive Prompt Blocking Execution

**Problem:** Al-khaser calls `system("pause")` at the end of its execution, producing a `Press any key to continue...` prompt. When invoked via subprocess with a connected stdin, this prompt caused the process to block indefinitely, preventing the framework from collecting the exit code and terminating cleanly.

**Solution:** The subprocess invocation passes `stdin=subprocess.DEVNULL`, which immediately signals EOF to al-khaser's stdin. The `system("pause")` call reads from stdin, receives EOF, and returns without blocking. This is transparent to al-khaser's check execution because stdin is not used for any functional check.

### 6.3 Pafish Output Classification Ambiguity

**Problem:** Pafish's CPU section (`[-] CPU information based detections`) contains checks that belong to two different scoring categories: CPUID-based hypervisor detection belongs in `vm_checks`, while RDTSC-based timing measurements belong in `timing_attacks`. A simple section-to-category mapping would incorrectly classify all CPU section checks as a single category.

**Solution:** The parser was designed to support per-label overrides in addition to section-level defaults. The `pafish_label_overrides` dictionary in each scenario YAML maps specific check labels to category IDs, taking precedence over the section default. The RDTSC checks are remapped to `timing_attacks` via label overrides, while the remaining CPU section checks retain their `vm_checks` classification. The same mechanism handles behavioral false-positives in the generic sandbox section, routing mouse-movement and dialog-confirmation checks to the `exclude` pseudo-category.

### 6.4 Double-Counting Overlapping Checks

**Problem:** Both al-khaser and pafish implement checks for certain artifacts, notably VirtualBox ACPI registry keys, MAC address prefixes, and CPUID hypervisor bits. Without deduplication, running both tools in the same scenario would count a single detected artifact twice, inflating the detection rate and producing a lower transparency score than warranted.

**Solution:** The `deduplicate_checks()` function was implemented to merge check results sharing the same `(category_id, check_id)` key. The `check_id` is derived by slugifying the check label — converting it to lowercase with spaces and punctuation replaced by underscores — so that al-khaser's `"Checking MAC address start with 08:00:27"` and pafish's `"Looking for a MAC address starting with 08:00:27"` produce different slugs (since they have different labels), while functionally identical checks that happen to have identical labels produce the same slug and are correctly merged. The conservative merge policy (detected beats not_detected) ensures that a detection by either tool is surfaced in the merged result.

### 6.5 Deferred Output Lines in Al-khaser

**Problem:** For some checks, al-khaser emits a `[!]` diagnostic line between the check label line and the result line. The diagnostic line contains additional context (such as the name of a detected process or the path of a found file) but does not match the expected `[*] label ... [ GOOD/BAD ]` inline pattern. A simple parser that only recognized inline patterns would miss these deferred results.

**Solution:** The `AlKhaserParser` was extended with a state machine that tracks pending label lines. When a `[*] label ...` line is encountered without an inline result, it is stored as the pending label. If the next matching line is an orphan `[ GOOD ]` or `[ BAD ]`, the pending label is combined with it to produce a complete check result. If any other line type intervenes, the pending label is discarded (treated as a non-result annotation).

### 6.6 Behavioral False Positives in Headless Environments

**Problem:** Pafish includes a set of checks for user behavioral realism: mouse movement detection, mouse speed, click activity, and dialog confirmation. In an automated, headless execution environment, these checks always report `traced!` (detected) because no human user is present to move the mouse or click dialog buttons. Including these checks in the scoring would penalize every automated run regardless of the actual VM hardening state, making the transparency score incomparable across environments.

**Solution:** The `exclude` pseudo-category was introduced in the `pafish_sections` and `pafish_label_overrides` mappings. Checks that resolve to `exclude` are silently dropped by the parser and never reach the scoring engine. The baseline scenario explicitly excludes the entire "Generic reverse turing tests" section and additionally excludes six specific mouse and dialog labels that appear in other sections. This decision is documented in the scenario YAML with a comment, making the exclusion transparent and auditable.

### 6.7 PyInstaller Path Resolution

**Problem:** When the framework is packaged as a PyInstaller single-file executable, the `sys._MEIPASS` temporary directory is used as the root for extracted files, but the working directory at runtime may be anywhere on the filesystem. Relative path references in the code (e.g., `configs/tools.yaml`, `probes/al-khaser/al-khaser_x86.exe`) would fail because they resolve relative to the working directory rather than the bundle root.

**Solution:** The `_paths.py` module provides two functions. `bundle_root()` returns `Path(sys._MEIPASS)` when frozen or `Path(__file__).parent` in development mode. `output_root()` returns the directory containing the executable (`Path(sys.executable).parent`) when frozen, so that reports and logs are written next to the executable rather than into the ephemeral extraction directory. All path resolution in config loading, tool invocation, and report writing uses these functions uniformly.

---

## 7. Preliminary Results

### 7.1 Framework Validation

The prototype was validated using the `--dry-run` mode against all five scenarios. Dry-run validation confirmed that all scenario YAML files pass structural validation, all al-khaser flag references are valid, all category weights sum to 1.0, all pafish section targets resolve to valid category identifiers, and all executable paths resolve correctly relative to the bundle root. The test suite in `tests/test_parser.py` was executed and all test cases passed, covering inline result parsing, deferred result parsing, pafish section routing, label override precedence, and the deduplication merge policy.

The complete test suite covers:
- Al-khaser inline result parsing (both GOOD and BAD)
- Al-khaser deferred result parsing (orphan BAD following a diagnostic)
- Al-khaser category assignment without keyword matching
- Pafish section-header tracking and category routing
- Pafish label override precedence over section defaults
- RDTSC timing check routing to `timing_attacks` via label override
- Deduplication: same check from two tools merged into one
- Deduplication: conservative policy (detected beats not_detected)
- Deduplication: multi-tool provenance recording

### 7.2 Check Coverage per Category

Based on the al-khaser flag groups and pafish section mappings implemented in the five scenarios, the framework covers the following approximate check counts per category:

| Category | Al-khaser Flags | Estimated Checks | Pafish Sections |
|---|---|---|---|
| VM Detection (vm_checks) | GEN_SANDBOX, VBOX, VMWARE, VPC, QEMU, KVM, XEN, WINE, PARALLELS, HYPERV | ~120 | VirtualBox, VMware, Qemu, Bochs, Wine, Sandboxie, Generic Sandbox, CPU (partial) |
| Anti-Debug (anti_debug) | DEBUG, TLS | ~60 | Debuggers, Hooks, Cuckoo |
| Timing Attacks (timing_attacks) | TIMING_ATTACKS | ~12 | CPU (RDTSC only), Generic Sandbox (Sleep patch) |
| Analysis Tool Detection (analysis_tools) | ANALYSIS_TOOLS, ANTI_DISASSM | ~35 | — |

The total check count across all categories in a baseline run is approximately 220 unique checks after deduplication, covering registry artifacts, file artifacts, device objects, process names, WMI hardware sensors, MAC addresses, CPUID and descriptor table values, firmware strings, timing measurements, and analysis tool processes.

### 7.3 MITRE ATT&CK Coverage

The `configs/check_mitre.yaml` mapping file contains over two hundred per-check entries covering all five relevant MITRE techniques. This provides per-check MITRE annotations for the majority of checks executed by the framework. Each entry includes the technique identifier, a reference URL to the Check Point Evasions Encyclopedia, and a one-to-two sentence technical description of why the check is relevant as a sandbox transparency indicator.

The MITRE mapping enables the HTML report to display per-check technique badges in the detected-artifacts summary section, and the JSON output to include `mitre` and `checkpoint_url` fields for each mapped check. This annotation layer is essential for the thesis results chapter, where detected artifacts need to be discussed in the context of their adversarial relevance rather than merely as a list of triggered checks.

### 7.4 Report Generation Quality

The HTML report generator produces self-contained reports with the following elements: a score card showing the global transparency score, risk badge, detection rate, run metadata, and tool version information; a detected-artifacts summary listing all checks where a detectable artifact was found, annotated with MITRE badges and Checkpoint Evasions links; a category breakdown table showing per-category score, weight, check count, detected count, and MITRE technique; a full checks table with client-side filtering by status (All, Detected, Clean), showing each check's label, tool provenance, raw value, normalized value, and MITRE classification.

The combined HTML report, generated for multi-scenario runs, presents per-scenario score cards with color-coded risk indicators and a summary table allowing direct comparison of transparency scores across different evasion families. This will serve as the primary visualization in the thesis results chapter.

---

## 8. Work Plan for Research 3

### 8.1 Data Collection Phase

The primary deliverable of the third research phase is a dataset of transparency evaluations across multiple sandbox environments. The planned environments for evaluation include at minimum: VirtualBox default configuration, VirtualBox with manual hardening applied (masking of CPUID hypervisor bit, renaming of VM-specific processes, registry artifact removal), Cuckoo Sandbox default deployment, and at least one commercial analysis platform (e.g., ANY.RUN or a comparable service reachable through an academic agreement).

For each environment, the full baseline scenario (`baseline_001`) will be executed, and at minimum the focused scenarios (`vm_checks_001`, `anti_debug_001`, `timing_attacks_001`, `analysis_tools_001`) will also be executed to allow category-level comparison. Each run produces a `report.json` with the complete check table and scoring data, forming the raw dataset for the results chapter.

### 8.2 Cross-Environment Comparative Analysis

A comparison script (`compare.py`) will be developed to read `report.json` files from multiple runs of the same scenario across different environments and produce a side-by-side comparison report in HTML and CSV formats. The comparison will show, for each check, whether it was detected or clean in each environment, enabling direct identification of checks that distinguish the environments from each other.

The comparison output will directly answer the central research question: which anti-analysis artifacts are still exposed by current sandbox configurations, and which hardening measures are effective at concealing them? The delta analysis between the default and hardened VirtualBox configurations will quantify the effectiveness of each hardening measure by showing which checks flipped from detected to clean.

The planned structure of the comparison report is:

```bash
python compare.py --scenario vm_checks \
    --runs reports/virtualbox_default   \
           reports/virtualbox_hardened  \
           reports/cuckoo_default
```

This produces a table where rows are checks and columns are environments, with the global and per-category transparency scores shown as summary rows.

### 8.3 Hardening Validation Workflow

The third research phase will implement and evaluate a complete hardening validation workflow:

1. Establish a baseline with `python main.py --scenario all --env vbox_default`
2. Apply a specific hardening measure (e.g., mask CPUID hypervisor bit via VBoxManage)
3. Re-evaluate with `python main.py --scenario all --env vbox_hardened`
4. Generate a delta report with `python compare.py`

This workflow will be documented as a reproducible methodology that sandbox operators can apply to evaluate the effectiveness of their own hardening measures. The thesis will present at least three distinct hardening iterations, demonstrating progressively improving transparency scores.

### 8.4 Remaining Taxonomy Coverage

Three al-khaser flag groups documented in the taxonomy but not yet covered by focused scenarios will be implemented in the third phase:

| Scenario to Create | Flags | Coverage |
|---|---|---|
| `injection.yaml` | `INJECTION` | EnumProcessModulesEx, ToolHelp32, LdrEnumerateLoadedModules |
| `code_injections.yaml` | `CODE_INJECTIONS` | CreateRemoteThread, SetWindowsHooksEx, NtCreateThreadEx, APC |
| `dumping.yaml` | `DUMPING_CHECK` | PE header erasure, SizeOfImage manipulation |

These three categories correspond to anti-dump and code injection in the original taxonomy. While they are less directly relevant to sandbox transparency evaluation (since they primarily concern malware's ability to resist forensic memory analysis rather than to detect an analysis environment), their inclusion will complete the framework's coverage of all al-khaser modules and allow the baseline scenario to incorporate them with appropriate weights.

### 8.5 Timeline

| Phase | Target | Deliverable |
|---|---|---|
| Data collection | Weeks 1–3 | Raw JSON reports for all planned environments |
| Comparison analysis | Weeks 3–5 | `compare.py` implementation and initial comparison tables |
| Hardening evaluation | Weeks 5–7 | Before/after comparison for 3 hardening measures |
| Remaining taxonomy | Weeks 7–8 | Injection and dumping scenario YAMLs and adapters |
| Thesis writing | Weeks 8–12 | Final results chapter, conclusions, consolidated bibliography |
| Demo video | Week 11 | ≤3 min demonstration of full pipeline on a target environment |

---

## 9. Demonstration Video

A video demonstration of the sbxprobe prototype is available at the following link:

[Prototype demonstration video — to be recorded upon first successful run against a target environment]

The video will demonstrate the following sequence:
1. Invocation of `python main.py --scenario baseline --env virtualbox_default`
2. Console output showing the execution of al-khaser per category and pafish once
3. Console output showing parsed check counts, deduplication statistics, and the computed transparency score
4. Opening the generated `report.html` in a browser, with the score card, detected-artifacts summary, and full check table visible
5. Opening the combined `index.html` for a multi-scenario run
6. Brief demonstration of the `--dry-run` flag for configuration validation

The maximum duration of the demonstration video is three minutes, per the research report requirements.

---

## Bibliography

[1] OPSWAT, "Threat Report 2025," [Online]. Available: https://www.opswat.com/resources/reports. Accessed 16.12.2025.

[2] M. Afianian et al., "Malware dynamic analysis evasion techniques: A survey," *ACM Comput. Surv.*, vol. 52, no. 6, pp. 1–34, Dec. 2020. [Online]. Available: https://arxiv.org/abs/1811.01190. Accessed 17.12.2025.

[3] AMTSO, "Sandbox Evaluation Framework," Anti-Malware Testing Standards Organization. [Online]. Available: https://www.amtso.org/wp-content/uploads/2025/03/AMTSO-Sandbox-Evaluation-Framework_FINAL_2025-03.pdf. Accessed 17.12.2025.

[4] ANY.RUN, "Malware Trends Overview Report: 2025," Jan. 2026. [Online]. Available: https://any.run/cybersecurity-blog/malware-trends-2025/. Accessed 22.01.2026.

[5] T. Porutiu, "How Sandbox Security Can Boost Your Detection and Malware Analysis Capabilities," Bitdefender Business Insights, Mar. 27, 2024. [Online]. Available: https://www.bitdefender.com/en-us/blog/businessinsights/how-sandbox-security-can-boost-your-detection-and-malware-analysis-capabilities. Accessed 22.01.2026.

[6] AMTSO Sandbox Evaluation Working Group, "Sandbox Evaluation Framework," Anti-Malware Testing Standards Organization, Mar. 2025. [Online]. Available: https://www.amtso.org/wp-content/uploads/2025/03/AMTSO-Sandbox-Evaluation-Framework_FINAL_2025-03.pdf. Accessed 22.01.2026.

[7] K. Cucci, "Evasive Malware: A Field Guide to Detecting, Analyzing, and Defeating Advanced Threats". Accessed 22.01.2026.

[8] C. Guarnieri, M. R. Hayajneh, and A. Richardson, "Cuckoo Sandbox: Design and Implementation," Black Hat USA, 2012. Accessed 23.01.2026.

[9] Jiaxuan Geng, Junfeng Wang, Zhiyang Fang, Yingjie Zhou, Di Wu, and Wenhan Ge. 2024. "A survey of strategy-driven evasion methods for PE malware: Transformation, concealment, and attack." *Comput. Secur.* 137, C (Feb 2024). Accessed 23.01.2026.

[10] L. Balev, "al-khaser: PoC malware techniques," GitHub, 2015–2026. [Online]. Available: https://github.com/ayoubfaouzi/al-khaser. Accessed 24.01.2026.

[11] A. Ortega, "Pafish: VM/sandbox detection tool," GitHub, 2012. [Online]. Available: https://github.com/a0rtega/pafish. Accessed 24.01.2026.

[12] hfiref0x, "VMDE: Virtual Machine Detection Environment," GitHub, 2014. [Online]. Available: https://github.com/hfiref0x/VMDE. Accessed 24.01.2026.

[13] Check Point Research, "InviZzzible: Virtual Environment Assessment," GitHub, 2016. [Online]. Available: https://github.com/CheckPointSW/InviZzzible. Accessed 24.01.2026.

[14] D. C. D'Elia, E. Coppa, F. Palmaro, and L. Cavallaro, "On the Dissection of Evasive Malware," in *IEEE Transactions on Information Forensics and Security*, vol. 15. Accessed 24.01.2026.

[15] season-lab, "bluepill: BluePill implementation," GitHub, 2019. [Online]. Available: https://github.com/season-lab/bluepill/. Accessed 24.01.2026.

[16] Check Point Research, "Malware Evasion Techniques Encyclopedia," Checkpoint Evasions, 2020. [Online]. Available: https://evasions.checkpoint.com/src/Evasions/index.html. Accessed 24.01.2026.

[17] Microsoft, "MITRE ATT&CK T1497 — Virtualization/Sandbox Evasion," MITRE ATT&CK v16. [Online]. Available: https://attack.mitre.org/techniques/T1497/. Accessed 10.06.2026.

[18] MITRE Corporation, "T1622 — Debugger Evasion," MITRE ATT&CK v16. [Online]. Available: https://attack.mitre.org/techniques/T1622/. Accessed 10.06.2026.

[19] MITRE Corporation, "T1518.001 — Security Software Discovery," MITRE ATT&CK v16. [Online]. Available: https://attack.mitre.org/techniques/T1518/001/. Accessed 10.06.2026.

[20] PyInstaller Development Team, "PyInstaller Manual," 2024. [Online]. Available: https://pyinstaller.org/en/stable/. Accessed 10.06.2026.
