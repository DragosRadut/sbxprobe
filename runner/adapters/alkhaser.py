from runner.executor import ExecutionResult, run_subprocess

VALID_CHECKS = {
    "TLS", "DEBUG", "INJECTION", "GEN_SANDBOX",
    "VBOX", "VMWARE", "VPC", "QEMU", "KVM", "XEN",
    "WINE", "PARALLELS", "HYPERV", "CODE_INJECTIONS",
    "TIMING_ATTACKS", "DUMPING_CHECK", "ANALYSIS_TOOLS", "ANTI_DISASSM",
}


def build_args(checks: list, sleep: int) -> list:
    """
    Convert a list of check names and a sleep value into al-khaser CLI args.
      checks=["VBOX","VMWARE"], sleep=5
      → ["--check", "VBOX", "--check", "VMWARE", "--sleep", "5"]
    """
    unknown = [c for c in checks if c.upper() not in VALID_CHECKS]
    if unknown:
        raise ValueError(f"Unknown al-khaser check type(s): {unknown}. Valid: {sorted(VALID_CHECKS)}")

    args = []
    for c in checks:
        args += ["--check", c.upper()]
    args += ["--sleep", str(sleep)]
    return args


class AlKhaserAdapter:
    """
    Invokes al-khaser.exe with scenario-driven --check flags and --sleep.
    Accepts the structured tool config block from the scenario YAML directly.
    """

    def __init__(self, tool_cfg: dict):
        self.executable = tool_cfg["executable"]
        self.timeout    = int(tool_cfg.get("timeout", 120))
        checks          = tool_cfg.get("checks", [])
        sleep           = int(tool_cfg.get("sleep", 10))
        self.args       = build_args(checks, sleep)

    def run(self, environment_label: str) -> ExecutionResult:
        return run_subprocess(
            tool_path=self.executable,
            args=self.args,
            timeout=self.timeout,
            environment_label=environment_label,
            check_id="alkhaser_run",
        )
