from runner.executor import ExecutionResult, run_subprocess


class PafishAdapter:
    """
    Invokes pafish.exe with no additional arguments — pafish runs all checks
    by default and does not accept --check style filtering.
    """

    def __init__(self, tool_cfg: dict):
        self.executable = tool_cfg["executable"]
        self.timeout    = int(tool_cfg.get("timeout", 60))

    def run(self, environment_label: str) -> ExecutionResult:
        return run_subprocess(
            tool_path=self.executable,
            args=[],
            timeout=self.timeout,
            environment_label=environment_label,
            check_id="pafish_run",
        )
