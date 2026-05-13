import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ExecutionResult:
    check_id: str
    tool: str
    return_code: int
    stdout: str
    stderr: str
    runtime_seconds: float
    timestamp: str
    environment_label: str
    error: Optional[str] = None


def run_subprocess(
    tool_path: str,
    args: list,
    timeout: int,
    environment_label: str,
    check_id: str = "run",
) -> ExecutionResult:
    timestamp = datetime.now(timezone.utc).isoformat()
    t_start = time.perf_counter()

    try:
        # stdin=DEVNULL prevents al-khaser's end-of-run "system("pause")" call
        # from blocking indefinitely when stdout is a pipe rather than a console.
        proc = subprocess.Popen(
            [tool_path] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            elapsed = time.perf_counter() - t_start
            return ExecutionResult(
                check_id=check_id,
                tool=tool_path,
                return_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                runtime_seconds=round(elapsed, 4),
                timestamp=timestamp,
                environment_label=environment_label,
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            elapsed = time.perf_counter() - t_start
            return ExecutionResult(
                check_id=check_id,
                tool=tool_path,
                return_code=-1,
                stdout=stdout or "",
                stderr=stderr or "",
                runtime_seconds=round(elapsed, 4),
                timestamp=timestamp,
                environment_label=environment_label,
                error=f"timeout after {timeout}s (partial output captured)",
            )

    except FileNotFoundError:
        elapsed = time.perf_counter() - t_start
        return ExecutionResult(
            check_id=check_id,
            tool=tool_path,
            return_code=-1,
            stdout="",
            stderr="",
            runtime_seconds=round(elapsed, 4),
            timestamp=timestamp,
            environment_label=environment_label,
            error=f"executable not found: {tool_path}",
        )

    except Exception as exc:
        elapsed = time.perf_counter() - t_start
        return ExecutionResult(
            check_id=check_id,
            tool=tool_path,
            return_code=-1,
            stdout="",
            stderr="",
            runtime_seconds=round(elapsed, 4),
            timestamp=timestamp,
            environment_label=environment_label,
            error=str(exc),
        )
