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
        # text=False + explicit decode: al-khaser/pafish run on Windows and may
        # output via the OEM/ANSI codepage.  Decoding as UTF-8 with errors='replace'
        # prevents silent truncation when a non-ASCII character (e.g. in a BIOS
        # vendor string or WMI value) appears mid-output.
        proc = subprocess.Popen(
            [tool_path] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
        try:
            stdout_b, stderr_b = proc.communicate(timeout=timeout)
            elapsed = time.perf_counter() - t_start
            return ExecutionResult(
                check_id=check_id,
                tool=tool_path,
                return_code=proc.returncode,
                stdout=stdout_b.decode("utf-8", errors="replace"),
                stderr=stderr_b.decode("utf-8", errors="replace"),
                runtime_seconds=round(elapsed, 4),
                timestamp=timestamp,
                environment_label=environment_label,
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_b, stderr_b = proc.communicate()
            elapsed = time.perf_counter() - t_start
            return ExecutionResult(
                check_id=check_id,
                tool=tool_path,
                return_code=-1,
                stdout=stdout_b.decode("utf-8", errors="replace") if stdout_b else "",
                stderr=stderr_b.decode("utf-8", errors="replace") if stderr_b else "",
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
