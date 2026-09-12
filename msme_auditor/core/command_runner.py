"""
Safe Subprocess Wrapper — kills silent failures
================================================
Every scanner call goes through this — one place to catch
timeouts / permissions / missing-binaries instead of scattering
try/excepts.

Usage:
    from msme_auditor.core.command_runner import run_command
    result = run_command(["net", "accounts"])
    if not result.success:
        print(result.error)  # "timeout" | "permission_denied" | "binary_not_found"
"""

import logging
import subprocess
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger("msme_auditor")


@dataclass
class CommandResult:
    """Structured result from a subprocess call."""

    success: bool
    stdout: str
    stderr: str
    returncode: Optional[int]
    error: Optional[str] = None


def run_command(
    cmd: List[str],
    timeout: int = 10,
    capture_output: bool = True,
) -> CommandResult:
    """
    Run a subprocess command safely with structured error handling.

    Args:
        cmd: Command and arguments as a list.
        timeout: Seconds before the process is killed.
        capture_output: Whether to capture stdout/stderr (default True).

    Returns:
        A :class:`CommandResult` with success flag, output, and error info.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            logger.warning(
                "Command %s exited %d: %s", cmd, proc.returncode, proc.stderr[:200]
            )
        return CommandResult(
            success=proc.returncode == 0,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
        )
    except subprocess.TimeoutExpired:
        logger.error("Command %s timed out after %ds", cmd, timeout)
        return CommandResult(
            success=False, stdout="", stderr="", returncode=None, error="timeout"
        )
    except PermissionError:
        logger.error("Command %s requires elevated privileges", cmd)
        return CommandResult(
            success=False, stdout="", stderr="", returncode=None, error="permission_denied"
        )
    except FileNotFoundError:
        logger.error("Command binary not found: %s", cmd[0] if cmd else cmd)
        return CommandResult(
            success=False, stdout="", stderr="", returncode=None, error="binary_not_found"
        )
    except OSError as exc:
        logger.error("Command %s failed with OSError: %s", cmd, exc)
        return CommandResult(
            success=False, stdout="", stderr="", returncode=None, error=str(exc)
        )
