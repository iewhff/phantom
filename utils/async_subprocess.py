"""
Safe Async Subprocess Utilities.

Provides helpers for running subprocesses with proper cleanup
to avoid 'Event loop is closed' errors.
"""

from __future__ import annotations

import asyncio
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional, Sequence

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SubprocessResult:
    """Result from a subprocess execution."""
    stdout: str
    stderr: str
    returncode: int
    success: bool
    timed_out: bool = False
    error: Optional[str] = None


@asynccontextmanager
async def managed_subprocess(
    *args: str,
    timeout: Optional[float] = None,
    **kwargs
):
    """
    Context manager for subprocess that ensures proper cleanup.

    Usage:
        async with managed_subprocess("nmap", "-sV", host) as proc:
            stdout, stderr = await proc.communicate()
    """
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **kwargs
        )
        yield proc
    finally:
        if proc is not None:
            try:
                # Check if process is still running
                if proc.returncode is None:
                    proc.kill()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        pass
            except ProcessLookupError:
                pass  # Process already dead
            except Exception:
                pass


async def run_subprocess(
    cmd: Sequence[str],
    timeout: Optional[float] = 60.0,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
) -> SubprocessResult:
    """
    Run a subprocess with proper timeout and cleanup handling.

    Args:
        cmd: Command and arguments to run
        timeout: Timeout in seconds (default 60)
        cwd: Working directory
        env: Environment variables

    Returns:
        SubprocessResult with stdout, stderr, returncode
    """
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )

            return SubprocessResult(
                stdout=stdout_bytes.decode('utf-8', errors='ignore'),
                stderr=stderr_bytes.decode('utf-8', errors='ignore'),
                returncode=proc.returncode or 0,
                success=proc.returncode == 0,
            )

        except asyncio.TimeoutError:
            # Kill the process on timeout
            try:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except Exception:
                pass

            return SubprocessResult(
                stdout="",
                stderr="",
                returncode=-1,
                success=False,
                timed_out=True,
                error=f"Process timed out after {timeout}s",
            )

    except Exception as e:
        return SubprocessResult(
            stdout="",
            stderr="",
            returncode=-1,
            success=False,
            error=str(e),
        )
    finally:
        # Ensure process is cleaned up
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
                # Don't wait here - let it die
            except Exception:
                pass


async def run_shell_command(
    command: str,
    timeout: Optional[float] = 60.0,
    cwd: Optional[str] = None,
) -> SubprocessResult:
    """
    Run a shell command with proper cleanup.

    Args:
        command: Shell command string
        timeout: Timeout in seconds
        cwd: Working directory

    Returns:
        SubprocessResult with output
    """
    proc = None
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )

            return SubprocessResult(
                stdout=stdout_bytes.decode('utf-8', errors='ignore'),
                stderr=stderr_bytes.decode('utf-8', errors='ignore'),
                returncode=proc.returncode or 0,
                success=proc.returncode == 0,
            )

        except asyncio.TimeoutError:
            try:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except Exception:
                pass

            return SubprocessResult(
                stdout="",
                stderr="",
                returncode=-1,
                success=False,
                timed_out=True,
                error=f"Process timed out after {timeout}s",
            )

    except Exception as e:
        return SubprocessResult(
            stdout="",
            stderr="",
            returncode=-1,
            success=False,
            error=str(e),
        )
    finally:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
            except Exception:
                pass


def suppress_subprocess_cleanup_errors():
    """
    Install a hook to suppress 'Event loop is closed' errors
    from subprocess cleanup during shutdown.

    This should be called once at startup.
    """
    original_hook = sys.unraisablehook

    def hook(args):
        if args.exc_type is RuntimeError:
            msg = str(args.exc_value)
            if "Event loop is closed" in msg:
                return  # Suppress
        if original_hook:
            original_hook(args)

    sys.unraisablehook = hook
