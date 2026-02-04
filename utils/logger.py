"""
Structured logging setup using structlog.

SECURITY: Uses rotating file handlers to prevent disk exhaustion (CWE-774).
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import structlog


# Log rotation settings
LOG_MAX_BYTES = 50 * 1024 * 1024  # 50 MB per file
LOG_BACKUP_COUNT = 10  # Keep 10 backup files (500 MB total max)


def setup_logging(
    level: str = "INFO",
    log_file: str | None = None,
    json_format: bool = False,
    max_bytes: int = LOG_MAX_BYTES,
    backup_count: int = LOG_BACKUP_COUNT,
) -> None:
    """
    Configure structured logging with rotation.

    SECURITY: Uses RotatingFileHandler to prevent disk exhaustion (CWE-774).

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        json_format: Use JSON format for logs
        max_bytes: Maximum log file size before rotation (default 50MB)
        backup_count: Number of backup files to keep (default 10)
    """
    # Configure standard logging
    log_level = getattr(logging, level.upper(), logging.INFO)

    handlers: list[logging.Handler] = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(log_level)
    handlers.append(console_handler)

    # Rotating file handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Use RotatingFileHandler to prevent disk exhaustion
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        handlers=handlers,
        force=True,
    )
    
    # Configure structlog
    processors: list[Any] = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]
    
    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=structlog.dev.plain_traceback,
            )
        )
    
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured logger
    """
    return structlog.get_logger(name)


class LogContext:
    """Context manager for structured log context."""
    
    def __init__(self, logger: structlog.stdlib.BoundLogger, **kwargs: Any) -> None:
        """
        Initialize context.
        
        Args:
            logger: The logger to bind context to
            **kwargs: Key-value pairs to add to log context
        """
        self.logger = logger
        self.context = kwargs
        self._previous_logger: structlog.stdlib.BoundLogger | None = None
    
    def __enter__(self) -> structlog.stdlib.BoundLogger:
        """Enter context and bind values."""
        self._previous_logger = self.logger
        return self.logger.bind(**self.context)
    
    def __exit__(self, *args: Any) -> None:
        """Exit context."""
        pass


class ScanLogger:
    """
    Specialized logger for scan operations.
    
    Provides structured logging with scan context.
    """
    
    def __init__(self, scan_id: str, target: str) -> None:
        """
        Initialize scan logger.
        
        Args:
            scan_id: Unique scan identifier
            target: Target being scanned
        """
        self.logger = get_logger("scan").bind(
            scan_id=scan_id,
            target=target,
        )
    
    def phase_start(self, phase: str) -> None:
        """Log phase start."""
        self.logger.info(f"Phase started: {phase}", phase=phase, event="phase_start")
    
    def phase_complete(self, phase: str, duration: float) -> None:
        """Log phase completion."""
        self.logger.info(
            f"Phase completed: {phase}",
            phase=phase,
            duration_seconds=duration,
            event="phase_complete",
        )
    
    def finding_discovered(
        self,
        name: str,
        severity: str,
        location: str,
    ) -> None:
        """Log new finding."""
        self.logger.info(
            f"Finding: [{severity}] {name}",
            finding_name=name,
            severity=severity,
            location=location,
            event="finding_discovered",
        )
    
    def error(self, message: str, **kwargs: Any) -> None:
        """Log error."""
        self.logger.error(message, event="scan_error", **kwargs)
    
    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning."""
        self.logger.warning(message, event="scan_warning", **kwargs)
    
    def progress(
        self,
        current: int,
        total: int,
        message: str = "",
    ) -> None:
        """Log progress."""
        pct = (current / total * 100) if total > 0 else 0
        self.logger.info(
            message or f"Progress: {current}/{total}",
            current=current,
            total=total,
            percent=round(pct, 1),
            event="progress",
        )


# =============================================================================
# PER-PENTEST LOGGING SYSTEM
# =============================================================================

class PentestLogger:
    """
    Per-pentest logging system that saves all actions to a dedicated log file.

    Creates a unique log file for each pentest/scan session that captures:
    - All tool executions
    - HTTP requests made
    - Findings discovered
    - Errors and warnings
    - Phase transitions
    - Configuration used

    Log files are stored in: ~/.phantom/pentest_logs/{scan_id}/
    """

    def __init__(
        self,
        scan_id: str,
        target: str,
        client_name: str | None = None,
        log_dir: str | Path | None = None,
    ) -> None:
        """
        Initialize per-pentest logger.

        Args:
            scan_id: Unique scan/pentest identifier
            target: Target being scanned
            client_name: Optional client name for the engagement
            log_dir: Custom log directory (defaults to ~/.phantom/pentest_logs)
        """
        self.scan_id = scan_id
        self.target = target
        self.client_name = client_name
        self.start_time = datetime.now()

        # Setup log directory
        if log_dir:
            self.log_dir = Path(log_dir)
        else:
            self.log_dir = Path.home() / ".phantom" / "pentest_logs" / scan_id

        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Main log file
        self.log_file = self.log_dir / f"pentest_{scan_id}.log"

        # Structured JSON log for machine parsing
        self.json_log_file = self.log_dir / f"pentest_{scan_id}.jsonl"

        # Setup dedicated file handler for this pentest
        self._setup_pentest_handler()

        # Log session start
        self._log_session_start()

    def _setup_pentest_handler(self) -> None:
        """Setup dedicated file handler for this pentest session."""
        from logging.handlers import RotatingFileHandler

        # Create pentest-specific logger
        self.logger = logging.getLogger(f"pentest.{self.scan_id}")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False  # Don't propagate to root logger

        # Clear any existing handlers
        self.logger.handlers.clear()

        # File handler with rotation
        file_handler = RotatingFileHandler(
            self.log_file,
            maxBytes=100 * 1024 * 1024,  # 100 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)

        # Detailed format for pentest logs
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def _log_session_start(self) -> None:
        """Log pentest session start."""
        self.logger.info("=" * 80)
        self.logger.info("PHANTOM AI - PENTEST SESSION STARTED")
        self.logger.info("=" * 80)
        self.logger.info(f"Scan ID: {self.scan_id}")
        self.logger.info(f"Target: {self.target}")
        self.logger.info(f"Client: {self.client_name or 'Not specified'}")
        self.logger.info(f"Start Time: {self.start_time.isoformat()}")
        self.logger.info(f"Log Directory: {self.log_dir}")
        self.logger.info("-" * 80)

        # JSON log entry
        self._write_json_log({
            "event": "session_start",
            "scan_id": self.scan_id,
            "target": self.target,
            "client_name": self.client_name,
            "start_time": self.start_time.isoformat(),
        })

    def _write_json_log(self, data: dict) -> None:
        """Write structured JSON log entry."""
        import json
        from datetime import datetime

        entry = {
            "timestamp": datetime.now().isoformat(),
            "scan_id": self.scan_id,
            **data,
        }

        with open(self.json_log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def log_config(self, config: dict) -> None:
        """Log scan configuration."""
        self.logger.info("SCAN CONFIGURATION:")
        for key, value in config.items():
            self.logger.info(f"  {key}: {value}")
        self.logger.info("-" * 80)

        self._write_json_log({
            "event": "config",
            "config": config,
        })

    def log_phase_start(self, phase: str, description: str = "") -> None:
        """Log phase start."""
        self.logger.info("")
        self.logger.info(f">>> PHASE START: {phase}")
        if description:
            self.logger.info(f"    {description}")

        self._write_json_log({
            "event": "phase_start",
            "phase": phase,
            "description": description,
        })

    def log_phase_end(self, phase: str, duration_seconds: float, summary: dict | None = None) -> None:
        """Log phase completion."""
        self.logger.info(f"<<< PHASE END: {phase} (Duration: {duration_seconds:.2f}s)")
        if summary:
            for key, value in summary.items():
                self.logger.info(f"    {key}: {value}")
        self.logger.info("-" * 40)

        self._write_json_log({
            "event": "phase_end",
            "phase": phase,
            "duration_seconds": duration_seconds,
            "summary": summary,
        })

    def log_tool_execution(
        self,
        tool: str,
        command: str | None = None,
        target: str | None = None,
        status: str = "started",
        output: str | None = None,
        duration: float | None = None,
        error: str | None = None,
    ) -> None:
        """Log tool execution."""
        if status == "started":
            self.logger.info(f"[TOOL] {tool} - STARTED")
            if command:
                self.logger.debug(f"  Command: {command}")
            if target:
                self.logger.debug(f"  Target: {target}")
        elif status == "completed":
            msg = f"[TOOL] {tool} - COMPLETED"
            if duration:
                msg += f" ({duration:.2f}s)"
            self.logger.info(msg)
            if output:
                # Truncate long output
                truncated = output[:500] + "..." if len(output) > 500 else output
                self.logger.debug(f"  Output: {truncated}")
        elif status == "failed":
            self.logger.error(f"[TOOL] {tool} - FAILED")
            if error:
                self.logger.error(f"  Error: {error}")

        self._write_json_log({
            "event": "tool_execution",
            "tool": tool,
            "command": command,
            "target": target,
            "status": status,
            "duration": duration,
            "error": error,
        })

    def log_http_request(
        self,
        method: str,
        url: str,
        status_code: int | None = None,
        response_time: float | None = None,
        payload: str | None = None,
        response_length: int | None = None,
    ) -> None:
        """Log HTTP request made during scanning."""
        status_str = f" -> {status_code}" if status_code else ""
        time_str = f" ({response_time:.3f}s)" if response_time else ""

        self.logger.debug(f"[HTTP] {method} {url}{status_str}{time_str}")

        if payload:
            self.logger.debug(f"  Payload: {payload[:200]}...")

        self._write_json_log({
            "event": "http_request",
            "method": method,
            "url": url,
            "status_code": status_code,
            "response_time": response_time,
            "response_length": response_length,
        })

    def log_finding(
        self,
        vulnerability_type: str,
        severity: str,
        url: str,
        confidence: float,
        parameter: str | None = None,
        payload: str | None = None,
        evidence: str | None = None,
        module: str | None = None,
    ) -> None:
        """Log discovered finding."""
        # Convert confidence to float if it's a string
        try:
            if isinstance(confidence, str):
                # Handle percentage strings like "90%"
                confidence = float(confidence.rstrip('%'))
                if confidence > 1:
                    confidence = confidence / 100.0
            confidence = float(confidence)
        except (ValueError, TypeError):
            confidence = 0.0

        # Normalize confidence: if > 1, it's already a percentage; if <= 1, convert to percentage
        confidence_pct = confidence if confidence > 1 else confidence * 100
        # Cap at 100%
        confidence_pct = min(confidence_pct, 100.0)

        self.logger.warning("")
        self.logger.warning(f"[FINDING] {severity.upper()} - {vulnerability_type}")
        self.logger.warning(f"  URL: {url}")
        self.logger.warning(f"  Confidence: {confidence_pct:.1f}%")
        if parameter:
            self.logger.warning(f"  Parameter: {parameter}")
        if payload:
            self.logger.warning(f"  Payload: {payload[:100]}...")
        if evidence:
            self.logger.warning(f"  Evidence: {evidence[:200]}...")
        if module:
            self.logger.warning(f"  Module: {module}")
        self.logger.warning("")

        self._write_json_log({
            "event": "finding",
            "vulnerability_type": vulnerability_type,
            "severity": severity,
            "url": url,
            "confidence": confidence,
            "parameter": parameter,
            "payload": payload,
            "evidence": evidence,
            "module": module,
        })

    def log_validation(
        self,
        finding_type: str,
        stage: str,
        result: str,
        confidence_before: float,
        confidence_after: float,
    ) -> None:
        """Log finding validation."""
        # Normalize confidence values
        conf_before_pct = min(confidence_before if confidence_before > 1 else confidence_before * 100, 100.0)
        conf_after_pct = min(confidence_after if confidence_after > 1 else confidence_after * 100, 100.0)

        self.logger.info(f"[VALIDATION] {finding_type} - Stage: {stage} - Result: {result}")
        self.logger.info(f"  Confidence: {conf_before_pct:.1f}% -> {conf_after_pct:.1f}%")

        self._write_json_log({
            "event": "validation",
            "finding_type": finding_type,
            "stage": stage,
            "result": result,
            "confidence_before": confidence_before,
            "confidence_after": confidence_after,
        })

    def log_chain(
        self,
        chain_id: str,
        vulnerabilities: list[str],
        impact: str,
        severity: str,
    ) -> None:
        """Log discovered vulnerability chain."""
        chain_str = " → ".join(vulnerabilities)
        self.logger.warning(f"[CHAIN] {severity.upper()} - {chain_str}")
        self.logger.warning(f"  Impact: {impact}")

        self._write_json_log({
            "event": "chain",
            "chain_id": chain_id,
            "vulnerabilities": vulnerabilities,
            "impact": impact,
            "severity": severity,
        })

    def log_error(self, message: str, exception: Exception | None = None, module: str | None = None) -> None:
        """Log error."""
        self.logger.error(f"[ERROR] {message}")
        if exception:
            self.logger.error(f"  Exception: {type(exception).__name__}: {exception}")
        if module:
            self.logger.error(f"  Module: {module}")

        self._write_json_log({
            "event": "error",
            "message": message,
            "exception": str(exception) if exception else None,
            "module": module,
        })

    def log_warning(self, message: str, context: dict | None = None) -> None:
        """Log warning."""
        self.logger.warning(f"[WARNING] {message}")
        if context:
            for key, value in context.items():
                self.logger.warning(f"  {key}: {value}")

        self._write_json_log({
            "event": "warning",
            "message": message,
            "context": context,
        })

    def log_info(self, message: str) -> None:
        """Log informational message."""
        self.logger.info(message)

        self._write_json_log({
            "event": "info",
            "message": message,
        })

    def log_progress(self, current: int, total: int, message: str = "") -> None:
        """Log scan progress."""
        pct = (current / total * 100) if total > 0 else 0
        self.logger.info(f"[PROGRESS] {current}/{total} ({pct:.1f}%) {message}")

        self._write_json_log({
            "event": "progress",
            "current": current,
            "total": total,
            "percent": round(pct, 1),
            "message": message,
        })

    def log_session_end(self, summary: dict) -> None:
        """Log pentest session end."""
        from datetime import datetime

        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        self.logger.info("")
        self.logger.info("=" * 80)
        self.logger.info("PHANTOM AI - PENTEST SESSION COMPLETED")
        self.logger.info("=" * 80)
        self.logger.info(f"Scan ID: {self.scan_id}")
        self.logger.info(f"End Time: {end_time.isoformat()}")
        self.logger.info(f"Duration: {duration:.2f} seconds ({duration / 60:.1f} minutes)")
        self.logger.info("-" * 40)
        self.logger.info("SUMMARY:")
        for key, value in summary.items():
            self.logger.info(f"  {key}: {value}")
        self.logger.info("=" * 80)

        self._write_json_log({
            "event": "session_end",
            "end_time": end_time.isoformat(),
            "duration_seconds": duration,
            "summary": summary,
        })

    def get_log_path(self) -> Path:
        """Get path to the log file."""
        return self.log_file

    def get_json_log_path(self) -> Path:
        """Get path to the JSON log file."""
        return self.json_log_file

    def get_log_dir(self) -> Path:
        """Get log directory path."""
        return self.log_dir


# Global pentest logger instance (set when scan starts)
_current_pentest_logger: PentestLogger | None = None


def get_pentest_logger() -> PentestLogger | None:
    """Get the current pentest logger instance."""
    return _current_pentest_logger


def set_pentest_logger(logger: PentestLogger | None) -> None:
    """Set the current pentest logger instance."""
    global _current_pentest_logger
    _current_pentest_logger = logger


def create_pentest_logger(
    scan_id: str,
    target: str,
    client_name: str | None = None,
    log_dir: str | Path | None = None,
) -> PentestLogger:
    """
    Create and register a new pentest logger.

    Args:
        scan_id: Unique scan/pentest identifier
        target: Target being scanned
        client_name: Optional client name for the engagement
        log_dir: Custom log directory

    Returns:
        PentestLogger instance
    """
    logger = PentestLogger(
        scan_id=scan_id,
        target=target,
        client_name=client_name,
        log_dir=log_dir,
    )
    set_pentest_logger(logger)
    return logger


# Import datetime for PentestLogger
from datetime import datetime


# Initialize default logging on import
setup_logging()
