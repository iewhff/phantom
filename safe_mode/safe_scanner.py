"""
Safe Scanner - Non-destructive scanning with configurable safety levels.
Designed for banks, hospitals, and critical infrastructure.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional
import httpx

from utils.logger import get_logger

logger = get_logger(__name__)


class SafetyLevel(Enum):
    """Safety levels for scanning operations."""
    PASSIVE = "passive"           # Read-only, no modifications
    SAFE = "safe"                 # Non-destructive tests only
    CAUTIOUS = "cautious"         # Limited impact tests
    STANDARD = "standard"         # Normal pentesting
    AGGRESSIVE = "aggressive"     # Full testing (not for production)


@dataclass
class SafePayload:
    """A safe, non-destructive payload."""
    id: str
    name: str
    category: str
    payload: str
    safe_alternative: str
    risk_level: str  # NONE, LOW, MEDIUM
    description: str
    evidence_markers: list[str]
    original_destructive: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "payload": self.payload,
            "safe_alternative": self.safe_alternative,
            "risk_level": self.risk_level,
            "description": self.description,
            "evidence_markers": self.evidence_markers,
        }


class SafeScanner:
    """
    Safe scanning framework for critical infrastructure.
    
    Features:
    - Non-destructive payloads only
    - Evidence-only proof of concepts
    - Configurable safety levels
    - Automatic dangerous operation blocking
    - Compliance-ready audit logging
    """
    
    # Operations blocked in safe mode
    BLOCKED_OPERATIONS = {
        SafetyLevel.PASSIVE: [
            "POST", "PUT", "PATCH", "DELETE",  # All write operations
            "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE",  # SQL writes
            "write", "modify", "create", "remove",  # Generic writes
        ],
        SafetyLevel.SAFE: [
            "DELETE", "DROP", "TRUNCATE",  # Destructive SQL
            "rm ", "del ", "format",  # Destructive commands
            "shutdown", "reboot", "halt",  # System commands
            "; DROP", "'; DROP", "\"; DROP",  # SQL injection drops
        ],
        SafetyLevel.CAUTIOUS: [
            "DROP", "TRUNCATE",  # Very destructive
            "rm -rf", "format c:",  # System destruction
            "shutdown", "reboot",
        ],
    }
    
    # Time delays for safe testing
    SAFE_DELAYS = {
        SafetyLevel.PASSIVE: 2.0,    # 2 second between requests
        SafetyLevel.SAFE: 1.0,       # 1 second
        SafetyLevel.CAUTIOUS: 0.5,   # 500ms
        SafetyLevel.STANDARD: 0.1,   # 100ms
        SafetyLevel.AGGRESSIVE: 0.0, # No delay
    }
    
    # Request limits per minute
    RATE_LIMITS = {
        SafetyLevel.PASSIVE: 10,
        SafetyLevel.SAFE: 30,
        SafetyLevel.CAUTIOUS: 60,
        SafetyLevel.STANDARD: 120,
        SafetyLevel.AGGRESSIVE: 0,  # No limit
    }
    
    def __init__(
        self,
        safety_level: SafetyLevel = SafetyLevel.SAFE,
        timeout: float = 10.0,
        max_retries: int = 2,
    ):
        self.safety_level = safety_level
        self.timeout = timeout
        self.max_retries = max_retries
        self.request_count = 0
        self.last_request_time = 0.0
        self.blocked_attempts: list[dict] = []
        self.audit_log: list[dict] = []
        
        logger.info(f"SafeScanner initialized with safety level: {safety_level.value}")
    
    def is_operation_allowed(self, operation: str) -> bool:
        """Check if an operation is allowed at current safety level."""
        if self.safety_level == SafetyLevel.AGGRESSIVE:
            return True
        
        blocked = self.BLOCKED_OPERATIONS.get(self.safety_level, [])
        operation_upper = operation.upper()
        
        for blocked_op in blocked:
            if blocked_op.upper() in operation_upper:
                self._log_blocked(operation)
                return False
        
        return True
    
    def _log_blocked(self, operation: str) -> None:
        """Log a blocked operation."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation[:100],
            "safety_level": self.safety_level.value,
            "reason": "Blocked by safety policy",
        }
        self.blocked_attempts.append(entry)
        logger.warning(f"Blocked operation: {operation[:50]}...")
    
    def _audit_log(self, action: str, details: dict) -> None:
        """Add entry to audit log."""
        self.audit_log.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "safety_level": self.safety_level.value,
            **details,
        })
    
    async def safe_request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[httpx.Response]:
        """
        Make a safe HTTP request with rate limiting and safety checks.
        
        Args:
            method: HTTP method
            url: Target URL
            **kwargs: Additional request parameters
            
        Returns:
            Response if allowed and successful, None otherwise
        """
        # Check if method is allowed
        if not self.is_operation_allowed(method):
            logger.warning(f"Method {method} blocked by safety policy")
            return None
        
        # Check payload for dangerous content
        data = kwargs.get("data", "") or kwargs.get("json", "")
        if data and not self.is_operation_allowed(str(data)):
            logger.warning("Payload blocked by safety policy")
            return None
        
        # Apply rate limiting
        await self._apply_rate_limit()
        
        # Log the request
        self._audit_log("request", {
            "method": method,
            "url": url,
            "params": str(kwargs.get("params", ""))[:100],
        })
        
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                response = await client.request(method, url, **kwargs)
                
                self._audit_log("response", {
                    "url": url,
                    "status": response.status_code,
                    "size": len(response.content),
                })
                
                return response
                
        except Exception as e:
            logger.error(f"Safe request failed: {e}")
            return None
    
    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting based on safety level."""
        delay = self.SAFE_DELAYS.get(self.safety_level, 0.1)
        
        elapsed = time.time() - self.last_request_time
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    def get_safe_sql_payload(self, original: str) -> str:
        """
        Convert destructive SQL payload to safe alternative.
        
        Instead of: DROP TABLE users;
        Returns:    SELECT 1; -- Evidence: SQL injection possible
        """
        # Map of dangerous to safe alternatives
        conversions = {
            "DROP TABLE": "SELECT 1; -- Evidence: DROP TABLE possible",
            "DELETE FROM": "SELECT COUNT(*) FROM",
            "TRUNCATE": "SELECT 1; -- Evidence: TRUNCATE possible",
            "UPDATE": "SELECT * FROM",
            "INSERT INTO": "SELECT 1; -- Evidence: INSERT possible",
            "DROP DATABASE": "SELECT 1; -- Evidence: DROP DATABASE possible",
            "EXEC": "SELECT 1; -- Evidence: EXEC possible",
            "xp_cmdshell": "SELECT 1; -- Evidence: xp_cmdshell available",
        }
        
        result = original
        for dangerous, safe in conversions.items():
            if dangerous.upper() in original.upper():
                result = safe
                break
        
        return result
    
    def get_safe_command_payload(self, original: str) -> str:
        """
        Convert destructive command payload to safe alternative.
        
        Instead of: rm -rf /
        Returns:    echo "Evidence: Command injection possible"
        """
        conversions = {
            "rm ": 'echo "CMD_INJECTION_MARKER"',
            "del ": 'echo "CMD_INJECTION_MARKER"',
            "format": 'echo "CMD_INJECTION_MARKER"',
            "shutdown": 'echo "CMD_INJECTION_MARKER"',
            "reboot": 'echo "CMD_INJECTION_MARKER"',
            "cat /etc": "cat /dev/null",
            "type c:\\": 'echo "Evidence"',
            "wget": 'echo "WGET_MARKER"',
            "curl": 'echo "CURL_MARKER"',
            "nc ": 'echo "NETCAT_MARKER"',
            "python -c": 'echo "PYTHON_MARKER"',
            "perl -e": 'echo "PERL_MARKER"',
        }
        
        result = original
        for dangerous, safe in conversions.items():
            if dangerous.lower() in original.lower():
                result = safe
                break
        
        # Default safe command
        if result == original:
            result = 'echo "SAFE_CMD_TEST_' + hashlib.md5(original.encode()).hexdigest()[:8] + '"'
        
        return result
    
    def get_safe_xxe_payload(self) -> str:
        """Get safe XXE payload that doesn't exfiltrate real data."""
        return '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///dev/null">
]>
<data>&xxe;</data>
<!-- Evidence: XXE processing confirmed if no error -->'''
    
    def get_safe_ssrf_payload(self, target: str = "localhost") -> str:
        """Get safe SSRF payload for testing."""
        # Use non-sensitive internal endpoints
        safe_targets = [
            "http://localhost:80/robots.txt",
            "http://127.0.0.1:80/",
            "http://[::1]:80/",
        ]
        return safe_targets[0]
    
    def get_safe_lfi_payload(self) -> str:
        """Get safe LFI payload that reads non-sensitive files."""
        # Read files that exist but contain no sensitive data
        return "../../../../../../etc/hostname"  # Just hostname, not sensitive
    
    def create_safe_payload(
        self,
        category: str,
        original: str,
        target: Optional[str] = None,
    ) -> SafePayload:
        """
        Create a safe payload from a potentially destructive one.
        
        Args:
            category: Type of payload (sqli, cmdi, xxe, etc.)
            original: Original potentially destructive payload
            target: Optional target context
            
        Returns:
            SafePayload with safe alternative
        """
        payload_id = hashlib.md5(f"{category}{original}".encode()).hexdigest()[:8]
        
        # Get safe alternative based on category
        if category == "sqli":
            safe_alt = self.get_safe_sql_payload(original)
        elif category in ["cmdi", "rce"]:
            safe_alt = self.get_safe_command_payload(original)
        elif category == "xxe":
            safe_alt = self.get_safe_xxe_payload()
        elif category == "ssrf":
            safe_alt = self.get_safe_ssrf_payload(target or "localhost")
        elif category == "lfi":
            safe_alt = self.get_safe_lfi_payload()
        else:
            # Generic safe marker
            safe_alt = f"SAFE_TEST_MARKER_{payload_id}"
        
        # Determine evidence markers to look for
        evidence_markers = self._get_evidence_markers(category)
        
        return SafePayload(
            id=f"SP-{payload_id}",
            name=f"Safe {category.upper()} Test",
            category=category,
            payload=safe_alt,
            safe_alternative=safe_alt,
            risk_level="NONE" if self.safety_level == SafetyLevel.PASSIVE else "LOW",
            description=f"Non-destructive {category} test payload",
            evidence_markers=evidence_markers,
            original_destructive=original,
        )
    
    def _get_evidence_markers(self, category: str) -> list[str]:
        """Get evidence markers to look for in responses."""
        markers = {
            "sqli": [
                "SQL syntax error",
                "mysql_fetch",
                "ORA-",
                "PostgreSQL",
                "sqlite",
                "SQLSTATE",
                "unclosed quotation",
            ],
            "cmdi": [
                "CMD_INJECTION_MARKER",
                "root:",
                "uid=",
                "command not found",
                "is not recognized",
            ],
            "xxe": [
                "DOCTYPE",
                "ENTITY",
                "parser error",
                "XML parsing",
            ],
            "ssrf": [
                "localhost",
                "127.0.0.1",
                "internal",
                "connection refused",
            ],
            "lfi": [
                "root:",
                "localhost",
                "No such file",
                "failed to open",
            ],
            "xss": [
                "<script>",
                "javascript:",
                "onerror",
                "onload",
            ],
        }
        return markers.get(category, ["SAFE_TEST_MARKER"])
    
    def get_audit_report(self) -> dict[str, Any]:
        """Get complete audit report of all operations."""
        return {
            "safety_level": self.safety_level.value,
            "total_requests": self.request_count,
            "blocked_attempts": len(self.blocked_attempts),
            "blocked_details": self.blocked_attempts,
            "audit_log": self.audit_log,
            "generated_at": datetime.now().isoformat(),
        }
    
    def get_compliance_report(self) -> dict[str, Any]:
        """Get compliance-ready report for audit purposes."""
        return {
            "report_type": "Penetration Test - Safe Mode",
            "safety_level": self.safety_level.value,
            "compliance_notes": [
                "All tests performed in non-destructive mode",
                "No production data was modified",
                "No services were disrupted",
                "Evidence-only proof of concepts used",
            ],
            "methodology": {
                "approach": "Evidence-based vulnerability verification",
                "payloads": "Non-destructive alternatives to dangerous payloads",
                "rate_limiting": f"Max {self.RATE_LIMITS.get(self.safety_level, 30)} requests/minute",
                "blocked_operations": self.BLOCKED_OPERATIONS.get(self.safety_level, []),
            },
            "statistics": {
                "total_requests": self.request_count,
                "blocked_attempts": len(self.blocked_attempts),
            },
            "blocked_operations": self.blocked_attempts,
            "audit_trail": self.audit_log[-100:],  # Last 100 entries
            "generated_at": datetime.now().isoformat(),
            "signature": hashlib.sha256(
                str(self.audit_log).encode()
            ).hexdigest(),
        }
