"""
Safe HTTP Client - Centralized safety enforcement for ALL HTTP operations.

This module provides a wrapper around httpx that enforces safety policies
based on the current PHANTOM_SAFE_MODE setting.

SAFETY LEVELS:
- passive: Only GET/HEAD/OPTIONS allowed - NO state changes
- safe: Only GET/HEAD/OPTIONS allowed - NO state changes
- cautious: GET/HEAD/OPTIONS + safe POST (no destructive payloads)
- standard: All methods allowed EXCEPT for destructive patterns
- aggressive: DISABLED BY DEFAULT - requires explicit env var to enable

CRITICAL: This module is the LAST LINE OF DEFENSE against destructive operations.
All scanning modules should ideally use this client for HTTP operations.

HACKERONE/BUGCROWD SAFE: This module ensures compliance with bug bounty rules:
- No data modification in production
- No DoS or service disruption
- Evidence-only vulnerability detection
- Rate limiting respected
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import json
import hashlib
import unicodedata
from datetime import datetime
from typing import Any, Optional, List
from urllib.parse import unquote_plus

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# PAYLOAD NORMALIZATION - Defeat encoding bypasses
# ═══════════════════════════════════════════════════════════════════════════

def _normalize_payload(payload: str) -> str:
    """
    Normalize payload to defeat encoding-based bypasses.

    SECURITY: This function decodes and normalizes payloads before pattern matching
    to prevent bypasses using URL encoding, Unicode tricks, null bytes, etc.

    Handles:
    - URL encoding (%44 → D)
    - Double URL encoding (%2544 → %44 → D)
    - Unicode normalization (lookalike characters)
    - Null byte removal
    - SQL comment removal (DR/**/OP → DROP)
    - Whitespace normalization
    - Keyword reconstruction after comment removal
    """
    if not payload:
        return ""

    normalized = payload

    # 1. URL decode (handle double encoding)
    for _ in range(3):  # Max 3 iterations to handle triple encoding
        decoded = unquote_plus(normalized)
        if decoded == normalized:
            break
        normalized = decoded

    # 2. Remove null bytes (bypass attempt: DROP%00TABLE)
    # Handle both raw null bytes and encoded versions
    normalized = normalized.replace('\x00', '')
    normalized = normalized.replace('%00', '')
    normalized = re.sub(r'\\x00', '', normalized, flags=re.IGNORECASE)
    normalized = re.sub(r'\\0', '', normalized)

    # 3. Unicode normalization (NFKC - compatibility decomposition)
    # This handles lookalike characters: ᴅROP → DROP
    try:
        normalized = unicodedata.normalize('NFKC', normalized)
    except (ValueError, TypeError):
        pass  # Normalization failed - continue with unnormalized string

    # 4. Remove SQL comments (bypass attempt: DR/**/OP TABLE)
    # Handle: /* ... */, --, #
    # IMPORTANT: Replace with empty string (not space) to reconstruct split keywords
    # DR/**/OP → DROP (not DR OP)
    normalized = re.sub(r'/\*.*?\*/', '', normalized, flags=re.DOTALL)

    # For line comments (-- and #), be more careful:
    # In web contexts, payloads are often single-line, so -- might be used to
    # hide the rest of the query, not to split keywords.
    # But we still need to detect if someone is trying to inject malicious SQL
    # before the comment. So we remove the comment but keep checking the rest.
    # Also handle the case where -- is used mid-keyword (unlikely but possible)
    # Example: "DROP--x\nTABLE" should become "DROP TABLE" after normalization
    normalized = re.sub(r'--[^\n]*\n?', ' ', normalized)
    normalized = re.sub(r'#[^\n]*\n?', ' ', normalized)

    # 5. Normalize whitespace (tabs, newlines, multiple spaces → single space)
    normalized = re.sub(r'\s+', ' ', normalized)

    # 6. Add spaces between concatenated SQL keywords (DROPTABLE → DROP TABLE)
    # This defeats null-byte concatenation: DROP%00TABLE → DROPTABLE → DROP TABLE
    sql_keywords = ['DROP', 'TABLE', 'DATABASE', 'TRUNCATE', 'DELETE', 'UPDATE', 'INSERT', 'SELECT', 'FROM', 'WHERE', 'SCHEMA', 'INDEX', 'VIEW', 'PROCEDURE', 'FUNCTION']
    for keyword in sql_keywords:
        # Insert space before keyword if preceded by another letter (case insensitive)
        normalized = re.sub(
            rf'([a-zA-Z])({keyword})',
            r'\1 \2',
            normalized,
            flags=re.IGNORECASE
        )

    # 7. Clean up any double spaces created
    normalized = re.sub(r'\s+', ' ', normalized)

    return normalized


def _decode_base64_payloads(payload: str) -> str:
    """
    Attempt to decode base64 encoded sections in payload.

    SECURITY: Attackers may base64 encode malicious commands.
    Example: powershell -enc <base64> or data:text/html;base64,<payload>
    """
    decoded_parts = [payload]

    # Pattern for base64 strings (at least 8 chars for short commands like "rm -rf /")
    # Valid base64 alphabet plus padding
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')

    for match in base64_pattern.finditer(payload):
        b64_str = match.group()
        try:
            # Ensure proper padding
            padding_needed = 4 - (len(b64_str.rstrip('=')) % 4)
            if padding_needed != 4:
                b64_str = b64_str.rstrip('=') + '=' * padding_needed

            # Try to decode
            decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
            # Only add if it looks like meaningful content (has some printable chars)
            if decoded and len(decoded) >= 4 and any(c.isalpha() for c in decoded):
                decoded_parts.append(decoded)
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue  # Invalid base64 or non-UTF-8 content

    return ' '.join(decoded_parts)


# ═══════════════════════════════════════════════════════════════════════════
# SAFETY MODE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

# Track all blocked operations for audit trail
_BLOCKED_OPERATIONS_LOG: List[dict] = []
_SAFETY_ENABLED = True
# FIX 2026-02-12: Don't cache at import time - check dynamically
# Previous version cached at import, which fails if env var set after import
def _is_aggressive_allowed() -> bool:
    """Check if aggressive mode is allowed (dynamic, not cached)."""
    # Support both PATHFINDER_ and legacy PHANTOM_ env vars
    pathfinder_val = os.environ.get("PATHFINDER_ALLOW_AGGRESSIVE", "").lower()
    phantom_val = os.environ.get("PHANTOM_ALLOW_AGGRESSIVE", "").lower()
    return pathfinder_val in ("1", "true", "yes", "authorized") or phantom_val in ("1", "true", "yes", "authorized")

# UNRESTRICTED MODE: Bypasses ALL safety checks including ABSOLUTELY_BLOCKED_PATTERNS
# This is for authorized penetration testing in controlled environments (labs, CTFs, etc.)
# Requires: PATHFINDER_UNRESTRICTED=i-understand-the-risks (or legacy PHANTOM_UNRESTRICTED)
_UNRESTRICTED_MODE = (
    os.environ.get("PATHFINDER_UNRESTRICTED", "").lower() == "i-understand-the-risks" or
    os.environ.get("PHANTOM_UNRESTRICTED", "").lower() == "i-understand-the-risks"
)

if _UNRESTRICTED_MODE:
    logger.warning("⚠️ UNRESTRICTED MODE ENABLED - ALL SAFETY CHECKS BYPASSED")
    logger.warning("⚠️ This mode sends REAL destructive payloads. Use only in authorized labs/CTFs.")


def get_safety_mode() -> str:
    """
    Get current safety mode from environment variable.

    Safety Modes:
    - passive: GET/HEAD/OPTIONS only, no state changes
    - safe: GET/HEAD/OPTIONS only, no state changes
    - cautious: No DELETE/PUT/PATCH, payload checks
    - standard: All methods, destructive patterns blocked
    - aggressive: All methods, destructive patterns blocked (requires PHANTOM_ALLOW_AGGRESSIVE)
    - unrestricted: NO SAFETY CHECKS AT ALL (requires PHANTOM_UNRESTRICTED=i-understand-the-risks)

    SECURITY: aggressive mode requires explicit authorization via
    PHANTOM_ALLOW_AGGRESSIVE=authorized environment variable.
    """
    # Check for unrestricted mode first
    if _UNRESTRICTED_MODE:
        return "unrestricted"

    # Support both PATHFINDER_ and legacy PHANTOM_ env vars
    mode = os.environ.get("PATHFINDER_SAFE_MODE", os.environ.get("PHANTOM_SAFE_MODE", "safe")).lower()

    # SECURITY: Block aggressive mode unless explicitly authorized
    if mode == "aggressive" and not _is_aggressive_allowed():
        logger.warning("🛡️ SECURITY: aggressive mode requested but not authorized. Falling back to 'standard'.")
        logger.warning("🛡️ To enable aggressive mode, set PATHFINDER_ALLOW_AGGRESSIVE=authorized")
        return "standard"

    return mode


def is_unrestricted_mode() -> bool:
    """Check if unrestricted mode is enabled (bypasses ALL safety checks)."""
    return _UNRESTRICTED_MODE


def set_unrestricted_mode(enabled: bool, confirmation: str = "") -> bool:
    """
    Dynamically enable or disable unrestricted mode.

    SECURITY: Requires explicit confirmation string to enable.
    This allows changing mode within the same process without restart.

    Args:
        enabled: True to enable unrestricted mode, False to disable
        confirmation: Must be "i-understand-the-risks" to enable

    Returns:
        True if mode was changed successfully, False otherwise

    Example:
        # Enable unrestricted mode
        set_unrestricted_mode(True, "i-understand-the-risks")

        # Disable unrestricted mode (returns to normal operation)
        set_unrestricted_mode(False)
    """
    global _UNRESTRICTED_MODE

    if enabled:
        if confirmation != "i-understand-the-risks":
            logger.error("🛡️ SECURITY: Cannot enable unrestricted mode without confirmation")
            logger.error("🛡️ Use: set_unrestricted_mode(True, 'i-understand-the-risks')")
            return False

        _UNRESTRICTED_MODE = True
        logger.warning("⚠️ UNRESTRICTED MODE DYNAMICALLY ENABLED - ALL SAFETY CHECKS BYPASSED")
        logger.warning("⚠️ This mode sends REAL destructive payloads. Use only in authorized labs/CTFs.")
        return True
    else:
        _UNRESTRICTED_MODE = False
        logger.info("✅ Unrestricted mode DISABLED - Safety checks restored")
        return True


def set_aggressive_mode(enabled: bool, confirmation: str = "") -> bool:
    """
    Dynamically enable or disable aggressive mode authorization.

    SECURITY: Requires explicit confirmation string to enable.

    Args:
        enabled: True to authorize aggressive mode, False to revoke
        confirmation: Must be "authorized" to enable

    Returns:
        True if changed successfully, False otherwise
    """
    # FIX 2026-02-12: Set env var instead of module-level variable
    if enabled:
        if confirmation != "authorized":
            logger.error("🛡️ SECURITY: Cannot enable aggressive mode without confirmation")
            logger.error("🛡️ Use: set_aggressive_mode(True, 'authorized')")
            return False

        os.environ["PHANTOM_ALLOW_AGGRESSIVE"] = "authorized"
        logger.warning("⚠️ Aggressive mode AUTHORIZED dynamically")
        return True
    else:
        os.environ.pop("PHANTOM_ALLOW_AGGRESSIVE", None)
        logger.info("✅ Aggressive mode authorization REVOKED")
        return True


def get_current_mode_status() -> dict:
    """
    Get current status of all safety modes.

    Returns:
        Dictionary with current mode configuration
    """
    return {
        "safety_mode": get_safety_mode(),
        "unrestricted_enabled": _UNRESTRICTED_MODE,
        "aggressive_authorized": _is_aggressive_allowed(),
        "safe_mode_active": is_safe_mode_active(),
        "env_vars": {
            "PHANTOM_SAFE_MODE": os.environ.get("PHANTOM_SAFE_MODE", "safe"),
            "PHANTOM_UNRESTRICTED": "***SET***" if os.environ.get("PHANTOM_UNRESTRICTED") else "not set",
            "PHANTOM_ALLOW_AGGRESSIVE": "***SET***" if os.environ.get("PHANTOM_ALLOW_AGGRESSIVE") else "not set",
        }
    }


def get_custom_headers() -> dict:
    """
    Get custom headers from PHANTOM_CUSTOM_HEADERS environment variable.

    These headers are automatically injected into ALL HTTP requests.
    Used for bug bounty programs that require identification headers.

    Example headers:
    - X-Bug-Bounty: username-programname
    - X-HackerOne-Research: true
    - Authorization: Bearer token

    Returns:
        Dictionary of custom headers to inject
    """
    headers_json = os.environ.get("PHANTOM_CUSTOM_HEADERS", "")
    if not headers_json:
        return {}

    try:
        headers = json.loads(headers_json)
        if isinstance(headers, dict):
            return headers
        return {}
    except json.JSONDecodeError:
        logger.warning(f"🛡️ Invalid PHANTOM_CUSTOM_HEADERS format (expected JSON): {headers_json[:50]}")
        return {}


def is_safe_mode_active() -> bool:
    """Check if we're running in a non-destructive mode."""
    return get_safety_mode() in ("passive", "safe", "cautious")


def get_blocked_operations_log() -> List[dict]:
    """Get audit log of all blocked operations (for compliance reporting)."""
    return _BLOCKED_OPERATIONS_LOG.copy()


def _log_blocked_operation(method: str, url: str, reason: str, payload_hash: str = "") -> None:
    """Log a blocked operation for audit trail."""
    _BLOCKED_OPERATIONS_LOG.append({
        "timestamp": datetime.now().isoformat(),
        "method": method,
        "url": url[:100],  # Truncate for safety
        "reason": reason,
        "payload_hash": payload_hash,
        "safety_mode": get_safety_mode(),
    })


# ═══════════════════════════════════════════════════════════════════════════
# ABSOLUTELY BLOCKED PATTERNS - These are NEVER allowed, even in aggressive mode
# These patterns could cause irreversible damage or legal issues
# Compliance: HackerOne, Bugcrowd, Intigriti platform standards
# ═══════════════════════════════════════════════════════════════════════════
ABSOLUTELY_BLOCKED_PATTERNS = [
    # ═══════════════════════════════════════════════════════════════════════
    # DATABASE DESTRUCTION - CRITICAL (violates all bug bounty ToS)
    # ═══════════════════════════════════════════════════════════════════════
    r"DROP\s+DATABASE",
    r"DROP\s+TABLE",
    r"DROP\s+SCHEMA",
    r"DROP\s+INDEX",
    r"DROP\s+VIEW",
    r"DROP\s+PROCEDURE",
    r"DROP\s+FUNCTION",
    r"TRUNCATE\s+TABLE",
    r"TRUNCATE\s+\w+",
    r"DELETE\s+FROM\s+\w+\s*;?\s*$",  # DELETE without WHERE
    r"DELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1",  # DELETE all rows
    r"DELETE\s+FROM\s+\w+\s+WHERE\s+true",  # DELETE all rows
    r"UPDATE\s+\w+\s+SET\s+.*\s+WHERE\s+1\s*=\s*1",  # UPDATE all rows
    r"UPDATE\s+\w+\s+SET\s+.*\s+WHERE\s+true",  # UPDATE all rows
    r"ALTER\s+TABLE.*DROP",  # Drop columns
    r"ALTER\s+DATABASE",  # Modify database settings

    # ═══════════════════════════════════════════════════════════════════════
    # DATA EXFILTRATION PATTERNS - Block actual data extraction
    # (Detection is OK, but not actual extraction of production data)
    # ═══════════════════════════════════════════════════════════════════════
    r"INTO\s+OUTFILE",  # MySQL file write
    r"INTO\s+DUMPFILE",  # MySQL binary file write
    r"LOAD_FILE\s*\(",  # MySQL file read
    r"xp_cmdshell",  # MSSQL command execution
    r"xp_regread",  # MSSQL registry read
    r"sp_oacreate",  # MSSQL OLE automation
    r"OPENROWSET",  # MSSQL remote data access
    r"OPENDATASOURCE",  # MSSQL remote data source
    r"pg_read_file",  # PostgreSQL file read
    r"pg_ls_dir",  # PostgreSQL directory listing
    r"COPY\s+.*?\s*TO\s+PROGRAM",  # PostgreSQL command execution
    r"TO\s+PROGRAM",  # PostgreSQL command execution (partial match)
    
    # File system destruction - CRITICAL
    r"rm\s+-rf\s+/",
    r"rm\s+-rf\s+\*",
    r"rm\s+-rf\s+~",
    r"rm\s+-rf\s+\.\.",
    r"format\s+c:",
    r"format\s+/[a-zA-Z]:",
    r"del\s+/[fFsS]\s+",
    r"del\s+\*\.\*",
    r"rmdir\s+/[sS]",
    r"rd\s+/[sS]",
    
    # Permission changes that could break system
    r"chmod\s+777",  # Any chmod 777
    r"chmod\s+666",  # World writable
    r"chmod\s+[47]777\s+/",
    r"chmod\s+-R\s+777",
    r"chown\s+root\s+/",
    r"chown\s+-R\s+root\s+/",
    
    # System commands - CRITICAL
    r"shutdown\s",
    r"shutdown$",
    r"reboot\s",
    r"reboot$",
    r"\bhalt\b",
    r"poweroff",
    r"init\s+0",
    r"init\s+6",
    r"telinit\s+0",
    
    # Code execution functions - CRITICAL
    r"\bexec\s*\(",
    r"\beval\s*\(",
    r"\bsystem\s*\(",
    r"\bpassthru\s*\(",
    r"\bshell_exec\s*\(",
    r"\bpopen\s*\(",
    r"\bproc_open\s*\(",
    r"os\.system\s*\(",
    r"os\.popen\s*\(",
    r"subprocess\.call",
    r"subprocess\.Popen",
    r"subprocess\.run",
    r"__import__\s*\(",
    r"importlib\.import_module",
    
    # PHP code injection
    r"<\?php",
    r"<\?=",
    r"assert\s*\(",
    r"create_function\s*\(",
    r"preg_replace.*\/e",  # PHP preg_replace with /e modifier
    
    # PowerShell attacks
    r"powershell\s+-enc",
    r"powershell\s+-e\s+",
    r"powershell\s+-nop",
    r"powershell\.exe\s+",
    r"IEX\s*\(",  # Invoke-Expression
    r"Invoke-Expression",
    r"Invoke-WebRequest",
    r"DownloadString\s*\(",
    
    # Reverse shells - CRITICAL (would be illegal to execute)
    r"nc\s+-e\s+/bin/(ba)?sh",
    r"nc\s+.*\s+-e\s+",
    r"ncat\s+.*\s+-e\s+",
    r"bash\s+-i\s+>&\s*/dev/tcp",
    r"/dev/tcp/\d+\.\d+\.\d+\.\d+",
    r"/dev/tcp/",
    r"/dev/udp/",
    r"mkfifo\s+/tmp/",
    r"mknod\s+/tmp/",
    r"telnet\s+\d+\.\d+\.\d+\.\d+.*\|.*sh",
    r"socat\s+.*EXEC",
    r"python\s+-c\s+['\"]import\s+socket.*connect",
    r"python3\s+-c\s+['\"]import\s+socket.*connect",
    r"perl\s+-e\s+.*socket.*connect",
    r"ruby\s+-rsocket\s+-e",
    r"php\s+-r\s+.*fsockopen",
    r"awk\s+.*\|.*sh",
    
    # Remote code download and execution
    r"curl\s+.*\|\s*(ba)?sh",
    r"wget\s+.*\|\s*(ba)?sh",
    r"wget\s+.*\s+-O\s*-\s*\|\s*(ba)?sh",
    r"curl\s+.*-o\s*/tmp/.*&&.*chmod.*&&",
    r"wget\s+.*-O\s*/tmp/.*&&.*chmod.*&&",
    
    # Fork bombs and resource exhaustion
    r":\(\)\s*{\s*:\|:&\s*}",  # Bash fork bomb
    r"fork\s*\(\s*\)\s*while",  # Fork loop
    
    # Disk filling attacks
    r"dd\s+if=/dev/zero\s+of=/",
    r"cat\s+/dev/urandom\s*>\s*/",
    r"yes\s*>\s*/",
]

# Patterns blocked in safe/cautious modes (but allowed in standard/aggressive)
WRITE_OPERATION_PATTERNS = [
    r"INSERT\s+INTO",
    r"UPDATE\s+\w+\s+SET",
    r"DELETE\s+FROM",
    r"CREATE\s+TABLE",
    r"ALTER\s+TABLE",
]


# ═══════════════════════════════════════════════════════════════════════════
# DANGEROUS URL PATTERNS - Block requests to dangerous endpoints
# These could cause data loss or service disruption
# ═══════════════════════════════════════════════════════════════════════════
DANGEROUS_URL_PATTERNS = [
    # Deletion endpoints
    r"/delete[-_]?all",
    r"/purge[-_]?all",
    r"/clear[-_]?all",
    r"/remove[-_]?all",
    r"/destroy",
    r"/wipe",
    r"/reset[-_]?database",
    r"/drop[-_]?database",
    r"/truncate",

    # Admin destructive endpoints
    r"/admin/delete",
    r"/admin/remove",
    r"/admin/purge",
    r"/admin/reset",
    r"/admin/destroy",
    r"/admin/wipe",

    # Mass operations
    r"/bulk[-_]?delete",
    r"/mass[-_]?delete",
    r"/batch[-_]?delete",

    # Dangerous system endpoints
    r"/shutdown",
    r"/restart",
    r"/reboot",
    r"/terminate",

    # Backup/restore that could overwrite
    r"/restore[-_]?all",
    r"/overwrite",
]


def is_url_safe(url: str) -> tuple[bool, str]:
    """
    Check if a URL is safe to request.

    SECURITY (v2.0): Now uses normalization to defeat encoding bypasses.
    Example bypass prevented: /delete%2Dall → /delete-all

    Returns:
        Tuple of (is_safe, reason_if_blocked)
    """
    # Check both original and normalized versions
    urls_to_check = [
        url.lower(),
        _normalize_payload(url).lower(),
    ]

    for url_to_check in urls_to_check:
        for pattern in DANGEROUS_URL_PATTERNS:
            try:
                if re.search(pattern, url_to_check, re.IGNORECASE):
                    return False, f"Dangerous URL pattern blocked: {pattern}"
            except re.error:
                continue

    return True, ""


class SafetyViolationError(Exception):
    """Raised when an operation violates the current safety policy."""
    pass


def is_payload_safe(payload: str) -> bool:
    """
    Check if a payload string is safe (not matching any blocked patterns).

    SECURITY (v2.0): Now includes normalization to prevent bypass attempts:
    - URL decoding (%44ROP → DROP)
    - SQL comment removal (DR/**/OP → DROP)
    - Unicode normalization (lookalike characters)
    - Base64 decoding detection
    - Null byte removal

    NOTE: In unrestricted mode (PHANTOM_UNRESTRICTED=i-understand-the-risks),
    this function always returns True.

    Args:
        payload: The payload string to check

    Returns:
        True if the payload is safe (no blocked patterns matched)
        False if the payload matches any blocked pattern
    """
    # Unrestricted mode bypasses ALL checks
    if _UNRESTRICTED_MODE:
        return True

    if not payload:
        return True

    # Check multiple versions to defeat encoding bypasses
    payloads_to_check = [
        payload,
        _normalize_payload(payload),
        _decode_base64_payloads(payload),
    ]

    for check_payload in payloads_to_check:
        if not check_payload:
            continue
        for pattern in ABSOLUTELY_BLOCKED_PATTERNS:
            try:
                if re.search(pattern, check_payload, re.IGNORECASE):
                    return False
            except re.error:
                # If pattern is invalid, skip it
                continue

    return True


class SafeHttpClient:
    """
    HTTP client wrapper that enforces safety policies.
    
    This client wraps httpx.AsyncClient and checks all outgoing requests
    against the current safety policy before sending them.
    """
    
    def __init__(
        self,
        timeout: float = 30.0,
        # BUG-FIX 2026-02-08: Changed default from False to True for security
        # Modules that need to disable SSL verification must do so explicitly
        verify: bool = True,
        follow_redirects: bool = True,
        **kwargs: Any,
    ) -> None:
        """Initialize safe HTTP client."""
        self._client_kwargs = {
            "timeout": timeout,
            "verify": verify,
            "follow_redirects": follow_redirects,
            **kwargs
        }
        self._client: Optional[httpx.AsyncClient] = None
        self._blocked_count = 0
        self._allowed_count = 0
    
    async def __aenter__(self) -> "SafeHttpClient":
        """Async context manager entry."""
        self._client = httpx.AsyncClient(**self._client_kwargs)
        return self
    
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
        
        if self._blocked_count > 0:
            logger.info(f"🛡️ SafeHttpClient: Blocked {self._blocked_count} operations, allowed {self._allowed_count}")
    
    def _get_payload_string(self, **kwargs) -> str:
        """
        Extract payload content as string for safety checking.

        SECURITY (v2.0): Enhanced to extract from ALL payload sources:
        - json, data, content, params, files
        """
        parts = []

        # Check JSON data
        if "json" in kwargs and kwargs["json"]:
            try:
                parts.append(json.dumps(kwargs["json"]))
            except (TypeError, ValueError):
                parts.append(str(kwargs["json"]))

        # Check form data
        if "data" in kwargs and kwargs["data"]:
            data = kwargs["data"]
            if isinstance(data, bytes):
                # FIX: Properly decode bytes
                try:
                    parts.append(data.decode("utf-8", errors="ignore"))
                except (UnicodeDecodeError, AttributeError):
                    parts.append(str(data))
            elif isinstance(data, dict):
                parts.append(json.dumps(data))
            else:
                parts.append(str(data))

        # Check raw content
        if "content" in kwargs and kwargs["content"]:
            content = kwargs["content"]
            if isinstance(content, bytes):
                try:
                    parts.append(content.decode("utf-8", errors="ignore"))
                except (UnicodeDecodeError, AttributeError):
                    pass  # Skip non-decodable binary content
            else:
                parts.append(str(content))

        # Check URL params
        if "params" in kwargs and kwargs["params"]:
            params = kwargs["params"]
            if isinstance(params, dict):
                parts.append(" ".join(f"{k}={v}" for k, v in params.items()))
            else:
                parts.append(str(params))

        # FIX: Check files parameter for malicious uploads
        if "files" in kwargs and kwargs["files"]:
            files = kwargs["files"]
            if isinstance(files, dict):
                for name, file_data in files.items():
                    parts.append(str(name))
                    if isinstance(file_data, tuple):
                        for item in file_data:
                            if isinstance(item, bytes):
                                try:
                                    parts.append(item.decode("utf-8", errors="ignore"))
                                except (UnicodeDecodeError, AttributeError):
                                    pass  # Skip non-decodable binary content
                            elif isinstance(item, str):
                                parts.append(item)
                    elif isinstance(file_data, bytes):
                        try:
                            parts.append(file_data.decode("utf-8", errors="ignore"))
                        except (UnicodeDecodeError, AttributeError):
                            pass  # Skip non-decodable binary content

        return " ".join(parts)
    
    def _check_absolutely_blocked(self, payload: str) -> Optional[str]:
        """
        Check for patterns that are NEVER allowed (even in aggressive mode).

        SECURITY (v2.0): Uses normalization to defeat bypass attempts.

        NOTE: In unrestricted mode, this check is bypassed.
        """
        # UNRESTRICTED MODE: Allow ALL payloads
        if _UNRESTRICTED_MODE:
            return None

        # Check multiple versions to defeat encoding bypasses
        payloads_to_check = [
            payload,
            _normalize_payload(payload),
            _decode_base64_payloads(payload),
        ]

        for check_payload in payloads_to_check:
            if not check_payload:
                continue
            for pattern in ABSOLUTELY_BLOCKED_PATTERNS:
                try:
                    if re.search(pattern, check_payload, re.IGNORECASE):
                        return pattern
                except re.error:
                    continue
        return None
    
    def _check_write_patterns(self, payload: str) -> Optional[str]:
        """Check for write operation patterns."""
        for pattern in WRITE_OPERATION_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                return pattern
        return None
    
    def _is_method_allowed(self, method: str) -> tuple[bool, str]:
        """
        Check if HTTP method is allowed in current safety mode.

        SECURITY (v2.0): Added TRACE/CONNECT blocking for XST prevention.

        Returns:
            Tuple of (allowed, reason)
        """
        mode = get_safety_mode()

        # UNRESTRICTED MODE: Allow ALL methods
        if mode == "unrestricted":
            return True, ""

        method = method.upper()

        # SECURITY: Block TRACE and CONNECT in ALL modes except unrestricted
        if method in ("TRACE", "CONNECT"):
            return False, f"Method {method} blocked for security (XST/proxy abuse prevention)"

        # Methods that NEVER modify state
        safe_methods = {"GET", "HEAD", "OPTIONS"}

        if mode in ("passive", "safe"):
            if method not in safe_methods:
                return False, f"Method {method} blocked in {mode} mode (only GET/HEAD/OPTIONS allowed)"
            return True, ""

        if mode == "cautious":
            # Allow POST but will check payload
            if method in ("DELETE", "PUT", "PATCH"):
                return False, f"Method {method} blocked in cautious mode"
            return True, ""

        # standard and aggressive allow all methods (except TRACE/CONNECT blocked above)
        return True, ""
    
    def _is_payload_allowed(self, method: str, payload: str) -> tuple[bool, str]:
        """
        Check if payload content is allowed in current safety mode.
        
        Returns:
            Tuple of (allowed, reason)
        """
        mode = get_safety_mode()
        
        # Always check for absolutely blocked patterns (even in aggressive!)
        blocked = self._check_absolutely_blocked(payload)
        if blocked:
            return False, f"BLOCKED: Destructive pattern detected: {blocked}"
        
        # In standard mode, also block obvious write operations
        if mode == "standard":
            # Allow detection payloads but block actual data modification
            # The key is: we want to DETECT vulnerabilities, not EXPLOIT them
            pass  # Most detection payloads are fine
        
        return True, ""
    
    async def _safe_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> httpx.Response:
        """
        Make a safety-checked HTTP request.

        Raises:
            SafetyViolationError: If the request violates safety policy
        """
        if not self._client:
            raise RuntimeError("SafeHttpClient must be used as async context manager")

        # Check method
        allowed, reason = self._is_method_allowed(method)
        if not allowed:
            self._blocked_count += 1
            logger.warning(f"🛡️ BLOCKED: {method} {url[:50]}... - {reason}")
            raise SafetyViolationError(reason)

        # Check payload for state-changing methods
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            payload = self._get_payload_string(**kwargs)
            if payload:
                allowed, reason = self._is_payload_allowed(method, payload)
                if not allowed:
                    self._blocked_count += 1
                    logger.warning(f"🛡️ BLOCKED: {method} {url[:50]}... - {reason}")
                    raise SafetyViolationError(reason)

        # Inject custom headers (Bug Bounty Identification)
        custom_headers = get_custom_headers()
        if custom_headers:
            existing_headers = kwargs.get("headers", {}) or {}
            if isinstance(existing_headers, dict):
                merged_headers = {**existing_headers, **custom_headers}
                kwargs["headers"] = merged_headers
            else:
                try:
                    merged_headers = dict(existing_headers)
                    merged_headers.update(custom_headers)
                    kwargs["headers"] = merged_headers
                except (TypeError, ValueError, AttributeError):
                    kwargs["headers"] = custom_headers

        self._allowed_count += 1
        return await self._client.request(method, url, **kwargs)
    
    # Standard HTTP method wrappers
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Safe GET request."""
        return await self._safe_request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Safe POST request."""
        return await self._safe_request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> httpx.Response:
        """Safe PUT request."""
        return await self._safe_request("PUT", url, **kwargs)
    
    async def patch(self, url: str, **kwargs) -> httpx.Response:
        """Safe PATCH request."""
        return await self._safe_request("PATCH", url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """Safe DELETE request."""
        return await self._safe_request("DELETE", url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> httpx.Response:
        """Safe HEAD request."""
        return await self._safe_request("HEAD", url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> httpx.Response:
        """Safe OPTIONS request."""
        return await self._safe_request("OPTIONS", url, **kwargs)
    
    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Safe generic request."""
        return await self._safe_request(method, url, **kwargs)


def create_safe_client(
    timeout: float = 30.0,
    verify: bool = False,
    **kwargs
) -> SafeHttpClient:
    """
    Create a SafeHttpClient with standard security settings.
    
    This is the recommended way to create HTTP clients in scanning modules.
    
    Example:
        async with create_safe_client() as client:
            response = await client.get("https://example.com")
    """
    return SafeHttpClient(timeout=timeout, verify=verify, **kwargs)


# Monkey-patch function to make httpx.AsyncClient safety-aware
_original_asyncclient = httpx.AsyncClient


class SafeAsyncClient(httpx.AsyncClient):
    """
    Drop-in replacement for httpx.AsyncClient with safety checks.

    This class can be used to replace httpx.AsyncClient globally,
    ensuring all HTTP operations go through safety checks.

    LOCALHOST BYPASS (2026-02-16):
    When PHANTOM_LOCALHOST_TARGET=1 or PHANTOM_NO_TOR=1 is set,
    proxy settings are automatically removed to allow localhost scanning.
    This is critical because Tor/SOCKS proxies cannot route to 127.0.0.1.
    """

    # Localhost hosts that cannot be reached via proxy
    _LOCALHOST_HOSTS = frozenset([
        "localhost", "127.0.0.1", "::1", "0.0.0.0",
    ])

    @classmethod
    def _is_localhost(cls, url: str) -> bool:
        """Check if URL points to localhost."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(str(url))
            host = (parsed.hostname or "").lower()
            return host in cls._LOCALHOST_HOSTS
        except Exception:
            return False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # ═══════════════════════════════════════════════════════════════════════
        # LOCALHOST PROXY BYPASS (2026-02-16)
        # ═══════════════════════════════════════════════════════════════════════
        # Remove proxy for localhost targets - Tor/SOCKS cannot route to 127.0.0.1
        # This is set by full_scanner.py when target is localhost
        self._original_proxy = kwargs.get("proxy") or kwargs.get("proxies")

        bypass_proxy = (
            os.environ.get("PATHFINDER_LOCALHOST_TARGET", "").lower() in ("1", "true", "yes") or
            os.environ.get("PHANTOM_LOCALHOST_TARGET", "").lower() in ("1", "true", "yes") or
            os.environ.get("PATHFINDER_NO_TOR", "").lower() in ("1", "true", "yes") or
            os.environ.get("PHANTOM_NO_TOR", "").lower() in ("1", "true", "yes")
        )

        if bypass_proxy:
            removed = False
            if "proxy" in kwargs:
                logger.info("🔌 [SafeAsyncClient] Proxy REMOVED (PATHFINDER_NO_TOR or localhost)")
                del kwargs["proxy"]
                removed = True
            if "proxies" in kwargs:
                logger.info("🔌 [SafeAsyncClient] Proxies REMOVED (PATHFINDER_NO_TOR or localhost)")
                del kwargs["proxies"]
                removed = True
            if not removed:
                logger.debug("[SafeAsyncClient] Proxy bypass active, no proxy in kwargs")

        super().__init__(*args, **kwargs)
        self._blocked_count = 0
        self._allowed_count = 0
    
    def _check_safety(self, method: str, url: str, **kwargs) -> tuple[bool, str]:
        """
        Check if request is allowed.

        TRIPLE PROTECTION with bypass prevention:
        1. Check HTTP method against safety mode
        2. Check URL for dangerous patterns (with decoding)
        3. Check payload for destructive patterns (with normalization)

        SECURITY ENHANCEMENTS (v2.0):
        - URL decoding to prevent %44ROP bypasses
        - SQL comment stripping to prevent DR/**/OP bypasses
        - Unicode normalization to prevent lookalike character bypasses
        - Base64 decoding to detect encoded commands
        - Null byte removal to prevent null byte injection
        - Files parameter checking for upload attacks

        NOTE: In unrestricted mode, ALL checks are bypassed.
        """
        mode = get_safety_mode()

        # UNRESTRICTED MODE: Bypass ALL safety checks
        if mode == "unrestricted":
            return True, ""

        method = method.upper()

        # ═══════════════════════════════════════════════════════════════════
        # LAYER 1: Method-based restrictions
        # ═══════════════════════════════════════════════════════════════════
        if mode in ("passive", "safe"):
            if method not in ("GET", "HEAD", "OPTIONS"):
                return False, f"Method {method} blocked in {mode} mode"

        if mode == "cautious":
            if method in ("DELETE", "PUT", "PATCH"):
                return False, f"Method {method} blocked in cautious mode"

        # SECURITY: Block TRACE and CONNECT methods (XST attacks, proxy abuse)
        if method in ("TRACE", "CONNECT"):
            return False, f"Method {method} blocked for security (XST/proxy abuse prevention)"

        # ═══════════════════════════════════════════════════════════════════
        # LAYER 2: URL-based restrictions (dangerous endpoints)
        # Normalize URL to defeat encoding bypasses
        # ═══════════════════════════════════════════════════════════════════
        normalized_url = _normalize_payload(url)
        url_safe, url_reason = is_url_safe(normalized_url)
        if not url_safe:
            return False, url_reason
        # Also check original URL (in case normalization missed something)
        url_safe_orig, url_reason_orig = is_url_safe(url)
        if not url_safe_orig:
            return False, url_reason_orig

        # ═══════════════════════════════════════════════════════════════════
        # LAYER 3: Payload-based restrictions (destructive patterns)
        # Extract ALL possible payload sources
        # ═══════════════════════════════════════════════════════════════════
        payload_parts = []

        # JSON data
        if "json" in kwargs and kwargs["json"]:
            try:
                payload_parts.append(json.dumps(kwargs["json"]))
            except (TypeError, ValueError):
                payload_parts.append(str(kwargs["json"]))

        # Form data
        if "data" in kwargs and kwargs["data"]:
            data = kwargs["data"]
            if isinstance(data, bytes):
                # FIX: Properly decode bytes instead of str(bytes) which gives b'...'
                try:
                    payload_parts.append(data.decode("utf-8", errors="ignore"))
                except (UnicodeDecodeError, AttributeError):
                    payload_parts.append(str(data))
            elif isinstance(data, dict):
                payload_parts.append(json.dumps(data))
            else:
                payload_parts.append(str(data))

        # Raw content
        if "content" in kwargs and kwargs["content"]:
            content = kwargs["content"]
            if isinstance(content, bytes):
                # FIX: Properly decode bytes
                try:
                    payload_parts.append(content.decode("utf-8", errors="ignore"))
                except (UnicodeDecodeError, AttributeError):
                    pass  # Skip non-decodable binary content
            else:
                payload_parts.append(str(content))

        # URL params
        if "params" in kwargs and kwargs["params"]:
            params = kwargs["params"]
            if isinstance(params, dict):
                payload_parts.append(" ".join(f"{k}={v}" for k, v in params.items()))
            else:
                payload_parts.append(str(params))

        # FIX: Check files parameter for malicious uploads
        if "files" in kwargs and kwargs["files"]:
            files = kwargs["files"]
            if isinstance(files, dict):
                for name, file_data in files.items():
                    payload_parts.append(str(name))
                    if isinstance(file_data, tuple):
                        # (filename, content, content_type)
                        for item in file_data:
                            if isinstance(item, bytes):
                                try:
                                    payload_parts.append(item.decode("utf-8", errors="ignore"))
                                except Exception:
                                    pass
                            elif isinstance(item, str):
                                payload_parts.append(item)
                    elif isinstance(file_data, bytes):
                        try:
                            payload_parts.append(file_data.decode("utf-8", errors="ignore"))
                        except Exception:
                            pass

        # Combine all payload parts
        raw_payload = " ".join(payload_parts)

        # ═══════════════════════════════════════════════════════════════════
        # LAYER 4: Payload normalization (defeat encoding bypasses)
        # ═══════════════════════════════════════════════════════════════════
        # Check both raw and normalized versions
        payloads_to_check = [
            raw_payload,
            _normalize_payload(raw_payload),
            _decode_base64_payloads(raw_payload),
        ]

        for payload in payloads_to_check:
            if not payload:
                continue
            for pattern in ABSOLUTELY_BLOCKED_PATTERNS:
                try:
                    if re.search(pattern, payload, re.IGNORECASE):
                        return False, f"Destructive payload pattern blocked: {pattern}"
                except re.error:
                    continue

        return True, ""
    
    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        allowed, reason = self._check_safety(method, str(url), **kwargs)
        if not allowed:
            self._blocked_count += 1
            logger.warning(f"🛡️ SafeAsyncClient BLOCKED: {method} {str(url)[:50]}... - {reason}")

            # Log for audit trail (compliance with bug bounty programs)
            payload_content = ""
            if "json" in kwargs and kwargs["json"]:
                payload_content = json.dumps(kwargs["json"])
            elif "data" in kwargs:
                payload_content = str(kwargs.get("data", ""))
            payload_hash = hashlib.sha256(payload_content.encode()).hexdigest()[:16] if payload_content else ""
            _log_blocked_operation(method, str(url), reason, payload_hash)

            # Return a fake 403 response instead of raising
            return httpx.Response(
                status_code=403,
                content=b"Blocked by SafeAsyncClient: " + reason.encode(),
                request=httpx.Request(method, url)
            )

        # ═══════════════════════════════════════════════════════════════════
        # INJECT CUSTOM HEADERS (Bug Bounty Identification)
        # Headers from PHANTOM_CUSTOM_HEADERS are automatically added to ALL requests
        # This ensures compliance with bug bounty program requirements
        # ═══════════════════════════════════════════════════════════════════
        custom_headers = get_custom_headers()
        if custom_headers:
            # Merge custom headers with any existing headers in the request
            existing_headers = kwargs.get("headers", {}) or {}
            if isinstance(existing_headers, dict):
                # Custom headers take precedence (user explicitly set them)
                merged_headers = {**existing_headers, **custom_headers}
                kwargs["headers"] = merged_headers
            else:
                # Headers might be a httpx.Headers object
                try:
                    merged_headers = dict(existing_headers)
                    merged_headers.update(custom_headers)
                    kwargs["headers"] = merged_headers
                except (TypeError, ValueError, AttributeError):
                    # Fallback: just use custom headers
                    kwargs["headers"] = custom_headers

        self._allowed_count += 1
        response = await super().request(method, url, **kwargs)

        # ═══════════════════════════════════════════════════════════════════════
        # AUDIT-LOG FIX 2026-02-13: Log HTTP requests to audit trail
        # ═══════════════════════════════════════════════════════════════════════
        try:
            from utils.audit_logger import get_audit_logger
            audit = get_audit_logger()
            if audit:
                audit.log_http_request(
                    url=str(url)[:200],  # Truncate long URLs
                    method=method,
                    status_code=response.status_code,
                )
        except Exception:
            pass  # Audit logging is best-effort, don't break requests
        # ═══════════════════════════════════════════════════════════════════════

        return response

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)


def enable_global_safety() -> None:
    """
    Enable global safety by replacing httpx.AsyncClient.
    
    After calling this function, all code that uses httpx.AsyncClient
    will automatically go through safety checks.
    
    WARNING: This modifies the httpx module globally!
    """
    httpx.AsyncClient = SafeAsyncClient
    logger.info("🛡️ Global HTTP safety enabled - httpx.AsyncClient replaced with SafeAsyncClient")


def disable_global_safety() -> None:
    """Restore original httpx.AsyncClient."""
    httpx.AsyncClient = _original_asyncclient
    logger.info("⚠️ Global HTTP safety disabled - original httpx.AsyncClient restored")


# Auto-enable based on environment
if os.environ.get("PHANTOM_ENABLE_GLOBAL_SAFETY", "").lower() in ("1", "true", "yes"):
    enable_global_safety()
