"""
WebAssembly Security Scanner - PHANTOM AI

Analyzes WebAssembly (.wasm) files for security issues:
1. Exported function analysis (dangerous patterns)
2. Hardcoded secrets detection
3. Memory safety concerns
4. Crypto misuse patterns
5. Eval-like dynamic execution

CWE Coverage:
- CWE-94: Improper Control of Generation of Code
- CWE-798: Use of Hard-coded Credentials
- CWE-327: Use of Broken or Risky Cryptographic Algorithm
- CWE-119: Improper Restriction of Operations within Memory Buffer

Author: PHANTOM AI Team
Version: 1.0.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from scanning.scan_context import ScanContext

logger = get_logger(__name__)


# =============================================================================
# WASM BINARY CONSTANTS
# =============================================================================

WASM_MAGIC = b'\x00asm'
WASM_VERSION = b'\x01\x00\x00\x00'

# Section IDs
SECTION_CUSTOM = 0
SECTION_TYPE = 1
SECTION_IMPORT = 2
SECTION_FUNCTION = 3
SECTION_TABLE = 4
SECTION_MEMORY = 5
SECTION_GLOBAL = 6
SECTION_EXPORT = 7
SECTION_START = 8
SECTION_ELEMENT = 9
SECTION_CODE = 10
SECTION_DATA = 11

# Export kinds
EXPORT_FUNC = 0
EXPORT_TABLE = 1
EXPORT_MEMORY = 2
EXPORT_GLOBAL = 3


# =============================================================================
# SECURITY PATTERNS
# =============================================================================

# Dangerous export name patterns
DANGEROUS_EXPORT_PATTERNS = [
    # Eval-like
    (r"eval|execute|run_code|exec|interpret", "CRITICAL", "Dynamic code execution export"),
    (r"compile|load_script|parse_code", "HIGH", "Code compilation export"),

    # Memory manipulation
    (r"free|malloc|alloc|realloc|dealloc", "MEDIUM", "Memory management export"),
    (r"memcpy|memmove|memset|strcpy|strcat", "MEDIUM", "Unsafe memory function export"),
    (r"buffer_overflow|stack_smash", "CRITICAL", "Obvious vulnerability indicator"),

    # Crypto operations
    (r"encrypt|decrypt|aes|des|rsa|ecdsa", "MEDIUM", "Cryptographic operation export"),
    (r"hash|md5|sha1|sha256|hmac", "LOW", "Hashing function export"),
    (r"key_gen|generate_key|derive_key", "HIGH", "Key generation export"),
    (r"sign|verify|signature", "MEDIUM", "Signature operation export"),

    # Sensitive operations
    (r"password|passwd|secret|credential", "HIGH", "Credential-related export"),
    (r"auth|authenticate|login|token", "MEDIUM", "Authentication export"),
    (r"admin|root|superuser|sudo", "HIGH", "Privileged operation export"),

    # File/system operations
    (r"file_read|file_write|open_file|read_file", "MEDIUM", "File operation export"),
    (r"system|shell|cmd|command|spawn", "CRITICAL", "System command export"),
    (r"network|socket|connect|send|recv", "MEDIUM", "Network operation export"),

    # Debug/internal
    (r"debug|trace|log_internal|dump", "LOW", "Debug function export"),
    (r"test_|_test|_debug|internal_", "LOW", "Internal function export"),
]

# Hardcoded secret patterns in data sections
SECRET_PATTERNS = [
    # API keys
    (r"['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]", "API key"),
    (r"['\"]?secret[_-]?key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]", "Secret key"),
    (r"['\"]?access[_-]?token['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]", "Access token"),

    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"[a-zA-Z0-9/+]{40}", "Potential AWS Secret Key"),

    # Private keys
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private key"),
    (r"-----BEGIN CERTIFICATE-----", "Certificate"),

    # JWT/tokens
    (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", "JWT token"),

    # Password patterns
    (r"password\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Hardcoded password"),
    (r"passwd\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Hardcoded password"),

    # Database connection strings
    (r"(?:mysql|postgres|mongodb)://[^\s'\"]+", "Database connection string"),
]

# Weak crypto indicators
WEAK_CRYPTO_PATTERNS = [
    (r"\bmd5\b", "MD5 (weak hash)"),
    (r"\bsha1\b", "SHA1 (weak hash)"),
    (r"\bdes\b", "DES (weak cipher)"),
    (r"\brc4\b", "RC4 (weak cipher)"),
    (r"\bblowfish\b", "Blowfish (deprecated)"),
]


# =============================================================================
# WASM PARSER
# =============================================================================

@dataclass
class WasmExport:
    """Represents a WASM export."""
    name: str
    kind: int  # 0=func, 1=table, 2=memory, 3=global
    index: int

    @property
    def kind_name(self) -> str:
        return {0: "function", 1: "table", 2: "memory", 3: "global"}.get(self.kind, "unknown")


@dataclass
class WasmImport:
    """Represents a WASM import."""
    module: str
    name: str
    kind: int
    index: int


@dataclass
class WasmAnalysis:
    """Results of WASM analysis."""
    valid: bool = False
    version: int = 0
    exports: list[WasmExport] = field(default_factory=list)
    imports: list[WasmImport] = field(default_factory=list)
    functions_count: int = 0
    memory_pages: int = 0
    data_segments: list[bytes] = field(default_factory=list)
    custom_sections: list[str] = field(default_factory=list)
    error: str = ""


class WasmParser:
    """Minimal WASM binary parser for security analysis."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def parse(self) -> WasmAnalysis:
        """Parse WASM binary and extract security-relevant information."""
        result = WasmAnalysis()

        try:
            # Check magic number
            if len(self.data) < 8:
                result.error = "File too small"
                return result

            if self.data[:4] != WASM_MAGIC:
                result.error = "Invalid WASM magic number"
                return result

            if self.data[4:8] != WASM_VERSION:
                result.error = f"Unsupported WASM version"
                return result

            result.valid = True
            result.version = 1
            self.pos = 8

            # Parse sections
            while self.pos < len(self.data):
                section_id = self._read_byte()
                section_size = self._read_leb128()

                if section_id is None or section_size is None:
                    break

                section_end = self.pos + section_size

                if section_id == SECTION_EXPORT:
                    result.exports = self._parse_exports(section_size)
                elif section_id == SECTION_IMPORT:
                    result.imports = self._parse_imports(section_size)
                elif section_id == SECTION_FUNCTION:
                    count = self._read_leb128() or 0
                    result.functions_count = count
                elif section_id == SECTION_MEMORY:
                    result.memory_pages = self._parse_memory()
                elif section_id == SECTION_DATA:
                    result.data_segments = self._parse_data_segments(section_size)
                elif section_id == SECTION_CUSTOM:
                    name = self._read_name()
                    if name:
                        result.custom_sections.append(name)

                self.pos = section_end

        except Exception as e:
            result.error = str(e)

        return result

    def _read_byte(self) -> Optional[int]:
        if self.pos >= len(self.data):
            return None
        b = self.data[self.pos]
        self.pos += 1
        return b

    def _read_leb128(self) -> Optional[int]:
        """Read LEB128 encoded unsigned integer."""
        result = 0
        shift = 0
        while True:
            b = self._read_byte()
            if b is None:
                return None
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
            if shift > 35:  # Prevent infinite loop
                return None
        return result

    def _read_name(self) -> Optional[str]:
        """Read length-prefixed name."""
        length = self._read_leb128()
        if length is None or self.pos + length > len(self.data):
            return None
        name = self.data[self.pos:self.pos + length]
        self.pos += length
        try:
            return name.decode('utf-8')
        except UnicodeDecodeError:
            return None

    def _parse_exports(self, section_size: int) -> list[WasmExport]:
        """Parse export section."""
        exports = []
        count = self._read_leb128()
        if count is None:
            return exports

        for _ in range(min(count, 1000)):  # Limit to prevent DoS
            name = self._read_name()
            kind = self._read_byte()
            index = self._read_leb128()

            if name is not None and kind is not None and index is not None:
                exports.append(WasmExport(name=name, kind=kind, index=index))

        return exports

    def _parse_imports(self, section_size: int) -> list[WasmImport]:
        """Parse import section."""
        imports = []
        count = self._read_leb128()
        if count is None:
            return imports

        for _ in range(min(count, 1000)):
            module = self._read_name()
            name = self._read_name()
            kind = self._read_byte()

            if module and name and kind is not None:
                # Skip the import descriptor (type index, etc.)
                if kind == 0:  # Function
                    self._read_leb128()  # type index
                elif kind == 1:  # Table
                    self._read_byte()  # elem type
                    self._parse_limits()
                elif kind == 2:  # Memory
                    self._parse_limits()
                elif kind == 3:  # Global
                    self._read_byte()  # value type
                    self._read_byte()  # mutability

                imports.append(WasmImport(
                    module=module, name=name, kind=kind, index=len(imports)
                ))

        return imports

    def _parse_limits(self) -> tuple[int, Optional[int]]:
        """Parse limits (min, max?)."""
        flags = self._read_byte() or 0
        min_val = self._read_leb128() or 0
        max_val = self._read_leb128() if flags & 1 else None
        return min_val, max_val

    def _parse_memory(self) -> int:
        """Parse memory section."""
        count = self._read_leb128()
        if not count:
            return 0
        min_pages, _ = self._parse_limits()
        return min_pages

    def _parse_data_segments(self, section_size: int) -> list[bytes]:
        """Parse data section for secrets analysis."""
        segments = []
        start_pos = self.pos
        count = self._read_leb128()
        if count is None:
            return segments

        for _ in range(min(count, 100)):  # Limit segments
            if self.pos >= start_pos + section_size:
                break

            # Skip memory index and offset expression
            mode = self._read_leb128()  # 0 = active, 1 = passive, 2 = active with memidx
            if mode in (0, 2):
                if mode == 2:
                    self._read_leb128()  # memidx
                # Skip offset expression (simplified: assume i32.const + end)
                while self.pos < len(self.data) and self.data[self.pos] != 0x0B:
                    self.pos += 1
                self.pos += 1  # Skip 0x0B (end)

            # Read data
            length = self._read_leb128()
            if length and self.pos + length <= len(self.data):
                segments.append(self.data[self.pos:self.pos + length])
                self.pos += length

        return segments


# =============================================================================
# WASM SCANNER MODULE
# =============================================================================

class WasmScanner(ScanModule):
    """WebAssembly Security Scanner."""

    name = "wasm_scanner"
    version = "1.0.0"

    # Common WASM paths
    WASM_PATHS = [
        "/static/app.wasm",
        "/static/main.wasm",
        "/assets/app.wasm",
        "/wasm/app.wasm",
        "/js/app.wasm",
        "/dist/app.wasm",
        "/build/app.wasm",
        "/pkg/app.wasm",  # wasm-pack default
        "/pkg/app_bg.wasm",  # wasm-pack bindgen
    ]

    def __init__(
        self,
        settings: Any,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = getattr(settings, 'request_timeout', 30)

    async def scan(
        self,
        target: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """
        Scan for WASM files and analyze them for security issues.

        Phases:
        1. Discover WASM files (from crawl data or common paths)
        2. Download and parse each WASM file
        3. Analyze exports for dangerous patterns
        4. Check data sections for hardcoded secrets
        5. Identify weak crypto usage
        """

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[dict] = []
        wasm_urls: set[str] = set()

        logger.info(f"[WASM] Starting scan of {target}")

        # Phase 1: Collect WASM URLs
        # From crawl data
        if isinstance(asset_data, dict):
            crawled_urls = asset_data.get("crawled_urls", [])
        for url in crawled_urls:
            if url.endswith(".wasm"):
                wasm_urls.add(url)

        # From script analysis (embedded WASM references)
        if isinstance(asset_data, dict):
            scripts = asset_data.get("scripts", [])
        for script in scripts:
            content = script.get("content", "")
            # Look for .wasm references
            for match in re.finditer(r'["\']([^"\']+\.wasm)["\']', content):
                wasm_path = match.group(1)
                if wasm_path.startswith("http"):
                    wasm_urls.add(wasm_path)
                else:
                    wasm_urls.add(urljoin(target, wasm_path))

        # Try common paths
        for path in self.WASM_PATHS:
            wasm_urls.add(urljoin(target, path))

        if not wasm_urls:
            logger.info("[WASM] No WASM files to scan")
            return {"findings": [], "info": []}

        # Phase 2: Analyze each WASM file
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            for wasm_url in wasm_urls:
                await rate_limiter.acquire()

                try:
                    response = await client.get(wasm_url)

                    # Check if it's actually WASM
                    if response.status_code != 200:
                        continue

                    content_type = response.headers.get("content-type", "")
                    if not (
                        "wasm" in content_type or
                        response.content[:4] == WASM_MAGIC
                    ):
                        continue

                    # Parse WASM
                    parser = WasmParser(response.content)
                    analysis = parser.parse()

                    if not analysis.valid:
                        logger.debug(f"[WASM] Invalid WASM at {wasm_url}: {analysis.error}")
                        continue

                    logger.info(
                        f"[WASM] Analyzing {wasm_url}: "
                        f"{len(analysis.exports)} exports, "
                        f"{analysis.functions_count} functions"
                    )

                    # Analyze exports
                    export_findings = self._analyze_exports(wasm_url, analysis)
                    findings.extend(export_findings)

                    # Analyze data sections for secrets
                    secret_findings = self._analyze_secrets(wasm_url, analysis)
                    findings.extend(secret_findings)

                    # Check for weak crypto
                    crypto_findings = self._analyze_crypto(wasm_url, analysis)
                    findings.extend(crypto_findings)

                except httpx.TimeoutException:
                    logger.debug(f"[WASM] Timeout fetching {wasm_url}")
                except Exception as e:
                    logger.debug(f"[WASM] Error analyzing {wasm_url}: {e}")

        logger.info(f"[WASM] Scan complete: {len(findings)} findings")
        return {"findings": findings}

    def _analyze_exports(
        self, wasm_url: str, analysis: WasmAnalysis
    ) -> list[dict]:
        """Analyze WASM exports for dangerous patterns."""
        findings = []

        for export in analysis.exports:
            if export.kind != EXPORT_FUNC:
                continue

            export_lower = export.name.lower()

            for pattern, severity, description in DANGEROUS_EXPORT_PATTERNS:
                if re.search(pattern, export_lower):
                    findings.append(Finding(
                        vuln_type=VulnType.OTHER,
                        name=f"WASM Dangerous Export: {export.name}",
                        severity=severity,
                        description=(
                            f"WebAssembly module exports a potentially dangerous function '{export.name}'. "
                            f"{description}. "
                            f"This could indicate unsafe operations accessible from JavaScript."
                        ),
                        host=urlparse(wasm_url).netloc,
                        endpoint=wasm_url,
                        evidence=[
                            f"Export name: {export.name}",
                            f"Export kind: {export.kind_name}",
                            f"Pattern matched: {pattern}",
                            f"WASM file: {wasm_url}",
                        ],
                        cvss_score={"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0}.get(severity, 5.0),
                        cwe_id="CWE-94" if "exec" in pattern else "CWE-676",
                        confidence_score=75,
                        remediation=(
                            "Review the WASM module for security implications. "
                            "Avoid exposing dangerous functions to JavaScript. "
                            "Use capability-based security to restrict WASM operations."
                        ),
                        metadata={
                            "module": "wasm_scanner",
                            "export_name": export.name,
                            "pattern": pattern,
                            "wasm_url": wasm_url,
                        },
                    ).to_dict())
                    break  # Only one finding per export

        return findings

    def _analyze_secrets(
        self, wasm_url: str, analysis: WasmAnalysis
    ) -> list[dict]:
        """Analyze WASM data sections for hardcoded secrets."""
        findings = []

        for segment in analysis.data_segments:
            # Convert to string for pattern matching
            try:
                text = segment.decode('utf-8', errors='ignore')
            except Exception:
                text = ""

            for pattern, secret_type in SECRET_PATTERNS:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches[:3]:  # Limit matches per pattern
                    # Redact the actual secret
                    redacted = match[:10] + "..." + match[-5:] if len(match) > 20 else match[:5] + "..."

                    findings.append(Finding(
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        name=f"WASM Hardcoded {secret_type}",
                        severity=Severity.HIGH,
                        description=(
                            f"WebAssembly module contains a hardcoded {secret_type}. "
                            f"Secrets embedded in WASM can be extracted by anyone with access "
                            f"to the file. This is a critical security issue."
                        ),
                        host=urlparse(wasm_url).netloc,
                        endpoint=wasm_url,
                        evidence=[
                            f"Secret type: {secret_type}",
                            f"Pattern: {pattern[:50]}...",
                            f"Sample (redacted): {redacted}",
                            f"WASM file: {wasm_url}",
                        ],
                        cvss_score=8.0,
                        cwe_id="CWE-798",
                        confidence_score=85,
                        remediation=(
                            "Remove hardcoded secrets from WASM modules. "
                            "Use environment variables or secure configuration management. "
                            "Rotate any exposed credentials immediately."
                        ),
                        metadata={
                            "module": "wasm_scanner",
                            "secret_type": secret_type,
                            "wasm_url": wasm_url,
                        },
                    ).to_dict())

        return findings

    def _analyze_crypto(
        self, wasm_url: str, analysis: WasmAnalysis
    ) -> list[dict]:
        """Analyze for weak cryptography usage."""
        findings = []
        weak_found = set()

        # Check export names
        for export in analysis.exports:
            export_lower = export.name.lower()
            for pattern, crypto_name in WEAK_CRYPTO_PATTERNS:
                if re.search(pattern, export_lower) and crypto_name not in weak_found:
                    weak_found.add(crypto_name)

        # Check data sections for crypto references
        for segment in analysis.data_segments:
            try:
                text = segment.decode('utf-8', errors='ignore').lower()
            except Exception:
                continue

            for pattern, crypto_name in WEAK_CRYPTO_PATTERNS:
                if re.search(pattern, text) and crypto_name not in weak_found:
                    weak_found.add(crypto_name)

        # Create findings for weak crypto
        for crypto_name in weak_found:
            findings.append(Finding(
                vuln_type=VulnType.OTHER,
                name=f"WASM Weak Cryptography: {crypto_name}",
                severity=Severity.MEDIUM,
                description=(
                    f"WebAssembly module appears to use {crypto_name}, which is considered "
                    f"cryptographically weak or deprecated. This could allow attackers to "
                    f"break encryption or forge signatures."
                ),
                host=urlparse(wasm_url).netloc,
                endpoint=wasm_url,
                evidence=[
                    f"Weak algorithm: {crypto_name}",
                    f"WASM file: {wasm_url}",
                ],
                cvss_score=5.3,
                cwe_id="CWE-327",
                confidence_score=70,
                remediation=(
                    f"Replace {crypto_name} with a stronger alternative. "
                    "Use SHA-256 or SHA-3 for hashing, AES-256-GCM for encryption. "
                    "Consult NIST guidelines for approved algorithms."
                ),
                metadata={
                    "module": "wasm_scanner",
                    "weak_crypto": crypto_name,
                    "wasm_url": wasm_url,
                },
            ).to_dict())

        return findings
