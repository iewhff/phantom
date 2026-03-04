"""
HTTP/3 (QUIC) Security Scanner for PHANTOM AI.

Tests for HTTP/3-specific vulnerabilities:
- 0-RTT replay attacks
- Connection migration abuse
- Stream multiplexing DoS
- Version downgrade attacks
- QUIC-specific header injection
- Alt-Svc hijacking

Version: 1.0.0
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from scanning.findings import Finding, Severity
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.http3_client import (
    HTTP3Client,
    HTTP3Status,
    HTTP3Response,
    is_http3_available,
    scan_quic_security,
)

logger = get_logger(__name__)

HTTP3_SCANNER_VERSION = "1.0.0"


class HTTP3VulnType(Enum):
    """HTTP/3 specific vulnerability types."""
    ZERO_RTT_REPLAY = "zero_rtt_replay"
    CONNECTION_MIGRATION = "connection_migration_abuse"
    STREAM_EXHAUSTION = "stream_exhaustion"
    VERSION_DOWNGRADE = "version_downgrade"
    ALT_SVC_HIJACK = "alt_svc_hijacking"
    HEADER_INJECTION = "h3_header_injection"
    PRIORITY_MANIPULATION = "priority_manipulation"
    SETTINGS_ABUSE = "settings_frame_abuse"
    GOAWAY_ABUSE = "goaway_flood"
    PUSH_PROMISE_ABUSE = "push_promise_abuse"


@dataclass
class HTTP3Finding:
    """HTTP/3 specific finding details."""
    vuln_type: HTTP3VulnType
    severity: str
    confidence: float
    evidence: dict[str, Any]
    quic_version: str | None = None
    stream_id: int | None = None
    recommendation: str = ""


@dataclass
class HTTP3ScanContext:
    """Context for HTTP/3 scanning session."""
    target_url: str
    host: str
    port: int
    quic_supported: bool = False
    quic_versions: list[str] = field(default_factory=list)
    h3_client: HTTP3Client | None = None
    initial_response: HTTP3Response | None = None


class HTTP3Scanner(ScanModule):
    """
    HTTP/3 (QUIC) Security Scanner.

    Detects and tests for vulnerabilities specific to HTTP/3 protocol:
    - 0-RTT early data replay risks
    - Connection migration exploits
    - Stream multiplexing attacks
    - Protocol downgrade vulnerabilities
    - Alt-Svc header manipulation
    """

    name = "http3_scanner"
    description = "HTTP/3 (QUIC) Protocol Security Scanner"
    version = HTTP3_SCANNER_VERSION
    category = "protocol"
    tags = ["http3", "quic", "protocol", "transport"]

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.findings: list[Finding] = []
        self.ctx: HTTP3ScanContext | None = None
        self._tested_endpoints: set[str] = set()

    async def scan(
        self,
        target_url: str,
        asset_data: dict | None = None,
        auth_context: Any | None = None,
    ) -> dict:
        """
        Perform HTTP/3 security scan.

        Args:
            target_url: Target URL to scan
            asset_data: Additional asset information
            auth_context: Authentication context

        Returns:
            Scan results dictionary
        """
        self.findings = []
        start_time = time.time()

        logger.info(f"[HTTP3] Starting HTTP/3 scan on {target_url}")

        # Check if HTTP/3 support is available
        if not is_http3_available():
            logger.warning("[HTTP3] aioquic not available - skipping HTTP/3 tests")
            return self._build_result(
                target_url,
                time.time() - start_time,
                skipped=True,
                skip_reason="aioquic library not installed",
            )

        # Initialize scan context
        parsed = urlparse(target_url)
        self.ctx = HTTP3ScanContext(
            target_url=target_url,
            host=parsed.hostname or "localhost",
            port=parsed.port or 443,
        )

        try:
            # Phase 1: Detect HTTP/3 support
            await self._phase_detect_http3()

            if not self.ctx.quic_supported:
                logger.info(f"[HTTP3] Target does not support HTTP/3")
                return self._build_result(
                    target_url,
                    time.time() - start_time,
                    http3_supported=False,
                )

            # Initialize HTTP/3 client
            self.ctx.h3_client = HTTP3Client(timeout=30.0)

            # Phase 2: Test 0-RTT vulnerabilities
            await self._phase_zero_rtt_tests()

            # Phase 3: Test connection migration
            await self._phase_connection_migration_tests()

            # Phase 4: Test stream multiplexing
            await self._phase_stream_multiplexing_tests()

            # Phase 5: Test version negotiation
            await self._phase_version_negotiation_tests()

            # Phase 6: Test Alt-Svc hijacking
            await self._phase_alt_svc_tests()

            # Phase 7: Test HTTP/3 header injection
            await self._phase_header_injection_tests()

            # Phase 8: Test priority manipulation
            await self._phase_priority_tests()

            # Phase 9: Test SETTINGS frame abuse
            await self._phase_settings_abuse_tests()

            # Cleanup
            if self.ctx.h3_client:
                await self.ctx.h3_client.close()

        except Exception as e:
            logger.error(f"[HTTP3] Scan error: {e}")

        elapsed = time.time() - start_time
        logger.info(f"[HTTP3] Scan complete: {len(self.findings)} findings in {elapsed:.2f}s")

        return self._build_result(target_url, elapsed)

    async def _phase_detect_http3(self):
        """Phase 1: Detect HTTP/3 support via Alt-Svc and QUIC probing."""
        logger.debug("[HTTP3] Phase 1: Detecting HTTP/3 support")

        # Check Alt-Svc header
        client = HTTP3Client()
        status, alt_svc = await client.check_http3_support(self.ctx.target_url)

        if status == HTTP3Status.AVAILABLE:
            self.ctx.quic_supported = True
            if alt_svc:
                self.ctx.quic_versions.append(alt_svc.protocol)
                logger.info(f"[HTTP3] HTTP/3 supported via Alt-Svc: {alt_svc.protocol}")

        # Deep QUIC scan
        quic_scan = await scan_quic_security(self.ctx.host, self.ctx.port)

        if quic_scan.quic_versions:
            self.ctx.quic_supported = True
            self.ctx.quic_versions.extend(quic_scan.quic_versions)
            logger.info(f"[HTTP3] QUIC versions detected: {quic_scan.quic_versions}")

            # Add findings from QUIC scan
            for vuln in quic_scan.vulnerabilities:
                if vuln.get("type") == "zero_rtt_replay":
                    self._add_finding(
                        vuln_type=HTTP3VulnType.ZERO_RTT_REPLAY,
                        severity=vuln.get("severity", "LOW"),
                        confidence=60.0,
                        evidence={
                            "quic_versions": quic_scan.quic_versions,
                            "message": vuln.get("message"),
                        },
                        recommendation=vuln.get("recommendation", ""),
                    )

    async def _phase_zero_rtt_tests(self):
        """Phase 2: Test 0-RTT early data vulnerabilities."""
        logger.debug("[HTTP3] Phase 2: Testing 0-RTT vulnerabilities")

        if not self.ctx.h3_client:
            return

        try:
            # Test 1: Send request with 0-RTT early data
            # First request establishes session
            response1 = await self.ctx.h3_client.get(self.ctx.target_url)

            if response1.protocol != "h3":
                logger.debug("[HTTP3] Not using HTTP/3, skipping 0-RTT tests")
                return

            # Second request with 0-RTT (if session resumption available)
            response2 = await self.ctx.h3_client.request(
                "GET",
                self.ctx.target_url,
                use_early_data=True,
            )

            if response2.early_data_accepted:
                # 0-RTT was accepted - potential replay risk
                self._add_finding(
                    vuln_type=HTTP3VulnType.ZERO_RTT_REPLAY,
                    severity=Severity.MEDIUM,
                    confidence=75.0,
                    evidence={
                        "early_data_accepted": True,
                        "response_status": response2.status_code,
                        "protocol": response2.protocol,
                    },
                    recommendation="Ensure 0-RTT requests are idempotent. "
                                   "Consider disabling 0-RTT for sensitive operations.",
                )

            # Test 2: Replay attack simulation
            # Try to replay same request data multiple times
            replay_count = 0
            for _ in range(3):
                try:
                    replay_resp = await self.ctx.h3_client.request(
                        "POST",
                        f"{self.ctx.target_url}/api/action",
                        headers={"Content-Type": "application/json"},
                        body=b'{"action":"test"}',
                        use_early_data=True,
                    )
                    if replay_resp.status_code in (200, 201):
                        replay_count += 1
                except Exception:
                    pass

            if replay_count >= 2:
                self._add_finding(
                    vuln_type=HTTP3VulnType.ZERO_RTT_REPLAY,
                    severity=Severity.HIGH,
                    confidence=80.0,
                    evidence={
                        "replay_success_count": replay_count,
                        "test_endpoint": "/api/action",
                    },
                    recommendation="Server accepts replayed 0-RTT requests. "
                                   "Implement anti-replay mechanisms for state-changing operations.",
                )

        except Exception as e:
            logger.debug(f"[HTTP3] 0-RTT test error: {e}")

    async def _phase_connection_migration_tests(self):
        """Phase 3: Test connection migration vulnerabilities."""
        logger.debug("[HTTP3] Phase 3: Testing connection migration")

        # Connection migration allows QUIC connections to survive IP changes
        # This can be abused for session hijacking or IP spoofing

        try:
            # Note: Full connection migration testing requires low-level QUIC access
            # We test for the presence of connection migration support

            if self.ctx.quic_supported:
                # Connection migration is a QUIC feature that can be abused
                self._add_finding(
                    vuln_type=HTTP3VulnType.CONNECTION_MIGRATION,
                    severity=Severity.INFO,
                    confidence=50.0,
                    evidence={
                        "quic_supported": True,
                        "quic_versions": self.ctx.quic_versions,
                    },
                    recommendation="Review connection migration policy. "
                                   "Consider binding sessions to connection IDs.",
                )

        except Exception as e:
            logger.debug(f"[HTTP3] Connection migration test error: {e}")

    async def _phase_stream_multiplexing_tests(self):
        """Phase 4: Test stream multiplexing vulnerabilities."""
        logger.debug("[HTTP3] Phase 4: Testing stream multiplexing")

        if not self.ctx.h3_client:
            return

        try:
            # Test 1: Open many concurrent streams
            # HTTP/3 allows many streams per connection - potential DoS vector

            tasks = []
            stream_count = 50  # Try to open 50 concurrent streams

            for i in range(stream_count):
                task = asyncio.create_task(
                    self.ctx.h3_client.get(
                        f"{self.ctx.target_url}?stream_test={i}"
                    )
                )
                tasks.append(task)

            # Wait with timeout
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=30.0,
                )

                successful = sum(1 for r in results if isinstance(r, HTTP3Response) and r.status_code < 500)

                if successful > 40:
                    # Server allowed many concurrent streams
                    self._add_finding(
                        vuln_type=HTTP3VulnType.STREAM_EXHAUSTION,
                        severity=Severity.LOW,
                        confidence=60.0,
                        evidence={
                            "streams_attempted": stream_count,
                            "streams_successful": successful,
                        },
                        recommendation="Configure MAX_CONCURRENT_STREAMS limit "
                                       "to prevent stream exhaustion attacks.",
                    )

            except asyncio.TimeoutError:
                logger.debug("[HTTP3] Stream test timed out")

        except Exception as e:
            logger.debug(f"[HTTP3] Stream multiplexing test error: {e}")

    async def _phase_version_negotiation_tests(self):
        """Phase 5: Test version negotiation vulnerabilities."""
        logger.debug("[HTTP3] Phase 5: Testing version negotiation")

        try:
            # Check for multiple QUIC versions
            if len(self.ctx.quic_versions) > 1:
                # Multiple versions = potential downgrade attack
                self._add_finding(
                    vuln_type=HTTP3VulnType.VERSION_DOWNGRADE,
                    severity=Severity.LOW,
                    confidence=55.0,
                    evidence={
                        "supported_versions": self.ctx.quic_versions,
                    },
                    recommendation="Consider limiting to latest QUIC version only "
                                   "to prevent version downgrade attacks.",
                )

            # Test if server negotiates older versions
            old_versions = ["h3-27", "h3-25", "h3-24"]
            for version in old_versions:
                if version in self.ctx.quic_versions:
                    self._add_finding(
                        vuln_type=HTTP3VulnType.VERSION_DOWNGRADE,
                        severity=Severity.MEDIUM,
                        confidence=70.0,
                        evidence={
                            "old_version_supported": version,
                            "all_versions": self.ctx.quic_versions,
                        },
                        recommendation=f"Disable support for deprecated QUIC version {version}.",
                    )

        except Exception as e:
            logger.debug(f"[HTTP3] Version negotiation test error: {e}")

    async def _phase_alt_svc_tests(self):
        """Phase 6: Test Alt-Svc header vulnerabilities."""
        logger.debug("[HTTP3] Phase 6: Testing Alt-Svc vulnerabilities")

        try:
            import httpx

            async with httpx.AsyncClient(http2=True, timeout=10.0) as client:
                response = await client.get(self.ctx.target_url)

                alt_svc = response.headers.get("alt-svc", "")

                if alt_svc:
                    # Test 1: Check for overly permissive Alt-Svc
                    if "*" in alt_svc or "0.0.0.0" in alt_svc:
                        self._add_finding(
                            vuln_type=HTTP3VulnType.ALT_SVC_HIJACK,
                            severity=Severity.HIGH,
                            confidence=85.0,
                            evidence={
                                "alt_svc_header": alt_svc,
                                "issue": "Wildcard or permissive Alt-Svc",
                            },
                            recommendation="Alt-Svc header should specify exact hosts, "
                                           "not wildcards.",
                        )

                    # Test 2: Check for long max-age (persistence attack)
                    if "ma=" in alt_svc:
                        try:
                            ma_value = int(alt_svc.split("ma=")[1].split(";")[0].split(",")[0])
                            if ma_value > 86400 * 30:  # > 30 days
                                self._add_finding(
                                    vuln_type=HTTP3VulnType.ALT_SVC_HIJACK,
                                    severity=Severity.LOW,
                                    confidence=50.0,
                                    evidence={
                                        "alt_svc_header": alt_svc,
                                        "max_age_seconds": ma_value,
                                        "max_age_days": ma_value / 86400,
                                    },
                                    recommendation="Consider reducing Alt-Svc max-age "
                                                   "to limit persistence attack window.",
                                )
                        except (ValueError, IndexError):
                            pass

                    # Test 3: Check for Alt-Svc pointing to different domain
                    parsed = urlparse(self.ctx.target_url)
                    original_host = parsed.hostname

                    for part in alt_svc.split(","):
                        if "=" in part:
                            _, value = part.split("=", 1)
                            value = value.strip().strip('"')
                            if value and not value.startswith(":"):
                                # Has explicit host
                                alt_host = value.split(":")[0]
                                if alt_host and alt_host != original_host:
                                    self._add_finding(
                                        vuln_type=HTTP3VulnType.ALT_SVC_HIJACK,
                                        severity=Severity.MEDIUM,
                                        confidence=70.0,
                                        evidence={
                                            "alt_svc_header": alt_svc,
                                            "original_host": original_host,
                                            "alt_host": alt_host,
                                        },
                                        recommendation="Alt-Svc points to different host. "
                                                       "Verify this is intentional.",
                                    )

        except Exception as e:
            logger.debug(f"[HTTP3] Alt-Svc test error: {e}")

    async def _phase_header_injection_tests(self):
        """Phase 7: Test HTTP/3 header injection vulnerabilities."""
        logger.debug("[HTTP3] Phase 7: Testing header injection")

        if not self.ctx.h3_client:
            return

        injection_payloads = [
            # Header injection via HPACK
            ("x-injected", "value\r\nX-Evil: injected"),
            ("x-null", "value\x00injected"),
            ("x-tab", "value\tinjected"),

            # Pseudo-header confusion
            (":path", "/admin"),
            (":authority", "evil.com"),
            (":scheme", "http"),

            # QPACK-specific
            ("x-huffman", "\xff\xff\xff"),
        ]

        for header_name, header_value in injection_payloads:
            try:
                response = await self.ctx.h3_client.get(
                    self.ctx.target_url,
                    headers={header_name: header_value},
                )

                # Check if injection was reflected or caused issues
                if header_name in response.headers:
                    self._add_finding(
                        vuln_type=HTTP3VulnType.HEADER_INJECTION,
                        severity=Severity.MEDIUM,
                        confidence=65.0,
                        evidence={
                            "injected_header": header_name,
                            "injected_value": header_value[:50],
                            "response_status": response.status_code,
                        },
                        recommendation="Server reflects custom headers. "
                                       "Validate header names and values strictly.",
                    )

                # Check for pseudo-header confusion
                if header_name.startswith(":") and response.status_code != 400:
                    self._add_finding(
                        vuln_type=HTTP3VulnType.HEADER_INJECTION,
                        severity=Severity.HIGH,
                        confidence=75.0,
                        evidence={
                            "pseudo_header": header_name,
                            "value": header_value,
                            "response_status": response.status_code,
                            "issue": "Server accepted custom pseudo-header",
                        },
                        recommendation="Reject requests with duplicate or custom pseudo-headers.",
                    )

            except Exception:
                # Error might indicate server rejected injection
                pass

    async def _phase_priority_tests(self):
        """Phase 8: Test HTTP/3 priority manipulation."""
        logger.debug("[HTTP3] Phase 8: Testing priority manipulation")

        if not self.ctx.h3_client:
            return

        try:
            # HTTP/3 uses urgency and incremental flags for priority
            # Test if server respects malicious priority hints

            # High urgency request (should be processed first)
            high_priority_resp = await self.ctx.h3_client.get(
                self.ctx.target_url,
                headers={"priority": "u=0, i"},  # Highest urgency, incremental
            )

            # Low urgency request
            low_priority_resp = await self.ctx.h3_client.get(
                self.ctx.target_url,
                headers={"priority": "u=7"},  # Lowest urgency
            )

            # Check if priority hints are processed
            if (high_priority_resp.rtt_ms and low_priority_resp.rtt_ms and
                    high_priority_resp.rtt_ms < low_priority_resp.rtt_ms * 0.5):
                self._add_finding(
                    vuln_type=HTTP3VulnType.PRIORITY_MANIPULATION,
                    severity=Severity.LOW,
                    confidence=55.0,
                    evidence={
                        "high_priority_rtt_ms": high_priority_resp.rtt_ms,
                        "low_priority_rtt_ms": low_priority_resp.rtt_ms,
                    },
                    recommendation="Client-specified priority significantly affects response time. "
                                   "Consider server-side priority limits.",
                )

        except Exception as e:
            logger.debug(f"[HTTP3] Priority test error: {e}")

    async def _phase_settings_abuse_tests(self):
        """Phase 9: Test SETTINGS frame abuse."""
        logger.debug("[HTTP3] Phase 9: Testing SETTINGS frame abuse")

        # Note: Full SETTINGS testing requires low-level QUIC/HTTP3 access
        # We test observable behaviors

        if not self.ctx.h3_client:
            return

        try:
            # Test with large request that might trigger flow control
            large_body = b"A" * 65536  # 64KB body

            response = await self.ctx.h3_client.post(
                f"{self.ctx.target_url}/upload",
                headers={"Content-Type": "application/octet-stream"},
                body=large_body,
            )

            # Check if server accepted large body without proper limits
            if response.status_code in (200, 201):
                self._add_finding(
                    vuln_type=HTTP3VulnType.SETTINGS_ABUSE,
                    severity=Severity.INFO,
                    confidence=45.0,
                    evidence={
                        "body_size": len(large_body),
                        "response_status": response.status_code,
                    },
                    recommendation="Verify MAX_FIELD_SECTION_SIZE and other "
                                   "SETTINGS parameters are appropriately limited.",
                )

        except Exception as e:
            logger.debug(f"[HTTP3] SETTINGS test error: {e}")

    def _add_finding(
        self,
        vuln_type: HTTP3VulnType,
        severity: str,
        confidence: float,
        evidence: dict,
        recommendation: str = "",
    ):
        """Add a finding to the results."""
        finding = Finding(
            name=f"HTTP/3 {vuln_type.value.replace('_', ' ').title()}",
            description=f"HTTP/3/QUIC protocol vulnerability: {vuln_type.value}",
            severity=severity,
            confidence=confidence,
            vuln_type=VulnType.OTHER,
            host=self.ctx.host if self.ctx else "",
            endpoint=self.ctx.target_url if self.ctx else "",
            evidence=[str(evidence)],
            metadata={
                "http3_vuln_type": vuln_type.value,
                "quic_versions": self.ctx.quic_versions if self.ctx else [],
                "evidence": evidence,
                "recommendation": recommendation,
                "cwe": self._get_cwe_for_vuln(vuln_type),
                "scanner": self.name,
                "scanner_version": self.version,
            },
        )
        self.findings.append(finding)
        logger.info(f"[HTTP3] Finding: {vuln_type.value} ({severity})")

    def _get_cwe_for_vuln(self, vuln_type: HTTP3VulnType) -> str:
        """Map vulnerability type to CWE."""
        cwe_map = {
            HTTP3VulnType.ZERO_RTT_REPLAY: "CWE-294",  # Authentication Bypass by Capture-replay
            HTTP3VulnType.CONNECTION_MIGRATION: "CWE-384",  # Session Fixation
            HTTP3VulnType.STREAM_EXHAUSTION: "CWE-400",  # Uncontrolled Resource Consumption
            HTTP3VulnType.VERSION_DOWNGRADE: "CWE-757",  # Selection of Less-Secure Algorithm
            HTTP3VulnType.ALT_SVC_HIJACK: "CWE-601",  # URL Redirection to Untrusted Site
            HTTP3VulnType.HEADER_INJECTION: "CWE-113",  # HTTP Response Splitting
            HTTP3VulnType.PRIORITY_MANIPULATION: "CWE-400",  # Resource Exhaustion
            HTTP3VulnType.SETTINGS_ABUSE: "CWE-400",  # Resource Exhaustion
            HTTP3VulnType.GOAWAY_ABUSE: "CWE-400",  # Resource Exhaustion
            HTTP3VulnType.PUSH_PROMISE_ABUSE: "CWE-441",  # Unintended Proxy or Intermediary
        }
        return cwe_map.get(vuln_type, "CWE-16")  # Configuration

    def _build_result(
        self,
        target_url: str,
        elapsed: float,
        skipped: bool = False,
        skip_reason: str = "",
        http3_supported: bool | None = None,
    ) -> dict:
        """Build scan result dictionary."""
        return {
            "scanner": self.name,
            "version": self.version,
            "target": target_url,
            "elapsed_seconds": elapsed,
            "findings": self.findings,
            "findings_count": len(self.findings),
            "skipped": skipped,
            "skip_reason": skip_reason,
            "http3_info": {
                "supported": http3_supported if http3_supported is not None else (
                    self.ctx.quic_supported if self.ctx else False
                ),
                "quic_versions": self.ctx.quic_versions if self.ctx else [],
                "aioquic_available": is_http3_available(),
            },
            "stats": self.ctx.h3_client.stats if self.ctx and self.ctx.h3_client else {},
        }


# ============================================================
# Convenience Functions
# ============================================================

async def quick_http3_scan(url: str) -> dict:
    """
    Quick HTTP/3 security scan of a URL.

    Returns:
        Scan results dictionary
    """
    scanner = HTTP3Scanner()
    return await scanner.scan(url)


async def check_http3_vulnerabilities(url: str) -> list[dict]:
    """
    Check for HTTP/3 vulnerabilities and return simplified results.

    Returns:
        List of vulnerability dictionaries
    """
    result = await quick_http3_scan(url)

    vulns = []
    for finding in result.get("findings", []):
        vulns.append({
            "type": finding.metadata.get("http3_vuln_type"),
            "severity": finding.severity,
            "confidence": finding.confidence,
            "cwe": finding.metadata.get("cwe"),
            "recommendation": finding.metadata.get("recommendation"),
        })

    return vulns


# ============================================================
# CLI Entry Point
# ============================================================

if __name__ == "__main__":
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python http3_scanner.py <url>")
            sys.exit(1)

        url = sys.argv[1]
        print(f"Scanning {url} for HTTP/3 vulnerabilities...")

        result = await quick_http3_scan(url)

        print(f"\nHTTP/3 Supported: {result['http3_info']['supported']}")
        print(f"QUIC Versions: {result['http3_info']['quic_versions']}")
        print(f"Findings: {result['findings_count']}")

        for finding in result["findings"]:
            print(f"\n[{finding.severity}] {finding.title}")
            print(f"  Confidence: {finding.confidence}%")
            print(f"  CWE: {finding.metadata.get('cwe')}")

    asyncio.run(main())
