"""
Benchmark Suite - Validate Against Known Vulnerable Targets.

Tests scanner modules against intentionally vulnerable applications
with known vulnerabilities to measure detection accuracy.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from utils.logger import get_logger
from validation.metrics import (
    FindingOutcome,
    FindingValidation,
    MetricsCollector,
    ModuleMetrics,
    ScanMetrics,
)

logger = get_logger(__name__)


class BenchmarkTarget(Enum):
    """Known vulnerable test targets."""
    DVWA = "dvwa"                           # Damn Vulnerable Web App
    JUICE_SHOP = "juice_shop"               # OWASP Juice Shop
    WEBGOAT = "webgoat"                     # OWASP WebGoat
    HACKTHEBOX = "hackthebox"               # HackTheBox machines
    VULNHUB = "vulnhub"                     # VulnHub VMs
    CUSTOM = "custom"                       # Custom test apps
    PORTSWIGGER = "portswigger"             # PortSwigger Labs
    OWASP_BENCHMARK = "owasp_benchmark"     # OWASP Benchmark Project


@dataclass
class KnownVulnerability:
    """A known vulnerability in a test target."""
    vuln_id: str
    target: BenchmarkTarget
    vuln_type: str
    location: str
    severity: str
    cwe_id: str | None = None
    description: str = ""
    detection_modules: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "vuln_id": self.vuln_id,
            "target": self.target.value,
            "vuln_type": self.vuln_type,
            "location": self.location,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "description": self.description,
            "detection_modules": self.detection_modules,
        }


@dataclass
class BenchmarkResult:
    """Result of a benchmark test."""
    benchmark_id: str
    target: BenchmarkTarget
    target_url: str
    started_at: datetime
    completed_at: datetime
    modules_tested: list[str]
    known_vulns: list[KnownVulnerability]
    found_vulns: list[dict]
    true_positives: list[str] = field(default_factory=list)    # Vuln IDs found correctly
    false_positives: list[dict] = field(default_factory=list)   # Findings that don't match known vulns
    false_negatives: list[str] = field(default_factory=list)    # Vuln IDs missed
    unverified_findings: list[dict] = field(default_factory=list)  # Findings we can't verify (target mismatch)
    target_validated: bool = True  # Whether target matches expected type
    
    @property
    def detection_rate(self) -> float:
        """Percentage of known vulns detected."""
        if not self.known_vulns:
            return 0.0
        return len(self.true_positives) / len(self.known_vulns)
    
    @property
    def precision(self) -> float:
        """TP / (TP + FP)"""
        total = len(self.true_positives) + len(self.false_positives)
        return len(self.true_positives) / total if total > 0 else 0.0
    
    @property
    def recall(self) -> float:
        """TP / (TP + FN)"""
        total = len(self.true_positives) + len(self.false_negatives)
        return len(self.true_positives) / total if total > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)
    
    @property
    def duration_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()
    
    def to_dict(self) -> dict:
        return {
            "benchmark_id": self.benchmark_id,
            "target": self.target.value,
            "target_url": self.target_url,
            "target_validated": self.target_validated,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 2),
            "modules_tested": self.modules_tested,
            "results": {
                "known_vulns": len(self.known_vulns),
                "found_vulns": len(self.found_vulns),
                "true_positives": len(self.true_positives),
                "false_positives": len(self.false_positives) if self.target_validated else 0,
                "false_negatives": len(self.false_negatives) if self.target_validated else 0,
                "unverified_findings": len(self.unverified_findings),
            },
            "metrics": {
                "detection_rate": round(self.detection_rate, 4) if self.target_validated else None,
                "precision": round(self.precision, 4) if self.target_validated else None,
                "recall": round(self.recall, 4) if self.target_validated else None,
                "f1_score": round(self.f1_score, 4) if self.target_validated else None,
                "note": None if self.target_validated else "Metrics unavailable - target doesn't match expected type",
            },
            "details": {
                "true_positives": self.true_positives,
                "false_negatives": self.false_negatives if self.target_validated else [],
                "unverified_findings_count": len(self.unverified_findings),
            },
        }


# Known vulnerabilities database for each benchmark target
BENCHMARK_VULNERABILITIES: dict[BenchmarkTarget, list[KnownVulnerability]] = {
    BenchmarkTarget.DVWA: [
        KnownVulnerability(
            vuln_id="DVWA-SQLI-001",
            target=BenchmarkTarget.DVWA,
            vuln_type="sql_injection",
            location="/vulnerabilities/sqli/",
            severity="HIGH",
            cwe_id="CWE-89",
            description="SQL Injection in user ID parameter",
            detection_modules=["sqli"],
        ),
        KnownVulnerability(
            vuln_id="DVWA-XSS-001",
            target=BenchmarkTarget.DVWA,
            vuln_type="xss_reflected",
            location="/vulnerabilities/xss_r/",
            severity="MEDIUM",
            cwe_id="CWE-79",
            description="Reflected XSS in name parameter",
            detection_modules=["xss"],
        ),
        KnownVulnerability(
            vuln_id="DVWA-XSS-002",
            target=BenchmarkTarget.DVWA,
            vuln_type="xss_stored",
            location="/vulnerabilities/xss_s/",
            severity="HIGH",
            cwe_id="CWE-79",
            description="Stored XSS in guestbook",
            detection_modules=["xss"],
        ),
        KnownVulnerability(
            vuln_id="DVWA-CMDI-001",
            target=BenchmarkTarget.DVWA,
            vuln_type="command_injection",
            location="/vulnerabilities/exec/",
            severity="CRITICAL",
            cwe_id="CWE-78",
            description="Command Injection in ping",
            detection_modules=["cmdi"],
        ),
        KnownVulnerability(
            vuln_id="DVWA-LFI-001",
            target=BenchmarkTarget.DVWA,
            vuln_type="lfi",
            location="/vulnerabilities/fi/",
            severity="HIGH",
            cwe_id="CWE-98",
            description="Local File Inclusion",
            detection_modules=["lfi"],
        ),
        KnownVulnerability(
            vuln_id="DVWA-UPLOAD-001",
            target=BenchmarkTarget.DVWA,
            vuln_type="file_upload",
            location="/vulnerabilities/upload/",
            severity="CRITICAL",
            cwe_id="CWE-434",
            description="Unrestricted File Upload",
            detection_modules=["dir", "cms"],
        ),
        KnownVulnerability(
            vuln_id="DVWA-CSRF-001",
            target=BenchmarkTarget.DVWA,
            vuln_type="csrf",
            location="/vulnerabilities/csrf/",
            severity="MEDIUM",
            cwe_id="CWE-352",
            description="Cross-Site Request Forgery",
            detection_modules=["csrf"],
        ),
        KnownVulnerability(
            vuln_id="DVWA-BRUTE-001",
            target=BenchmarkTarget.DVWA,
            vuln_type="brute_force",
            location="/vulnerabilities/brute/",
            severity="MEDIUM",
            cwe_id="CWE-307",
            description="Brute Force Login",
            detection_modules=["auth", "ratelimit"],
        ),
    ],
    BenchmarkTarget.JUICE_SHOP: [
        KnownVulnerability(
            vuln_id="JUICE-SQLI-001",
            target=BenchmarkTarget.JUICE_SHOP,
            vuln_type="sql_injection",
            location="/rest/products/search",
            severity="HIGH",
            cwe_id="CWE-89",
            description="SQL Injection in search",
            detection_modules=["sqli"],
        ),
        KnownVulnerability(
            vuln_id="JUICE-XSS-001",
            target=BenchmarkTarget.JUICE_SHOP,
            vuln_type="xss_dom",
            location="/#/search",
            severity="MEDIUM",
            cwe_id="CWE-79",
            description="DOM XSS in search",
            detection_modules=["xss"],
        ),
        KnownVulnerability(
            vuln_id="JUICE-IDOR-001",
            target=BenchmarkTarget.JUICE_SHOP,
            vuln_type="idor",
            location="/rest/basket/",
            severity="HIGH",
            cwe_id="CWE-639",
            description="IDOR in basket access",
            detection_modules=["authz", "api"],
        ),
        KnownVulnerability(
            vuln_id="JUICE-JWT-001",
            target=BenchmarkTarget.JUICE_SHOP,
            vuln_type="jwt_none_algorithm",
            location="/rest/user/login",
            severity="CRITICAL",
            cwe_id="CWE-347",
            description="JWT None Algorithm Bypass",
            detection_modules=["oauth", "auth"],
        ),
        KnownVulnerability(
            vuln_id="JUICE-XXE-001",
            target=BenchmarkTarget.JUICE_SHOP,
            vuln_type="xxe",
            location="/file-upload",
            severity="HIGH",
            cwe_id="CWE-611",
            description="XXE in file upload",
            detection_modules=["xxe"],
        ),
        KnownVulnerability(
            vuln_id="JUICE-NOSQL-001",
            target=BenchmarkTarget.JUICE_SHOP,
            vuln_type="nosql_injection",
            location="/rest/products/reviews",
            severity="HIGH",
            cwe_id="CWE-943",
            description="NoSQL Injection",
            detection_modules=["nosql"],
        ),
    ],
    BenchmarkTarget.WEBGOAT: [
        KnownVulnerability(
            vuln_id="WG-SQLI-001",
            target=BenchmarkTarget.WEBGOAT,
            vuln_type="sql_injection",
            location="/SqlInjection/attack5a",
            severity="HIGH",
            cwe_id="CWE-89",
            description="SQL Injection lesson",
            detection_modules=["sqli"],
        ),
        KnownVulnerability(
            vuln_id="WG-XXE-001",
            target=BenchmarkTarget.WEBGOAT,
            vuln_type="xxe",
            location="/xxe/simple",
            severity="HIGH",
            cwe_id="CWE-611",
            description="XXE lesson",
            detection_modules=["xxe"],
        ),
        KnownVulnerability(
            vuln_id="WG-DESER-001",
            target=BenchmarkTarget.WEBGOAT,
            vuln_type="deserialization",
            location="/InsecureDeserialization/task",
            severity="CRITICAL",
            cwe_id="CWE-502",
            description="Insecure Deserialization",
            detection_modules=["deser"],
        ),
        KnownVulnerability(
            vuln_id="WG-JWT-001",
            target=BenchmarkTarget.WEBGOAT,
            vuln_type="jwt_weak_secret",
            location="/JWT/decode",
            severity="HIGH",
            cwe_id="CWE-347",
            description="JWT Weak Secret",
            detection_modules=["oauth", "auth"],
        ),
    ],
    BenchmarkTarget.PORTSWIGGER: [
        KnownVulnerability(
            vuln_id="PS-SQLI-001",
            target=BenchmarkTarget.PORTSWIGGER,
            vuln_type="sql_injection",
            location="/filter?category=",
            severity="HIGH",
            cwe_id="CWE-89",
            description="SQL Injection in category filter",
            detection_modules=["sqli"],
        ),
        KnownVulnerability(
            vuln_id="PS-SSRF-001",
            target=BenchmarkTarget.PORTSWIGGER,
            vuln_type="ssrf",
            location="/product/stock",
            severity="HIGH",
            cwe_id="CWE-918",
            description="SSRF via stock check",
            detection_modules=["ssrf"],
        ),
        KnownVulnerability(
            vuln_id="PS-SSTI-001",
            target=BenchmarkTarget.PORTSWIGGER,
            vuln_type="ssti",
            location="/",
            severity="CRITICAL",
            cwe_id="CWE-94",
            description="Server-Side Template Injection",
            detection_modules=["ssti"],
        ),
        KnownVulnerability(
            vuln_id="PS-SMUGGLE-001",
            target=BenchmarkTarget.PORTSWIGGER,
            vuln_type="http_smuggling",
            location="/",
            severity="CRITICAL",
            cwe_id="CWE-444",
            description="HTTP Request Smuggling",
            detection_modules=["smuggling"],
        ),
        KnownVulnerability(
            vuln_id="PS-CACHE-001",
            target=BenchmarkTarget.PORTSWIGGER,
            vuln_type="cache_poisoning",
            location="/",
            severity="HIGH",
            cwe_id="CWE-349",
            description="Web Cache Poisoning",
            detection_modules=["cache"],
        ),
        KnownVulnerability(
            vuln_id="PS-PROTO-001",
            target=BenchmarkTarget.PORTSWIGGER,
            vuln_type="prototype_pollution",
            location="/",
            severity="HIGH",
            cwe_id="CWE-1321",
            description="Prototype Pollution",
            detection_modules=["prototype"],
        ),
    ],
}


class BenchmarkSuite:
    """
    Run comprehensive benchmarks against known vulnerable targets.
    
    Features:
    - Test against DVWA, Juice Shop, WebGoat, PortSwigger
    - Automatic vulnerability matching
    - Detailed precision/recall metrics
    - Per-module effectiveness scoring
    - Exportable reports
    """
    
    def __init__(self, metrics_collector: MetricsCollector | None = None):
        self.metrics = metrics_collector or MetricsCollector()
        self.results: list[BenchmarkResult] = []
        
    async def run_benchmark(
        self,
        target: BenchmarkTarget,
        target_url: str,
        modules: list[str] | None = None,
        skip_target_validation: bool = False,
    ) -> BenchmarkResult:
        """
        Run benchmark against a known vulnerable target.
        
        Args:
            target: Type of benchmark target
            target_url: URL of the running target
            modules: Specific modules to test (None = all)
            skip_target_validation: Skip checking if target matches expected type
            
        Returns:
            BenchmarkResult with detection metrics
        """
        logger.info(f"Starting benchmark against {target.value} at {target_url}")
        started_at = datetime.now()
        
        # Validate target type
        target_validated = True
        if not skip_target_validation:
            target_valid, target_warning = await self._validate_target_type(target, target_url)
            if not target_valid:
                target_validated = False
                logger.warning(f"⚠️  TARGET VALIDATION: {target_warning}")
                logger.warning(f"   The URL doesn't appear to be a {target.value} instance.")
                logger.warning(f"   Findings will be marked as 'unverified' instead of 'false positives'.")
                logger.warning(f"   Use --skip-validation to force benchmark anyway.")
        
        # Get known vulnerabilities for this target
        known_vulns = BENCHMARK_VULNERABILITIES.get(target, [])
        
        if not known_vulns:
            logger.warning(f"No known vulnerabilities defined for {target.value}")
        
        # Determine which modules to test
        if modules is None:
            modules = list(set(
                module
                for vuln in known_vulns
                for module in vuln.detection_modules
            ))
        
        # Import and run scanner
        from core.config_manager import get_settings
        from scanning.full_scanner import FullScanner
        
        settings = get_settings()
        scanner = FullScanner(settings=settings, safe_mode="safe")
        scan_result = await scanner.scan(target_url, modules=modules)
        
        completed_at = datetime.now()
        
        # Match findings to known vulnerabilities
        # Handle both dict and ScanResult object
        if hasattr(scan_result, 'findings'):
            found_vulns = scan_result.findings
        else:
            found_vulns = scan_result.get("findings", [])
        
        true_positives, unmatched_findings, false_negatives = self._match_findings(
            known_vulns, found_vulns
        )
        
        # If target wasn't validated, unmatched findings are "unverified" not "false positives"
        if target_validated:
            false_positives = unmatched_findings
            unverified_findings = []
        else:
            false_positives = []  # Can't claim FP if target doesn't match
            unverified_findings = unmatched_findings
            false_negatives = []  # Can't claim FN if target doesn't match
        
        result = BenchmarkResult(
            benchmark_id=f"BM-{target.value}-{started_at.strftime('%Y%m%d%H%M%S')}",
            target=target,
            target_url=target_url,
            started_at=started_at,
            completed_at=completed_at,
            modules_tested=modules,
            known_vulns=known_vulns,
            found_vulns=found_vulns,
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            unverified_findings=unverified_findings,
            target_validated=target_validated,
        )
        
        self.results.append(result)
        
        # Only update metrics if target was validated
        if target_validated:
            self._update_metrics(result)
        
        if target_validated:
            logger.info(
                f"Benchmark complete: {len(true_positives)}/{len(known_vulns)} detected "
                f"(precision={result.precision:.2f}, recall={result.recall:.2f})"
            )
        else:
            logger.info(
                f"Benchmark complete: {len(found_vulns)} findings (unverified - target mismatch)"
            )
        
        return result
    
    async def _validate_target_type(
        self,
        expected_target: BenchmarkTarget,
        target_url: str,
    ) -> tuple[bool, str]:
        """
        Validate that the target URL matches the expected target type.
        
        Returns:
            Tuple of (is_valid, warning_message)
        """
        import httpx
        
        # Fingerprints for each target type
        fingerprints = {
            BenchmarkTarget.DVWA: [
                "Damn Vulnerable Web Application",
                "DVWA",
                "/dvwa/",
                "vulnerabilities/sqli",
            ],
            BenchmarkTarget.JUICE_SHOP: [
                "OWASP Juice Shop",
                "juice-shop",
                "bkimminich",
                "/api/Challenges",
            ],
            BenchmarkTarget.WEBGOAT: [
                "WebGoat",
                "webgoat",
                "/WebGoat/",
            ],
            BenchmarkTarget.PORTSWIGGER: [
                "portswigger",
                "web-security-academy",
                "burp",
            ],
        }
        
        target_fingerprints = fingerprints.get(expected_target, [])
        if not target_fingerprints:
            return True, ""  # No fingerprints defined, assume valid
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                response = await client.get(target_url)
                content = response.text.lower()
                
                for fp in target_fingerprints:
                    if fp.lower() in content:
                        return True, ""
                
                return False, f"No {expected_target.value} fingerprints found in response"
        except Exception as e:
            return False, f"Could not validate target: {e}"
    
    def _match_findings(
        self,
        known_vulns: list[KnownVulnerability],
        found_vulns: list[dict],
    ) -> tuple[list[str], list[dict], list[str]]:
        """Match scanner findings to known vulnerabilities."""
        true_positives = []
        false_negatives = []
        matched_findings = set()
        
        for vuln in known_vulns:
            matched = False
            for i, finding in enumerate(found_vulns):
                if i in matched_findings:
                    continue
                
                # Check if finding matches known vulnerability
                if self._finding_matches_vuln(finding, vuln):
                    true_positives.append(vuln.vuln_id)
                    matched_findings.add(i)
                    matched = True
                    break
            
            if not matched:
                false_negatives.append(vuln.vuln_id)
        
        # Remaining findings are false positives
        false_positives = [
            found_vulns[i] for i in range(len(found_vulns))
            if i not in matched_findings
        ]
        
        return true_positives, false_positives, false_negatives
    
    def _finding_matches_vuln(
        self,
        finding: dict,
        vuln: KnownVulnerability,
    ) -> bool:
        """Check if a scanner finding matches a known vulnerability."""
        # Match by vulnerability type
        finding_type = finding.get("type", "").lower()
        vuln_type = vuln.vuln_type.lower()
        
        # Type aliases
        type_matches = {
            "sql_injection": ["sqli", "sql_injection", "sql injection"],
            "xss_reflected": ["xss", "xss_reflected", "reflected xss", "cross-site scripting"],
            "xss_stored": ["xss", "xss_stored", "stored xss", "persistent xss"],
            "xss_dom": ["xss", "xss_dom", "dom xss", "dom-based xss"],
            "command_injection": ["cmdi", "command_injection", "os command injection", "rce"],
            "lfi": ["lfi", "local file inclusion", "path traversal"],
            "xxe": ["xxe", "xml external entity"],
            "ssrf": ["ssrf", "server-side request forgery"],
            "ssti": ["ssti", "server-side template injection", "template injection"],
            "nosql_injection": ["nosql", "nosql_injection", "mongodb injection"],
            "deserialization": ["deser", "deserialization", "insecure deserialization"],
            "http_smuggling": ["smuggling", "http request smuggling", "request smuggling"],
            "cache_poisoning": ["cache", "cache poisoning", "web cache poisoning"],
            "prototype_pollution": ["prototype", "prototype pollution"],
            "jwt_none_algorithm": ["jwt", "jwt_bypass", "authentication bypass"],
            "jwt_weak_secret": ["jwt", "weak_secret", "authentication"],
            "idor": ["idor", "insecure direct object reference", "authorization"],
            "csrf": ["csrf", "cross-site request forgery"],
            "brute_force": ["brute", "brute_force", "rate limiting"],
            "file_upload": ["upload", "file_upload", "unrestricted upload"],
        }
        
        vuln_aliases = type_matches.get(vuln_type, [vuln_type])
        
        if any(alias in finding_type for alias in vuln_aliases):
            # Also check location if available
            finding_url = finding.get("url", finding.get("location", ""))
            if vuln.location in finding_url or not finding_url:
                return True
        
        return False
    
    def _update_metrics(self, result: BenchmarkResult) -> None:
        """Update metrics collector with benchmark results."""
        # Create validation records for each finding
        for vuln_id in result.true_positives:
            vuln = next(v for v in result.known_vulns if v.vuln_id == vuln_id)
            for module in vuln.detection_modules:
                validation = FindingValidation(
                    finding_id=vuln_id,
                    module=module,
                    vulnerability_type=vuln.vuln_type,
                    target=result.target_url,
                    outcome=FindingOutcome.TRUE_POSITIVE,
                    confidence=0.9,
                    verified_by="benchmark",
                )
                
                if module not in self.metrics.module_aggregates:
                    self.metrics.module_aggregates[module] = ModuleMetrics(module_name=module)
                self.metrics.module_aggregates[module].add_validation(validation)
        
        for vuln_id in result.false_negatives:
            vuln = next(v for v in result.known_vulns if v.vuln_id == vuln_id)
            for module in vuln.detection_modules:
                validation = FindingValidation(
                    finding_id=f"FN-{vuln_id}",
                    module=module,
                    vulnerability_type=vuln.vuln_type,
                    target=result.target_url,
                    outcome=FindingOutcome.FALSE_NEGATIVE,
                    confidence=0.0,
                    verified_by="benchmark",
                )
                
                if module not in self.metrics.module_aggregates:
                    self.metrics.module_aggregates[module] = ModuleMetrics(module_name=module)
                self.metrics.module_aggregates[module].add_validation(validation)
        
        for fp in result.false_positives:
            module = fp.get("module", "unknown")
            validation = FindingValidation(
                finding_id=f"FP-{id(fp)}",
                module=module,
                vulnerability_type=fp.get("type", "unknown"),
                target=result.target_url,
                outcome=FindingOutcome.FALSE_POSITIVE,
                confidence=fp.get("confidence", 0.5),
                verified_by="benchmark",
            )
            
            if module not in self.metrics.module_aggregates:
                self.metrics.module_aggregates[module] = ModuleMetrics(module_name=module)
            self.metrics.module_aggregates[module].add_validation(validation)
    
    def generate_report(self) -> dict:
        """Generate comprehensive benchmark report."""
        if not self.results:
            return {"status": "NO_BENCHMARKS_RUN"}
        
        total_known = sum(len(r.known_vulns) for r in self.results)
        total_found = sum(len(r.true_positives) for r in self.results)
        total_fp = sum(len(r.false_positives) for r in self.results)
        
        return {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "benchmarks_run": len(self.results),
                "total_known_vulns": total_known,
                "total_detected": total_found,
                "total_false_positives": total_fp,
                "overall_detection_rate": round(total_found / total_known, 4) if total_known > 0 else 0,
                "overall_precision": round(
                    total_found / (total_found + total_fp), 4
                ) if (total_found + total_fp) > 0 else 0,
            },
            "by_target": {
                r.target.value: r.to_dict() for r in self.results
            },
            "by_vulnerability_type": self._aggregate_by_vuln_type(),
            "module_effectiveness": self.metrics.get_framework_health(),
            "recommendations": self._generate_recommendations(),
        }
    
    def _aggregate_by_vuln_type(self) -> dict:
        """Aggregate detection rates by vulnerability type."""
        vuln_stats: dict[str, dict] = {}
        
        for result in self.results:
            for vuln in result.known_vulns:
                if vuln.vuln_type not in vuln_stats:
                    vuln_stats[vuln.vuln_type] = {"known": 0, "detected": 0}
                
                vuln_stats[vuln.vuln_type]["known"] += 1
                if vuln.vuln_id in result.true_positives:
                    vuln_stats[vuln.vuln_type]["detected"] += 1
        
        return {
            vuln_type: {
                **stats,
                "detection_rate": round(stats["detected"] / stats["known"], 4) if stats["known"] > 0 else 0,
            }
            for vuln_type, stats in vuln_stats.items()
        }
    
    def _generate_recommendations(self) -> list[str]:
        """Generate recommendations based on benchmark results."""
        recs = []
        
        by_type = self._aggregate_by_vuln_type()
        
        # Find low detection rates
        for vuln_type, stats in by_type.items():
            if stats["detection_rate"] < 0.5:
                recs.append(
                    f"⚠️ Low detection for {vuln_type}: {stats['detection_rate']*100:.0f}% - "
                    f"Review and improve {vuln_type} scanner signatures"
                )
        
        # Check for high FP modules
        for module, metrics in self.metrics.module_aggregates.items():
            if metrics.false_positive_rate > 0.3:
                recs.append(
                    f"🎯 High false positive rate in {module}: {metrics.false_positive_rate*100:.0f}% - "
                    f"Tighten detection rules"
                )
        
        if not recs:
            recs.append("✅ Framework performing well overall")
        
        return recs
    
    def save_report(self, filepath: str) -> None:
        """Save benchmark report to file."""
        report = self.generate_report()
        Path(filepath).write_text(json.dumps(report, indent=2))
        logger.info(f"Benchmark report saved to {filepath}")
