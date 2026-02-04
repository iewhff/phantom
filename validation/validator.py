"""
Module Validator - Validate Individual Scanner Modules.

Tests scanner modules against known test cases and measures accuracy.
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
from validation.metrics import FindingOutcome, FindingValidation, ModuleMetrics

logger = get_logger(__name__)


class ValidationStatus(Enum):
    """Status of a validation test."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class TestCase:
    """A test case for module validation."""
    test_id: str
    module: str
    description: str
    input_data: dict[str, Any]
    expected_outcome: FindingOutcome
    expected_findings: list[dict[str, Any]] = field(default_factory=list)
    timeout_seconds: int = 30
    tags: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "module": self.module,
            "description": self.description,
            "expected_outcome": self.expected_outcome.value,
            "expected_findings_count": len(self.expected_findings),
            "timeout_seconds": self.timeout_seconds,
            "tags": self.tags,
        }


@dataclass
class TestResult:
    """Result of running a test case."""
    test_case: TestCase
    status: ValidationStatus
    actual_findings: list[dict] = field(default_factory=list)
    execution_time_ms: float = 0
    error_message: str = ""
    notes: str = ""
    
    @property
    def is_success(self) -> bool:
        return self.status == ValidationStatus.PASSED
    
    def to_dict(self) -> dict:
        return {
            "test_id": self.test_case.test_id,
            "status": self.status.value,
            "expected_outcome": self.test_case.expected_outcome.value,
            "expected_findings": len(self.test_case.expected_findings),
            "actual_findings": len(self.actual_findings),
            "execution_time_ms": round(self.execution_time_ms, 2),
            "error_message": self.error_message,
            "notes": self.notes,
        }


@dataclass
class ValidationReport:
    """Report from validation run."""
    report_id: str
    started_at: datetime
    completed_at: datetime
    modules_tested: list[str]
    test_results: list[TestResult]
    module_metrics: dict[str, ModuleMetrics] = field(default_factory=dict)
    
    @property
    def total_tests(self) -> int:
        return len(self.test_results)
    
    @property
    def passed_tests(self) -> int:
        return sum(1 for r in self.test_results if r.status == ValidationStatus.PASSED)
    
    @property
    def failed_tests(self) -> int:
        return sum(1 for r in self.test_results if r.status == ValidationStatus.FAILED)
    
    @property
    def error_tests(self) -> int:
        return sum(1 for r in self.test_results if r.status == ValidationStatus.ERROR)
    
    @property
    def success_rate(self) -> float:
        return self.passed_tests / self.total_tests if self.total_tests > 0 else 0.0
    
    @property
    def duration_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()
    
    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 2),
            "summary": {
                "modules_tested": len(self.modules_tested),
                "total_tests": self.total_tests,
                "passed": self.passed_tests,
                "failed": self.failed_tests,
                "errors": self.error_tests,
                "success_rate": round(self.success_rate, 4),
            },
            "modules": self.modules_tested,
            "results": [r.to_dict() for r in self.test_results],
            "module_metrics": {k: v.to_dict() for k, v in self.module_metrics.items()},
        }


# Pre-defined test cases for each module
MODULE_TEST_CASES: dict[str, list[TestCase]] = {
    "sqli": [
        TestCase(
            test_id="SQLI-001",
            module="sqli",
            description="Detect basic SQL injection in login form",
            input_data={
                "url": "http://testphp.vulnweb.com/login.php",
                "method": "POST",
                "params": {"username": "admin' OR '1'='1", "password": "test"},
            },
            expected_outcome=FindingOutcome.TRUE_POSITIVE,
            expected_findings=[{"type": "sql_injection"}],
            tags=["basic", "authentication"],
        ),
        TestCase(
            test_id="SQLI-002",
            module="sqli",
            description="Detect UNION-based SQL injection",
            input_data={
                "url": "http://testphp.vulnweb.com/listproducts.php",
                "method": "GET",
                "params": {"cat": "1 UNION SELECT NULL,NULL,NULL--"},
            },
            expected_outcome=FindingOutcome.TRUE_POSITIVE,
            expected_findings=[{"type": "sql_injection", "subtype": "union"}],
            tags=["union", "data-extraction"],
        ),
        TestCase(
            test_id="SQLI-003",
            module="sqli",
            description="No false positive on safe input",
            input_data={
                "url": "http://testphp.vulnweb.com/listproducts.php",
                "method": "GET",
                "params": {"cat": "1"},
            },
            expected_outcome=FindingOutcome.TRUE_NEGATIVE,
            expected_findings=[],
            tags=["negative-test"],
        ),
    ],
    "xss": [
        TestCase(
            test_id="XSS-001",
            module="xss",
            description="Detect reflected XSS",
            input_data={
                "url": "http://testphp.vulnweb.com/search.php",
                "method": "GET",
                "params": {"test": "<script>alert(1)</script>"},
            },
            expected_outcome=FindingOutcome.TRUE_POSITIVE,
            expected_findings=[{"type": "xss", "subtype": "reflected"}],
            tags=["reflected", "basic"],
        ),
        TestCase(
            test_id="XSS-002",
            module="xss",
            description="Detect XSS with encoding bypass",
            input_data={
                "url": "http://testphp.vulnweb.com/search.php",
                "method": "GET",
                "params": {"test": "<img src=x onerror=alert(1)>"},
            },
            expected_outcome=FindingOutcome.TRUE_POSITIVE,
            expected_findings=[{"type": "xss", "subtype": "event-handler"}],
            tags=["event-handler", "img"],
        ),
    ],
    "headers": [
        TestCase(
            test_id="HEADERS-001",
            module="headers",
            description="Detect missing security headers",
            input_data={
                "url": "http://testphp.vulnweb.com/",
            },
            expected_outcome=FindingOutcome.TRUE_POSITIVE,
            expected_findings=[
                {"type": "missing_header", "header": "X-Content-Type-Options"},
                {"type": "missing_header", "header": "X-Frame-Options"},
            ],
            tags=["security-headers"],
        ),
    ],
    "ssl": [
        TestCase(
            test_id="SSL-001",
            module="ssl",
            description="Detect weak SSL configuration",
            input_data={
                "url": "https://ssl-test-weak.example.com/",
            },
            expected_outcome=FindingOutcome.TRUE_POSITIVE,
            expected_findings=[{"type": "weak_ssl", "issue": "old_tls_version"}],
            tags=["ssl", "tls"],
        ),
        TestCase(
            test_id="SSL-002",
            module="ssl",
            description="Pass on strong SSL configuration",
            input_data={
                "url": "https://www.google.com/",
            },
            expected_outcome=FindingOutcome.TRUE_NEGATIVE,
            expected_findings=[],
            tags=["ssl", "negative-test"],
        ),
    ],
    "cmdi": [
        TestCase(
            test_id="CMDI-001",
            module="cmdi",
            description="Detect command injection",
            input_data={
                "url": "http://vulnerable-app/ping",
                "method": "POST",
                "params": {"host": "127.0.0.1; id"},
            },
            expected_outcome=FindingOutcome.TRUE_POSITIVE,
            expected_findings=[{"type": "command_injection"}],
            tags=["os-command", "basic"],
        ),
    ],
    "xxe": [
        TestCase(
            test_id="XXE-001",
            module="xxe",
            description="Detect XXE vulnerability",
            input_data={
                "url": "http://vulnerable-app/api/xml",
                "method": "POST",
                "content_type": "application/xml",
                "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            },
            expected_outcome=FindingOutcome.TRUE_POSITIVE,
            expected_findings=[{"type": "xxe"}],
            tags=["xml", "external-entity"],
        ),
    ],
    "ssrf": [
        TestCase(
            test_id="SSRF-001",
            module="ssrf",
            description="Detect SSRF vulnerability",
            input_data={
                "url": "http://vulnerable-app/fetch",
                "method": "POST",
                "params": {"url": "http://169.254.169.254/latest/meta-data/"},
            },
            expected_outcome=FindingOutcome.TRUE_POSITIVE,
            expected_findings=[{"type": "ssrf", "target": "aws-metadata"}],
            tags=["ssrf", "cloud"],
        ),
    ],
}


class ModuleValidator:
    """
    Validate scanner modules against test cases.
    
    Features:
    - Run predefined test cases
    - Measure precision/recall per module
    - Generate validation reports
    - Track historical validation results
    """
    
    def __init__(self, storage_path: str = "data/validation"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.test_cases = MODULE_TEST_CASES
        self.results: list[ValidationReport] = []
    
    def add_test_case(self, test_case: TestCase) -> None:
        """Add a custom test case."""
        if test_case.module not in self.test_cases:
            self.test_cases[test_case.module] = []
        self.test_cases[test_case.module].append(test_case)
    
    async def validate_module(
        self,
        module_name: str,
        target_url: str | None = None,
    ) -> list[TestResult]:
        """
        Validate a single module against its test cases.
        
        Args:
            module_name: Name of the module to validate
            target_url: Override URL for tests
            
        Returns:
            List of test results
        """
        test_cases = self.test_cases.get(module_name, [])
        if not test_cases:
            logger.warning(f"No test cases defined for module: {module_name}")
            return []
        
        results = []
        for test_case in test_cases:
            result = await self._run_test_case(test_case, target_url)
            results.append(result)
        
        return results
    
    async def validate_all(
        self,
        modules: list[str] | None = None,
    ) -> ValidationReport:
        """
        Validate all modules (or specified list).
        
        Args:
            modules: List of modules to validate (None = all)
            
        Returns:
            ValidationReport with all results
        """
        started_at = datetime.now()
        
        if modules is None:
            modules = list(self.test_cases.keys())
        
        all_results = []
        module_metrics: dict[str, ModuleMetrics] = {}
        
        for module_name in modules:
            logger.info(f"Validating module: {module_name}")
            results = await self.validate_module(module_name)
            all_results.extend(results)
            
            # Calculate metrics for this module
            metrics = self._calculate_module_metrics(module_name, results)
            module_metrics[module_name] = metrics
        
        completed_at = datetime.now()
        
        report = ValidationReport(
            report_id=f"VAL-{started_at.strftime('%Y%m%d%H%M%S')}",
            started_at=started_at,
            completed_at=completed_at,
            modules_tested=modules,
            test_results=all_results,
            module_metrics=module_metrics,
        )
        
        self.results.append(report)
        self._save_report(report)
        
        return report
    
    async def _run_test_case(
        self,
        test_case: TestCase,
        target_url: str | None = None,
    ) -> TestResult:
        """Run a single test case."""
        start_time = time.time()
        
        try:
            # Load and run the module
            from core.config_manager import get_settings
            from scanning.full_scanner import FullScanner
            
            settings = get_settings()
            scanner = FullScanner(settings=settings, safe_mode="safe")
            url = target_url or test_case.input_data.get("url", "")
            
            # Run scan with timeout
            result = await asyncio.wait_for(
                scanner.scan(url, modules=[test_case.module]),
                timeout=test_case.timeout_seconds,
            )
            
            # Handle both dict and ScanResult object
            if hasattr(result, 'findings'):
                actual_findings = result.findings
            else:
                actual_findings = result.get("findings", [])
            
            execution_time = (time.time() - start_time) * 1000
            
            # Evaluate result
            status = self._evaluate_result(test_case, actual_findings)
            
            return TestResult(
                test_case=test_case,
                status=status,
                actual_findings=actual_findings,
                execution_time_ms=execution_time,
            )
            
        except asyncio.TimeoutError:
            return TestResult(
                test_case=test_case,
                status=ValidationStatus.ERROR,
                error_message=f"Timeout after {test_case.timeout_seconds}s",
                execution_time_ms=(time.time() - start_time) * 1000,
            )
        except Exception as e:
            return TestResult(
                test_case=test_case,
                status=ValidationStatus.ERROR,
                error_message=str(e),
                execution_time_ms=(time.time() - start_time) * 1000,
            )
    
    def _evaluate_result(
        self,
        test_case: TestCase,
        actual_findings: list[dict],
    ) -> ValidationStatus:
        """Evaluate if test passed or failed."""
        expected = test_case.expected_outcome
        
        if expected == FindingOutcome.TRUE_POSITIVE:
            # Should find vulnerabilities
            if actual_findings:
                # Check if expected types are found
                expected_types = {f.get("type") for f in test_case.expected_findings}
                actual_types = {f.get("type", "").lower() for f in actual_findings}
                
                if expected_types.issubset(actual_types) or actual_types:
                    return ValidationStatus.PASSED
            return ValidationStatus.FAILED
        
        elif expected == FindingOutcome.TRUE_NEGATIVE:
            # Should NOT find vulnerabilities
            if not actual_findings:
                return ValidationStatus.PASSED
            return ValidationStatus.FAILED
        
        elif expected == FindingOutcome.FALSE_POSITIVE:
            # Checking if scanner produces false positive
            if actual_findings:
                return ValidationStatus.PASSED  # Confirmed FP
            return ValidationStatus.FAILED  # No FP (good)
        
        elif expected == FindingOutcome.FALSE_NEGATIVE:
            # Checking if scanner misses known vuln
            if not actual_findings:
                return ValidationStatus.PASSED  # Confirmed FN
            return ValidationStatus.FAILED  # Found it (good)
        
        return ValidationStatus.ERROR
    
    def _calculate_module_metrics(
        self,
        module_name: str,
        results: list[TestResult],
    ) -> ModuleMetrics:
        """Calculate metrics for a module from test results."""
        metrics = ModuleMetrics(module_name=module_name)
        
        for result in results:
            test_case = result.test_case
            
            if result.status == ValidationStatus.PASSED:
                if test_case.expected_outcome == FindingOutcome.TRUE_POSITIVE:
                    metrics.true_positives += 1
                elif test_case.expected_outcome == FindingOutcome.TRUE_NEGATIVE:
                    metrics.true_negatives += 1
            elif result.status == ValidationStatus.FAILED:
                if test_case.expected_outcome == FindingOutcome.TRUE_POSITIVE:
                    metrics.false_negatives += 1  # Missed detection
                elif test_case.expected_outcome == FindingOutcome.TRUE_NEGATIVE:
                    metrics.false_positives += 1  # False alarm
            
            metrics.total_scans += 1
        
        # Calculate average execution time
        valid_times = [r.execution_time_ms for r in results if r.execution_time_ms > 0]
        if valid_times:
            metrics.avg_scan_time_ms = sum(valid_times) / len(valid_times)
        
        return metrics
    
    def _save_report(self, report: ValidationReport) -> None:
        """Save validation report to storage."""
        filepath = self.storage_path / f"{report.report_id}.json"
        filepath.write_text(json.dumps(report.to_dict(), indent=2))
        logger.info(f"Validation report saved to {filepath}")
    
    def get_module_status(self, module_name: str) -> dict:
        """Get current validation status for a module."""
        if not self.results:
            return {"status": "NOT_VALIDATED", "message": "No validation runs yet"}
        
        # Get latest report
        latest = self.results[-1]
        
        if module_name not in latest.module_metrics:
            return {"status": "NOT_TESTED", "message": f"Module {module_name} not in latest run"}
        
        metrics = latest.module_metrics[module_name]
        
        return {
            "status": "VALIDATED",
            "module": module_name,
            "metrics": metrics.to_dict(),
            "last_validated": latest.completed_at.isoformat(),
            "recommendation": self._get_recommendation(metrics),
        }
    
    def _get_recommendation(self, metrics: ModuleMetrics) -> str:
        """Get recommendation based on metrics."""
        if metrics.effectiveness_score >= 80:
            return "✅ Production ready"
        if metrics.effectiveness_score >= 60:
            return "🔶 Needs improvement - review detection rules"
        if metrics.false_positive_rate > 0.3:
            return "🎯 Too many false positives - tighten rules"
        if metrics.false_negative_rate > 0.3:
            return "🔍 Missing detections - add more signatures"
        return "🔴 Unreliable - major review needed"
    
    def generate_summary(self) -> dict:
        """Generate summary of all validation results."""
        if not self.results:
            return {"status": "NO_DATA", "message": "Run validation first"}
        
        latest = self.results[-1]
        
        return {
            "last_run": latest.completed_at.isoformat(),
            "summary": {
                "modules_tested": len(latest.modules_tested),
                "total_tests": latest.total_tests,
                "passed": latest.passed_tests,
                "failed": latest.failed_tests,
                "success_rate": f"{latest.success_rate * 100:.1f}%",
            },
            "module_grades": {
                name: metrics.grade
                for name, metrics in latest.module_metrics.items()
            },
            "needs_attention": [
                name for name, metrics in latest.module_metrics.items()
                if metrics.effectiveness_score < 70
            ],
            "production_ready": [
                name for name, metrics in latest.module_metrics.items()
                if metrics.effectiveness_score >= 80
            ],
        }
