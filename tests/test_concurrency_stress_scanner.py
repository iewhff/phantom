"""
Tests for scanning/modules/concurrency_stress_scanner.py

Covers:
- ConcurrencyTest dataclass (defaults, full creation)
- ConcurrencyResult dataclass (all fields, defaults)
- CONCURRENCY_TESTS constant list (count, entries, structure)
- ConcurrencyStressScanner class (name, identity, constants, init)
- ScanModule subclass verification
"""

import pytest
from dataclasses import fields as dc_fields

from scanning.modules.concurrency_stress_scanner import (
    ConcurrencyTest,
    ConcurrencyResult,
    CONCURRENCY_TESTS,
    ConcurrencyStressScanner,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# DATACLASS: ConcurrencyTest
# =============================================================================

class TestConcurrencyTest:
    def test_defaults(self):
        ct = ConcurrencyTest(
            name="Test",
            description="A test",
            concurrency_levels=[10],
        )
        assert ct.method == "GET"
        assert ct.requires_auth is False
        assert ct.severity_if_vulnerable == "HIGH"

    def test_full_creation(self):
        ct = ConcurrencyTest(
            name="Full Test",
            description="Full description",
            concurrency_levels=[5, 10, 20],
            method="POST",
            requires_auth=True,
            severity_if_vulnerable="CRITICAL",
        )
        assert ct.name == "Full Test"
        assert ct.description == "Full description"
        assert ct.concurrency_levels == [5, 10, 20]
        assert ct.method == "POST"
        assert ct.requires_auth is True
        assert ct.severity_if_vulnerable == "CRITICAL"

    def test_field_count(self):
        assert len(dc_fields(ConcurrencyTest)) == 6

    def test_concurrency_levels_is_list(self):
        ct = ConcurrencyTest(
            name="X",
            description="X",
            concurrency_levels=[1, 2, 3],
        )
        assert isinstance(ct.concurrency_levels, list)
        assert len(ct.concurrency_levels) == 3


# =============================================================================
# DATACLASS: ConcurrencyResult
# =============================================================================

class TestConcurrencyResult:
    def test_creation_all_fields(self):
        cr = ConcurrencyResult(
            concurrency_level=25,
            total_requests=50,
            successful_requests=45,
            failed_requests=5,
            total_time_ms=1200.0,
            avg_response_time_ms=24.0,
            min_response_time_ms=10.0,
            max_response_time_ms=150.0,
            p95_response_time_ms=120.0,
            unique_responses=2,
            rate_limited_count=3,
            error_count=5,
        )
        assert cr.concurrency_level == 25
        assert cr.total_requests == 50
        assert cr.successful_requests == 45
        assert cr.failed_requests == 5
        assert cr.total_time_ms == 1200.0
        assert cr.avg_response_time_ms == 24.0
        assert cr.min_response_time_ms == 10.0
        assert cr.max_response_time_ms == 150.0
        assert cr.p95_response_time_ms == 120.0
        assert cr.unique_responses == 2
        assert cr.rate_limited_count == 3
        assert cr.error_count == 5

    def test_default_responses_hash_distribution(self):
        cr = ConcurrencyResult(
            concurrency_level=1,
            total_requests=5,
            successful_requests=5,
            failed_requests=0,
            total_time_ms=100.0,
            avg_response_time_ms=20.0,
            min_response_time_ms=15.0,
            max_response_time_ms=30.0,
            p95_response_time_ms=28.0,
            unique_responses=1,
            rate_limited_count=0,
            error_count=0,
        )
        assert cr.responses_hash_distribution == {}
        assert isinstance(cr.responses_hash_distribution, dict)

    def test_custom_hash_distribution(self):
        cr = ConcurrencyResult(
            concurrency_level=10,
            total_requests=20,
            successful_requests=20,
            failed_requests=0,
            total_time_ms=500.0,
            avg_response_time_ms=25.0,
            min_response_time_ms=10.0,
            max_response_time_ms=80.0,
            p95_response_time_ms=70.0,
            unique_responses=3,
            rate_limited_count=0,
            error_count=0,
            responses_hash_distribution={"abc123": 15, "def456": 3, "ghi789": 2},
        )
        assert len(cr.responses_hash_distribution) == 3
        assert cr.responses_hash_distribution["abc123"] == 15

    def test_field_count(self):
        assert len(dc_fields(ConcurrencyResult)) == 13


# =============================================================================
# CONCURRENCY_TESTS CONSTANT LIST
# =============================================================================

class TestConcurrencyTestsList:
    def test_count(self):
        assert len(CONCURRENCY_TESTS) == 4

    def test_all_are_concurrency_test_instances(self):
        for ct in CONCURRENCY_TESTS:
            assert isinstance(ct, ConcurrencyTest)

    def test_rate_limit_bypass(self):
        ct = CONCURRENCY_TESTS[0]
        assert ct.name == "Rate Limit Bypass via Concurrency"
        assert ct.concurrency_levels == [10, 25, 50]
        assert ct.method == "GET"
        assert ct.requires_auth is False
        assert ct.severity_if_vulnerable == "HIGH"

    def test_connection_pool_exhaustion(self):
        ct = CONCURRENCY_TESTS[1]
        assert ct.name == "Connection Pool Exhaustion"
        assert ct.concurrency_levels == [20, 50]
        assert ct.severity_if_vulnerable == "HIGH"

    def test_state_desynchronization(self):
        ct = CONCURRENCY_TESTS[2]
        assert ct.name == "State Desynchronization"
        assert ct.concurrency_levels == [10, 25]
        assert ct.severity_if_vulnerable == "MEDIUM"

    def test_response_time_degradation(self):
        ct = CONCURRENCY_TESTS[3]
        assert ct.name == "Response Time Degradation"
        assert ct.concurrency_levels == [10, 25, 50]
        assert ct.severity_if_vulnerable == "MEDIUM"

    def test_all_have_descriptions(self):
        for ct in CONCURRENCY_TESTS:
            assert ct.description, f"Missing description for {ct.name}"
            assert len(ct.description) > 10

    def test_all_have_concurrency_levels(self):
        for ct in CONCURRENCY_TESTS:
            assert len(ct.concurrency_levels) >= 1, f"Empty concurrency_levels for {ct.name}"
            for level in ct.concurrency_levels:
                assert isinstance(level, int)
                assert level > 0

    def test_names_are_unique(self):
        names = [ct.name for ct in CONCURRENCY_TESTS]
        assert len(names) == len(set(names))

    def test_severity_values_valid(self):
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for ct in CONCURRENCY_TESTS:
            assert ct.severity_if_vulnerable in valid_severities, (
                f"Invalid severity '{ct.severity_if_vulnerable}' for {ct.name}"
            )

    def test_methods_valid(self):
        valid_methods = {"GET", "POST", "PUT", "PATCH", "DELETE"}
        for ct in CONCURRENCY_TESTS:
            assert ct.method in valid_methods, (
                f"Invalid method '{ct.method}' for {ct.name}"
            )


# =============================================================================
# SCANNER CLASS IDENTITY & CONSTANTS
# =============================================================================

class TestConcurrencyStressScannerIdentity:
    def test_name_attribute(self):
        assert ConcurrencyStressScanner.name == "concurrency_stress"

    def test_description_attribute(self):
        assert ConcurrencyStressScanner.description is not None
        assert len(ConcurrencyStressScanner.description) > 10

    def test_version_attribute(self):
        assert ConcurrencyStressScanner.version == "1.0.0"

    def test_author_attribute(self):
        assert ConcurrencyStressScanner.author == "PHANTOM AI"

    def test_tags_attribute(self):
        tags = ConcurrencyStressScanner.tags
        assert isinstance(tags, list)
        assert "concurrency" in tags
        assert "stress" in tags
        assert "race" in tags
        assert "rate_limit" in tags
        assert len(tags) == 4

    def test_min_safety_level(self):
        assert ConcurrencyStressScanner.min_safety_level == "standard"

    def test_is_scan_module_subclass(self):
        assert issubclass(ConcurrencyStressScanner, ScanModule)

    def test_has_scan_method(self):
        assert hasattr(ConcurrencyStressScanner, "scan")
        assert callable(getattr(ConcurrencyStressScanner, "scan"))


# =============================================================================
# SCANNER INSTANCE DEFAULTS
# =============================================================================

class TestConcurrencyStressScannerInit:
    def test_default_init(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ConcurrencyStressScanner(settings=settings)
        assert scanner.timeout == 15.0
        assert scanner.max_concurrency == 50
        assert scanner.requests_per_test == 100
        assert scanner._auth_headers == {}

    def test_timeout_value(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ConcurrencyStressScanner(settings=settings)
        assert isinstance(scanner.timeout, float)
        assert scanner.timeout > 0

    def test_max_concurrency_value(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ConcurrencyStressScanner(settings=settings)
        assert isinstance(scanner.max_concurrency, int)
        assert scanner.max_concurrency == 50

    def test_requests_per_test_value(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ConcurrencyStressScanner(settings=settings)
        assert isinstance(scanner.requests_per_test, int)
        assert scanner.requests_per_test == 100

    def test_auth_headers_empty_on_init(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ConcurrencyStressScanner(settings=settings)
        assert scanner._auth_headers == {}
        assert isinstance(scanner._auth_headers, dict)

    def test_instance_is_scan_module(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner = ConcurrencyStressScanner(settings=settings)
        assert isinstance(scanner, ScanModule)


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_concurrency_result_zero_values(self):
        cr = ConcurrencyResult(
            concurrency_level=0,
            total_requests=0,
            successful_requests=0,
            failed_requests=0,
            total_time_ms=0.0,
            avg_response_time_ms=0.0,
            min_response_time_ms=0.0,
            max_response_time_ms=0.0,
            p95_response_time_ms=0.0,
            unique_responses=0,
            rate_limited_count=0,
            error_count=0,
        )
        assert cr.total_requests == 0
        assert cr.responses_hash_distribution == {}

    def test_concurrency_test_single_level(self):
        ct = ConcurrencyTest(
            name="Minimal",
            description="Minimal test",
            concurrency_levels=[1],
        )
        assert len(ct.concurrency_levels) == 1
        assert ct.concurrency_levels[0] == 1

    def test_concurrency_tests_all_concurrency_levels_sorted(self):
        """Each test scenario should have concurrency levels in ascending order."""
        for ct in CONCURRENCY_TESTS:
            assert ct.concurrency_levels == sorted(ct.concurrency_levels), (
                f"Concurrency levels not sorted for {ct.name}"
            )

    def test_multiple_scanner_instances_independent(self):
        settings = {"target_url": "http://test.local", "safety_level": "safe"}
        scanner1 = ConcurrencyStressScanner(settings=settings)
        scanner2 = ConcurrencyStressScanner(settings=settings)
        scanner1._auth_headers["X-Test"] = "value"
        assert scanner2._auth_headers == {}

    def test_concurrency_result_hash_distribution_independent(self):
        """Verify that default hash_distribution is independent across instances."""
        cr1 = ConcurrencyResult(
            concurrency_level=1, total_requests=1, successful_requests=1,
            failed_requests=0, total_time_ms=10.0, avg_response_time_ms=10.0,
            min_response_time_ms=10.0, max_response_time_ms=10.0,
            p95_response_time_ms=10.0, unique_responses=1,
            rate_limited_count=0, error_count=0,
        )
        cr2 = ConcurrencyResult(
            concurrency_level=1, total_requests=1, successful_requests=1,
            failed_requests=0, total_time_ms=10.0, avg_response_time_ms=10.0,
            min_response_time_ms=10.0, max_response_time_ms=10.0,
            p95_response_time_ms=10.0, unique_responses=1,
            rate_limited_count=0, error_count=0,
        )
        cr1.responses_hash_distribution["abc"] = 5
        assert "abc" not in cr2.responses_hash_distribution
