"""Tests for scanning.modules.concurrency_state_modeler — static structure tests."""

import pytest

from scanning.modules.concurrency_state_modeler import (
    ConcurrencyStateModeler,
    RACE_PRONE_PATTERNS,
    RaceConditionType,
    RaceTestCase,
    RaceTestResult,
    STATE_CHANGE_OPERATIONS,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# ENUM: RaceConditionType
# =============================================================================

class TestRaceConditionType:
    """Test RaceConditionType enum."""

    def test_member_count(self):
        assert len(RaceConditionType) == 7

    def test_toctou(self):
        assert RaceConditionType.TOCTOU is not None

    def test_double_spend(self):
        assert RaceConditionType.DOUBLE_SPEND is not None

    def test_double_apply(self):
        assert RaceConditionType.DOUBLE_APPLY is not None

    def test_read_modify_write(self):
        assert RaceConditionType.READ_MODIFY_WRITE is not None

    def test_order_dependency(self):
        assert RaceConditionType.ORDER_DEPENDENCY is not None

    def test_lock_bypass(self):
        assert RaceConditionType.LOCK_BYPASS is not None

    def test_state_desync(self):
        assert RaceConditionType.STATE_DESYNC is not None

    def test_unique_values(self):
        values = [m.value for m in RaceConditionType]
        assert len(values) == len(set(values))


# =============================================================================
# DATACLASS: RaceTestCase
# =============================================================================

class TestRaceTestCase:
    """Test RaceTestCase dataclass."""

    def test_minimal_creation(self):
        tc = RaceTestCase(name="test", race_type=RaceConditionType.DOUBLE_SPEND)
        assert tc.name == "test"
        assert tc.race_type == RaceConditionType.DOUBLE_SPEND

    def test_defaults(self):
        tc = RaceTestCase(name="x", race_type=RaceConditionType.TOCTOU)
        assert tc.setup_request is None
        assert tc.competing_requests == []
        assert tc.verification_request is None
        assert tc.expected_behavior == ""
        assert tc.vulnerability_indicator == ""
        assert tc.concurrency_levels == [2, 5, 10, 20]
        assert tc.timing_delays_ms == [0, 1, 5, 10, 50]


# =============================================================================
# DATACLASS: RaceTestResult
# =============================================================================

class TestRaceTestResult:
    """Test RaceTestResult dataclass."""

    def test_creation(self):
        tc = RaceTestCase(name="test", race_type=RaceConditionType.DOUBLE_APPLY)
        r = RaceTestResult(test_case=tc, concurrency_level=5, timing_delay_ms=10)
        assert r.concurrency_level == 5

    def test_defaults(self):
        tc = RaceTestCase(name="test", race_type=RaceConditionType.TOCTOU)
        r = RaceTestResult(test_case=tc, concurrency_level=2, timing_delay_ms=0)
        assert r.success_count == 0
        assert r.failure_count == 0
        assert r.anomaly_count == 0
        assert r.total_time_ms == 0.0
        assert r.state_before == ""
        assert r.state_after == ""
        assert r.response_variations == []
        assert r.is_vulnerable is False
        assert r.vulnerability_evidence == ""


# =============================================================================
# CONSTANT: RACE_PRONE_PATTERNS
# =============================================================================

class TestRacePronePatterns:
    """Test RACE_PRONE_PATTERNS dict."""

    def test_is_dict(self):
        assert isinstance(RACE_PRONE_PATTERNS, dict)

    def test_key_count(self):
        assert len(RACE_PRONE_PATTERNS) == 5

    def test_has_double_spend(self):
        assert RaceConditionType.DOUBLE_SPEND in RACE_PRONE_PATTERNS

    def test_has_double_apply(self):
        assert RaceConditionType.DOUBLE_APPLY in RACE_PRONE_PATTERNS

    def test_has_toctou(self):
        assert RaceConditionType.TOCTOU in RACE_PRONE_PATTERNS

    def test_has_read_modify_write(self):
        assert RaceConditionType.READ_MODIFY_WRITE in RACE_PRONE_PATTERNS

    def test_has_order_dependency(self):
        assert RaceConditionType.ORDER_DEPENDENCY in RACE_PRONE_PATTERNS

    def test_double_spend_has_patterns(self):
        entry = RACE_PRONE_PATTERNS[RaceConditionType.DOUBLE_SPEND]
        patterns = entry[0]
        assert any("transfer" in p for p in patterns)

    def test_double_apply_has_coupon(self):
        entry = RACE_PRONE_PATTERNS[RaceConditionType.DOUBLE_APPLY]
        patterns = entry[0]
        assert any("coupon" in p for p in patterns)


# =============================================================================
# CONSTANT: STATE_CHANGE_OPERATIONS
# =============================================================================

class TestStateChangeOperations:
    """Test STATE_CHANGE_OPERATIONS dict."""

    def test_is_dict(self):
        assert isinstance(STATE_CHANGE_OPERATIONS, dict)

    def test_count(self):
        assert len(STATE_CHANGE_OPERATIONS) == 7

    def test_has_add_to_cart(self):
        assert "add_to_cart" in STATE_CHANGE_OPERATIONS

    def test_has_apply_coupon(self):
        assert "apply_coupon" in STATE_CHANGE_OPERATIONS

    def test_has_transfer_funds(self):
        assert "transfer_funds" in STATE_CHANGE_OPERATIONS

    def test_has_checkout(self):
        assert "checkout" in STATE_CHANGE_OPERATIONS

    def test_has_vote(self):
        assert "vote" in STATE_CHANGE_OPERATIONS

    def test_has_claim_reward(self):
        assert "claim_reward" in STATE_CHANGE_OPERATIONS

    def test_all_have_endpoints(self):
        for op, data in STATE_CHANGE_OPERATIONS.items():
            assert "endpoints" in data, f"{op} missing endpoints"
            assert len(data["endpoints"]) > 0

    def test_all_have_method(self):
        for op, data in STATE_CHANGE_OPERATIONS.items():
            assert "method" in data, f"{op} missing method"

    def test_all_have_body_template(self):
        for op, data in STATE_CHANGE_OPERATIONS.items():
            assert "body_template" in data, f"{op} missing body_template"


# =============================================================================
# SCANNER IDENTITY
# =============================================================================

class TestScannerIdentity:
    """Test ConcurrencyStateModeler scanner identity."""

    def test_is_scan_module_subclass(self):
        assert issubclass(ConcurrencyStateModeler, ScanModule)

    def test_name_attribute(self):
        assert ConcurrencyStateModeler.name == "concurrency_state"

    def test_description(self):
        assert ConcurrencyStateModeler.description is not None
        assert len(ConcurrencyStateModeler.description) > 0

    def test_version(self):
        assert ConcurrencyStateModeler.version == "1.0.0"

    def test_tags(self):
        tags = ConcurrencyStateModeler.tags
        assert "concurrency" in tags
        assert "race_condition" in tags

    def test_instantiation(self):
        scanner = ConcurrencyStateModeler(
            settings={"target_url": "http://test.local", "safety_level": "safe"}
        )
        assert scanner is not None
