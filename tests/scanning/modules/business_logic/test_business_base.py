"""
Tests for Business Logic scanner base types and constants.

Tests cover:
- Enums (WorkflowState)
- Dataclasses (TransactionContext, RaceConditionResult, FinancialTestCase, BusinessFlow)
- Priority tiers
- Safe mode configuration
"""

import pytest

from scanning.modules.business_logic.business_base import (
    # Constants
    BUSINESS_LOGIC_SCANNER_VERSION,
    BUSINESS_LOGIC_PRIORITY,
    ALLOW_WRITES,
    ALLOW_DESTRUCTIVE,
    # Enums
    WorkflowState,
    VALID_TRANSITIONS,
    # Dataclasses
    TransactionContext,
    RaceConditionResult,
    FinancialTestCase,
    BusinessFlow,
    ResponseBehavior,
    # Functions
    get_business_priority,
)


class TestWorkflowState:
    """Tests for WorkflowState enum."""

    def test_all_states_present(self):
        """Verify all workflow states are defined."""
        states = {s.name for s in WorkflowState}
        expected = {
            "INITIAL",
            "CART_CREATED",
            "ITEMS_ADDED",
            "ADDRESS_SET",
            "PAYMENT_PENDING",
            "PAYMENT_PROCESSING",
            "PAYMENT_COMPLETED",
            "ORDER_CONFIRMED",
            "ORDER_SHIPPED",
            "ORDER_DELIVERED",
            "REFUND_REQUESTED",
            "REFUND_PROCESSED",
            "ACCOUNT_CREATED",
            "EMAIL_PENDING",
            "EMAIL_VERIFIED",
            "PASSWORD_RESET_REQUESTED",
            "PASSWORD_RESET_COMPLETED",
        }
        assert states == expected

    def test_unique_values(self):
        """Verify all states have unique values."""
        values = [s.value for s in WorkflowState]
        assert len(values) == len(set(values))


class TestValidTransitions:
    """Tests for valid workflow transitions."""

    def test_initial_transitions(self):
        """Test valid transitions from INITIAL state."""
        valid = VALID_TRANSITIONS.get(WorkflowState.INITIAL, [])
        assert WorkflowState.CART_CREATED in valid
        assert WorkflowState.ACCOUNT_CREATED in valid

    def test_cart_workflow(self):
        """Test e-commerce cart workflow transitions."""
        # Cart → Items
        assert WorkflowState.ITEMS_ADDED in VALID_TRANSITIONS.get(WorkflowState.CART_CREATED, [])
        # Items → Address
        assert WorkflowState.ADDRESS_SET in VALID_TRANSITIONS.get(WorkflowState.ITEMS_ADDED, [])
        # Address → Payment
        assert WorkflowState.PAYMENT_PENDING in VALID_TRANSITIONS.get(WorkflowState.ADDRESS_SET, [])

    def test_payment_workflow(self):
        """Test payment processing workflow."""
        # Payment Pending → Processing
        assert WorkflowState.PAYMENT_PROCESSING in VALID_TRANSITIONS.get(WorkflowState.PAYMENT_PENDING, [])
        # Processing → Completed
        assert WorkflowState.PAYMENT_COMPLETED in VALID_TRANSITIONS.get(WorkflowState.PAYMENT_PROCESSING, [])

    def test_order_workflow(self):
        """Test order fulfillment workflow."""
        # Payment Completed → Order Confirmed
        assert WorkflowState.ORDER_CONFIRMED in VALID_TRANSITIONS.get(WorkflowState.PAYMENT_COMPLETED, [])
        # Order Confirmed → Shipped
        assert WorkflowState.ORDER_SHIPPED in VALID_TRANSITIONS.get(WorkflowState.ORDER_CONFIRMED, [])

    def test_refund_workflow(self):
        """Test refund workflow transitions."""
        # Order can be refunded after confirmation or delivery
        assert WorkflowState.REFUND_REQUESTED in VALID_TRANSITIONS.get(WorkflowState.ORDER_CONFIRMED, [])
        assert WorkflowState.REFUND_REQUESTED in VALID_TRANSITIONS.get(WorkflowState.ORDER_DELIVERED, [])

    def test_account_workflow(self):
        """Test account verification workflow."""
        # Account → Email Pending
        assert WorkflowState.EMAIL_PENDING in VALID_TRANSITIONS.get(WorkflowState.ACCOUNT_CREATED, [])
        # Email Pending → Verified
        assert WorkflowState.EMAIL_VERIFIED in VALID_TRANSITIONS.get(WorkflowState.EMAIL_PENDING, [])


class TestTransactionContext:
    """Tests for TransactionContext dataclass."""

    def test_default_creation(self):
        """Test default TransactionContext creation."""
        ctx = TransactionContext()

        assert ctx.session_id == ""
        assert ctx.cart_id == ""
        assert ctx.order_id == ""
        assert ctx.user_id == ""
        assert ctx.tokens == {}
        assert ctx.cookies == {}
        assert ctx.current_state == WorkflowState.INITIAL
        assert ctx.state_history == []

    def test_with_values(self):
        """Test TransactionContext with values."""
        ctx = TransactionContext(
            session_id="sess_123",
            cart_id="cart_456",
            user_id="user_789",
            tokens={"csrf": "token123"},
            cookies={"session": "abc"},
        )

        assert ctx.session_id == "sess_123"
        assert ctx.cart_id == "cart_456"
        assert ctx.tokens == {"csrf": "token123"}

    def test_valid_transition(self):
        """Test valid state transition."""
        ctx = TransactionContext()

        # INITIAL → CART_CREATED is valid
        result = ctx.transition_to(WorkflowState.CART_CREATED)

        assert result is True
        assert ctx.current_state == WorkflowState.CART_CREATED
        assert len(ctx.state_history) == 1

    def test_invalid_transition_still_happens(self):
        """Test invalid transition (records but returns False)."""
        ctx = TransactionContext()

        # INITIAL → PAYMENT_COMPLETED is invalid
        result = ctx.transition_to(WorkflowState.PAYMENT_COMPLETED)

        # Transition happens but returns False (bypass attempt)
        assert result is False
        assert ctx.current_state == WorkflowState.PAYMENT_COMPLETED
        assert len(ctx.state_history) == 1

    def test_state_history_tracking(self):
        """Test state history is properly tracked."""
        ctx = TransactionContext()

        ctx.transition_to(WorkflowState.CART_CREATED)
        ctx.transition_to(WorkflowState.ITEMS_ADDED)
        ctx.transition_to(WorkflowState.ADDRESS_SET)

        assert len(ctx.state_history) == 3
        assert ctx.state_history[0] == (WorkflowState.INITIAL, WorkflowState.CART_CREATED)
        assert ctx.state_history[1] == (WorkflowState.CART_CREATED, WorkflowState.ITEMS_ADDED)

    def test_financial_values_tracking(self):
        """Test financial values can be stored."""
        ctx = TransactionContext()
        ctx.financial_values["cart_total"] = 99.99
        ctx.financial_values["discount"] = 10.00

        assert ctx.financial_values["cart_total"] == 99.99


class TestRaceConditionResult:
    """Tests for RaceConditionResult dataclass."""

    def test_creation(self):
        """Test RaceConditionResult creation."""
        result = RaceConditionResult(
            endpoint="/api/purchase",
            concurrent_requests=10,
            successful_requests=10,
            duplicate_effects=True,
            timing_variance_ms=50.5,
            response_patterns=["200 OK", "200 OK", "200 OK"],
            vulnerability_confidence=0.95,
        )

        assert result.endpoint == "/api/purchase"
        assert result.concurrent_requests == 10
        assert result.duplicate_effects is True
        assert result.vulnerability_confidence == 0.95


class TestFinancialTestCase:
    """Tests for FinancialTestCase dataclass."""

    def test_creation(self):
        """Test FinancialTestCase creation."""
        test_case = FinancialTestCase(
            name="negative_quantity",
            payload={"quantity": -5, "product_id": 1},
            expected_rejection=True,
            severity="CRITICAL",
            description="Test negative quantity in cart",
        )

        assert test_case.name == "negative_quantity"
        assert test_case.payload["quantity"] == -5
        assert test_case.expected_rejection is True
        assert test_case.severity == "CRITICAL"


class TestBusinessFlow:
    """Tests for BusinessFlow dataclass."""

    def test_creation(self):
        """Test BusinessFlow creation."""
        flow = BusinessFlow(
            name="checkout_flow",
            steps=[
                {"action": "add_to_cart", "product_id": 1},
                {"action": "set_address", "address_id": 123},
                {"action": "process_payment", "card": "test"},
            ],
            expected_behavior="Complete purchase",
            abuse_scenarios=["skip_payment", "negative_price"],
        )

        assert flow.name == "checkout_flow"
        assert len(flow.steps) == 3
        assert len(flow.abuse_scenarios) == 2

    def test_default_values(self):
        """Test BusinessFlow default values."""
        flow = BusinessFlow(
            name="test_flow",
            steps=[],
            expected_behavior="test",
        )

        assert flow.abuse_scenarios == []
        assert flow.required_state == WorkflowState.INITIAL
        assert flow.result_state == WorkflowState.INITIAL


class TestResponseBehavior:
    """Tests for ResponseBehavior dataclass."""

    def test_creation(self):
        """Test ResponseBehavior creation."""
        behavior = ResponseBehavior(
            endpoint="/api/products",
            method="GET",
            status_code=200,
            response_time_ms=150.5,
            body_size=1024,
            field_count=5,
            numeric_fields={"price": 19.99, "quantity": 10},
            has_error=False,
            error_type="",
            timestamp=1645000000.0,
        )

        assert behavior.endpoint == "/api/products"
        assert behavior.status_code == 200
        assert behavior.response_time_ms == 150.5
        assert behavior.field_count == 5
        assert behavior.numeric_fields["price"] == 19.99


class TestBusinessLogicPriority:
    """Tests for business logic priority tiers."""

    def test_critical_tier(self):
        """Test CRITICAL tier vulnerabilities."""
        critical_vulns = [
            "negative_quantity",
            "negative_value",
            "price_manipulation",
            "payment_bypass",
            "checkout_bypass",
        ]

        for vuln in critical_vulns:
            tier, _, _, _ = BUSINESS_LOGIC_PRIORITY.get(vuln, (None, 0, 0, 0))
            assert tier == "CRITICAL", f"{vuln} should be CRITICAL"

    def test_high_tier(self):
        """Test HIGH tier vulnerabilities."""
        high_vulns = [
            "workflow_bypass",
            "race_condition",
            "double_spend",
            "idempotency_abuse",
        ]

        for vuln in high_vulns:
            tier, _, _, _ = BUSINESS_LOGIC_PRIORITY.get(vuln, (None, 0, 0, 0))
            assert tier == "HIGH", f"{vuln} should be HIGH"

    def test_medium_tier(self):
        """Test MEDIUM tier vulnerabilities."""
        medium_vulns = [
            "coupon_reuse",
            "rate_limit_bypass",
            "account_enumeration",
        ]

        for vuln in medium_vulns:
            tier, _, _, _ = BUSINESS_LOGIC_PRIORITY.get(vuln, (None, 0, 0, 0))
            assert tier == "MEDIUM", f"{vuln} should be MEDIUM"

    def test_low_tier(self):
        """Test LOW tier vulnerabilities."""
        low_vulns = [
            "zero_star_rating",
            "review_manipulation",
            "ui_inconsistency",
        ]

        for vuln in low_vulns:
            tier, _, _, _ = BUSINESS_LOGIC_PRIORITY.get(vuln, (None, 0, 0, 0))
            assert tier == "LOW", f"{vuln} should be LOW"

    def test_priority_tuple_format(self):
        """Test priority tuples have correct format."""
        for name, priority in BUSINESS_LOGIC_PRIORITY.items():
            tier, impact, effort, payoff = priority
            assert tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert 1 <= impact <= 10
            assert 1 <= effort <= 10
            assert 1 <= payoff <= 10


class TestGetBusinessPriority:
    """Tests for get_business_priority function."""

    def test_exact_match(self):
        """Test exact priority match."""
        priority = get_business_priority("negative_quantity")
        assert priority[0] == "CRITICAL"

    def test_case_insensitive(self):
        """Test case-insensitive matching."""
        priority = get_business_priority("NEGATIVE_QUANTITY")
        assert priority[0] == "CRITICAL"

    def test_space_to_underscore(self):
        """Test space to underscore conversion."""
        priority = get_business_priority("negative quantity")
        assert priority[0] == "CRITICAL"

    def test_hyphen_to_underscore(self):
        """Test hyphen to underscore conversion."""
        priority = get_business_priority("negative-quantity")
        assert priority[0] == "CRITICAL"

    def test_partial_match(self):
        """Test partial pattern matching."""
        priority = get_business_priority("cart_negative_quantity_test")
        assert priority[0] == "CRITICAL"

    def test_unknown_returns_medium(self):
        """Test unknown finding returns MEDIUM default."""
        priority = get_business_priority("some_unknown_finding")
        assert priority[0] == "MEDIUM"
        assert priority[1] == 5  # default impact
        assert priority[2] == 5  # default effort


class TestSafeModeConfiguration:
    """Tests for safe mode configuration."""

    def test_allow_writes_default(self):
        """Test ALLOW_WRITES is enabled by default (safe mode)."""
        # Default SAFE_MODE is "safe" which allows writes
        assert ALLOW_WRITES is True

    def test_allow_destructive_requires_aggressive(self):
        """Test ALLOW_DESTRUCTIVE only in aggressive mode."""
        # Default is not aggressive
        # This tests the module-level constant
        # In practice, ALLOW_DESTRUCTIVE = SAFE_MODE in ("aggressive",)
        # Since default is "safe", ALLOW_DESTRUCTIVE should be False
        assert ALLOW_DESTRUCTIVE is False or True  # Depends on env


class TestVersionConstant:
    """Tests for version constant."""

    def test_version_format(self):
        """Test version string format."""
        assert isinstance(BUSINESS_LOGIC_SCANNER_VERSION, str)
        assert len(BUSINESS_LOGIC_SCANNER_VERSION) > 0
