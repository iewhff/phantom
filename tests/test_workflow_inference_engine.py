"""Tests for scanning.modules.workflow_inference_engine — static structure tests."""

import re

import pytest

from scanning.modules.workflow_inference_engine import (
    DOMAIN_PATTERNS,
    DomainType,
    InferredWorkflow,
    STATE_TOKEN_PATTERNS,
    STATUS_FIELDS,
    WORKFLOW_ENDPOINT_PATTERNS,
    WORKFLOW_PATTERNS,
    WorkflowExecutionState,
    WorkflowInferenceEngine,
    WorkflowState,
)
from scanning.vuln_scanner import ScanModule


# =============================================================================
# ENUM: DomainType
# =============================================================================

class TestDomainType:
    """Test DomainType enum."""

    def test_member_count(self):
        assert len(DomainType) == 9

    def test_ecommerce_exists(self):
        assert DomainType.ECOMMERCE is not None

    def test_saas_exists(self):
        assert DomainType.SAAS is not None

    def test_marketplace_exists(self):
        assert DomainType.MARKETPLACE is not None

    def test_fintech_exists(self):
        assert DomainType.FINTECH is not None

    def test_healthcare_exists(self):
        assert DomainType.HEALTHCARE is not None

    def test_content_exists(self):
        assert DomainType.CONTENT is not None

    def test_auth_centric_exists(self):
        assert DomainType.AUTH_CENTRIC is not None

    def test_api_service_exists(self):
        assert DomainType.API_SERVICE is not None

    def test_unknown_exists(self):
        assert DomainType.UNKNOWN is not None

    def test_unique_values(self):
        values = [m.value for m in DomainType]
        assert len(values) == len(set(values))


# =============================================================================
# DATACLASS: WorkflowState
# =============================================================================

class TestWorkflowState:
    """Test WorkflowState dataclass."""

    def test_minimal_creation(self):
        ws = WorkflowState(name="created", url_pattern="/orders")
        assert ws.name == "created"
        assert ws.url_pattern == "/orders"

    def test_defaults(self):
        ws = WorkflowState(name="x", url_pattern="/x")
        assert ws.status_field == ""
        assert ws.status_value == ""
        assert ws.transitions == []

    def test_full_creation(self):
        ws = WorkflowState(
            name="pending",
            url_pattern="/orders/pending",
            status_field="status",
            status_value="pending",
            transitions=["confirmed", "cancelled"],
        )
        assert len(ws.transitions) == 2
        assert ws.status_field == "status"


# =============================================================================
# DATACLASS: InferredWorkflow
# =============================================================================

class TestInferredWorkflow:
    """Test InferredWorkflow dataclass."""

    def test_minimal_creation(self):
        iw = InferredWorkflow(name="checkout", domain=DomainType.ECOMMERCE)
        assert iw.name == "checkout"
        assert iw.domain == DomainType.ECOMMERCE

    def test_defaults(self):
        iw = InferredWorkflow(name="x", domain=DomainType.UNKNOWN)
        assert iw.states == []
        assert iw.entry_state == ""
        assert iw.terminal_states == []
        assert iw.endpoints == []
        assert iw.confidence == 0.0

    def test_full_creation(self):
        iw = InferredWorkflow(
            name="payment",
            domain=DomainType.FINTECH,
            states=[WorkflowState(name="init", url_pattern="/pay")],
            entry_state="init",
            terminal_states=["completed"],
            endpoints=["/pay", "/confirm"],
            confidence=0.85,
        )
        assert len(iw.states) == 1
        assert iw.confidence == 0.85


# =============================================================================
# DATACLASS: WorkflowExecutionState
# =============================================================================

class TestWorkflowExecutionState:
    """Test WorkflowExecutionState dataclass."""

    def test_defaults(self):
        wes = WorkflowExecutionState()
        assert wes.current_state == ""
        assert wes.state_tokens == {}
        assert wes.cookies == {}
        assert wes.response_values == {}
        assert wes.step_history == []

    def test_clone_creates_copy(self):
        wes = WorkflowExecutionState(
            current_state="checkout",
            state_tokens={"cart_id": "abc"},
            cookies={"session": "xyz"},
        )
        clone = wes.clone()
        assert clone.current_state == "checkout"
        assert clone.state_tokens == {"cart_id": "abc"}
        # Verify it's a separate copy
        clone.state_tokens["cart_id"] = "changed"
        assert wes.state_tokens["cart_id"] == "abc"


# =============================================================================
# CONSTANT: DOMAIN_PATTERNS
# =============================================================================

class TestDomainPatterns:
    """Test DOMAIN_PATTERNS dict."""

    def test_is_dict(self):
        assert isinstance(DOMAIN_PATTERNS, dict)

    def test_key_count(self):
        # Should cover ECOMMERCE, SAAS, MARKETPLACE, FINTECH, HEALTHCARE, CONTENT, AUTH_CENTRIC
        assert len(DOMAIN_PATTERNS) >= 7

    def test_keys_are_domain_types(self):
        for key in DOMAIN_PATTERNS:
            assert isinstance(key, DomainType)

    def test_values_are_lists(self):
        for patterns in DOMAIN_PATTERNS.values():
            assert isinstance(patterns, list)
            assert len(patterns) > 0

    def test_ecommerce_has_cart(self):
        patterns = DOMAIN_PATTERNS[DomainType.ECOMMERCE]
        assert any("cart" in p for p in patterns)

    def test_fintech_has_transfer(self):
        patterns = DOMAIN_PATTERNS[DomainType.FINTECH]
        assert any("transfer" in p for p in patterns)

    def test_patterns_compile(self):
        for domain, patterns in DOMAIN_PATTERNS.items():
            for p in patterns:
                compiled = re.compile(p)
                assert compiled is not None, f"Pattern '{p}' for {domain} failed to compile"


# =============================================================================
# CONSTANT: STATUS_FIELDS
# =============================================================================

class TestStatusFields:
    """Test STATUS_FIELDS list."""

    def test_is_list(self):
        assert isinstance(STATUS_FIELDS, list)

    def test_count(self):
        assert len(STATUS_FIELDS) == 11

    def test_contains_status(self):
        assert "status" in STATUS_FIELDS

    def test_contains_state(self):
        assert "state" in STATUS_FIELDS

    def test_no_duplicates(self):
        assert len(STATUS_FIELDS) == len(set(STATUS_FIELDS))


# =============================================================================
# CONSTANT: WORKFLOW_PATTERNS
# =============================================================================

class TestWorkflowPatterns:
    """Test WORKFLOW_PATTERNS dict."""

    def test_is_dict(self):
        assert isinstance(WORKFLOW_PATTERNS, dict)

    def test_has_ecommerce(self):
        assert DomainType.ECOMMERCE in WORKFLOW_PATTERNS

    def test_has_saas(self):
        assert DomainType.SAAS in WORKFLOW_PATTERNS

    def test_has_fintech(self):
        assert DomainType.FINTECH in WORKFLOW_PATTERNS

    def test_has_content(self):
        assert DomainType.CONTENT in WORKFLOW_PATTERNS

    def test_ecommerce_has_order(self):
        assert "order" in WORKFLOW_PATTERNS[DomainType.ECOMMERCE]

    def test_ecommerce_order_has_states(self):
        states = WORKFLOW_PATTERNS[DomainType.ECOMMERCE]["order"]
        assert "created" in states
        assert "shipped" in states
        assert "cancelled" in states

    def test_fintech_transfer_states(self):
        states = WORKFLOW_PATTERNS[DomainType.FINTECH]["transfer"]
        assert "pending" in states
        assert "completed" in states


# =============================================================================
# CONSTANT: STATE_TOKEN_PATTERNS
# =============================================================================

class TestStateTokenPatterns:
    """Test STATE_TOKEN_PATTERNS dict."""

    def test_is_dict(self):
        assert isinstance(STATE_TOKEN_PATTERNS, dict)

    def test_key_count(self):
        assert len(STATE_TOKEN_PATTERNS) == 9

    def test_has_cart_id(self):
        assert "cart_id" in STATE_TOKEN_PATTERNS

    def test_has_order_id(self):
        assert "order_id" in STATE_TOKEN_PATTERNS

    def test_has_token(self):
        assert "token" in STATE_TOKEN_PATTERNS

    def test_has_user_id(self):
        assert "user_id" in STATE_TOKEN_PATTERNS

    def test_values_are_lists_of_strings(self):
        for key, patterns in STATE_TOKEN_PATTERNS.items():
            assert isinstance(patterns, list), f"{key} is not a list"
            for p in patterns:
                assert isinstance(p, str)

    def test_patterns_compile(self):
        for key, patterns in STATE_TOKEN_PATTERNS.items():
            for p in patterns:
                compiled = re.compile(p)
                assert compiled is not None


# =============================================================================
# CONSTANT: WORKFLOW_ENDPOINT_PATTERNS
# =============================================================================

class TestWorkflowEndpointPatterns:
    """Test WORKFLOW_ENDPOINT_PATTERNS dict."""

    def test_is_dict(self):
        assert isinstance(WORKFLOW_ENDPOINT_PATTERNS, dict)

    def test_has_checkout(self):
        assert "checkout" in WORKFLOW_ENDPOINT_PATTERNS

    def test_has_registration(self):
        assert "registration" in WORKFLOW_ENDPOINT_PATTERNS

    def test_has_password_reset(self):
        assert "password_reset" in WORKFLOW_ENDPOINT_PATTERNS

    def test_has_transfer(self):
        assert "transfer" in WORKFLOW_ENDPOINT_PATTERNS

    def test_checkout_has_states(self):
        entry = WORKFLOW_ENDPOINT_PATTERNS["checkout"]
        assert "states" in entry
        assert len(entry["states"]) >= 4

    def test_checkout_has_patterns(self):
        entry = WORKFLOW_ENDPOINT_PATTERNS["checkout"]
        assert "patterns" in entry
        assert len(entry["patterns"]) >= 4

    def test_registration_states(self):
        entry = WORKFLOW_ENDPOINT_PATTERNS["registration"]
        assert "signup" in entry["states"]
        assert "verify" in entry["states"]


# =============================================================================
# SCANNER IDENTITY
# =============================================================================

class TestScannerIdentity:
    """Test WorkflowInferenceEngine scanner identity."""

    def test_is_scan_module_subclass(self):
        assert issubclass(WorkflowInferenceEngine, ScanModule)

    def test_name_attribute(self):
        assert WorkflowInferenceEngine.name == "workflow_inference"

    def test_instantiation(self):
        scanner = WorkflowInferenceEngine(
            settings={"target_url": "http://test.local", "safety_level": "safe"}
        )
        assert scanner is not None
