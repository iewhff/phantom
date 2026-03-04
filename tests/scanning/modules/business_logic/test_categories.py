"""
Tests for Business Logic scanner categories.

Tests cover:
- Category base classes (CategoryResult, CategoryContext, BaseBusinessCategory)
- FinancialEdgeCasesCategory
- RaceConditionsCategory
- WorkflowBypassCategory
- IDORTestingCategory
- IdempotencyAbuseCategory
- InventoryManipulationCategory
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from scanning.modules.business_logic.categories.base import (
    CategoryResult,
    CategoryContext,
    BaseBusinessCategory,
    BusinessCategory,
)
from scanning.modules.business_logic.business_base import (
    TransactionContext,
    WorkflowState,
)


class TestCategoryResult:
    """Tests for CategoryResult dataclass."""

    def test_not_found_factory(self):
        """Test CategoryResult.not_found factory method."""
        result = CategoryResult.not_found()

        assert result.found is False
        assert result.findings == []
        assert result.attempts == 0
        assert result.errors == []

    def test_not_found_with_attempts(self):
        """Test CategoryResult.not_found with attempts count."""
        result = CategoryResult.not_found(attempts=20)

        assert result.found is False
        assert result.attempts == 20

    def test_not_found_with_errors(self):
        """Test CategoryResult.not_found with error list."""
        errors = ["API timeout", "Rate limited"]
        result = CategoryResult.not_found(attempts=5, errors=errors)

        assert result.found is False
        assert result.errors == errors

    def test_vulnerable_factory(self):
        """Test CategoryResult.vulnerable factory method."""
        findings = [
            {"type": "business_logic", "name": "negative_quantity", "severity": "CRITICAL"},
            {"type": "business_logic", "name": "price_manipulation", "severity": "CRITICAL"},
        ]
        result = CategoryResult.vulnerable(findings, attempts=10)

        assert result.found is True
        assert len(result.findings) == 2
        assert result.attempts == 10


class TestCategoryContext:
    """Tests for CategoryContext dataclass."""

    def test_basic_creation(self):
        """Test basic CategoryContext creation."""
        ctx = CategoryContext(
            base_url="https://shop.example.com",
            host="shop.example.com",
        )

        assert ctx.base_url == "https://shop.example.com"
        assert ctx.host == "shop.example.com"

    def test_default_values(self):
        """Test CategoryContext default values."""
        ctx = CategoryContext(
            base_url="https://example.com",
            host="example.com",
        )

        assert ctx.endpoints == []
        assert ctx.forms == []
        assert ctx.auth_headers == {}
        assert ctx.timeout == 30.0
        assert ctx.allow_writes is True
        assert ctx.allow_destructive is False
        assert ctx.transaction_ctx is None
        assert ctx.anomaly_detector is None

    def test_with_endpoints(self):
        """Test CategoryContext with endpoints."""
        ctx = CategoryContext(
            base_url="https://shop.example.com",
            host="shop.example.com",
            endpoints=[
                "/api/cart",
                "/api/checkout",
                "/api/payment",
                "/api/orders",
            ],
        )

        assert len(ctx.endpoints) == 4

    def test_with_transaction_context(self):
        """Test CategoryContext with transaction context."""
        tx_ctx = TransactionContext(
            session_id="sess_123",
            cart_id="cart_456",
        )
        ctx = CategoryContext(
            base_url="https://shop.example.com",
            host="shop.example.com",
            transaction_ctx=tx_ctx,
        )

        assert ctx.transaction_ctx is not None
        assert ctx.transaction_ctx.session_id == "sess_123"

    @pytest.mark.asyncio
    async def test_acquire_rate_limit_with_callback(self):
        """Test rate limit acquisition with callback."""
        async_mock = AsyncMock()

        ctx = CategoryContext(
            base_url="https://example.com",
            host="example.com",
            rate_limiter_acquire=async_mock,
        )

        await ctx.acquire_rate_limit()

        async_mock.assert_called_once_with("example.com")

    @pytest.mark.asyncio
    async def test_acquire_rate_limit_without_callback(self):
        """Test rate limit acquisition without callback does nothing."""
        ctx = CategoryContext(
            base_url="https://example.com",
            host="example.com",
        )

        # Should not raise
        await ctx.acquire_rate_limit()

    def test_get_endpoints_matching(self):
        """Test endpoint pattern matching."""
        ctx = CategoryContext(
            base_url="https://shop.example.com",
            host="shop.example.com",
            endpoints=[
                "/api/cart",
                "/api/cart/add",
                "/api/checkout",
                "/api/payment",
                "/api/orders",
                "/api/products",
            ],
        )

        cart_endpoints = ctx.get_endpoints_matching(["cart"])
        assert len(cart_endpoints) == 2
        assert "/api/cart" in cart_endpoints
        assert "/api/cart/add" in cart_endpoints

    def test_get_endpoints_matching_multiple_patterns(self):
        """Test endpoint matching with multiple patterns."""
        ctx = CategoryContext(
            base_url="https://shop.example.com",
            host="shop.example.com",
            endpoints=[
                "/api/cart",
                "/api/checkout",
                "/api/payment",
                "/api/orders",
            ],
        )

        payment_endpoints = ctx.get_endpoints_matching(["payment", "checkout"])
        assert len(payment_endpoints) == 2

    def test_get_endpoints_matching_case_insensitive(self):
        """Test endpoint matching is case-insensitive."""
        ctx = CategoryContext(
            base_url="https://shop.example.com",
            host="shop.example.com",
            endpoints=[
                "/API/Cart",
                "/api/CHECKOUT",
            ],
        )

        cart_endpoints = ctx.get_endpoints_matching(["cart"])
        assert len(cart_endpoints) == 1


class TestBaseBusinessCategory:
    """Tests for BaseBusinessCategory abstract base class."""

    def test_create_finding(self):
        """Test _create_finding helper method."""

        class ConcreteCategory(BaseBusinessCategory):
            @property
            def name(self):
                return "test"

            @property
            def priority_tier(self):
                return 1

            async def test(self, ctx):
                pass

        category = ConcreteCategory()

        finding = category._create_finding(
            name="Negative Quantity Accepted",
            severity="CRITICAL",
            description="Cart accepts negative quantities",
            host="shop.example.com",
            endpoint="/api/cart/add",
            evidence=["quantity=-5 accepted", "total became negative"],
        )

        assert finding["type"] == "business_logic"
        assert finding["name"] == "Negative Quantity Accepted"
        assert finding["severity"] == "CRITICAL"
        assert finding["host"] == "shop.example.com"
        assert finding["endpoint"] == "/api/cart/add"
        assert len(finding["evidence"]) == 2

    def test_create_finding_defaults(self):
        """Test _create_finding with default values."""

        class ConcreteCategory(BaseBusinessCategory):
            @property
            def name(self):
                return "test"

            @property
            def priority_tier(self):
                return 1

            async def test(self, ctx):
                pass

        category = ConcreteCategory()

        finding = category._create_finding(
            name="Test",
            severity="HIGH",
            description="Test finding",
            host="example.com",
            endpoint="/api/test",
            evidence=["test"],
        )

        assert finding["cvss_score"] == 7.0
        assert finding["cwe_id"] == "CWE-840"
        assert finding["confidence_score"] == 85.0
        assert finding["metadata"] == {}

    def test_extract_numeric_fields(self):
        """Test _extract_numeric_fields helper."""

        class ConcreteCategory(BaseBusinessCategory):
            @property
            def name(self):
                return "test"

            @property
            def priority_tier(self):
                return 1

            async def test(self, ctx):
                pass

        category = ConcreteCategory()

        data = {
            "quantity": 5,
            "price": 19.99,
            "discount": "10.00",
            "name": "Product",
            "total": "invalid",
        }

        numeric = category._extract_numeric_fields(data)

        assert numeric["quantity"] == 5.0
        assert numeric["price"] == 19.99
        assert numeric["discount"] == 10.00
        assert "name" not in numeric
        assert "total" not in numeric


class TestBusinessCategoryProtocol:
    """Tests for BusinessCategory protocol compliance."""

    def test_all_categories_implement_protocol(self):
        """Test all categories implement the protocol correctly."""
        from scanning.modules.business_logic.categories.financial_edge_cases import FinancialEdgeCasesCategory
        from scanning.modules.business_logic.categories.race_conditions import RaceConditionsCategory
        from scanning.modules.business_logic.categories.workflow_bypass import WorkflowBypassCategory
        from scanning.modules.business_logic.categories.idor_testing import IDORTestingCategory
        from scanning.modules.business_logic.categories.idempotency_abuse import IdempotencyAbuseCategory
        from scanning.modules.business_logic.categories.inventory_manipulation import InventoryManipulationCategory

        categories = [
            FinancialEdgeCasesCategory(),
            RaceConditionsCategory(),
            WorkflowBypassCategory(),
            IDORTestingCategory(),
            IdempotencyAbuseCategory(),
            InventoryManipulationCategory(),
        ]

        for category in categories:
            assert isinstance(category, BusinessCategory)
            assert isinstance(category.name, str)
            assert isinstance(category.priority_tier, int)
            assert 1 <= category.priority_tier <= 4


class TestFinancialEdgeCasesCategory:
    """Tests for FinancialEdgeCasesCategory."""

    def test_category_properties(self):
        """Test FinancialEdgeCasesCategory properties."""
        from scanning.modules.business_logic.categories.financial_edge_cases import FinancialEdgeCasesCategory

        category = FinancialEdgeCasesCategory()

        assert category.name == "financial_edge_cases"
        assert category.priority_tier == 1  # CRITICAL


class TestRaceConditionsCategory:
    """Tests for RaceConditionsCategory."""

    def test_category_properties(self):
        """Test RaceConditionsCategory properties."""
        from scanning.modules.business_logic.categories.race_conditions import RaceConditionsCategory

        category = RaceConditionsCategory()

        assert category.name == "race_conditions"
        assert category.priority_tier == 1  # CRITICAL (financial impact)


class TestWorkflowBypassCategory:
    """Tests for WorkflowBypassCategory."""

    def test_category_properties(self):
        """Test WorkflowBypassCategory properties."""
        from scanning.modules.business_logic.categories.workflow_bypass import WorkflowBypassCategory

        category = WorkflowBypassCategory()

        assert category.name == "workflow_bypass"
        assert category.priority_tier == 1  # CRITICAL


class TestIDORTestingCategory:
    """Tests for IDORTestingCategory."""

    def test_category_properties(self):
        """Test IDORTestingCategory properties."""
        from scanning.modules.business_logic.categories.idor_testing import IDORTestingCategory

        category = IDORTestingCategory()

        assert category.name == "idor_testing"
        assert category.priority_tier == 2  # HIGH


class TestIdempotencyAbuseCategory:
    """Tests for IdempotencyAbuseCategory."""

    def test_category_properties(self):
        """Test IdempotencyAbuseCategory properties."""
        from scanning.modules.business_logic.categories.idempotency_abuse import IdempotencyAbuseCategory

        category = IdempotencyAbuseCategory()

        assert category.name == "idempotency_abuse"
        assert category.priority_tier == 2  # HIGH


class TestInventoryManipulationCategory:
    """Tests for InventoryManipulationCategory."""

    def test_category_properties(self):
        """Test InventoryManipulationCategory properties."""
        from scanning.modules.business_logic.categories.inventory_manipulation import InventoryManipulationCategory

        category = InventoryManipulationCategory()

        assert category.name == "inventory_manipulation"
        assert category.priority_tier == 2  # HIGH


class TestCategoryNamesUnique:
    """Tests to ensure category names are unique."""

    def test_all_categories_have_unique_names(self):
        """Test that each category has a unique name."""
        from scanning.modules.business_logic.categories.financial_edge_cases import FinancialEdgeCasesCategory
        from scanning.modules.business_logic.categories.race_conditions import RaceConditionsCategory
        from scanning.modules.business_logic.categories.workflow_bypass import WorkflowBypassCategory
        from scanning.modules.business_logic.categories.idor_testing import IDORTestingCategory
        from scanning.modules.business_logic.categories.idempotency_abuse import IdempotencyAbuseCategory
        from scanning.modules.business_logic.categories.inventory_manipulation import InventoryManipulationCategory

        categories = [
            FinancialEdgeCasesCategory(),
            RaceConditionsCategory(),
            WorkflowBypassCategory(),
            IDORTestingCategory(),
            IdempotencyAbuseCategory(),
            InventoryManipulationCategory(),
        ]

        names = [c.name for c in categories]
        assert len(names) == len(set(names)), "Categories should have unique names"


class TestCategoryPriorityTiers:
    """Tests for category priority tiers."""

    def test_priority_tiers_valid_range(self):
        """Test that all priority tiers are in valid range (1-4)."""
        from scanning.modules.business_logic.categories.financial_edge_cases import FinancialEdgeCasesCategory
        from scanning.modules.business_logic.categories.race_conditions import RaceConditionsCategory
        from scanning.modules.business_logic.categories.workflow_bypass import WorkflowBypassCategory
        from scanning.modules.business_logic.categories.idor_testing import IDORTestingCategory
        from scanning.modules.business_logic.categories.idempotency_abuse import IdempotencyAbuseCategory
        from scanning.modules.business_logic.categories.inventory_manipulation import InventoryManipulationCategory

        categories = [
            FinancialEdgeCasesCategory(),
            RaceConditionsCategory(),
            WorkflowBypassCategory(),
            IDORTestingCategory(),
            IdempotencyAbuseCategory(),
            InventoryManipulationCategory(),
        ]

        for category in categories:
            assert 1 <= category.priority_tier <= 4, f"{category.name} has invalid priority tier"

    def test_critical_categories_tier_1(self):
        """Test that critical categories are tier 1."""
        from scanning.modules.business_logic.categories.financial_edge_cases import FinancialEdgeCasesCategory
        from scanning.modules.business_logic.categories.workflow_bypass import WorkflowBypassCategory

        # Financial manipulation and workflow bypass are critical
        assert FinancialEdgeCasesCategory().priority_tier == 1
        assert WorkflowBypassCategory().priority_tier == 1
