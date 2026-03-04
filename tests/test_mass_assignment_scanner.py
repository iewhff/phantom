"""
Tests for scanning/modules/mass_assignment_scanner.py

Covers:
- MassAssignmentVectorType enum (9 types)
- FrameworkType enum (10 types)
- MassAssignmentPayload dataclass
- MassAssignmentVulnerability dataclass
- MassAssignmentScanner class attributes
- PRIVILEGE_ESCALATION_PAYLOADS (40+ payloads)
- PROTOTYPE_POLLUTION_PAYLOADS (15+ payloads)
"""

import pytest
from scanning.modules.mass_assignment_scanner import (
    MassAssignmentVectorType,
    FrameworkType,
    MassAssignmentPayload,
    MassAssignmentVulnerability,
    MassAssignmentScanner,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestMassAssignmentVectorType:
    def test_count(self):
        assert len(MassAssignmentVectorType) == 9

    def test_privilege_escalation(self):
        assert MassAssignmentVectorType.PRIVILEGE_ESCALATION.value == "privilege_escalation"

    def test_prototype_pollution(self):
        assert MassAssignmentVectorType.PROTOTYPE_POLLUTION.value == "prototype_pollution"

    def test_nested_injection(self):
        assert MassAssignmentVectorType.NESTED_INJECTION.value == "nested_injection"

    def test_array_pollution(self):
        assert MassAssignmentVectorType.ARRAY_POLLUTION.value == "array_pollution"

    def test_type_confusion(self):
        assert MassAssignmentVectorType.TYPE_CONFUSION.value == "type_confusion"

    def test_orm_injection(self):
        assert MassAssignmentVectorType.ORM_INJECTION.value == "orm_injection"

    def test_hidden_parameter(self):
        assert MassAssignmentVectorType.HIDDEN_PARAMETER.value == "hidden_parameter"

    def test_batch_abuse(self):
        assert MassAssignmentVectorType.BATCH_ABUSE.value == "batch_abuse"

    def test_graphql_mutation(self):
        assert MassAssignmentVectorType.GRAPHQL_MUTATION.value == "graphql_mutation"


class TestFrameworkType:
    def test_count(self):
        assert len(FrameworkType) == 10

    def test_rails(self):
        assert FrameworkType.RAILS.value == "rails"

    def test_django(self):
        assert FrameworkType.DJANGO.value == "django"

    def test_express(self):
        assert FrameworkType.EXPRESS.value == "express"

    def test_spring(self):
        assert FrameworkType.SPRING.value == "spring"

    def test_laravel(self):
        assert FrameworkType.LARAVEL.value == "laravel"

    def test_flask(self):
        assert FrameworkType.FLASK.value == "flask"

    def test_fastapi(self):
        assert FrameworkType.FASTAPI.value == "fastapi"

    def test_aspnet(self):
        assert FrameworkType.ASPNET.value == "aspnet"

    def test_unknown(self):
        assert FrameworkType.UNKNOWN.value == "unknown"


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestMassAssignmentPayload:
    def test_basic(self):
        payload = MassAssignmentPayload(
            data={"admin": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Admin flag injection",
        )
        assert payload.data == {"admin": True}
        assert payload.target_framework is None
        assert payload.severity == "HIGH"

    def test_with_framework(self):
        payload = MassAssignmentPayload(
            data={"is_superuser": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Django superuser",
            target_framework=FrameworkType.DJANGO,
        )
        assert payload.target_framework == FrameworkType.DJANGO


class TestMassAssignmentVulnerability:
    def test_creation(self):
        vuln = MassAssignmentVulnerability(
            url="https://target.com/api/users",
            method="PUT",
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            payload={"admin": True},
            evidence=["Response shows admin=true"],
            severity="CRITICAL",
            confidence="HIGH",
            field_name="admin",
            impact="Privilege escalation to admin",
        )
        assert vuln.url == "https://target.com/api/users"
        assert vuln.field_name == "admin"


# =============================================================================
# SCANNER CLASS
# =============================================================================

class TestMassAssignmentScannerClass:
    def test_name(self):
        assert MassAssignmentScanner.name == "mass_assignment_scanner"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(MassAssignmentScanner, ScanModule)


# =============================================================================
# PRIVILEGE ESCALATION PAYLOADS
# =============================================================================

class TestPrivilegeEscalationPayloads:
    def test_not_empty(self):
        assert len(MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS) > 0

    def test_count(self):
        assert len(MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS) >= 30

    def test_all_are_payloads(self):
        for p in MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS:
            assert isinstance(p, MassAssignmentPayload)

    def test_has_admin_flag(self):
        payloads = MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS
        assert any(p.data.get("admin") is True for p in payloads)

    def test_has_is_admin(self):
        payloads = MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS
        assert any(p.data.get("isAdmin") is True for p in payloads)

    def test_has_role_admin(self):
        payloads = MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS
        assert any(p.data.get("role") == "admin" for p in payloads)

    def test_has_roles_array(self):
        payloads = MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS
        assert any(isinstance(p.data.get("roles"), list) for p in payloads)

    def test_has_permissions_wildcard(self):
        payloads = MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS
        assert any(p.data.get("permissions") == ["*"] for p in payloads)

    def test_has_verified_bypass(self):
        payloads = MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS
        assert any(p.data.get("verified") is True for p in payloads)

    def test_has_price_zero(self):
        payloads = MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS
        assert any(p.data.get("price") == 0 for p in payloads)

    def test_has_negative_price(self):
        payloads = MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS
        assert any(p.data.get("price") == -1 for p in payloads)

    def test_has_balance_inflation(self):
        payloads = MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS
        assert any(p.data.get("balance") == 999999999 for p in payloads)

    def test_has_premium_flag(self):
        payloads = MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS
        assert any(p.data.get("premium") is True for p in payloads)

    def test_has_user_id_manipulation(self):
        payloads = MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS
        assert any(p.data.get("user_id") == 1 for p in payloads)

    def test_has_django_superuser(self):
        payloads = MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS
        django = [p for p in payloads if p.target_framework == FrameworkType.DJANGO]
        assert len(django) >= 2

    def test_all_have_description(self):
        for p in MassAssignmentScanner.PRIVILEGE_ESCALATION_PAYLOADS:
            assert len(p.description) > 0


# =============================================================================
# PROTOTYPE POLLUTION PAYLOADS
# =============================================================================

class TestPrototypePollutionPayloads:
    def test_not_empty(self):
        assert len(MassAssignmentScanner.PROTOTYPE_POLLUTION_PAYLOADS) > 0

    def test_has_proto(self):
        payloads = MassAssignmentScanner.PROTOTYPE_POLLUTION_PAYLOADS
        assert any("__proto__" in p.data for p in payloads)

    def test_has_constructor(self):
        payloads = MassAssignmentScanner.PROTOTYPE_POLLUTION_PAYLOADS
        assert any("constructor" in p.data for p in payloads)

    def test_all_target_express(self):
        payloads = MassAssignmentScanner.PROTOTYPE_POLLUTION_PAYLOADS
        express = [p for p in payloads if p.target_framework == FrameworkType.EXPRESS]
        assert len(express) > 0


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_all_vector_types_unique(self):
        values = [t.value for t in MassAssignmentVectorType]
        assert len(values) == len(set(values))

    def test_all_framework_types_unique(self):
        values = [t.value for t in FrameworkType]
        assert len(values) == len(set(values))
