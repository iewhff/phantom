"""
Tests for utils/cvss_calculator.py - CVSS v3.1 score calculation.

Covers:
- AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, Impact enums
- CVSSVector dataclass (creation, from_string, to_string)
- CVSSCalculator (calculate, estimate_from_vulnerability, severity rating)
- Known CVSS scores from NVD for validation
"""

import pytest
from utils.cvss_calculator import (
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    Impact,
    CVSSVector,
    CVSSCalculator,
    calculate_cvss,
    estimate_cvss,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestAttackVector:
    """Tests for AttackVector enum."""

    def test_network_value(self):
        assert AttackVector.NETWORK.value == "N"

    def test_adjacent_value(self):
        assert AttackVector.ADJACENT.value == "A"

    def test_local_value(self):
        assert AttackVector.LOCAL.value == "L"

    def test_physical_value(self):
        assert AttackVector.PHYSICAL.value == "P"

    def test_all_values_present(self):
        assert len(AttackVector) == 4


class TestAttackComplexity:
    """Tests for AttackComplexity enum."""

    def test_low_value(self):
        assert AttackComplexity.LOW.value == "L"

    def test_high_value(self):
        assert AttackComplexity.HIGH.value == "H"


class TestPrivilegesRequired:
    """Tests for PrivilegesRequired enum."""

    def test_none_value(self):
        assert PrivilegesRequired.NONE.value == "N"

    def test_low_value(self):
        assert PrivilegesRequired.LOW.value == "L"

    def test_high_value(self):
        assert PrivilegesRequired.HIGH.value == "H"


class TestUserInteraction:
    """Tests for UserInteraction enum."""

    def test_none_value(self):
        assert UserInteraction.NONE.value == "N"

    def test_required_value(self):
        assert UserInteraction.REQUIRED.value == "R"


class TestScope:
    """Tests for Scope enum."""

    def test_unchanged_value(self):
        assert Scope.UNCHANGED.value == "U"

    def test_changed_value(self):
        assert Scope.CHANGED.value == "C"


class TestImpact:
    """Tests for Impact enum."""

    def test_none_value(self):
        assert Impact.NONE.value == "N"

    def test_low_value(self):
        assert Impact.LOW.value == "L"

    def test_high_value(self):
        assert Impact.HIGH.value == "H"


# =============================================================================
# CVSSVector TESTS
# =============================================================================

class TestCVSSVector:
    """Tests for CVSSVector dataclass."""

    def test_default_creation(self):
        """Test creating vector with defaults."""
        vector = CVSSVector()
        assert vector.attack_vector == AttackVector.NETWORK
        assert vector.attack_complexity == AttackComplexity.LOW
        assert vector.privileges_required == PrivilegesRequired.NONE
        assert vector.user_interaction == UserInteraction.NONE
        assert vector.scope == Scope.UNCHANGED
        assert vector.confidentiality == Impact.NONE
        assert vector.integrity == Impact.NONE
        assert vector.availability == Impact.NONE

    def test_custom_creation(self):
        """Test creating vector with custom values."""
        vector = CVSSVector(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.LOW,
            availability=Impact.NONE,
        )
        assert vector.attack_vector == AttackVector.LOCAL
        assert vector.scope == Scope.CHANGED
        assert vector.confidentiality == Impact.HIGH

    def test_from_string_full_vector(self):
        """Test parsing full CVSS vector string."""
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vector = CVSSVector.from_string(vector_str)

        assert vector.attack_vector == AttackVector.NETWORK
        assert vector.attack_complexity == AttackComplexity.LOW
        assert vector.privileges_required == PrivilegesRequired.NONE
        assert vector.user_interaction == UserInteraction.NONE
        assert vector.scope == Scope.UNCHANGED
        assert vector.confidentiality == Impact.HIGH
        assert vector.integrity == Impact.HIGH
        assert vector.availability == Impact.HIGH

    def test_from_string_without_prefix(self):
        """Test parsing vector string without CVSS:3.1 prefix."""
        vector_str = "AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"
        vector = CVSSVector.from_string(vector_str)

        assert vector.attack_vector == AttackVector.NETWORK
        assert vector.attack_complexity == AttackComplexity.HIGH
        assert vector.privileges_required == PrivilegesRequired.LOW
        assert vector.user_interaction == UserInteraction.REQUIRED
        assert vector.scope == Scope.CHANGED

    def test_from_string_physical_attack_vector(self):
        """Test parsing vector with physical attack vector."""
        vector_str = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vector = CVSSVector.from_string(vector_str)

        assert vector.attack_vector == AttackVector.PHYSICAL

    def test_from_string_adjacent_attack_vector(self):
        """Test parsing vector with adjacent network attack vector."""
        vector_str = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        vector = CVSSVector.from_string(vector_str)

        assert vector.attack_vector == AttackVector.ADJACENT

    def test_to_string(self):
        """Test converting vector to string."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )

        result = vector.to_string()
        assert result == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_roundtrip_conversion(self):
        """Test that from_string -> to_string preserves data."""
        original = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N"
        vector = CVSSVector.from_string(original)
        result = vector.to_string()

        assert result == original


# =============================================================================
# CVSSCalculator TESTS
# =============================================================================

class TestCVSSCalculatorBasicScores:
    """Tests for basic CVSS score calculations."""

    def test_critical_score_rce(self):
        """Test critical severity for RCE (9.8)."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )

        calc = CVSSCalculator()
        result = calc.calculate(vector)

        assert result["score"] == 9.8
        assert result["severity"] == "CRITICAL"

    def test_high_score_sqli(self):
        """Test high severity score."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.NONE,
        )

        calc = CVSSCalculator()
        result = calc.calculate(vector)

        assert 7.0 <= result["score"] < 9.0
        assert result["severity"] == "HIGH"

    def test_medium_score_info_disclosure(self):
        """Test medium severity score."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        )

        calc = CVSSCalculator()
        result = calc.calculate(vector)

        assert 4.0 <= result["score"] < 7.0
        assert result["severity"] == "MEDIUM"

    def test_low_score(self):
        """Test low severity score."""
        vector = CVSSVector(
            attack_vector=AttackVector.PHYSICAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        )

        calc = CVSSCalculator()
        result = calc.calculate(vector)

        assert result["score"] < 4.0
        assert result["severity"] == "LOW"

    def test_none_severity_no_impact(self):
        """Test score is 0 when all impacts are NONE."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.NONE,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        )

        calc = CVSSCalculator()
        result = calc.calculate(vector)

        assert result["score"] == 0.0
        assert result["severity"] == "NONE"


class TestCVSSCalculatorScopeChanged:
    """Tests for CVSS calculations with scope changed."""

    def test_xss_scope_changed(self):
        """Test XSS with scope changed (crosses security boundary)."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.CHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.LOW,
            availability=Impact.NONE,
        )

        calc = CVSSCalculator()
        result = calc.calculate(vector)

        # XSS with scope changed should be around 6.1
        assert 5.5 <= result["score"] <= 6.5
        assert result["severity"] == "MEDIUM"

    def test_pr_weights_change_with_scope(self):
        """Test that privileges required weights change with scope."""
        calc = CVSSCalculator()

        # Scope unchanged: PR=L is 0.62
        vector_unchanged = CVSSVector(
            privileges_required=PrivilegesRequired.LOW,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
        )

        # Scope changed: PR=L is 0.68
        vector_changed = CVSSVector(
            privileges_required=PrivilegesRequired.LOW,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
        )

        result_unchanged = calc.calculate(vector_unchanged)
        result_changed = calc.calculate(vector_changed)

        # Score with scope changed should be higher due to PR weight and impact formula
        assert result_changed["score"] > result_unchanged["score"]


class TestCVSSCalculatorFromString:
    """Tests for calculating from vector strings."""

    def test_calculate_from_string(self):
        """Test calculation from vector string."""
        calc = CVSSCalculator()
        result = calc.calculate_from_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        assert result["score"] == 9.8
        assert result["severity"] == "CRITICAL"
        assert result["vector_string"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_result_includes_components(self):
        """Test that result includes exploitability and impact components."""
        calc = CVSSCalculator()
        result = calc.calculate_from_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        assert "exploitability" in result
        assert "impact" in result
        assert isinstance(result["exploitability"], float)
        assert isinstance(result["impact"], float)


class TestCVSSEstimateFromVulnerability:
    """Tests for estimating CVSS from vulnerability type."""

    def test_estimate_sql_injection(self):
        """Test estimation for SQL injection."""
        calc = CVSSCalculator()
        result = calc.estimate_from_vulnerability("SQL_INJECTION")

        assert result["score"] == 9.8
        assert result["severity"] == "CRITICAL"
        assert result.get("estimated") is True

    def test_estimate_xss(self):
        """Test estimation for XSS."""
        calc = CVSSCalculator()
        result = calc.estimate_from_vulnerability("XSS")

        # XSS typically scores around 6.1
        assert 5.5 <= result["score"] <= 7.0
        assert result["severity"] in ("MEDIUM", "HIGH")

    def test_estimate_rce(self):
        """Test estimation for RCE."""
        calc = CVSSCalculator()
        result = calc.estimate_from_vulnerability("RCE")

        assert result["score"] == 10.0
        assert result["severity"] == "CRITICAL"

    def test_estimate_ssrf(self):
        """Test estimation for SSRF."""
        calc = CVSSCalculator()
        result = calc.estimate_from_vulnerability("SSRF")

        assert result["score"] >= 7.0
        assert result["severity"] in ("HIGH", "CRITICAL")

    def test_estimate_idor(self):
        """Test estimation for IDOR."""
        calc = CVSSCalculator()
        result = calc.estimate_from_vulnerability("IDOR")

        assert result["score"] >= 5.0
        assert result["severity"] in ("MEDIUM", "HIGH")

    def test_estimate_lfi(self):
        """Test estimation for LFI."""
        calc = CVSSCalculator()
        result = calc.estimate_from_vulnerability("LFI")

        assert result["score"] >= 7.0

    def test_estimate_xxe(self):
        """Test estimation for XXE."""
        calc = CVSSCalculator()
        result = calc.estimate_from_vulnerability("XXE")

        assert result["score"] >= 7.0

    def test_estimate_csrf(self):
        """Test estimation for CSRF."""
        calc = CVSSCalculator()
        result = calc.estimate_from_vulnerability("CSRF")

        # CSRF requires user interaction, typically medium
        assert result["severity"] in ("MEDIUM", "HIGH")

    def test_estimate_unknown_type(self):
        """Test estimation for unknown vulnerability type."""
        calc = CVSSCalculator()
        result = calc.estimate_from_vulnerability("UNKNOWN_VULN_TYPE")

        # Should default to medium severity
        assert result["severity"] == "MEDIUM"

    def test_estimate_case_insensitive(self):
        """Test that estimation works with different cases."""
        calc = CVSSCalculator()

        result_upper = calc.estimate_from_vulnerability("SQL_INJECTION")
        result_lower = calc.estimate_from_vulnerability("sql_injection")

        assert result_upper["score"] == result_lower["score"]

    def test_estimate_with_context_requires_auth(self):
        """Test estimation with requires_auth context."""
        calc = CVSSCalculator()

        result_no_auth = calc.estimate_from_vulnerability("SQL_INJECTION")
        result_with_auth = calc.estimate_from_vulnerability(
            "SQL_INJECTION",
            context={"requires_auth": True}
        )

        # With auth requirement, score should be lower
        assert result_with_auth["score"] <= result_no_auth["score"]

    def test_estimate_with_context_user_action(self):
        """Test estimation with requires_user_action context."""
        calc = CVSSCalculator()

        result_no_action = calc.estimate_from_vulnerability("SSRF")
        result_with_action = calc.estimate_from_vulnerability(
            "SSRF",
            context={"requires_user_action": True}
        )

        # With user action requirement, score should be lower
        assert result_with_action["score"] < result_no_action["score"]


class TestCVSSCalculatorSeverityMethods:
    """Tests for severity-related methods."""

    def test_get_severity_none(self):
        """Test severity for score 0."""
        assert CVSSCalculator._get_severity(0) == "NONE"

    def test_get_severity_low(self):
        """Test severity for low scores."""
        assert CVSSCalculator._get_severity(0.1) == "LOW"
        assert CVSSCalculator._get_severity(3.9) == "LOW"

    def test_get_severity_medium(self):
        """Test severity for medium scores."""
        assert CVSSCalculator._get_severity(4.0) == "MEDIUM"
        assert CVSSCalculator._get_severity(6.9) == "MEDIUM"

    def test_get_severity_high(self):
        """Test severity for high scores."""
        assert CVSSCalculator._get_severity(7.0) == "HIGH"
        assert CVSSCalculator._get_severity(8.9) == "HIGH"

    def test_get_severity_critical(self):
        """Test severity for critical scores."""
        assert CVSSCalculator._get_severity(9.0) == "CRITICAL"
        assert CVSSCalculator._get_severity(10.0) == "CRITICAL"

    def test_severity_to_score_range_none(self):
        """Test score range for NONE severity."""
        min_score, max_score = CVSSCalculator.severity_to_score_range("NONE")
        assert min_score == 0.0
        assert max_score == 0.0

    def test_severity_to_score_range_low(self):
        """Test score range for LOW severity."""
        min_score, max_score = CVSSCalculator.severity_to_score_range("LOW")
        assert min_score == 0.1
        assert max_score == 3.9

    def test_severity_to_score_range_medium(self):
        """Test score range for MEDIUM severity."""
        min_score, max_score = CVSSCalculator.severity_to_score_range("MEDIUM")
        assert min_score == 4.0
        assert max_score == 6.9

    def test_severity_to_score_range_high(self):
        """Test score range for HIGH severity."""
        min_score, max_score = CVSSCalculator.severity_to_score_range("HIGH")
        assert min_score == 7.0
        assert max_score == 8.9

    def test_severity_to_score_range_critical(self):
        """Test score range for CRITICAL severity."""
        min_score, max_score = CVSSCalculator.severity_to_score_range("CRITICAL")
        assert min_score == 9.0
        assert max_score == 10.0

    def test_severity_to_score_range_case_insensitive(self):
        """Test that severity_to_score_range is case insensitive."""
        range1 = CVSSCalculator.severity_to_score_range("critical")
        range2 = CVSSCalculator.severity_to_score_range("CRITICAL")
        assert range1 == range2

    def test_severity_to_score_range_unknown(self):
        """Test score range for unknown severity."""
        min_score, max_score = CVSSCalculator.severity_to_score_range("INVALID")
        assert min_score == 0.0
        assert max_score == 10.0


class TestCVSSCalculatorRounding:
    """Tests for CVSS rounding behavior."""

    def test_roundup_basic(self):
        """Test roundup function."""
        assert CVSSCalculator._roundup(7.54) == 7.6
        assert CVSSCalculator._roundup(7.50) == 7.5
        assert CVSSCalculator._roundup(7.51) == 7.6

    def test_roundup_preserves_exact(self):
        """Test roundup preserves exact decimals."""
        assert CVSSCalculator._roundup(9.0) == 9.0
        assert CVSSCalculator._roundup(10.0) == 10.0

    def test_roundup_small_decimal(self):
        """Test roundup for very small decimals."""
        assert CVSSCalculator._roundup(7.001) == 7.1


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================

class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_calculate_cvss_function(self):
        """Test calculate_cvss convenience function."""
        result = calculate_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        assert result["score"] == 9.8
        assert result["severity"] == "CRITICAL"

    def test_estimate_cvss_function(self):
        """Test estimate_cvss convenience function."""
        result = estimate_cvss("SQL_INJECTION")

        assert result["score"] == 9.8
        assert result.get("estimated") is True

    def test_estimate_cvss_with_kwargs(self):
        """Test estimate_cvss with context kwargs."""
        result = estimate_cvss("SQL_INJECTION", requires_auth=True)

        # Should adjust for auth requirement
        assert result["score"] < 9.8


# =============================================================================
# KNOWN VECTOR TESTS (Validation against real-world CVEs)
# =============================================================================

class TestKnownCVSSVectors:
    """Tests validating against known CVE CVSS scores."""

    def test_log4shell_style_vector(self):
        """Test Log4Shell-like vector (CVSS 10.0)."""
        # CVE-2021-44228 style: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
        result = calculate_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert result["score"] == 10.0
        assert result["severity"] == "CRITICAL"

    def test_heartbleed_style_vector(self):
        """Test Heartbleed-like vector (CVSS ~7.5)."""
        # CVE-2014-0160 style: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
        result = calculate_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        assert 7.0 <= result["score"] <= 8.0
        assert result["severity"] == "HIGH"

    def test_reflected_xss_vector(self):
        """Test typical reflected XSS vector."""
        # Reflected XSS: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
        result = calculate_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
        assert 6.0 <= result["score"] <= 6.5
        assert result["severity"] == "MEDIUM"

    def test_local_privilege_escalation_vector(self):
        """Test local privilege escalation vector."""
        # LPE: AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
        result = calculate_cvss("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        assert 7.5 <= result["score"] <= 8.0
        assert result["severity"] == "HIGH"


# =============================================================================
# EDGE CASES AND ERROR HANDLING
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_max_exploitability_min_impact(self):
        """Test maximum exploitability with minimum non-zero impact."""
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.LOW,
            integrity=Impact.NONE,
            availability=Impact.NONE,
        )

        calc = CVSSCalculator()
        result = calc.calculate(vector)

        # Should still produce a valid score
        assert result["score"] > 0
        assert result["score"] < 10.0

    def test_min_exploitability_max_impact(self):
        """Test minimum exploitability with maximum impact."""
        vector = CVSSVector(
            attack_vector=AttackVector.PHYSICAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.HIGH,
            user_interaction=UserInteraction.REQUIRED,
            scope=Scope.UNCHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )

        calc = CVSSCalculator()
        result = calc.calculate(vector)

        # Low exploitability reduces score despite high impact
        assert result["score"] < 7.0

    def test_partial_vector_string(self):
        """Test parsing partial vector string with missing components."""
        # from_string should use defaults for missing values
        vector = CVSSVector.from_string("AV:N/C:H")

        assert vector.attack_vector == AttackVector.NETWORK
        assert vector.confidentiality == Impact.HIGH
        # Defaults for others
        assert vector.attack_complexity == AttackComplexity.LOW

    def test_score_never_exceeds_10(self):
        """Test that score is capped at 10.0."""
        # Maximum everything
        vector = CVSSVector(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED,
            confidentiality=Impact.HIGH,
            integrity=Impact.HIGH,
            availability=Impact.HIGH,
        )

        calc = CVSSCalculator()
        result = calc.calculate(vector)

        assert result["score"] <= 10.0
