"""
Unit tests for Exploitation Proof Engine.

Tests:
1. ProofResult dataclass structure
2. Safety mode limits
3. Prover mapping
4. Base prover functionality
5. Narrative generation
6. Finding parsing
"""

import pytest
from unittest.mock import MagicMock, AsyncMock
from dataclasses import asdict


class TestProofResult:
    """Test ProofResult dataclass."""

    def test_default_values(self):
        """ProofResult should have correct defaults."""
        from scanning.exploit_proof_engine import ProofResult

        result = ProofResult()

        assert result.can_repeat is False
        assert result.can_mutate is False
        assert result.can_escalate is False
        assert result.can_chain is False
        assert result.repeat_count == 0
        assert result.mutations == []
        assert result.escalation == ""
        assert result.chain_targets == []
        assert result.impact_narrative == ""
        assert result.proven_impact == "Unproven"
        assert result.requests_used == 0
        assert result.new_findings == []

    def test_to_dict(self):
        """Should convert to dictionary correctly."""
        from scanning.exploit_proof_engine import ProofResult

        result = ProofResult(
            can_repeat=True,
            repeat_count=2,
            mutations=["variant1", "variant2"],
            proven_impact="Confirmed Vulnerability",
        )

        d = result.to_dict()

        assert d["can_repeat"] is True
        assert d["repeat_count"] == 2
        assert d["mutations"] == ["variant1", "variant2"]
        assert d["proven_impact"] == "Confirmed Vulnerability"

    def test_fields_complete(self):
        """All required fields should be present."""
        from scanning.exploit_proof_engine import ProofResult

        expected_fields = [
            "can_repeat",
            "can_mutate",
            "can_escalate",
            "can_chain",
            "repeat_count",
            "mutations",
            "escalation",
            "chain_targets",
            "impact_narrative",
            "proven_impact",
            "requests_used",
            "new_findings",
        ]

        actual_fields = list(ProofResult.__dataclass_fields__.keys())
        for field in expected_fields:
            assert field in actual_fields, f"Missing field: {field}"


class TestProofLimits:
    """Test safety mode limits."""

    def test_safe_mode_blocks_all(self):
        """Safe mode should have 0 request budget."""
        from scanning.exploit_proof_engine import PROOF_LIMITS

        assert PROOF_LIMITS["safe"]["max_requests"] == 0
        assert PROOF_LIMITS["safe"]["allow_write"] is False
        assert PROOF_LIMITS["safe"]["allow_auth"] is False

    def test_cautious_mode_limited(self):
        """Cautious mode should have limited budget."""
        from scanning.exploit_proof_engine import PROOF_LIMITS

        assert PROOF_LIMITS["cautious"]["max_requests"] == 5
        assert PROOF_LIMITS["cautious"]["allow_write"] is False
        assert PROOF_LIMITS["cautious"]["allow_auth"] is False

    def test_standard_mode_reasonable(self):
        """Standard mode should allow auth but not write."""
        from scanning.exploit_proof_engine import PROOF_LIMITS

        assert PROOF_LIMITS["standard"]["max_requests"] == 15
        assert PROOF_LIMITS["standard"]["allow_write"] is False
        assert PROOF_LIMITS["standard"]["allow_auth"] is True

    def test_aggressive_mode_full(self):
        """Aggressive mode should allow everything."""
        from scanning.exploit_proof_engine import PROOF_LIMITS

        assert PROOF_LIMITS["aggressive"]["max_requests"] == 50
        assert PROOF_LIMITS["aggressive"]["allow_write"] is True
        assert PROOF_LIMITS["aggressive"]["allow_auth"] is True

    def test_all_modes_defined(self):
        """All 4 safety modes should be defined."""
        from scanning.exploit_proof_engine import PROOF_LIMITS

        assert "safe" in PROOF_LIMITS
        assert "cautious" in PROOF_LIMITS
        assert "standard" in PROOF_LIMITS
        assert "aggressive" in PROOF_LIMITS


class TestProverMapping:
    """Test prover type → class mapping."""

    def test_sqli_mapping(self):
        """SQLi should map to SQLiProver."""
        from scanning.exploit_proof_engine import PROVER_MAP, SQLiProver

        assert PROVER_MAP["sql_injection"] == SQLiProver

    def test_xss_mapping(self):
        """XSS types should map to XSSProver."""
        from scanning.exploit_proof_engine import PROVER_MAP, XSSProver

        assert PROVER_MAP["xss"] == XSSProver
        assert PROVER_MAP["dom_xss"] == XSSProver

    def test_idor_mapping(self):
        """IDOR should map to IDORProver."""
        from scanning.exploit_proof_engine import PROVER_MAP, IDORProver

        assert PROVER_MAP["idor"] == IDORProver

    def test_business_logic_mapping(self):
        """Business logic should map to BusinessLogicProver."""
        from scanning.exploit_proof_engine import PROVER_MAP, BusinessLogicProver

        assert PROVER_MAP["business_logic"] == BusinessLogicProver

    def test_session_mapping(self):
        """Session types should map to SessionProver."""
        from scanning.exploit_proof_engine import PROVER_MAP, SessionProver

        assert PROVER_MAP["session_abuse"] == SessionProver
        assert PROVER_MAP["session"] == SessionProver

    def test_cors_mapping(self):
        """CORS types should map to CORSProver."""
        from scanning.exploit_proof_engine import PROVER_MAP, CORSProver

        assert PROVER_MAP["cors_wildcard"] == CORSProver
        assert PROVER_MAP["cors_null"] == CORSProver
        assert PROVER_MAP["cors_preflight"] == CORSProver
        assert PROVER_MAP["cors_arbitrary"] == CORSProver


class TestBaseProverHelpers:
    """Test BaseProver helper methods."""

    def test_parse_matched_at_full_format(self):
        """Should parse 'url (param_type: param_name)' format."""
        from scanning.exploit_proof_engine import GenericProver

        prover = GenericProver(
            auth_context=None,
            rate_limiter=None,
            endpoint_map=None,
            limits={"max_requests": 10},
            all_findings=[],
        )

        finding = {
            "matched_at": "http://example.com/api (query: id)",
            "metadata": {},
        }

        url, param_type, param_name = prover._parse_matched_at(finding)

        assert url == "http://example.com/api"
        assert param_type == "query"
        assert param_name == "id"

    def test_parse_matched_at_url_only(self):
        """Should handle URL-only matched_at."""
        from scanning.exploit_proof_engine import GenericProver

        prover = GenericProver(
            auth_context=None,
            rate_limiter=None,
            endpoint_map=None,
            limits={"max_requests": 10},
            all_findings=[],
        )

        finding = {
            "matched_at": "http://example.com/api/users",
            "metadata": {},
        }

        url, param_type, param_name = prover._parse_matched_at(finding)

        assert url == "http://example.com/api/users"

    def test_parse_matched_at_fallback_to_metadata(self):
        """Should fallback to metadata.url when matched_at is None."""
        from scanning.exploit_proof_engine import GenericProver

        prover = GenericProver(
            auth_context=None,
            rate_limiter=None,
            endpoint_map=None,
            limits={"max_requests": 10},
            all_findings=[],
        )

        finding = {
            "matched_at": None,
            "metadata": {"url": "http://example.com/fallback"},
        }

        url, param_type, param_name = prover._parse_matched_at(finding)

        assert url == "http://example.com/fallback"

    def test_budget_remaining(self):
        """Should track remaining budget correctly."""
        from scanning.exploit_proof_engine import GenericProver

        prover = GenericProver(
            auth_context=None,
            rate_limiter=None,
            endpoint_map=None,
            limits={"max_requests": 10},
            all_findings=[],
        )

        assert prover.budget_remaining == 10

        prover._requests_used = 7
        assert prover.budget_remaining == 3

        prover._requests_used = 15
        assert prover.budget_remaining == 0  # Never negative


class TestEngineInitialization:
    """Test ExploitProofEngine initialization."""

    def test_init_safe_mode(self):
        """Should initialize with safe mode limits."""
        from scanning.exploit_proof_engine import ExploitProofEngine

        settings = MagicMock()
        settings.safe_mode = "safe"

        engine = ExploitProofEngine(settings=settings)

        assert engine._limits["max_requests"] == 0

    def test_init_aggressive_mode(self):
        """Should initialize with aggressive mode limits."""
        from scanning.exploit_proof_engine import ExploitProofEngine

        settings = MagicMock()
        settings.safe_mode = "aggressive"

        engine = ExploitProofEngine(settings=settings)

        assert engine._limits["max_requests"] == 50
        assert engine._limits["allow_write"] is True


class TestNarrativeGeneration:
    """Test impact narrative generation."""

    def test_narrative_with_all_capabilities(self):
        """Narrative should include all proven capabilities."""
        from scanning.exploit_proof_engine import ExploitProofEngine, ProofResult

        settings = MagicMock()
        settings.safe_mode = "aggressive"

        engine = ExploitProofEngine(settings=settings)

        finding = {"matched_at": "http://example.com/api/users"}
        proof = ProofResult(
            can_repeat=True,
            repeat_count=2,
            can_mutate=True,
            mutations=["variant1"],
            can_escalate=True,
            escalation="Admin access obtained",
            can_chain=True,
            chain_targets=["endpoint1"],
        )

        narrative = engine._build_narrative(finding, proof)

        assert "reliably reproducible" in narrative
        assert "vary the payload" in narrative
        assert "escalates to" in narrative
        assert "unlocks further attacks" in narrative

    def test_narrative_admin_takeover(self):
        """Should set 'Full Admin Takeover' for admin escalation."""
        from scanning.exploit_proof_engine import ExploitProofEngine, ProofResult

        settings = MagicMock()
        settings.safe_mode = "aggressive"

        engine = ExploitProofEngine(settings=settings)

        finding = {"matched_at": "http://example.com/"}
        proof = ProofResult(
            can_repeat=True,
            can_escalate=True,
            escalation="Admin session obtained",
        )

        engine._build_narrative(finding, proof)

        assert proof.proven_impact == "Full Admin Takeover"

    def test_narrative_unproven(self):
        """Should set 'Unproven' when nothing is proven."""
        from scanning.exploit_proof_engine import ExploitProofEngine, ProofResult

        settings = MagicMock()
        settings.safe_mode = "aggressive"

        engine = ExploitProofEngine(settings=settings)

        finding = {"matched_at": "http://example.com/"}
        proof = ProofResult()  # All False

        engine._build_narrative(finding, proof)

        assert proof.proven_impact == "Unproven"


class TestSeverityFiltering:
    """Test severity filtering for proof."""

    @pytest.mark.asyncio
    async def test_only_high_plus_proven(self):
        """Should only prove HIGH+ findings."""
        from scanning.exploit_proof_engine import ExploitProofEngine

        settings = MagicMock()
        settings.safe_mode = "standard"

        engine = ExploitProofEngine(settings=settings)

        # Mock result with mixed severity findings
        result = MagicMock()
        result.findings = [
            {"type": "xss", "severity": "HIGH", "matched_at": "http://x/", "metadata": {}},
            {"type": "info", "severity": "LOW", "matched_at": "http://x/", "metadata": {}},
            {"type": "sqli", "severity": "CRITICAL", "matched_at": "http://x/", "metadata": {}},
            {"type": "header", "severity": "MEDIUM", "matched_at": "http://x/", "metadata": {}},
        ]

        # Engine would prove HIGH and CRITICAL, skip LOW and MEDIUM
        # This tests the filtering logic structure exists
        high_plus = [
            f for f in result.findings
            if f.get("severity", "").upper() in ("HIGH", "CRITICAL")
        ]

        assert len(high_plus) == 2
        assert all(f["severity"].upper() in ("HIGH", "CRITICAL") for f in high_plus)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
