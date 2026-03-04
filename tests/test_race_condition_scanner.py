"""
Tests for scanning/modules/race_condition_scanner.py

Covers:
- RaceVulnType enum (14 types)
- AttackTechnique enum (7 types)
- RacePattern enum (8 patterns)
- RaceEndpoint dataclass
- RaceRequest dataclass
- RaceResult dataclass
- RaceFinding dataclass
- ScanConfig dataclass
- RACE_PATTERNS constant
- TimingAnalyzer class
- SinglePacketAttack class
- Safety mode constants
"""

import pytest
from scanning.modules.race_condition_scanner import (
    VERSION,
    RaceVulnType,
    AttackTechnique,
    RacePattern,
    RaceEndpoint,
    RaceRequest,
    RaceResult,
    RaceFinding,
    ScanConfig,
    RACE_PATTERNS,
    TimingAnalyzer,
    SinglePacketAttack,
    MAX_CONCURRENT_REQUESTS,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestRaceVulnType:
    def test_count(self):
        assert len(RaceVulnType) == 14

    def test_limit_overrun(self):
        assert RaceVulnType.LIMIT_OVERRUN is not None

    def test_double_spend(self):
        assert RaceVulnType.DOUBLE_SPEND is not None

    def test_toctou(self):
        assert RaceVulnType.TOCTOU is not None

    def test_privilege_escalation(self):
        assert RaceVulnType.PRIVILEGE_ESCALATION is not None

    def test_coupon_abuse(self):
        assert RaceVulnType.COUPON_ABUSE is not None

    def test_balance_manipulation(self):
        assert RaceVulnType.BALANCE_MANIPULATION is not None

    def test_inventory_manipulation(self):
        assert RaceVulnType.INVENTORY_MANIPULATION is not None

    def test_token_reuse(self):
        assert RaceVulnType.TOKEN_REUSE is not None

    def test_vote_manipulation(self):
        assert RaceVulnType.VOTE_MANIPULATION is not None

    def test_subscription_abuse(self):
        assert RaceVulnType.SUBSCRIPTION_ABUSE is not None


class TestAttackTechnique:
    def test_count(self):
        assert len(AttackTechnique) == 7

    def test_single_packet(self):
        assert AttackTechnique.SINGLE_PACKET is not None

    def test_last_byte_sync(self):
        assert AttackTechnique.LAST_BYTE_SYNC is not None

    def test_connection_warming(self):
        assert AttackTechnique.CONNECTION_WARMING is not None

    def test_turbo_intruder(self):
        assert AttackTechnique.TURBO_INTRUDER is not None

    def test_multi_endpoint(self):
        assert AttackTechnique.MULTI_ENDPOINT is not None

    def test_state_machine(self):
        assert AttackTechnique.STATE_MACHINE is not None

    def test_read_modify_write(self):
        assert AttackTechnique.READ_MODIFY_WRITE is not None


class TestRacePattern:
    def test_count(self):
        assert len(RacePattern) == 8

    def test_redeem_reward(self):
        assert RacePattern.REDEEM_REWARD is not None

    def test_update_balance(self):
        assert RacePattern.UPDATE_BALANCE is not None

    def test_check_then_act(self):
        assert RacePattern.CHECK_THEN_ACT is not None

    def test_inventory_check(self):
        assert RacePattern.INVENTORY_CHECK is not None

    def test_session_update(self):
        assert RacePattern.SESSION_UPDATE is not None

    def test_email_verification(self):
        assert RacePattern.EMAIL_VERIFICATION is not None


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestRaceEndpoint:
    def test_defaults(self):
        ep = RaceEndpoint(url="https://target.com/api/redeem")
        assert ep.method == "POST"
        assert ep.headers == {}
        assert ep.params == {}
        assert ep.body is None
        assert ep.content_type == "application/x-www-form-urlencoded"
        assert ep.requires_auth is False
        assert ep.session_cookie is None
        assert ep.csrf_token is None
        assert ep.expected_success_code == 200

    def test_custom(self):
        ep = RaceEndpoint(
            url="https://target.com/api/checkout",
            method="POST",
            body='{"coupon": "DISCOUNT50"}',
            content_type="application/json",
            requires_auth=True,
            session_cookie="session=abc123",
            csrf_token="token123",
        )
        assert ep.requires_auth is True
        assert ep.csrf_token == "token123"


class TestRaceRequest:
    def test_defaults(self):
        ep = RaceEndpoint(url="https://target.com/api/redeem")
        req = RaceRequest(endpoint=ep)
        assert len(req.request_id) == 8
        assert req.timestamp_sent == 0.0
        assert req.response_code == 0
        assert req.was_successful is False
        assert req.error is None


class TestRaceResult:
    def test_creation(self):
        result = RaceResult(
            technique=AttackTechnique.SINGLE_PACKET,
            requests=[],
            total_sent=10,
            total_success=3,
            total_failures=7,
            avg_response_time=0.05,
            response_variance=0.01,
            evidence={"successes": 3},
            is_vulnerable=True,
            confidence=0.85,
        )
        assert result.is_vulnerable is True
        assert result.total_sent == 10


class TestRaceFinding:
    def test_creation(self):
        ep = RaceEndpoint(url="https://target.com/api/coupon")
        finding = RaceFinding(
            id="RACE-0001",
            vuln_type=RaceVulnType.COUPON_ABUSE,
            severity="HIGH",
            confidence=0.9,
            endpoint=ep,
            technique=AttackTechnique.SINGLE_PACKET,
            pattern=RacePattern.REDEEM_REWARD,
            description="Coupon code can be redeemed multiple times",
            impact="Financial loss through discount abuse",
            remediation="Use database-level locking",
            evidence={"successes": 5, "expected": 1},
            cwe_id=362,
            cvss_score=7.5,
            requests_needed=10,
            success_rate=50.0,
            timing_window_ms=5.0,
        )
        assert finding.cwe_id == 362
        assert finding.success_rate == 50.0


class TestScanConfig:
    def test_defaults(self):
        config = ScanConfig(target_url="https://target.com")
        assert config.max_concurrent_requests == 20
        assert config.burst_size == 10
        assert config.timeout == 30.0
        assert config.warmup_requests == 5
        assert config.iterations == 3
        assert config.use_http2 is True
        assert config.use_single_packet is True
        assert config.use_last_byte_sync is True
        assert config.safe_mode is True
        assert config.statistical_threshold == 0.1
        assert config.success_threshold == 2


# =============================================================================
# RACE PATTERNS CONSTANT
# =============================================================================

class TestRacePatterns:
    def test_not_empty(self):
        assert len(RACE_PATTERNS) > 0

    def test_has_coupon_redeem(self):
        assert "coupon_redeem" in RACE_PATTERNS
        coupon = RACE_PATTERNS["coupon_redeem"]
        assert "indicators" in coupon
        assert "params" in coupon
        assert coupon["vuln_type"] == RaceVulnType.COUPON_ABUSE

    def test_has_balance_transfer(self):
        assert "balance_transfer" in RACE_PATTERNS
        transfer = RACE_PATTERNS["balance_transfer"]
        assert transfer["vuln_type"] == RaceVulnType.BALANCE_MANIPULATION

    def test_has_purchase(self):
        assert "purchase" in RACE_PATTERNS
        purchase = RACE_PATTERNS["purchase"]
        assert purchase["vuln_type"] == RaceVulnType.INVENTORY_MANIPULATION

    def test_has_password_reset(self):
        assert "password_reset" in RACE_PATTERNS
        reset = RACE_PATTERNS["password_reset"]
        assert reset["vuln_type"] == RaceVulnType.TOKEN_REUSE

    def test_has_email_verification(self):
        assert "email_verification" in RACE_PATTERNS

    def test_has_session_update(self):
        assert "session_update" in RACE_PATTERNS
        session = RACE_PATTERNS["session_update"]
        assert session["vuln_type"] == RaceVulnType.PRIVILEGE_ESCALATION

    def test_has_file_upload(self):
        assert "file_upload" in RACE_PATTERNS
        upload = RACE_PATTERNS["file_upload"]
        assert upload["vuln_type"] == RaceVulnType.FILE_RACE

    def test_has_vote(self):
        assert "vote" in RACE_PATTERNS
        vote = RACE_PATTERNS["vote"]
        assert vote["vuln_type"] == RaceVulnType.VOTE_MANIPULATION

    def test_has_trial(self):
        assert "trial" in RACE_PATTERNS
        trial = RACE_PATTERNS["trial"]
        assert trial["vuln_type"] == RaceVulnType.SUBSCRIPTION_ABUSE

    def test_all_have_indicators(self):
        for name, pattern in RACE_PATTERNS.items():
            assert "indicators" in pattern, f"Missing indicators for {name}"
            assert len(pattern["indicators"]) > 0

    def test_all_have_params(self):
        for name, pattern in RACE_PATTERNS.items():
            assert "params" in pattern, f"Missing params for {name}"

    def test_all_have_vuln_type(self):
        for name, pattern in RACE_PATTERNS.items():
            assert "vuln_type" in pattern, f"Missing vuln_type for {name}"

    def test_all_have_pattern(self):
        for name, pattern in RACE_PATTERNS.items():
            assert "pattern" in pattern, f"Missing pattern for {name}"


# =============================================================================
# TIMING ANALYZER
# =============================================================================

class TestTimingAnalyzer:
    def test_version(self):
        assert TimingAnalyzer.VERSION == "3.0.0"

    def test_init(self):
        analyzer = TimingAnalyzer()
        assert analyzer.threshold == 0.1
        assert analyzer.baseline_times == []
        assert analyzer.race_times == []

    def test_custom_threshold(self):
        analyzer = TimingAnalyzer(threshold=0.05)
        assert analyzer.threshold == 0.05

    def test_set_baseline(self):
        analyzer = TimingAnalyzer()
        analyzer.set_baseline([0.1, 0.12, 0.11, 0.13])
        assert len(analyzer.baseline_times) == 4

    def test_add_race_times(self):
        analyzer = TimingAnalyzer()
        analyzer.add_race_times([0.05, 0.5, 0.06, 0.48])
        assert len(analyzer.race_times) == 4

    def test_analyze_insufficient_data(self):
        analyzer = TimingAnalyzer()
        result = analyzer.analyze()
        assert "error" in result

    def test_analyze_normal_times(self):
        analyzer = TimingAnalyzer()
        analyzer.set_baseline([0.1, 0.11, 0.1, 0.12])
        analyzer.add_race_times([0.1, 0.11, 0.12, 0.1])
        result = analyzer.analyze()
        assert "baseline_avg_ms" in result
        assert "race_avg_ms" in result
        assert "indicates_race" in result

    def test_analyze_bimodal_detection(self):
        analyzer = TimingAnalyzer()
        analyzer.set_baseline([0.1, 0.11, 0.1, 0.12])
        # Bimodal: some fast, some slow
        analyzer.add_race_times([0.05, 0.06, 0.5, 0.48, 0.05, 0.51])
        result = analyzer.analyze()
        assert "is_bimodal" in result

    def test_detect_bimodal_too_few(self):
        analyzer = TimingAnalyzer()
        result = analyzer._detect_bimodal([0.1, 0.2])
        assert result is False


# =============================================================================
# SINGLE PACKET ATTACK
# =============================================================================

class TestSinglePacketAttack:
    def test_version(self):
        assert SinglePacketAttack.VERSION == "3.0.1"

    def test_init(self):
        attack = SinglePacketAttack()
        assert attack.http_client is None
        assert attack._baseline_successes == 0


# =============================================================================
# SAFETY CONSTANTS
# =============================================================================

class TestSafetyConstants:
    def test_safe_mode_zero(self):
        assert MAX_CONCURRENT_REQUESTS["safe"] == 0

    def test_cautious_mode_limited(self):
        assert MAX_CONCURRENT_REQUESTS["cautious"] > 0
        assert MAX_CONCURRENT_REQUESTS["cautious"] <= 5

    def test_standard_mode(self):
        assert MAX_CONCURRENT_REQUESTS["standard"] >= 5

    def test_aggressive_mode_high(self):
        assert MAX_CONCURRENT_REQUESTS["aggressive"] >= 20


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_version(self):
        assert VERSION == "3.0.0"

    def test_all_vuln_types_unique(self):
        values = [t.value for t in RaceVulnType]
        assert len(values) == len(set(values))

    def test_all_techniques_unique(self):
        values = [t.value for t in AttackTechnique]
        assert len(values) == len(set(values))

    def test_all_patterns_unique(self):
        values = [p.value for p in RacePattern]
        assert len(values) == len(set(values))

    def test_race_patterns_count(self):
        assert len(RACE_PATTERNS) >= 10
