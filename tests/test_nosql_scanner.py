"""
Tests for scanning/modules/nosql_scanner.py

Covers:
- NoSQLDatabase enum (10 databases)
- InjectionType enum (15 types)
- WAFType enum (15 types)
- InjectionResult dataclass
- BaselineResponse dataclass
- NoSQLPayloads class (all payload categories)
- WAFDetector class
- DatabaseFingerprinter class
"""

import pytest
from unittest.mock import MagicMock, patch
from scanning.modules.nosql_scanner import (
    NOSQL_SCANNER_VERSION,
    NoSQLDatabase,
    InjectionType,
    WAFType,
    InjectionResult,
    BaselineResponse,
    NoSQLPayloads,
    WAFDetector,
    DatabaseFingerprinter,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestNoSQLDatabase:
    """Test NoSQLDatabase enum."""

    def test_count(self):
        assert len(NoSQLDatabase) == 10

    def test_mongodb(self):
        assert NoSQLDatabase.MONGODB is not None

    def test_couchdb(self):
        assert NoSQLDatabase.COUCHDB is not None

    def test_redis(self):
        assert NoSQLDatabase.REDIS is not None

    def test_cassandra(self):
        assert NoSQLDatabase.CASSANDRA is not None

    def test_firebase(self):
        assert NoSQLDatabase.FIREBASE is not None

    def test_dynamodb(self):
        assert NoSQLDatabase.DYNAMODB is not None

    def test_elasticsearch(self):
        assert NoSQLDatabase.ELASTICSEARCH is not None

    def test_neo4j(self):
        assert NoSQLDatabase.NEO4J is not None

    def test_arangodb(self):
        assert NoSQLDatabase.ARANGODB is not None

    def test_unknown(self):
        assert NoSQLDatabase.UNKNOWN is not None


class TestInjectionType:
    """Test InjectionType enum."""

    def test_count(self):
        assert len(InjectionType) == 15

    def test_operator_injection(self):
        assert InjectionType.OPERATOR_INJECTION is not None

    def test_where_injection(self):
        assert InjectionType.WHERE_INJECTION is not None

    def test_array_injection(self):
        assert InjectionType.ARRAY_INJECTION is not None

    def test_json_injection(self):
        assert InjectionType.JSON_INJECTION is not None

    def test_auth_bypass(self):
        assert InjectionType.AUTH_BYPASS is not None

    def test_blind_boolean(self):
        assert InjectionType.BLIND_BOOLEAN is not None

    def test_blind_time(self):
        assert InjectionType.BLIND_TIME is not None

    def test_error_based(self):
        assert InjectionType.ERROR_BASED is not None

    def test_union_based(self):
        assert InjectionType.UNION_BASED is not None

    def test_oob_injection(self):
        assert InjectionType.OOB_INJECTION is not None

    def test_prototype_pollution(self):
        assert InjectionType.PROTOTYPE_POLLUTION is not None

    def test_graphql_nosql(self):
        assert InjectionType.GRAPHQL_NOSQL is not None

    def test_aggregation_injection(self):
        assert InjectionType.AGGREGATION_INJECTION is not None

    def test_mapreduce_injection(self):
        assert InjectionType.MAPREDUCE_INJECTION is not None

    def test_regex_dos(self):
        assert InjectionType.REGEX_DOS is not None


class TestWAFType:
    """Test WAFType enum."""

    def test_count(self):
        assert len(WAFType) == 15

    def test_cloudflare(self):
        assert WAFType.CLOUDFLARE is not None

    def test_akamai(self):
        assert WAFType.AKAMAI is not None

    def test_aws_waf(self):
        assert WAFType.AWS_WAF is not None

    def test_imperva(self):
        assert WAFType.IMPERVA is not None

    def test_none(self):
        assert WAFType.NONE is not None

    def test_unknown(self):
        assert WAFType.UNKNOWN is not None

    def test_from_base_cloudflare(self):
        """Test conversion from base WAF type."""
        from utils.scanner_helpers import WAFType as BaseWAFType
        result = WAFType.from_base(BaseWAFType.CLOUDFLARE)
        assert result == WAFType.CLOUDFLARE

    def test_from_base_none(self):
        from utils.scanner_helpers import WAFType as BaseWAFType
        result = WAFType.from_base(BaseWAFType.NONE)
        assert result == WAFType.NONE

    def test_from_base_unknown_default(self):
        """Unknown base types should map to UNKNOWN."""
        # Create a mock that's not in the mapping
        mock_base = MagicMock()
        result = WAFType.from_base(mock_base)
        assert result == WAFType.UNKNOWN


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestInjectionResult:
    """Test InjectionResult dataclass."""

    def test_basic_creation(self):
        result = InjectionResult(
            vulnerable=True,
            injection_type=InjectionType.OPERATOR_INJECTION,
            database=NoSQLDatabase.MONGODB,
            payload='{"$ne": ""}',
            parameter="password",
            evidence="Authentication bypassed",
            confidence=85,
            response_time=0.15,
            status_code=200,
        )
        assert result.vulnerable is True
        assert result.injection_type == InjectionType.OPERATOR_INJECTION
        assert result.database == NoSQLDatabase.MONGODB
        assert result.confidence == 85
        assert result.waf_detected == WAFType.NONE
        assert result.can_extract_data is False
        assert result.rce_possible is False
        assert result.extracted_data == {}

    def test_with_data_extraction(self):
        result = InjectionResult(
            vulnerable=True,
            injection_type=InjectionType.WHERE_INJECTION,
            database=NoSQLDatabase.MONGODB,
            payload='{"$where": "throw JSON.stringify(this)"}',
            parameter="username",
            evidence="Data exposed: admin",
            confidence=95,
            response_time=0.3,
            status_code=500,
            can_extract_data=True,
            rce_possible=True,
            extracted_data={"username": "admin", "role": "superuser"},
        )
        assert result.can_extract_data is True
        assert result.rce_possible is True
        assert result.extracted_data["username"] == "admin"

    def test_with_waf(self):
        result = InjectionResult(
            vulnerable=False,
            injection_type=InjectionType.OPERATOR_INJECTION,
            database=NoSQLDatabase.UNKNOWN,
            payload='{"$ne": ""}',
            parameter="password",
            evidence="WAF blocked",
            confidence=0,
            response_time=0.05,
            status_code=403,
            waf_detected=WAFType.CLOUDFLARE,
        )
        assert result.vulnerable is False
        assert result.waf_detected == WAFType.CLOUDFLARE


class TestBaselineResponse:
    """Test BaselineResponse dataclass."""

    def test_basic_creation(self):
        baseline = BaselineResponse(
            status_code=200,
            content_length=5000,
            response_time=0.1,
            content_hash="abc123",
        )
        assert baseline.status_code == 200
        assert baseline.content_length == 5000
        assert baseline.error_patterns == []
        assert baseline.headers == {}

    def test_with_errors(self):
        baseline = BaselineResponse(
            status_code=200,
            content_length=3000,
            response_time=0.2,
            content_hash="def456",
            error_patterns=["error", "exception"],
            headers={"Content-Type": "text/html"},
        )
        assert len(baseline.error_patterns) == 2
        assert baseline.headers["Content-Type"] == "text/html"


# =============================================================================
# PAYLOAD TESTS
# =============================================================================

class TestMongoOperatorsBasic:
    """Test MongoDB basic operator payloads."""

    def test_not_empty(self):
        assert len(NoSQLPayloads.MONGO_OPERATORS_BASIC) > 0

    def test_has_ne_empty(self):
        assert {"$ne": ""} in NoSQLPayloads.MONGO_OPERATORS_BASIC

    def test_has_ne_null(self):
        assert {"$ne": None} in NoSQLPayloads.MONGO_OPERATORS_BASIC

    def test_has_gt_empty(self):
        assert {"$gt": ""} in NoSQLPayloads.MONGO_OPERATORS_BASIC

    def test_has_regex(self):
        assert {"$regex": ".*"} in NoSQLPayloads.MONGO_OPERATORS_BASIC

    def test_has_regex_admin(self):
        assert {"$regex": "^admin"} in NoSQLPayloads.MONGO_OPERATORS_BASIC

    def test_has_exists(self):
        assert {"$exists": True} in NoSQLPayloads.MONGO_OPERATORS_BASIC

    def test_has_type_checks(self):
        type_payloads = [p for p in NoSQLPayloads.MONGO_OPERATORS_BASIC if "$type" in p]
        assert len(type_payloads) >= 5

    def test_has_in_array(self):
        in_payloads = [p for p in NoSQLPayloads.MONGO_OPERATORS_BASIC if "$in" in p]
        assert len(in_payloads) >= 1

    def test_has_elemmatch(self):
        em_payloads = [p for p in NoSQLPayloads.MONGO_OPERATORS_BASIC if "$elemMatch" in p]
        assert len(em_payloads) >= 1

    def test_all_are_dicts(self):
        for p in NoSQLPayloads.MONGO_OPERATORS_BASIC:
            assert isinstance(p, dict)


class TestMongoOperatorsAdvanced:
    """Test MongoDB advanced operator payloads."""

    def test_not_empty(self):
        assert len(NoSQLPayloads.MONGO_OPERATORS_ADVANCED) > 0

    def test_has_or_operator(self):
        or_payloads = [p for p in NoSQLPayloads.MONGO_OPERATORS_ADVANCED if "$or" in p]
        assert len(or_payloads) >= 1

    def test_has_and_operator(self):
        and_payloads = [p for p in NoSQLPayloads.MONGO_OPERATORS_ADVANCED if "$and" in p]
        assert len(and_payloads) >= 1

    def test_has_not_operator(self):
        not_payloads = [p for p in NoSQLPayloads.MONGO_OPERATORS_ADVANCED if "$not" in p]
        assert len(not_payloads) >= 1

    def test_has_expr(self):
        expr_payloads = [p for p in NoSQLPayloads.MONGO_OPERATORS_ADVANCED if "$expr" in p]
        assert len(expr_payloads) >= 1

    def test_has_text_search(self):
        text_payloads = [p for p in NoSQLPayloads.MONGO_OPERATORS_ADVANCED if "$text" in p]
        assert len(text_payloads) >= 1

    def test_has_where(self):
        where_payloads = [p for p in NoSQLPayloads.MONGO_OPERATORS_ADVANCED if "$where" in p]
        assert len(where_payloads) >= 1


class TestMongoOperatorsEncoded:
    """Test encoded MongoDB operator payloads."""

    def test_not_empty(self):
        assert len(NoSQLPayloads.MONGO_OPERATORS_ENCODED) > 0

    def test_has_url_encoded_ne(self):
        assert "%24ne" in NoSQLPayloads.MONGO_OPERATORS_ENCODED

    def test_has_double_encoded(self):
        double = [p for p in NoSQLPayloads.MONGO_OPERATORS_ENCODED if "%25" in str(p)]
        assert len(double) >= 1

    def test_has_case_variations(self):
        assert "$NE" in NoSQLPayloads.MONGO_OPERATORS_ENCODED
        assert "$REGEX" in NoSQLPayloads.MONGO_OPERATORS_ENCODED


class TestWherePayloads:
    """Test $where JavaScript injection payloads."""

    def test_basic_not_empty(self):
        assert len(NoSQLPayloads.WHERE_PAYLOADS_BASIC) > 0

    def test_has_true_condition(self):
        assert "1==1" in NoSQLPayloads.WHERE_PAYLOADS_BASIC

    def test_has_string_comparison(self):
        assert "'a'=='a'" in NoSQLPayloads.WHERE_PAYLOADS_BASIC

    def test_has_function(self):
        assert any("function" in p for p in NoSQLPayloads.WHERE_PAYLOADS_BASIC)

    def test_has_this_access(self):
        assert any("this." in p for p in NoSQLPayloads.WHERE_PAYLOADS_BASIC)

    def test_time_based_not_empty(self):
        assert len(NoSQLPayloads.WHERE_PAYLOADS_TIME_BASED) > 0

    def test_time_based_has_sleep(self):
        assert any("sleep" in p for p in NoSQLPayloads.WHERE_PAYLOADS_TIME_BASED)

    def test_rce_not_empty(self):
        assert len(NoSQLPayloads.WHERE_PAYLOADS_RCE) > 0

    def test_rce_has_child_process(self):
        assert any("child_process" in p for p in NoSQLPayloads.WHERE_PAYLOADS_RCE)

    def test_rce_has_execsync(self):
        assert any("execSync" in p for p in NoSQLPayloads.WHERE_PAYLOADS_RCE)

    def test_rce_has_require(self):
        assert any("require" in p for p in NoSQLPayloads.WHERE_PAYLOADS_RCE)

    def test_data_exfil_not_empty(self):
        assert len(NoSQLPayloads.WHERE_PAYLOADS_DATA_EXFIL) > 0

    def test_data_exfil_has_throw(self):
        assert any("throw" in p for p in NoSQLPayloads.WHERE_PAYLOADS_DATA_EXFIL)

    def test_data_exfil_has_password_enum(self):
        assert any("password" in p for p in NoSQLPayloads.WHERE_PAYLOADS_DATA_EXFIL)


class TestArrayPayloads:
    """Test array/parameter injection payloads."""

    def test_not_empty(self):
        assert len(NoSQLPayloads.ARRAY_PAYLOADS) > 0

    def test_has_ne_bracket(self):
        assert "[$ne]=" in NoSQLPayloads.ARRAY_PAYLOADS

    def test_has_gt_bracket(self):
        assert "[$gt]=" in NoSQLPayloads.ARRAY_PAYLOADS

    def test_has_regex_bracket(self):
        assert "[$regex]=.*" in NoSQLPayloads.ARRAY_PAYLOADS

    def test_has_in_array(self):
        assert any("$in" in p for p in NoSQLPayloads.ARRAY_PAYLOADS)

    def test_has_or_array(self):
        assert any("$or" in p for p in NoSQLPayloads.ARRAY_PAYLOADS)

    def test_encoded_not_empty(self):
        assert len(NoSQLPayloads.ARRAY_PAYLOADS_ENCODED) > 0

    def test_encoded_has_url_encoded_brackets(self):
        assert any("%5B" in p for p in NoSQLPayloads.ARRAY_PAYLOADS_ENCODED)


class TestJSONPayloads:
    """Test JSON body injection payloads."""

    def test_not_empty(self):
        assert len(NoSQLPayloads.JSON_PAYLOADS) > 0

    def test_has_ne_json(self):
        assert '{"$ne": ""}' in NoSQLPayloads.JSON_PAYLOADS

    def test_has_where_json(self):
        assert '{"$where": "1==1"}' in NoSQLPayloads.JSON_PAYLOADS

    def test_has_or_json(self):
        assert any("$or" in p for p in NoSQLPayloads.JSON_PAYLOADS)

    def test_has_nested_json(self):
        assert any("username" in p and "password" in p for p in NoSQLPayloads.JSON_PAYLOADS)

    def test_prototype_not_empty(self):
        assert len(NoSQLPayloads.JSON_PAYLOADS_PROTOTYPE) > 0

    def test_prototype_has_proto(self):
        assert any("__proto__" in p for p in NoSQLPayloads.JSON_PAYLOADS_PROTOTYPE)

    def test_prototype_has_constructor(self):
        assert any("constructor" in p for p in NoSQLPayloads.JSON_PAYLOADS_PROTOTYPE)


class TestAuthBypassPayloads:
    """Test authentication bypass payloads."""

    def test_not_empty(self):
        assert len(NoSQLPayloads.AUTH_BYPASS_PAYLOADS) > 0

    def test_all_are_dicts(self):
        for p in NoSQLPayloads.AUTH_BYPASS_PAYLOADS:
            assert isinstance(p, dict)

    def test_has_classic_ne_bypass(self):
        """Classic $ne bypass: both username and password $ne empty."""
        assert {"username": {"$ne": ""}, "password": {"$ne": ""}} in NoSQLPayloads.AUTH_BYPASS_PAYLOADS

    def test_has_regex_bypass(self):
        regex_payloads = [p for p in NoSQLPayloads.AUTH_BYPASS_PAYLOADS if any(
            isinstance(v, dict) and "$regex" in v for v in p.values() if isinstance(v, dict)
        )]
        assert len(regex_payloads) >= 1

    def test_has_admin_target(self):
        admin_payloads = [p for p in NoSQLPayloads.AUTH_BYPASS_PAYLOADS
                          if p.get("username") == "admin"]
        assert len(admin_payloads) >= 1

    def test_has_where_bypass(self):
        where_payloads = [p for p in NoSQLPayloads.AUTH_BYPASS_PAYLOADS if "$where" in p]
        assert len(where_payloads) >= 1

    def test_has_or_bypass(self):
        or_payloads = [p for p in NoSQLPayloads.AUTH_BYPASS_PAYLOADS if "$or" in p]
        assert len(or_payloads) >= 1


class TestDatabaseSpecificPayloads:
    """Test database-specific payloads."""

    def test_couchdb_not_empty(self):
        assert len(NoSQLPayloads.COUCHDB_PAYLOADS) > 0

    def test_couchdb_has_selector(self):
        assert any("selector" in p for p in NoSQLPayloads.COUCHDB_PAYLOADS)

    def test_redis_not_empty(self):
        assert len(NoSQLPayloads.REDIS_PAYLOADS) > 0

    def test_redis_has_eval(self):
        assert any("EVAL" in p for p in NoSQLPayloads.REDIS_PAYLOADS)

    def test_redis_has_keys(self):
        assert any("KEYS" in p for p in NoSQLPayloads.REDIS_PAYLOADS)

    def test_cassandra_not_empty(self):
        assert len(NoSQLPayloads.CASSANDRA_PAYLOADS) > 0

    def test_cassandra_has_sql_like(self):
        assert any("OR" in p for p in NoSQLPayloads.CASSANDRA_PAYLOADS)

    def test_firebase_not_empty(self):
        assert len(NoSQLPayloads.FIREBASE_PAYLOADS) > 0

    def test_firebase_has_json(self):
        assert any(".json" in p for p in NoSQLPayloads.FIREBASE_PAYLOADS)

    def test_elasticsearch_not_empty(self):
        assert len(NoSQLPayloads.ELASTICSEARCH_PAYLOADS) > 0

    def test_elasticsearch_has_match_all(self):
        assert any("match_all" in p for p in NoSQLPayloads.ELASTICSEARCH_PAYLOADS)

    def test_neo4j_not_empty(self):
        assert len(NoSQLPayloads.NEO4J_PAYLOADS) > 0

    def test_neo4j_has_cypher(self):
        assert any("RETURN" in p or "MATCH" in p for p in NoSQLPayloads.NEO4J_PAYLOADS)

    def test_arangodb_not_empty(self):
        assert len(NoSQLPayloads.ARANGODB_PAYLOADS) > 0

    def test_dynamodb_not_empty(self):
        assert len(NoSQLPayloads.DYNAMODB_PAYLOADS) > 0

    def test_dynamodb_has_partiql(self):
        assert any("OR" in p for p in NoSQLPayloads.DYNAMODB_PAYLOADS)

    def test_influxdb_not_empty(self):
        assert len(NoSQLPayloads.INFLUXDB_PAYLOADS) > 0


class TestWAFBypassPayloads:
    """Test WAF bypass payloads."""

    def test_not_empty(self):
        assert len(NoSQLPayloads.WAF_BYPASS_PAYLOADS) > 0

    def test_all_are_dicts(self):
        for p in NoSQLPayloads.WAF_BYPASS_PAYLOADS:
            assert isinstance(p, dict)

    def test_has_unicode_escape(self):
        assert any("\\u" in str(k) for p in NoSQLPayloads.WAF_BYPASS_PAYLOADS for k in p.keys())

    def test_has_case_variation(self):
        assert any("$NE" in str(k) for p in NoSQLPayloads.WAF_BYPASS_PAYLOADS for k in p.keys())

    def test_has_double_encoding(self):
        assert any("%25" in str(k) for p in NoSQLPayloads.WAF_BYPASS_PAYLOADS for k in p.keys())


class TestBlindInjectionPayloads:
    """Test blind injection detection payloads."""

    def test_boolean_not_empty(self):
        assert len(NoSQLPayloads.BLIND_BOOLEAN_PAYLOADS) > 0

    def test_boolean_has_true_and_false(self):
        trues = [p for p, expected in NoSQLPayloads.BLIND_BOOLEAN_PAYLOADS if expected is True]
        falses = [p for p, expected in NoSQLPayloads.BLIND_BOOLEAN_PAYLOADS if expected is False]
        assert len(trues) >= 1
        assert len(falses) >= 1

    def test_time_not_empty(self):
        assert len(NoSQLPayloads.BLIND_TIME_PAYLOADS) > 0

    def test_time_has_sleep(self):
        assert any("sleep" in p for p, delay in NoSQLPayloads.BLIND_TIME_PAYLOADS)

    def test_time_delays_positive(self):
        for payload, delay in NoSQLPayloads.BLIND_TIME_PAYLOADS:
            assert delay > 0


class TestErrorPayloads:
    """Test error-based payloads."""

    def test_not_empty(self):
        assert len(NoSQLPayloads.ERROR_PAYLOADS) > 0

    def test_has_invalid_operator(self):
        assert any("invalidOp" in p for p in NoSQLPayloads.ERROR_PAYLOADS)

    def test_has_invalid_regex(self):
        """Invalid regex should trigger error messages."""
        assert any('"["' in p or "'['" in p or '$regex": "[' in p for p in NoSQLPayloads.ERROR_PAYLOADS)


class TestAggregationPayloads:
    """Test MongoDB aggregation pipeline payloads."""

    def test_not_empty(self):
        assert len(NoSQLPayloads.AGGREGATION_PAYLOADS) > 0

    def test_has_match(self):
        assert any("$match" in p for p in NoSQLPayloads.AGGREGATION_PAYLOADS)

    def test_has_group(self):
        assert any("$group" in p for p in NoSQLPayloads.AGGREGATION_PAYLOADS)

    def test_has_lookup(self):
        assert any("$lookup" in p for p in NoSQLPayloads.AGGREGATION_PAYLOADS)

    def test_has_out(self):
        assert any("$out" in p for p in NoSQLPayloads.AGGREGATION_PAYLOADS)


# =============================================================================
# WAF DETECTOR TESTS
# =============================================================================

class TestWAFDetector:
    """Test WAFDetector class."""

    @patch("scanning.modules.nosql_scanner.BaseWAFDetector")
    def test_detect_cloudflare(self, mock_base):
        from utils.scanner_helpers import WAFType as BaseWAFType
        mock_base.detect.return_value = (BaseWAFType.CLOUDFLARE, True)
        mock_response = MagicMock()
        result = WAFDetector.detect(mock_response)
        assert result == WAFType.CLOUDFLARE

    @patch("scanning.modules.nosql_scanner.BaseWAFDetector")
    def test_detect_none(self, mock_base):
        from utils.scanner_helpers import WAFType as BaseWAFType
        mock_base.detect.return_value = (BaseWAFType.NONE, False)
        mock_response = MagicMock()
        result = WAFDetector.detect(mock_response)
        assert result == WAFType.NONE

    @patch("scanning.modules.nosql_scanner.BaseWAFDetector")
    def test_is_blocked_true(self, mock_base):
        from utils.scanner_helpers import WAFType as BaseWAFType
        mock_base.detect.return_value = (BaseWAFType.CLOUDFLARE, True)
        mock_response = MagicMock()
        assert WAFDetector.is_blocked(mock_response) is True

    @patch("scanning.modules.nosql_scanner.BaseWAFDetector")
    def test_is_blocked_false(self, mock_base):
        from utils.scanner_helpers import WAFType as BaseWAFType
        mock_base.detect.return_value = (BaseWAFType.NONE, False)
        mock_response = MagicMock()
        assert WAFDetector.is_blocked(mock_response) is False


# =============================================================================
# DATABASE FINGERPRINTER TESTS
# =============================================================================

class TestDatabaseFingerprinter:
    """Test DatabaseFingerprinter class."""

    def test_has_error_patterns(self):
        assert len(DatabaseFingerprinter.ERROR_PATTERNS) > 0

    def test_mongodb_patterns(self):
        patterns = DatabaseFingerprinter.ERROR_PATTERNS[NoSQLDatabase.MONGODB]
        assert any("mongodb" in p for p in patterns)
        assert any("bson" in p for p in patterns)

    def test_couchdb_patterns(self):
        patterns = DatabaseFingerprinter.ERROR_PATTERNS[NoSQLDatabase.COUCHDB]
        assert any("couchdb" in p for p in patterns)

    def test_redis_patterns(self):
        patterns = DatabaseFingerprinter.ERROR_PATTERNS[NoSQLDatabase.REDIS]
        assert any("redis" in p for p in patterns)

    def test_cassandra_patterns(self):
        patterns = DatabaseFingerprinter.ERROR_PATTERNS[NoSQLDatabase.CASSANDRA]
        assert any("cassandra" in p for p in patterns)

    def test_elasticsearch_patterns(self):
        patterns = DatabaseFingerprinter.ERROR_PATTERNS[NoSQLDatabase.ELASTICSEARCH]
        assert any("elasticsearch" in p for p in patterns)

    def test_neo4j_patterns(self):
        patterns = DatabaseFingerprinter.ERROR_PATTERNS[NoSQLDatabase.NEO4J]
        assert any("neo4j" in p for p in patterns)

    def test_firebase_patterns(self):
        patterns = DatabaseFingerprinter.ERROR_PATTERNS[NoSQLDatabase.FIREBASE]
        assert any("firebase" in p for p in patterns)

    def test_dynamodb_patterns(self):
        patterns = DatabaseFingerprinter.ERROR_PATTERNS[NoSQLDatabase.DYNAMODB]
        assert any("dynamodb" in p for p in patterns)

    def test_arangodb_patterns(self):
        patterns = DatabaseFingerprinter.ERROR_PATTERNS[NoSQLDatabase.ARANGODB]
        assert any("arangodb" in p for p in patterns)

    def test_all_databases_covered(self):
        """All non-UNKNOWN databases should have fingerprint patterns."""
        for db in NoSQLDatabase:
            if db != NoSQLDatabase.UNKNOWN:
                assert db in DatabaseFingerprinter.ERROR_PATTERNS, f"Missing patterns for {db}"


# =============================================================================
# ATTACK SCENARIOS
# =============================================================================

class TestAttackScenarios:
    """Test realistic NoSQL injection attack scenarios."""

    def test_auth_bypass_scenario(self):
        """MongoDB auth bypass via $ne operator."""
        result = InjectionResult(
            vulnerable=True,
            injection_type=InjectionType.AUTH_BYPASS,
            database=NoSQLDatabase.MONGODB,
            payload='{"username": {"$ne": ""}, "password": {"$ne": ""}}',
            parameter="login_form",
            evidence="Redirected to dashboard, admin access granted",
            confidence=95,
            response_time=0.12,
            status_code=302,
        )
        assert result.vulnerable is True
        assert result.confidence == 95

    def test_blind_boolean_scenario(self):
        """Boolean-based blind NoSQL injection for data extraction."""
        result = InjectionResult(
            vulnerable=True,
            injection_type=InjectionType.BLIND_BOOLEAN,
            database=NoSQLDatabase.MONGODB,
            payload='{"password": {"$regex": "^a"}}',
            parameter="password",
            evidence="Different response for true vs false conditions",
            confidence=80,
            response_time=0.15,
            status_code=200,
            can_extract_data=True,
        )
        assert result.can_extract_data is True

    def test_rce_via_where(self):
        """RCE via $where clause in MongoDB."""
        result = InjectionResult(
            vulnerable=True,
            injection_type=InjectionType.WHERE_INJECTION,
            database=NoSQLDatabase.MONGODB,
            payload="this.constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')",
            parameter="search",
            evidence="uid=1000(node) gid=1000(node)",
            confidence=100,
            response_time=0.5,
            status_code=200,
            rce_possible=True,
            extracted_data={"command_output": "uid=1000(node) gid=1000(node)"},
        )
        assert result.rce_possible is True
        assert result.confidence == 100

    def test_prototype_pollution_scenario(self):
        """Prototype pollution via __proto__."""
        result = InjectionResult(
            vulnerable=True,
            injection_type=InjectionType.PROTOTYPE_POLLUTION,
            database=NoSQLDatabase.MONGODB,
            payload='{"__proto__": {"isAdmin": true}}',
            parameter="user_settings",
            evidence="isAdmin property added to all objects",
            confidence=75,
            response_time=0.2,
            status_code=200,
        )
        assert result.injection_type == InjectionType.PROTOTYPE_POLLUTION

    def test_time_based_blind_scenario(self):
        """Time-based blind NoSQL injection."""
        result = InjectionResult(
            vulnerable=True,
            injection_type=InjectionType.BLIND_TIME,
            database=NoSQLDatabase.MONGODB,
            payload='{"$where": "sleep(5000)"}',
            parameter="query",
            evidence="Response delayed by 5.1 seconds (baseline: 0.1s)",
            confidence=85,
            response_time=5.1,
            status_code=200,
        )
        assert result.response_time > 5.0


# =============================================================================
# EDGE CASES & VERSION
# =============================================================================

class TestEdgeCases:
    """Test edge cases."""

    def test_version(self):
        assert NOSQL_SCANNER_VERSION == "3.0.0-GOD-MODE"

    def test_injection_result_zero_confidence(self):
        result = InjectionResult(
            vulnerable=False,
            injection_type=InjectionType.OPERATOR_INJECTION,
            database=NoSQLDatabase.UNKNOWN,
            payload="test",
            parameter="test",
            evidence="",
            confidence=0,
            response_time=0.0,
            status_code=200,
        )
        assert result.confidence == 0

    def test_all_injection_types_unique(self):
        values = [t.value for t in InjectionType]
        assert len(values) == len(set(values))

    def test_all_databases_unique(self):
        values = [d.value for d in NoSQLDatabase]
        assert len(values) == len(set(values))
