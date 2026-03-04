"""
Tests for scanning/modules/backend_detector.py

Covers:
- BackendType enum (6 members)
- SupabaseConfig dataclass (defaults, is_valid, has_service_role)
- FirebaseConfig dataclass (defaults, is_valid)
- ThirdPartyKeys dataclass (defaults, has_critical_exposure)
- BackendDetectionResult dataclass (get_applicable_phases for each backend type)
"""

import pytest
from scanning.modules.backend_detector import (
    BackendType,
    SupabaseConfig,
    FirebaseConfig,
    ThirdPartyKeys,
    BackendDetectionResult,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestBackendType:
    """Test BackendType enum."""

    def test_count(self):
        assert len(BackendType) == 6

    def test_supabase(self):
        assert BackendType.SUPABASE is not None

    def test_firebase(self):
        assert BackendType.FIREBASE is not None

    def test_mongodb_atlas(self):
        assert BackendType.MONGODB_ATLAS is not None

    def test_custom_rest(self):
        assert BackendType.CUSTOM_REST is not None

    def test_custom_graphql(self):
        assert BackendType.CUSTOM_GRAPHQL is not None

    def test_unknown(self):
        assert BackendType.UNKNOWN is not None

    def test_all_unique(self):
        values = [member.value for member in BackendType]
        assert len(values) == len(set(values))


# =============================================================================
# SUPABASE CONFIG TESTS
# =============================================================================

class TestSupabaseConfig:
    """Test SupabaseConfig dataclass."""

    def test_defaults(self):
        config = SupabaseConfig()
        assert config.project_url == ""
        assert config.anon_key == ""
        assert config.service_role_key == ""
        assert config.project_ref == ""

    def test_is_valid_requires_url_and_key(self):
        config = SupabaseConfig()
        assert config.is_valid is False

    def test_is_valid_with_url_only(self):
        config = SupabaseConfig(project_url="https://abc.supabase.co")
        assert config.is_valid is False

    def test_is_valid_with_key_only(self):
        config = SupabaseConfig(anon_key="eyJtest.eyJtest.test")
        assert config.is_valid is False

    def test_is_valid_with_both(self):
        config = SupabaseConfig(
            project_url="https://abc.supabase.co",
            anon_key="eyJtest.eyJtest.test",
        )
        assert config.is_valid is True

    def test_has_service_role_false_by_default(self):
        config = SupabaseConfig()
        assert config.has_service_role is False

    def test_has_service_role_true_when_set(self):
        config = SupabaseConfig(service_role_key="eyJservice.eyJrole.key")
        assert config.has_service_role is True

    def test_has_service_role_false_for_empty_string(self):
        config = SupabaseConfig(service_role_key="")
        assert config.has_service_role is False

    def test_custom_values(self):
        config = SupabaseConfig(
            project_url="https://myproj.supabase.co",
            anon_key="anon_key_value",
            service_role_key="srk_value",
            project_ref="myproj",
        )
        assert config.project_url == "https://myproj.supabase.co"
        assert config.anon_key == "anon_key_value"
        assert config.service_role_key == "srk_value"
        assert config.project_ref == "myproj"


# =============================================================================
# FIREBASE CONFIG TESTS
# =============================================================================

class TestFirebaseConfig:
    """Test FirebaseConfig dataclass."""

    def test_defaults(self):
        config = FirebaseConfig()
        assert config.api_key == ""
        assert config.auth_domain == ""
        assert config.project_id == ""
        assert config.storage_bucket == ""
        assert config.messaging_sender_id == ""
        assert config.app_id == ""
        assert config.database_url == ""

    def test_is_valid_requires_api_key_and_project_id(self):
        config = FirebaseConfig()
        assert config.is_valid is False

    def test_is_valid_with_api_key_only(self):
        config = FirebaseConfig(api_key="AIzaSyTest123")
        assert config.is_valid is False

    def test_is_valid_with_project_id_only(self):
        config = FirebaseConfig(project_id="my-project")
        assert config.is_valid is False

    def test_is_valid_with_both(self):
        config = FirebaseConfig(
            api_key="AIzaSyTest123",
            project_id="my-project",
        )
        assert config.is_valid is True

    def test_custom_values(self):
        config = FirebaseConfig(
            api_key="AIzaSyTest123",
            auth_domain="myapp.firebaseapp.com",
            project_id="my-project",
            storage_bucket="my-project.appspot.com",
            messaging_sender_id="123456789",
            app_id="1:123456789:web:abc123",
            database_url="my-project.firebaseio.com",
        )
        assert config.api_key == "AIzaSyTest123"
        assert config.auth_domain == "myapp.firebaseapp.com"
        assert config.project_id == "my-project"
        assert config.storage_bucket == "my-project.appspot.com"
        assert config.messaging_sender_id == "123456789"
        assert config.app_id == "1:123456789:web:abc123"
        assert config.database_url == "my-project.firebaseio.com"
        assert config.is_valid is True


# =============================================================================
# THIRD PARTY KEYS TESTS
# =============================================================================

class TestThirdPartyKeys:
    """Test ThirdPartyKeys dataclass."""

    def test_defaults(self):
        keys = ThirdPartyKeys()
        assert keys.stripe_publishable == []
        assert keys.stripe_secret == []
        assert keys.sentry_dsn == []
        assert keys.posthog_key == ""
        assert keys.google_analytics == []
        assert keys.facebook_pixel == []
        assert keys.recaptcha_sitekey == ""
        assert keys.hcaptcha_sitekey == ""

    def test_has_critical_exposure_false_by_default(self):
        keys = ThirdPartyKeys()
        assert keys.has_critical_exposure is False

    def test_has_critical_exposure_true_with_stripe_secret(self):
        keys = ThirdPartyKeys(stripe_secret=["sk_live_abc123"])
        assert keys.has_critical_exposure is True

    def test_has_critical_exposure_false_with_empty_stripe_secret(self):
        keys = ThirdPartyKeys(stripe_secret=[])
        assert keys.has_critical_exposure is False

    def test_has_critical_exposure_true_with_multiple_secrets(self):
        keys = ThirdPartyKeys(
            stripe_secret=["sk_live_abc123", "sk_test_xyz789"]
        )
        assert keys.has_critical_exposure is True

    def test_publishable_key_not_critical(self):
        keys = ThirdPartyKeys(
            stripe_publishable=["pk_live_abc123"],
        )
        assert keys.has_critical_exposure is False

    def test_sentry_dsn_not_critical(self):
        keys = ThirdPartyKeys(
            sentry_dsn=["https://abc@o123.ingest.sentry.io/456"],
        )
        assert keys.has_critical_exposure is False

    def test_list_fields_are_independent(self):
        """Ensure default_factory creates separate list instances."""
        keys1 = ThirdPartyKeys()
        keys2 = ThirdPartyKeys()
        keys1.stripe_publishable.append("pk_test_123")
        assert keys2.stripe_publishable == []


# =============================================================================
# BACKEND DETECTION RESULT TESTS
# =============================================================================

class TestBackendDetectionResult:
    """Test BackendDetectionResult dataclass."""

    def test_defaults(self):
        result = BackendDetectionResult(
            backend_type=BackendType.UNKNOWN,
            confidence=0.0,
        )
        assert result.backend_type == BackendType.UNKNOWN
        assert result.confidence == 0.0
        assert result.supabase_config is None
        assert result.firebase_config is None
        assert isinstance(result.third_party, ThirdPartyKeys)
        assert result.api_endpoints == []
        assert result.graphql_endpoint == ""
        assert result.websocket_endpoint == ""
        assert result.detected_frameworks == []
        assert result.env_variables == {}

    def test_common_phases_present_for_all_types(self):
        """All backend types must include common phases."""
        common = ["0", "7", "10", "12", "14", "15", "19", "CSRF", "XSS", "SQLI", "HEADERS"]
        for bt in BackendType:
            result = BackendDetectionResult(backend_type=bt, confidence=0.5)
            phases = result.get_applicable_phases()
            for phase in common:
                assert phase in phases, (
                    f"Phase {phase} missing for {bt.name}"
                )

    def test_supabase_phases(self):
        result = BackendDetectionResult(
            backend_type=BackendType.SUPABASE,
            confidence=0.95,
        )
        phases = result.get_applicable_phases()
        supabase_specific = ["2", "3", "4", "5", "6", "20", "20-ADV"]
        for phase in supabase_specific:
            assert phase in phases, (
                f"Supabase-specific phase {phase} missing"
            )

    def test_supabase_phases_exclude_firebase(self):
        result = BackendDetectionResult(
            backend_type=BackendType.SUPABASE,
            confidence=0.95,
        )
        phases = result.get_applicable_phases()
        assert "F1" not in phases
        assert "F2" not in phases

    def test_firebase_phases(self):
        result = BackendDetectionResult(
            backend_type=BackendType.FIREBASE,
            confidence=0.95,
        )
        phases = result.get_applicable_phases()
        firebase_specific = ["F1", "F2", "F3", "F4"]
        for phase in firebase_specific:
            assert phase in phases, (
                f"Firebase-specific phase {phase} missing"
            )

    def test_firebase_phases_exclude_supabase(self):
        result = BackendDetectionResult(
            backend_type=BackendType.FIREBASE,
            confidence=0.95,
        )
        phases = result.get_applicable_phases()
        assert "2" not in phases
        assert "20-ADV" not in phases

    def test_custom_rest_phases(self):
        result = BackendDetectionResult(
            backend_type=BackendType.CUSTOM_REST,
            confidence=0.5,
        )
        phases = result.get_applicable_phases()
        custom_specific = ["C1", "C2", "C3", "C4"]
        for phase in custom_specific:
            assert phase in phases, (
                f"Custom REST phase {phase} missing"
            )

    def test_custom_graphql_phases(self):
        result = BackendDetectionResult(
            backend_type=BackendType.CUSTOM_GRAPHQL,
            confidence=0.7,
        )
        phases = result.get_applicable_phases()
        custom_specific = ["C1", "C2", "C3", "C4"]
        for phase in custom_specific:
            assert phase in phases, (
                f"Custom GraphQL phase {phase} missing"
            )

    def test_unknown_phases(self):
        result = BackendDetectionResult(
            backend_type=BackendType.UNKNOWN,
            confidence=0.0,
        )
        phases = result.get_applicable_phases()
        custom_specific = ["C1", "C2", "C3", "C4"]
        for phase in custom_specific:
            assert phase in phases, (
                f"Unknown backend phase {phase} missing"
            )

    def test_mongodb_atlas_phases(self):
        result = BackendDetectionResult(
            backend_type=BackendType.MONGODB_ATLAS,
            confidence=0.8,
        )
        phases = result.get_applicable_phases()
        # MongoDB falls into the else branch (custom API phases)
        custom_specific = ["C1", "C2", "C3", "C4"]
        for phase in custom_specific:
            assert phase in phases, (
                f"MongoDB Atlas phase {phase} missing"
            )

    def test_with_supabase_config(self):
        sc = SupabaseConfig(
            project_url="https://abc.supabase.co",
            anon_key="test_key",
        )
        result = BackendDetectionResult(
            backend_type=BackendType.SUPABASE,
            confidence=0.95,
            supabase_config=sc,
        )
        assert result.supabase_config is sc
        assert result.supabase_config.is_valid is True

    def test_with_firebase_config(self):
        fc = FirebaseConfig(
            api_key="AIzaSyTest",
            project_id="my-project",
        )
        result = BackendDetectionResult(
            backend_type=BackendType.FIREBASE,
            confidence=0.95,
            firebase_config=fc,
        )
        assert result.firebase_config is fc
        assert result.firebase_config.is_valid is True

    def test_with_third_party_keys(self):
        tp = ThirdPartyKeys(stripe_secret=["sk_live_abc"])
        result = BackendDetectionResult(
            backend_type=BackendType.CUSTOM_REST,
            confidence=0.5,
            third_party=tp,
        )
        assert result.third_party.has_critical_exposure is True

    def test_list_fields_are_independent(self):
        """Ensure default_factory creates separate list instances."""
        r1 = BackendDetectionResult(
            backend_type=BackendType.UNKNOWN, confidence=0.0
        )
        r2 = BackendDetectionResult(
            backend_type=BackendType.UNKNOWN, confidence=0.0
        )
        r1.api_endpoints.append("/api/test")
        assert r2.api_endpoints == []

    def test_confidence_range(self):
        result = BackendDetectionResult(
            backend_type=BackendType.SUPABASE,
            confidence=0.95,
        )
        assert 0.0 <= result.confidence <= 1.0
