"""
Tests for scanning/modules/cloud_scanner.py

Covers:
- CloudProvider enum (11 members)
- CredentialType enum (12 members)
- CloudResource dataclass
- CredentialLeak dataclass
- CloudScanner class attributes and pattern lists
- AWS patterns: S3, Lambda, API Gateway, Cognito
- Azure patterns: Blob, Function, KeyVault, CosmosDB, ACR
- GCP patterns: Storage, Functions, Firebase, BigQuery, GCR
- Other provider patterns: DigitalOcean, Oracle, Alibaba, Heroku, Vercel, Netlify
- Credential patterns: AWS keys, Azure secrets, GCP keys, private keys, JWTs,
  database URLs, API keys, GitHub tokens, Stripe keys, Slack tokens, etc.
"""

import re
import pytest
from dataclasses import fields

from scanning.modules.cloud_scanner import (
    CloudProvider,
    CredentialType,
    CloudResource,
    CredentialLeak,
    CloudScanner,
)


# =============================================================================
# CloudProvider ENUM
# =============================================================================

class TestCloudProviderEnum:
    def test_member_count(self):
        assert len(CloudProvider) == 11

    def test_aws(self):
        assert CloudProvider.AWS.value == "aws"

    def test_azure(self):
        assert CloudProvider.AZURE.value == "azure"

    def test_gcp(self):
        assert CloudProvider.GCP.value == "gcp"

    def test_digitalocean(self):
        assert CloudProvider.DIGITALOCEAN.value == "digitalocean"

    def test_oracle(self):
        assert CloudProvider.ORACLE.value == "oracle"

    def test_alibaba(self):
        assert CloudProvider.ALIBABA.value == "alibaba"

    def test_ibm(self):
        assert CloudProvider.IBM.value == "ibm"

    def test_firebase(self):
        assert CloudProvider.FIREBASE.value == "firebase"

    def test_heroku(self):
        assert CloudProvider.HEROKU.value == "heroku"

    def test_vercel(self):
        assert CloudProvider.VERCEL.value == "vercel"

    def test_netlify(self):
        assert CloudProvider.NETLIFY.value == "netlify"

    def test_all_values_unique(self):
        values = [m.value for m in CloudProvider]
        assert len(values) == len(set(values))

    def test_all_values_lowercase(self):
        for member in CloudProvider:
            assert member.value == member.value.lower()


# =============================================================================
# CredentialType ENUM
# =============================================================================

class TestCredentialTypeEnum:
    def test_member_count(self):
        assert len(CredentialType) == 12

    def test_aws_access_key(self):
        assert CredentialType.AWS_ACCESS_KEY.value == "aws_access_key"

    def test_aws_secret_key(self):
        assert CredentialType.AWS_SECRET_KEY.value == "aws_secret_key"

    def test_aws_session_token(self):
        assert CredentialType.AWS_SESSION_TOKEN.value == "aws_session_token"

    def test_azure_client_secret(self):
        assert CredentialType.AZURE_CLIENT_SECRET.value == "azure_client_secret"

    def test_azure_connection_string(self):
        assert CredentialType.AZURE_CONNECTION_STRING.value == "azure_connection_string"

    def test_gcp_service_account(self):
        assert CredentialType.GCP_SERVICE_ACCOUNT.value == "gcp_service_account"

    def test_gcp_api_key(self):
        assert CredentialType.GCP_API_KEY.value == "gcp_api_key"

    def test_private_key(self):
        assert CredentialType.PRIVATE_KEY.value == "private_key"

    def test_jwt_secret(self):
        assert CredentialType.JWT_SECRET.value == "jwt_secret"

    def test_api_key(self):
        assert CredentialType.API_KEY.value == "api_key"

    def test_oauth_token(self):
        assert CredentialType.OAUTH_TOKEN.value == "oauth_token"

    def test_database_url(self):
        assert CredentialType.DATABASE_URL.value == "database_url"

    def test_all_values_unique(self):
        values = [m.value for m in CredentialType]
        assert len(values) == len(set(values))


# =============================================================================
# CloudResource DATACLASS
# =============================================================================

class TestCloudResource:
    def test_required_fields(self):
        r = CloudResource(
            provider=CloudProvider.AWS,
            resource_type="s3_bucket",
            identifier="my-bucket",
            url="https://my-bucket.s3.amazonaws.com",
        )
        assert r.provider == CloudProvider.AWS
        assert r.resource_type == "s3_bucket"
        assert r.identifier == "my-bucket"
        assert r.url == "https://my-bucket.s3.amazonaws.com"

    def test_default_public_false(self):
        r = CloudResource(
            provider=CloudProvider.AZURE,
            resource_type="blob",
            identifier="store1",
            url="https://store1.blob.core.windows.net",
        )
        assert r.public is False

    def test_default_misconfigured_false(self):
        r = CloudResource(
            provider=CloudProvider.GCP,
            resource_type="storage",
            identifier="bucket1",
            url="https://storage.googleapis.com/bucket1",
        )
        assert r.misconfigured is False

    def test_default_details_empty_dict(self):
        r = CloudResource(
            provider=CloudProvider.AWS,
            resource_type="lambda",
            identifier="fn1",
            url="https://fn1.lambda-url.us-east-1.on.aws",
        )
        assert r.details == {}

    def test_details_independent_per_instance(self):
        r1 = CloudResource(
            provider=CloudProvider.AWS,
            resource_type="s3",
            identifier="a",
            url="https://a.s3.amazonaws.com",
        )
        r2 = CloudResource(
            provider=CloudProvider.AWS,
            resource_type="s3",
            identifier="b",
            url="https://b.s3.amazonaws.com",
        )
        r1.details["key"] = "val"
        assert "key" not in r2.details

    def test_custom_values(self):
        r = CloudResource(
            provider=CloudProvider.HEROKU,
            resource_type="app",
            identifier="myapp",
            url="https://myapp.herokuapp.com",
            public=True,
            misconfigured=True,
            details={"status": "exposed"},
        )
        assert r.public is True
        assert r.misconfigured is True
        assert r.details == {"status": "exposed"}

    def test_field_names(self):
        names = {f.name for f in fields(CloudResource)}
        expected = {"provider", "resource_type", "identifier", "url", "public", "misconfigured", "details"}
        assert names == expected


# =============================================================================
# CredentialLeak DATACLASS
# =============================================================================

class TestCredentialLeak:
    def test_all_fields(self):
        leak = CredentialLeak(
            credential_type=CredentialType.AWS_ACCESS_KEY,
            value_masked="AKIA****EXAMPLE",
            location="/config.js",
            context="var key = 'AKIA...'",
            severity="CRITICAL",
        )
        assert leak.credential_type == CredentialType.AWS_ACCESS_KEY
        assert leak.value_masked == "AKIA****EXAMPLE"
        assert leak.location == "/config.js"
        assert leak.context == "var key = 'AKIA...'"
        assert leak.severity == "CRITICAL"

    def test_field_names(self):
        names = {f.name for f in fields(CredentialLeak)}
        expected = {"credential_type", "value_masked", "location", "context", "severity"}
        assert names == expected


# =============================================================================
# CloudScanner CLASS ATTRIBUTES
# =============================================================================

class TestCloudScannerClass:
    def test_name(self):
        assert CloudScanner.name == "cloud_scanner"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(CloudScanner, ScanModule)


# =============================================================================
# PATTERN LIST COUNTS
# =============================================================================

class TestPatternCounts:
    """Verify each pattern list has the expected number of entries."""

    # AWS
    def test_aws_s3_patterns_count(self):
        assert len(CloudScanner.AWS_S3_PATTERNS) == 7

    def test_aws_lambda_patterns_count(self):
        assert len(CloudScanner.AWS_LAMBDA_PATTERNS) == 2

    def test_aws_api_gateway_patterns_count(self):
        assert len(CloudScanner.AWS_API_GATEWAY_PATTERNS) == 1

    def test_aws_cognito_patterns_count(self):
        assert len(CloudScanner.AWS_COGNITO_PATTERNS) == 3

    def test_aws_regions_count(self):
        assert len(CloudScanner.AWS_REGIONS) == 19

    # Azure
    def test_azure_blob_patterns_count(self):
        assert len(CloudScanner.AZURE_BLOB_PATTERNS) == 5

    def test_azure_function_patterns_count(self):
        assert len(CloudScanner.AZURE_FUNCTION_PATTERNS) == 2

    def test_azure_keyvault_patterns_count(self):
        assert len(CloudScanner.AZURE_KEYVAULT_PATTERNS) == 1

    def test_azure_cosmosdb_patterns_count(self):
        assert len(CloudScanner.AZURE_COSMOSDB_PATTERNS) == 2

    def test_azure_acr_patterns_count(self):
        assert len(CloudScanner.AZURE_ACR_PATTERNS) == 1

    # GCP
    def test_gcp_storage_patterns_count(self):
        assert len(CloudScanner.GCP_STORAGE_PATTERNS) == 3

    def test_gcp_function_patterns_count(self):
        assert len(CloudScanner.GCP_FUNCTION_PATTERNS) == 2

    def test_gcp_firebase_patterns_count(self):
        assert len(CloudScanner.GCP_FIREBASE_PATTERNS) == 4

    def test_gcp_bigquery_patterns_count(self):
        assert len(CloudScanner.GCP_BIGQUERY_PATTERNS) == 1

    def test_gcp_gcr_patterns_count(self):
        assert len(CloudScanner.GCP_GCR_PATTERNS) == 2

    # Other providers
    def test_digitalocean_patterns_count(self):
        assert len(CloudScanner.DIGITALOCEAN_PATTERNS) == 4

    def test_oracle_patterns_count(self):
        assert len(CloudScanner.ORACLE_PATTERNS) == 1

    def test_alibaba_patterns_count(self):
        assert len(CloudScanner.ALIBABA_PATTERNS) == 1

    def test_heroku_patterns_count(self):
        assert len(CloudScanner.HEROKU_PATTERNS) == 1

    def test_vercel_patterns_count(self):
        assert len(CloudScanner.VERCEL_PATTERNS) == 2

    def test_netlify_patterns_count(self):
        assert len(CloudScanner.NETLIFY_PATTERNS) == 2

    # Credentials
    def test_credential_patterns_at_least_60(self):
        assert len(CloudScanner.CREDENTIAL_PATTERNS) >= 60

    # Common containers
    def test_common_s3_containers_not_empty(self):
        assert len(CloudScanner.COMMON_S3_CONTAINERS) >= 20


# =============================================================================
# ALL PATTERNS COMPILE
# =============================================================================

class TestPatternsCompile:
    """Every regex pattern must compile without error."""

    @pytest.mark.parametrize("pattern", CloudScanner.AWS_S3_PATTERNS)
    def test_aws_s3_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.AWS_LAMBDA_PATTERNS)
    def test_aws_lambda_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.AWS_API_GATEWAY_PATTERNS)
    def test_aws_api_gateway_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.AWS_COGNITO_PATTERNS)
    def test_aws_cognito_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.AZURE_BLOB_PATTERNS)
    def test_azure_blob_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.AZURE_FUNCTION_PATTERNS)
    def test_azure_function_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.AZURE_KEYVAULT_PATTERNS)
    def test_azure_keyvault_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.AZURE_COSMOSDB_PATTERNS)
    def test_azure_cosmosdb_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.AZURE_ACR_PATTERNS)
    def test_azure_acr_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.GCP_STORAGE_PATTERNS)
    def test_gcp_storage_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.GCP_FUNCTION_PATTERNS)
    def test_gcp_function_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.GCP_FIREBASE_PATTERNS)
    def test_gcp_firebase_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.GCP_BIGQUERY_PATTERNS)
    def test_gcp_bigquery_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.GCP_GCR_PATTERNS)
    def test_gcp_gcr_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.DIGITALOCEAN_PATTERNS)
    def test_digitalocean_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.ORACLE_PATTERNS)
    def test_oracle_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.ALIBABA_PATTERNS)
    def test_alibaba_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.HEROKU_PATTERNS)
    def test_heroku_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.VERCEL_PATTERNS)
    def test_vercel_compiles(self, pattern):
        re.compile(pattern)

    @pytest.mark.parametrize("pattern", CloudScanner.NETLIFY_PATTERNS)
    def test_netlify_compiles(self, pattern):
        re.compile(pattern)

    def test_all_credential_patterns_compile(self):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            re.compile(pattern_str)


# =============================================================================
# CREDENTIAL PATTERN STRUCTURE
# =============================================================================

class TestCredentialPatternStructure:
    """Every credential pattern tuple must have (regex, CredentialType, desc, severity)."""

    def test_all_are_4_tuples(self):
        for entry in CloudScanner.CREDENTIAL_PATTERNS:
            assert len(entry) == 4, f"Expected 4-tuple, got {len(entry)}-tuple: {entry}"

    def test_all_have_string_pattern(self):
        for pattern_str, _, _, _ in CloudScanner.CREDENTIAL_PATTERNS:
            assert isinstance(pattern_str, str)

    def test_all_have_credential_type(self):
        for _, cred_type, _, _ in CloudScanner.CREDENTIAL_PATTERNS:
            assert isinstance(cred_type, CredentialType)

    def test_all_have_description(self):
        for _, _, desc, _ in CloudScanner.CREDENTIAL_PATTERNS:
            assert isinstance(desc, str)
            assert len(desc) > 0

    def test_all_have_valid_severity(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for _, _, _, severity in CloudScanner.CREDENTIAL_PATTERNS:
            assert severity in valid, f"Invalid severity: {severity}"


# =============================================================================
# AWS S3 PATTERN MATCHING
# =============================================================================

class TestAwsS3PatternMatching:
    """Verify S3 patterns match realistic S3 URLs."""

    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.AWS_S3_PATTERNS)

    # Virtual-hosted style
    def test_virtual_hosted_plain(self):
        assert self._matches_any("my-bucket.s3.amazonaws.com")

    def test_virtual_hosted_with_region_dash(self):
        assert self._matches_any("my-bucket.s3-us-west-2.amazonaws.com")

    def test_virtual_hosted_with_region_dot(self):
        assert self._matches_any("my-bucket.s3.us-east-1.amazonaws.com")

    # Path style
    def test_path_style_plain(self):
        assert self._matches_any("s3.amazonaws.com/my-bucket")

    def test_path_style_with_region_dash(self):
        assert self._matches_any("s3-us-west-2.amazonaws.com/my-bucket")

    def test_path_style_with_region_dot(self):
        assert self._matches_any("s3.us-east-1.amazonaws.com/my-bucket")

    # Website endpoint
    def test_website_endpoint(self):
        assert self._matches_any("my-bucket.s3-website-us-east-1.amazonaws.com")

    def test_website_endpoint_dot_style(self):
        assert self._matches_any("my-bucket.s3-website.us-west-2.amazonaws.com")

    # Embedded in larger text
    def test_s3_url_in_html(self):
        html = '<img src="https://images.s3.amazonaws.com/photo.jpg">'
        assert self._matches_any(html)

    def test_s3_url_in_js(self):
        js = "var url = 'https://my-app-assets.s3.us-east-1.amazonaws.com/bundle.js';"
        assert self._matches_any(js)

    # Should not match garbage
    def test_no_match_random_text(self):
        assert not self._matches_any("hello world nothing here")


# =============================================================================
# AWS LAMBDA PATTERN MATCHING
# =============================================================================

class TestAwsLambdaPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.AWS_LAMBDA_PATTERNS)

    def test_lambda_url(self):
        assert self._matches_any("abc123def.lambda-url.us-east-1.on.aws")

    def test_execute_api_with_stage(self):
        assert self._matches_any("execute-api.us-east-1.amazonaws.com/prod")

    def test_no_match_random(self):
        assert not self._matches_any("example.com/api/test")


# =============================================================================
# AWS API GATEWAY PATTERN MATCHING
# =============================================================================

class TestAwsApiGatewayPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.AWS_API_GATEWAY_PATTERNS)

    def test_api_gateway_url(self):
        assert self._matches_any("abc123xyz.execute-api.eu-west-1.amazonaws.com")

    def test_no_match_random(self):
        assert not self._matches_any("api.example.com")


# =============================================================================
# AWS COGNITO PATTERN MATCHING
# =============================================================================

class TestAwsCognitoPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.AWS_COGNITO_PATTERNS)

    def test_cognito_idp(self):
        assert self._matches_any("cognito-idp.us-east-1.amazonaws.com")

    def test_cognito_identity(self):
        assert self._matches_any("cognito-identity.eu-west-1.amazonaws.com")

    def test_cognito_auth(self):
        assert self._matches_any("my-app.auth.us-east-1.amazoncognito.com")

    def test_no_match_random(self):
        assert not self._matches_any("auth.example.com")


# =============================================================================
# AWS REGIONS
# =============================================================================

class TestAwsRegions:
    def test_count(self):
        assert len(CloudScanner.AWS_REGIONS) == 19

    def test_us_east_1_present(self):
        assert "us-east-1" in CloudScanner.AWS_REGIONS

    def test_eu_west_1_present(self):
        assert "eu-west-1" in CloudScanner.AWS_REGIONS

    def test_ap_southeast_1_present(self):
        assert "ap-southeast-1" in CloudScanner.AWS_REGIONS

    def test_all_unique(self):
        assert len(CloudScanner.AWS_REGIONS) == len(set(CloudScanner.AWS_REGIONS))

    def test_all_match_region_format(self):
        for region in CloudScanner.AWS_REGIONS:
            assert re.match(r'^[a-z]{2}-[a-z]+-\d$', region), f"Bad format: {region}"


# =============================================================================
# AZURE PATTERN MATCHING
# =============================================================================

class TestAzureBlobPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.AZURE_BLOB_PATTERNS)

    def test_blob_storage(self):
        assert self._matches_any("myaccount.blob.core.windows.net")

    def test_dfs_storage(self):
        assert self._matches_any("myaccount.dfs.core.windows.net")

    def test_file_storage(self):
        assert self._matches_any("myaccount.file.core.windows.net")

    def test_queue_storage(self):
        assert self._matches_any("myaccount.queue.core.windows.net")

    def test_table_storage(self):
        assert self._matches_any("myaccount.table.core.windows.net")

    def test_no_match_random(self):
        assert not self._matches_any("example.windows.net")


class TestAzureFunctionPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.AZURE_FUNCTION_PATTERNS)

    def test_azurewebsites(self):
        assert self._matches_any("my-app.azurewebsites.net")

    def test_scm_azurewebsites(self):
        assert self._matches_any("my-app.scm.azurewebsites.net")

    def test_no_match_random(self):
        assert not self._matches_any("example.com")


class TestAzureKeyvaultPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.AZURE_KEYVAULT_PATTERNS)

    def test_keyvault(self):
        assert self._matches_any("my-vault.vault.azure.net")

    def test_no_match_random(self):
        assert not self._matches_any("vault.example.com")


class TestAzureCosmosdbPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.AZURE_COSMOSDB_PATTERNS)

    def test_documents(self):
        assert self._matches_any("my-db.documents.azure.com")

    def test_mongo_cosmos(self):
        assert self._matches_any("my-db.mongo.cosmos.azure.com")

    def test_no_match_random(self):
        assert not self._matches_any("cosmos.example.com")


class TestAzureAcrPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.AZURE_ACR_PATTERNS)

    def test_acr(self):
        assert self._matches_any("myregistry.azurecr.io")

    def test_no_match_random(self):
        assert not self._matches_any("docker.io/myimage")


# =============================================================================
# GCP PATTERN MATCHING
# =============================================================================

class TestGcpStoragePatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.GCP_STORAGE_PATTERNS)

    def test_path_style(self):
        assert self._matches_any("storage.googleapis.com/my-bucket")

    def test_virtual_hosted(self):
        assert self._matches_any("my-bucket.storage.googleapis.com")

    def test_cloud_storage(self):
        assert self._matches_any("storage.cloud.google.com/my-bucket")

    def test_no_match_random(self):
        assert not self._matches_any("storage.example.com/bucket")


class TestGcpFunctionPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.GCP_FUNCTION_PATTERNS)

    def test_cloudfunctions(self):
        assert self._matches_any("us-central1-myproject.cloudfunctions.net")

    def test_cloud_run(self):
        assert self._matches_any("my-service.run.app")

    def test_no_match_random(self):
        assert not self._matches_any("functions.example.com")


class TestGcpFirebasePatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.GCP_FIREBASE_PATTERNS)

    def test_firebaseio(self):
        assert self._matches_any("my-app.firebaseio.com")

    def test_firebaseapp(self):
        assert self._matches_any("my-app.firebaseapp.com")

    def test_web_app(self):
        assert self._matches_any("my-app.web.app")

    def test_firestore_api(self):
        assert self._matches_any("firestore.googleapis.com/v1/projects/my-project")

    def test_no_match_random(self):
        assert not self._matches_any("firebase.example.com")


class TestGcpBigqueryPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.GCP_BIGQUERY_PATTERNS)

    def test_bigquery_api(self):
        assert self._matches_any("bigquery.googleapis.com/bigquery/v2/projects/my-project")

    def test_no_match_random(self):
        assert not self._matches_any("bigquery.example.com")


class TestGcpGcrPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.GCP_GCR_PATTERNS)

    def test_gcr(self):
        assert self._matches_any("gcr.io/my-project")

    def test_artifact_registry(self):
        assert self._matches_any("us-docker.pkg.dev/my-project")

    def test_no_match_random(self):
        assert not self._matches_any("docker.io/myimage")


# =============================================================================
# OTHER PROVIDER PATTERN MATCHING
# =============================================================================

class TestDigitalOceanPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.DIGITALOCEAN_PATTERNS)

    def test_spaces(self):
        assert self._matches_any("my-space.digitaloceanspaces.com")

    def test_spaces_nyc3(self):
        assert self._matches_any("my-space.nyc3.digitaloceanspaces.com")

    def test_spaces_ams3(self):
        assert self._matches_any("my-space.ams3.digitaloceanspaces.com")

    def test_spaces_sgp1(self):
        assert self._matches_any("my-space.sgp1.digitaloceanspaces.com")

    def test_no_match_random(self):
        assert not self._matches_any("spaces.example.com")


class TestOraclePatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.ORACLE_PATTERNS)

    def test_object_storage(self):
        assert self._matches_any("objectstorage.us-ashburn-1.oraclecloud.com/n/my-namespace")

    def test_no_match_random(self):
        assert not self._matches_any("oracle.example.com")


class TestAlibabaPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.ALIBABA_PATTERNS)

    def test_oss(self):
        assert self._matches_any("my-bucket.oss-cn-hangzhou.aliyuncs.com")

    def test_no_match_random(self):
        assert not self._matches_any("aliyun.example.com")


class TestHerokuPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.HEROKU_PATTERNS)

    def test_heroku_app(self):
        assert self._matches_any("my-app.herokuapp.com")

    def test_no_match_random(self):
        assert not self._matches_any("heroku.example.com")


class TestVercelPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.VERCEL_PATTERNS)

    def test_vercel_app(self):
        assert self._matches_any("my-project.vercel.app")

    def test_now_sh(self):
        assert self._matches_any("my-project.now.sh")

    def test_no_match_random(self):
        assert not self._matches_any("vercel.example.com")


class TestNetlifyPatternMatching:
    def _matches_any(self, text):
        return any(re.search(p, text) for p in CloudScanner.NETLIFY_PATTERNS)

    def test_netlify_app(self):
        assert self._matches_any("my-site.netlify.app")

    def test_netlify_com(self):
        assert self._matches_any("my-site.netlify.com")

    def test_no_match_random(self):
        assert not self._matches_any("netlify.example.com")


# =============================================================================
# CREDENTIAL PATTERN MATCHING - AWS
# =============================================================================

class TestCredentialPatternsAws:
    """Test AWS credential patterns match realistic examples."""

    def _matches_any(self, text, target_type=None):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if target_type and cred_type != target_type:
                continue
            if re.search(pattern_str, text):
                return True
        return False

    def _match_details(self, text):
        """Return all matching (cred_type, desc, severity) tuples."""
        matches = []
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if re.search(pattern_str, text):
                matches.append((cred_type, desc, severity))
        return matches

    def test_aws_access_key_akia(self):
        assert self._matches_any("AKIAIOSFODNN7EXAMPLE", CredentialType.AWS_ACCESS_KEY)

    def test_aws_access_key_abia(self):
        assert self._matches_any("ABIAIOSFODNN7EXAMPLE", CredentialType.AWS_ACCESS_KEY)

    def test_aws_access_key_aroa(self):
        assert self._matches_any("AROAIOSFODNN7EXAMPLE", CredentialType.AWS_ACCESS_KEY)

    def test_aws_access_key_aida(self):
        assert self._matches_any("AIDAIOSFODNN7EXAMPLE", CredentialType.AWS_ACCESS_KEY)

    def test_aws_session_token_asia(self):
        assert self._matches_any("ASIAIOSFODNN7EXAMPLE", CredentialType.AWS_SESSION_TOKEN)

    def test_aws_secret_key(self):
        text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        assert self._matches_any(text, CredentialType.AWS_SECRET_KEY)

    def test_aws_secret_key_colon(self):
        text = 'aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        assert self._matches_any(text, CredentialType.AWS_SECRET_KEY)

    def test_aws_access_key_severity_critical(self):
        matches = self._match_details("AKIAIOSFODNN7EXAMPLE")
        assert any(s == "CRITICAL" for _, _, s in matches)

    def test_no_match_short_key(self):
        # Only 10 chars after AKIA, needs 16
        assert not self._matches_any("AKIA12345678", CredentialType.AWS_ACCESS_KEY)


# =============================================================================
# CREDENTIAL PATTERN MATCHING - AZURE
# =============================================================================

class TestCredentialPatternsAzure:
    def _matches_any(self, text, target_type=None):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if target_type and cred_type != target_type:
                continue
            if re.search(pattern_str, text):
                return True
        return False

    def test_azure_storage_account_key(self):
        # 88-char base64 key
        key = "A" * 86 + "=="
        text = f"AccountKey={key}"
        assert self._matches_any(text, CredentialType.AZURE_CONNECTION_STRING)

    def test_azure_sas_token(self):
        text = "SharedAccessSignature=sv2020%2F08%2F04srt"
        assert self._matches_any(text, CredentialType.AZURE_CONNECTION_STRING)

    def test_azure_connection_string_full(self):
        key = "A" * 86 + "=="
        text = f"DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey={key}"
        assert self._matches_any(text, CredentialType.AZURE_CONNECTION_STRING)

    def test_azure_guid(self):
        text = "12345678-abcd-1234-abcd-123456789012"
        assert self._matches_any(text, CredentialType.AZURE_CLIENT_SECRET)


# =============================================================================
# CREDENTIAL PATTERN MATCHING - GCP
# =============================================================================

class TestCredentialPatternsGcp:
    def _matches_any(self, text, target_type=None):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if target_type and cred_type != target_type:
                continue
            if re.search(pattern_str, text):
                return True
        return False

    def test_gcp_service_account_json(self):
        text = '{"type": "service_account", "project_id": "my-project"}'
        assert self._matches_any(text, CredentialType.GCP_SERVICE_ACCOUNT)

    def test_gcp_service_account_private_key(self):
        text = '"private_key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIE..."'
        assert self._matches_any(text, CredentialType.GCP_SERVICE_ACCOUNT)

    def test_gcp_api_key(self):
        # AIza + 35 chars
        key = "AIza" + "A" * 35
        assert self._matches_any(key, CredentialType.GCP_API_KEY)

    def test_google_oauth_token(self):
        assert self._matches_any("ya29.a0ARrdaM-something-long", CredentialType.OAUTH_TOKEN)


# =============================================================================
# CREDENTIAL PATTERN MATCHING - PRIVATE KEYS
# =============================================================================

class TestCredentialPatternsPrivateKeys:
    def _matches_any(self, text, target_type=None):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if target_type and cred_type != target_type:
                continue
            if re.search(pattern_str, text):
                return True
        return False

    def test_rsa_private_key(self):
        assert self._matches_any("-----BEGIN RSA PRIVATE KEY-----", CredentialType.PRIVATE_KEY)

    def test_dsa_private_key(self):
        assert self._matches_any("-----BEGIN DSA PRIVATE KEY-----", CredentialType.PRIVATE_KEY)

    def test_ec_private_key(self):
        assert self._matches_any("-----BEGIN EC PRIVATE KEY-----", CredentialType.PRIVATE_KEY)

    def test_openssh_private_key(self):
        assert self._matches_any("-----BEGIN OPENSSH PRIVATE KEY-----", CredentialType.PRIVATE_KEY)

    def test_pgp_private_key(self):
        assert self._matches_any("-----BEGIN PGP PRIVATE KEY BLOCK-----", CredentialType.PRIVATE_KEY)

    def test_encrypted_private_key(self):
        assert self._matches_any("-----BEGIN ENCRYPTED PRIVATE KEY-----", CredentialType.PRIVATE_KEY)


# =============================================================================
# CREDENTIAL PATTERN MATCHING - JWT
# =============================================================================

class TestCredentialPatternsJwt:
    def _matches_any(self, text, target_type=None):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if target_type and cred_type != target_type:
                continue
            if re.search(pattern_str, text):
                return True
        return False

    def test_jwt_token(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert self._matches_any(token, CredentialType.JWT_SECRET)

    def test_jwt_secret_equals(self):
        text = 'jwt_secret = "mySuperSecretKey123456"'
        assert self._matches_any(text, CredentialType.JWT_SECRET)

    def test_jwt_secret_colon(self):
        text = 'jwt-secret: "mySuperSecretKey123456"'
        assert self._matches_any(text, CredentialType.JWT_SECRET)


# =============================================================================
# CREDENTIAL PATTERN MATCHING - DATABASE URLS
# =============================================================================

class TestCredentialPatternsDatabase:
    def _matches_any(self, text, target_type=None):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if target_type and cred_type != target_type:
                continue
            if re.search(pattern_str, text):
                return True
        return False

    def test_mongodb(self):
        text = "mongodb://user:pass@host:27017/db"
        assert self._matches_any(text, CredentialType.DATABASE_URL)

    def test_mongodb_srv(self):
        text = "mongodb+srv://user:pass@cluster.mongodb.net/db"
        assert self._matches_any(text, CredentialType.DATABASE_URL)

    def test_postgresql(self):
        text = "postgresql://user:pass@host:5432/db"
        assert self._matches_any(text, CredentialType.DATABASE_URL)

    def test_postgres(self):
        text = "postgres://user:pass@host:5432/db"
        assert self._matches_any(text, CredentialType.DATABASE_URL)

    def test_mysql(self):
        text = "mysql://user:pass@host:3306/db"
        assert self._matches_any(text, CredentialType.DATABASE_URL)

    def test_redis(self):
        text = "redis://user:pass@host:6379/0"
        assert self._matches_any(text, CredentialType.DATABASE_URL)

    def test_amqp(self):
        text = "amqp://user:pass@host:5672/vhost"
        assert self._matches_any(text, CredentialType.DATABASE_URL)


# =============================================================================
# CREDENTIAL PATTERN MATCHING - GITHUB TOKENS
# =============================================================================

class TestCredentialPatternsGithub:
    def _matches_any(self, text, target_type=None):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if target_type and cred_type != target_type:
                continue
            if re.search(pattern_str, text):
                return True
        return False

    def test_ghp_personal_access_token(self):
        token = "ghp_" + "a" * 36
        assert self._matches_any(token, CredentialType.OAUTH_TOKEN)

    def test_gho_oauth_token(self):
        token = "gho_" + "A" * 36
        assert self._matches_any(token, CredentialType.OAUTH_TOKEN)

    def test_ghu_user_token(self):
        token = "ghu_" + "B" * 36
        assert self._matches_any(token, CredentialType.OAUTH_TOKEN)

    def test_ghr_refresh_token(self):
        token = "ghr_" + "C" * 36
        assert self._matches_any(token, CredentialType.OAUTH_TOKEN)

    def test_ghs_server_token(self):
        token = "ghs_" + "D" * 36
        assert self._matches_any(token, CredentialType.OAUTH_TOKEN)


# =============================================================================
# CREDENTIAL PATTERN MATCHING - STRIPE KEYS
# =============================================================================

class TestCredentialPatternsStripe:
    def _matches_any(self, text, target_type=None):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if target_type and cred_type != target_type:
                continue
            if re.search(pattern_str, text):
                return True
        return False

    def _match_details(self, text):
        matches = []
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if re.search(pattern_str, text):
                matches.append((cred_type, desc, severity))
        return matches

    def test_stripe_secret_key(self):
        key = "sk_live_" + "a" * 24
        assert self._matches_any(key, CredentialType.API_KEY)

    def test_stripe_test_key(self):
        key = "sk_test_" + "b" * 24
        assert self._matches_any(key, CredentialType.API_KEY)

    def test_stripe_publishable_key(self):
        key = "pk_live_" + "c" * 24
        assert self._matches_any(key, CredentialType.API_KEY)

    def test_stripe_restricted_key(self):
        key = "rk_live_" + "d" * 24
        assert self._matches_any(key, CredentialType.API_KEY)

    def test_stripe_live_severity_critical(self):
        key = "sk_live_" + "a" * 24
        matches = self._match_details(key)
        assert any(s == "CRITICAL" for _, _, s in matches)

    def test_stripe_test_severity_medium(self):
        key = "sk_test_" + "b" * 24
        matches = self._match_details(key)
        assert any(s == "MEDIUM" for _, _, s in matches)

    def test_stripe_publishable_severity_low(self):
        key = "pk_live_" + "c" * 24
        matches = self._match_details(key)
        assert any(s == "LOW" for _, _, s in matches)


# =============================================================================
# CREDENTIAL PATTERN MATCHING - SLACK TOKENS
# =============================================================================

class TestCredentialPatternsSlack:
    def _matches_any(self, text, target_type=None):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if target_type and cred_type != target_type:
                continue
            if re.search(pattern_str, text):
                return True
        return False

    def test_slack_bot_token(self):
        assert self._matches_any("xoxb-123456789012-abcdefghij", CredentialType.OAUTH_TOKEN)

    def test_slack_app_token(self):
        assert self._matches_any("xoxp-123456789012-abcdefghij", CredentialType.OAUTH_TOKEN)

    def test_slack_webhook_url(self):
        assert self._matches_any(
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
            CredentialType.API_KEY,
        )

    def test_slack_webhook_id(self):
        assert self._matches_any(
            "T0123456789/B0123456789/abcdefghijklmnopqrstuvwx",
            CredentialType.API_KEY,
        )


# =============================================================================
# CREDENTIAL PATTERN MATCHING - MISC SERVICES
# =============================================================================

class TestCredentialPatternsMiscServices:
    def _matches_any(self, text, target_type=None):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if target_type and cred_type != target_type:
                continue
            if re.search(pattern_str, text):
                return True
        return False

    def test_sendgrid_api_key(self):
        key = "SG." + "a" * 22 + "." + "b" * 43
        assert self._matches_any(key, CredentialType.API_KEY)

    def test_mailgun_api_key(self):
        key = "key-" + "a" * 32
        assert self._matches_any(key, CredentialType.API_KEY)

    def test_mailchimp_api_key(self):
        key = "a" * 32 + "-us10"
        assert self._matches_any(key, CredentialType.API_KEY)

    def test_openai_api_key(self):
        key = "sk-" + "a" * 48
        assert self._matches_any(key, CredentialType.API_KEY)

    def test_twilio_account_sid(self):
        sid = "AC" + "a" * 32
        assert self._matches_any(sid, CredentialType.API_KEY)

    def test_twilio_auth_token(self):
        token = "SK" + "a" * 32
        assert self._matches_any(token, CredentialType.API_KEY)

    def test_telegram_bot_token(self):
        token = "123456789:AA" + "a" * 33
        assert self._matches_any(token, CredentialType.API_KEY)

    def test_gitlab_pat(self):
        token = "glpat-" + "a" * 20
        assert self._matches_any(token, CredentialType.OAUTH_TOKEN)

    def test_square_access_token(self):
        token = "sq0atp-" + "a" * 22
        assert self._matches_any(token, CredentialType.API_KEY)

    def test_square_oauth_secret(self):
        token = "sq0csp-" + "a" * 43
        assert self._matches_any(token, CredentialType.API_KEY)

    def test_paypal_braintree_token(self):
        token = "access_token$production$" + "a" * 16 + "$" + "a" * 32
        assert self._matches_any(token, CredentialType.API_KEY)


# =============================================================================
# CREDENTIAL PATTERN MATCHING - GENERIC PATTERNS
# =============================================================================

class TestCredentialPatternsGeneric:
    def _matches_any(self, text, target_type=None):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if target_type and cred_type != target_type:
                continue
            if re.search(pattern_str, text):
                return True
        return False

    def test_api_key_equals(self):
        text = 'api_key = "abcdefghijklmnopqrstuvwxyz1234"'
        assert self._matches_any(text, CredentialType.API_KEY)

    def test_api_key_colon(self):
        text = 'api-key: "abcdefghijklmnopqrstuvwxyz1234"'
        assert self._matches_any(text, CredentialType.API_KEY)

    def test_secret_key_equals(self):
        text = 'secret_key = "abcdefghijklmnopqrstuvwxyz1234"'
        assert self._matches_any(text, CredentialType.API_KEY)

    def test_access_token_equals(self):
        text = 'access_token = "abcdefghijklmnopqrstuvwxyz1234"'
        assert self._matches_any(text, CredentialType.OAUTH_TOKEN)

    def test_auth_token_equals(self):
        text = 'auth_token = "abcdefghijklmnopqrstuvwxyz1234"'
        assert self._matches_any(text, CredentialType.OAUTH_TOKEN)

    def test_bearer_token(self):
        text = "bearer abcdefghijklmnopqrstuvwxyz1234"
        assert self._matches_any(text, CredentialType.OAUTH_TOKEN)


# =============================================================================
# CREDENTIAL PATTERNS - NEGATIVE TESTS
# =============================================================================

class TestCredentialPatternsNegative:
    """Patterns should NOT match benign/short strings."""

    def _matches_any_credential(self, text):
        for pattern_str, cred_type, desc, severity in CloudScanner.CREDENTIAL_PATTERNS:
            if re.search(pattern_str, text):
                return True
        return False

    def test_no_match_hello_world(self):
        assert not self._matches_any_credential("hello world")

    def test_no_match_normal_html(self):
        assert not self._matches_any_credential("<html><body>Hello</body></html>")

    def test_no_match_short_api_key(self):
        # api_key with value too short (<20 chars)
        assert not self._matches_any_credential('api_key = "short"')

    def test_no_match_empty(self):
        assert not self._matches_any_credential("")


# =============================================================================
# COMMON S3 CONTAINERS
# =============================================================================

class TestCommonS3Containers:
    def test_contains_assets(self):
        assert "assets" in CloudScanner.COMMON_S3_CONTAINERS

    def test_contains_backup(self):
        assert "backup" in CloudScanner.COMMON_S3_CONTAINERS

    def test_contains_uploads(self):
        assert "uploads" in CloudScanner.COMMON_S3_CONTAINERS

    def test_contains_static(self):
        assert "static" in CloudScanner.COMMON_S3_CONTAINERS

    def test_contains_production(self):
        assert "production" in CloudScanner.COMMON_S3_CONTAINERS

    def test_contains_staging(self):
        assert "staging" in CloudScanner.COMMON_S3_CONTAINERS

    def test_all_lowercase(self):
        for name in CloudScanner.COMMON_S3_CONTAINERS:
            assert name == name.lower()

    def test_all_are_strings(self):
        for name in CloudScanner.COMMON_S3_CONTAINERS:
            assert isinstance(name, str)
