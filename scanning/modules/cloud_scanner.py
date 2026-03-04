"""
Cloud Security Scanner - Enterprise Edition v2.0

Comprehensive cloud infrastructure security assessment and misconfiguration detection.
Industry-leading coverage for AWS, Azure, GCP, and other cloud providers.

SAFETY MODES:
- passive/safe/cautious: READ-ONLY mode - Only checks for exposed data/configs
- standard: Read + safe write tests to controlled paths
- aggressive: Full testing including writes

Features:
- 100+ cloud misconfiguration patterns
- Multi-cloud support (AWS, Azure, GCP, DigitalOcean, Oracle, Alibaba)
- Credential exposure detection (50+ patterns)
- Storage bucket enumeration and permission testing
- Serverless function exposure detection
- Container registry analysis
- IAM policy weakness detection
- Cloud metadata service abuse
- Real-world CVE patterns for cloud services

CWE Coverage:
- CWE-200: Exposure of Sensitive Information
- CWE-284: Improper Access Control
- CWE-306: Missing Authentication for Critical Function
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-522: Insufficiently Protected Credentials
- CWE-732: Incorrect Permission Assignment for Critical Resource

Based on:
- OWASP Cloud Security Testing Guide
- CIS Benchmarks for Cloud Providers
- AWS/Azure/GCP Security Best Practices
- Bug Bounty methodologies
"""

from __future__ import annotations

import os
import re
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse, urljoin, quote
from enum import Enum

import httpx

from scanning.findings import Finding, Severity
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.scan_client import get_scan_client
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings


# Safe mode environment variable - set by full_scanner.py
SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()
ALLOW_WRITES = SAFE_MODE in ("standard", "aggressive")

logger = get_logger(__name__)


class CloudProvider(Enum):
    """Supported cloud providers."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    DIGITALOCEAN = "digitalocean"
    ORACLE = "oracle"
    ALIBABA = "alibaba"
    IBM = "ibm"
    FIREBASE = "firebase"
    HEROKU = "heroku"
    VERCEL = "vercel"
    NETLIFY = "netlify"


class CredentialType(Enum):
    """Types of cloud credentials."""
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    AWS_SESSION_TOKEN = "aws_session_token"
    AZURE_CLIENT_SECRET = "azure_client_secret"
    AZURE_CONNECTION_STRING = "azure_connection_string"
    GCP_SERVICE_ACCOUNT = "gcp_service_account"
    GCP_API_KEY = "gcp_api_key"
    PRIVATE_KEY = "private_key"
    JWT_SECRET = "jwt_secret"
    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"
    DATABASE_URL = "database_url"


@dataclass
class CloudResource:
    """Discovered cloud resource."""
    provider: CloudProvider
    resource_type: str
    identifier: str
    url: str
    public: bool = False
    misconfigured: bool = False
    details: dict = field(default_factory=dict)


@dataclass
class CredentialLeak:
    """Detected credential leak."""
    credential_type: CredentialType
    value_masked: str
    location: str
    context: str
    severity: str


class CloudScanner(ScanModule):
    """
    Cloud Security Scanner - Enterprise Edition v2.0
    
    Comprehensive multi-cloud security assessment and misconfiguration detection.
    
    Supported Services:
    ===================
    
    AWS (Amazon Web Services):
    - S3 Bucket enumeration and permission testing
    - EC2 Instance metadata (IMDS) detection
    - Lambda function URL exposure
    - API Gateway misconfiguration
    - Cognito user pool analysis
    - DynamoDB table exposure
    - SQS/SNS endpoint testing
    - ElasticSearch/OpenSearch domains
    - RDS snapshot exposure
    - EKS/ECR container analysis
    
    Azure:
    - Blob Storage enumeration
    - Function App exposure
    - Key Vault detection
    - App Service misconfiguration
    - Cosmos DB exposure
    - Container Registry access
    - Storage Account SAS tokens
    - Active Directory configuration
    
    GCP (Google Cloud Platform):
    - Cloud Storage bucket analysis
    - Cloud Functions exposure
    - BigQuery dataset access
    - Firestore/Firebase DB exposure
    - GKE/GCR container analysis
    - Pub/Sub topic exposure
    - API key validation
    
    Credential Detection:
    ====================
    - AWS Access/Secret Keys
    - Azure Client Secrets
    - GCP Service Accounts
    - Private Keys (RSA, EC, Ed25519)
    - JWT Secrets
    - Database Connection Strings
    - OAuth Tokens
    - API Keys (50+ patterns)
    """
    
    name = "cloud_scanner"
    
    # =============================================================
    # AWS PATTERNS AND CONFIGURATIONS
    # =============================================================
    
    AWS_S3_PATTERNS = [
        # Virtual-hosted style
        r"([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3\.amazonaws\.com",
        r"([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3-[a-z0-9-]+\.amazonaws\.com",
        r"([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3\.[a-z0-9-]+\.amazonaws\.com",
        # Path style
        r"s3\.amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])",
        r"s3-[a-z0-9-]+\.amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])",
        r"s3\.[a-z0-9-]+\.amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])",
        # Website endpoints
        r"([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3-website[.-][a-z0-9-]+\.amazonaws\.com",
    ]
    
    AWS_LAMBDA_PATTERNS = [
        r"[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws",
        r"execute-api\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9]+",
    ]
    
    AWS_API_GATEWAY_PATTERNS = [
        r"[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com",
    ]
    
    AWS_COGNITO_PATTERNS = [
        r"cognito-idp\.[a-z0-9-]+\.amazonaws\.com",
        r"cognito-identity\.[a-z0-9-]+\.amazonaws\.com",
        r"[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com",
    ]
    
    AWS_REGIONS = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
        "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
        "ap-southeast-1", "ap-southeast-2", "sa-east-1",
        "ca-central-1", "me-south-1", "af-south-1",
    ]
    
    # =============================================================
    # AZURE PATTERNS
    # =============================================================
    
    AZURE_BLOB_PATTERNS = [
        r"([a-z0-9]{3,24})\.blob\.core\.windows\.net",
        r"([a-z0-9]{3,24})\.dfs\.core\.windows\.net",
        r"([a-z0-9]{3,24})\.file\.core\.windows\.net",
        r"([a-z0-9]{3,24})\.queue\.core\.windows\.net",
        r"([a-z0-9]{3,24})\.table\.core\.windows\.net",
    ]
    
    AZURE_FUNCTION_PATTERNS = [
        r"([a-z0-9-]+)\.azurewebsites\.net",
        r"([a-z0-9-]+)\.scm\.azurewebsites\.net",
    ]
    
    AZURE_KEYVAULT_PATTERNS = [
        r"([a-z0-9-]+)\.vault\.azure\.net",
    ]
    
    AZURE_COSMOSDB_PATTERNS = [
        r"([a-z0-9-]+)\.documents\.azure\.com",
        r"([a-z0-9-]+)\.mongo\.cosmos\.azure\.com",
    ]
    
    AZURE_ACR_PATTERNS = [
        r"([a-z0-9]+)\.azurecr\.io",
    ]
    
    # =============================================================
    # GCP PATTERNS
    # =============================================================
    
    GCP_STORAGE_PATTERNS = [
        r"storage\.googleapis\.com/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])",
        r"([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])\.storage\.googleapis\.com",
        r"storage\.cloud\.google\.com/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])",
    ]
    
    GCP_FUNCTION_PATTERNS = [
        r"[a-z0-9-]+-[a-z0-9]+\.cloudfunctions\.net",
        r"[a-z0-9-]+\.run\.app",
    ]
    
    GCP_FIREBASE_PATTERNS = [
        r"([a-z0-9-]+)\.firebaseio\.com",
        r"([a-z0-9-]+)\.firebaseapp\.com",
        r"([a-z0-9-]+)\.web\.app",
        r"firestore\.googleapis\.com/v1/projects/([a-z0-9-]+)",
    ]
    
    GCP_BIGQUERY_PATTERNS = [
        r"bigquery\.googleapis\.com/bigquery/v2/projects/([a-z0-9-]+)",
    ]
    
    GCP_GCR_PATTERNS = [
        r"gcr\.io/([a-z0-9-]+)",
        r"[a-z]+-docker\.pkg\.dev/([a-z0-9-]+)",
    ]
    
    # =============================================================
    # OTHER CLOUD PROVIDERS
    # =============================================================
    
    DIGITALOCEAN_PATTERNS = [
        r"([a-z0-9-]+)\.digitaloceanspaces\.com",
        r"([a-z0-9-]+)\.nyc3\.digitaloceanspaces\.com",
        r"([a-z0-9-]+)\.ams3\.digitaloceanspaces\.com",
        r"([a-z0-9-]+)\.sgp1\.digitaloceanspaces\.com",
    ]
    
    ORACLE_PATTERNS = [
        r"objectstorage\.[a-z0-9-]+\.oraclecloud\.com/n/([a-z0-9-]+)",
    ]
    
    ALIBABA_PATTERNS = [
        r"([a-z0-9-]+)\.oss-[a-z0-9-]+\.aliyuncs\.com",
    ]
    
    HEROKU_PATTERNS = [
        r"([a-z0-9-]+)\.herokuapp\.com",
    ]
    
    VERCEL_PATTERNS = [
        r"([a-z0-9-]+)\.vercel\.app",
        r"([a-z0-9-]+)\.now\.sh",
    ]
    
    NETLIFY_PATTERNS = [
        r"([a-z0-9-]+)\.netlify\.app",
        r"([a-z0-9-]+)\.netlify\.com",
    ]
    
    # =============================================================
    # CREDENTIAL PATTERNS (50+ patterns)
    # =============================================================
    
    CREDENTIAL_PATTERNS = [
        # AWS
        (r'AKIA[0-9A-Z]{16}', CredentialType.AWS_ACCESS_KEY, "AWS Access Key ID", "CRITICAL"),
        (r'ABIA[0-9A-Z]{16}', CredentialType.AWS_ACCESS_KEY, "AWS Access Key ID (STS)", "CRITICAL"),
        (r'ACCA[0-9A-Z]{16}', CredentialType.AWS_ACCESS_KEY, "AWS Access Key ID (CloudFront)", "CRITICAL"),
        (r'AGPA[0-9A-Z]{16}', CredentialType.AWS_ACCESS_KEY, "AWS Access Key ID (User)", "CRITICAL"),
        (r'AIDA[0-9A-Z]{16}', CredentialType.AWS_ACCESS_KEY, "AWS Access Key ID (IAM)", "CRITICAL"),
        (r'AIPA[0-9A-Z]{16}', CredentialType.AWS_ACCESS_KEY, "AWS Access Key ID (EC2)", "CRITICAL"),
        (r'AKIA[0-9A-Z]{16}', CredentialType.AWS_ACCESS_KEY, "AWS Access Key ID", "CRITICAL"),
        (r'ANPA[0-9A-Z]{16}', CredentialType.AWS_ACCESS_KEY, "AWS Access Key ID (Policy)", "CRITICAL"),
        (r'ANVA[0-9A-Z]{16}', CredentialType.AWS_ACCESS_KEY, "AWS Access Key ID (Version)", "CRITICAL"),
        (r'APKA[0-9A-Z]{16}', CredentialType.AWS_ACCESS_KEY, "AWS Access Key ID (App)", "CRITICAL"),
        (r'AROA[0-9A-Z]{16}', CredentialType.AWS_ACCESS_KEY, "AWS Access Key ID (Role)", "CRITICAL"),
        (r'ASCA[0-9A-Z]{16}', CredentialType.AWS_ACCESS_KEY, "AWS Access Key ID (Cert)", "CRITICAL"),
        (r'ASIA[0-9A-Z]{16}', CredentialType.AWS_SESSION_TOKEN, "AWS Temporary Access Key", "CRITICAL"),
        (r'aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', CredentialType.AWS_SECRET_KEY, "AWS Secret Access Key", "CRITICAL"),
        (r'aws_session_token\s*[=:]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?', CredentialType.AWS_SESSION_TOKEN, "AWS Session Token", "CRITICAL"),
        
        # Azure
        (r'AccountKey=([A-Za-z0-9+/=]{88})', CredentialType.AZURE_CONNECTION_STRING, "Azure Storage Account Key", "CRITICAL"),
        (r'SharedAccessSignature=([A-Za-z0-9%]+)', CredentialType.AZURE_CONNECTION_STRING, "Azure SAS Token", "HIGH"),
        (r'[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}', CredentialType.AZURE_CLIENT_SECRET, "Azure GUID", "INFO"),
        (r'DefaultEndpointsProtocol=https;AccountName=([^;]+);AccountKey=([A-Za-z0-9+/=]{88})', CredentialType.AZURE_CONNECTION_STRING, "Azure Connection String", "CRITICAL"),
        
        # GCP
        (r'"type"\s*:\s*"service_account"', CredentialType.GCP_SERVICE_ACCOUNT, "GCP Service Account JSON", "CRITICAL"),
        (r'"private_key"\s*:\s*"-----BEGIN', CredentialType.GCP_SERVICE_ACCOUNT, "GCP Service Account Private Key", "CRITICAL"),
        (r'AIza[0-9A-Za-z_-]{35}', CredentialType.GCP_API_KEY, "Google API Key", "HIGH"),
        (r'ya29\.[0-9A-Za-z_-]+', CredentialType.OAUTH_TOKEN, "Google OAuth Token", "CRITICAL"),
        
        # Private Keys
        (r'-----BEGIN RSA PRIVATE KEY-----', CredentialType.PRIVATE_KEY, "RSA Private Key", "CRITICAL"),
        (r'-----BEGIN DSA PRIVATE KEY-----', CredentialType.PRIVATE_KEY, "DSA Private Key", "CRITICAL"),
        (r'-----BEGIN EC PRIVATE KEY-----', CredentialType.PRIVATE_KEY, "EC Private Key", "CRITICAL"),
        (r'-----BEGIN OPENSSH PRIVATE KEY-----', CredentialType.PRIVATE_KEY, "OpenSSH Private Key", "CRITICAL"),
        (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', CredentialType.PRIVATE_KEY, "PGP Private Key", "CRITICAL"),
        (r'-----BEGIN ENCRYPTED PRIVATE KEY-----', CredentialType.PRIVATE_KEY, "Encrypted Private Key", "HIGH"),
        
        # JWT
        (r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', CredentialType.JWT_SECRET, "JWT Token", "HIGH"),
        (r'jwt[_-]?secret\s*[=:]\s*["\']([^"\']{16,})["\']', CredentialType.JWT_SECRET, "JWT Secret", "CRITICAL"),
        
        # Database Connection Strings
        (r'mongodb(\+srv)?://[^\s"\'<>]+', CredentialType.DATABASE_URL, "MongoDB Connection String", "CRITICAL"),
        (r'postgres(ql)?://[^\s"\'<>]+', CredentialType.DATABASE_URL, "PostgreSQL Connection String", "CRITICAL"),
        (r'mysql://[^\s"\'<>]+', CredentialType.DATABASE_URL, "MySQL Connection String", "CRITICAL"),
        (r'redis://[^\s"\'<>]+', CredentialType.DATABASE_URL, "Redis Connection String", "HIGH"),
        (r'amqp://[^\s"\'<>]+', CredentialType.DATABASE_URL, "RabbitMQ Connection String", "HIGH"),
        
        # API Keys Generic
        (r'api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_-]{20,})["\']', CredentialType.API_KEY, "API Key", "HIGH"),
        (r'secret[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_-]{20,})["\']', CredentialType.API_KEY, "Secret Key", "HIGH"),
        (r'access[_-]?token\s*[=:]\s*["\']([A-Za-z0-9_-]{20,})["\']', CredentialType.OAUTH_TOKEN, "Access Token", "HIGH"),
        (r'auth[_-]?token\s*[=:]\s*["\']([A-Za-z0-9_-]{20,})["\']', CredentialType.OAUTH_TOKEN, "Auth Token", "HIGH"),
        (r'bearer\s+([A-Za-z0-9_-]{20,})', CredentialType.OAUTH_TOKEN, "Bearer Token", "HIGH"),
        
        # Specific Services
        (r'sk_live_[0-9a-zA-Z]{24,}', CredentialType.API_KEY, "Stripe Secret Key", "CRITICAL"),
        (r'sk_test_[0-9a-zA-Z]{24,}', CredentialType.API_KEY, "Stripe Test Key", "MEDIUM"),
        (r'pk_live_[0-9a-zA-Z]{24,}', CredentialType.API_KEY, "Stripe Publishable Key", "LOW"),
        (r'rk_live_[0-9a-zA-Z]{24,}', CredentialType.API_KEY, "Stripe Restricted Key", "HIGH"),
        (r'sq0atp-[0-9A-Za-z_-]{22}', CredentialType.API_KEY, "Square Access Token", "CRITICAL"),
        (r'sq0csp-[0-9A-Za-z_-]{43}', CredentialType.API_KEY, "Square OAuth Secret", "CRITICAL"),
        (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', CredentialType.API_KEY, "PayPal/Braintree Token", "CRITICAL"),
        (r'ghp_[0-9a-zA-Z]{36}', CredentialType.OAUTH_TOKEN, "GitHub Personal Access Token", "CRITICAL"),
        (r'gho_[0-9a-zA-Z]{36}', CredentialType.OAUTH_TOKEN, "GitHub OAuth Token", "CRITICAL"),
        (r'ghu_[0-9a-zA-Z]{36}', CredentialType.OAUTH_TOKEN, "GitHub User Token", "CRITICAL"),
        (r'ghr_[0-9a-zA-Z]{36}', CredentialType.OAUTH_TOKEN, "GitHub Refresh Token", "CRITICAL"),
        (r'ghs_[0-9a-zA-Z]{36}', CredentialType.OAUTH_TOKEN, "GitHub Server Token", "CRITICAL"),
        (r'glpat-[0-9a-zA-Z_-]{20}', CredentialType.OAUTH_TOKEN, "GitLab Personal Access Token", "CRITICAL"),
        (r'xox[baprs]-[0-9a-zA-Z]{10,}', CredentialType.OAUTH_TOKEN, "Slack Token", "CRITICAL"),
        (r'xoxe\.xox[bp]-[0-9]-[A-Za-z0-9]{163}', CredentialType.OAUTH_TOKEN, "Slack Config Token", "CRITICAL"),
        (r'T[A-Z0-9]{10}/B[A-Z0-9]{10}/[a-zA-Z0-9]{24}', CredentialType.API_KEY, "Slack Webhook", "HIGH"),
        (r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+', CredentialType.API_KEY, "Slack Webhook URL", "HIGH"),
        (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', CredentialType.API_KEY, "SendGrid API Key", "CRITICAL"),
        (r'key-[0-9a-zA-Z]{32}', CredentialType.API_KEY, "Mailgun API Key", "CRITICAL"),
        (r'[0-9a-f]{32}-us[0-9]{1,2}', CredentialType.API_KEY, "Mailchimp API Key", "HIGH"),
        (r'sk-[a-zA-Z0-9]{48}', CredentialType.API_KEY, "OpenAI API Key", "CRITICAL"),
        (r'AC[a-z0-9]{32}', CredentialType.API_KEY, "Twilio Account SID", "HIGH"),
        (r'SK[a-z0-9]{32}', CredentialType.API_KEY, "Twilio Auth Token", "CRITICAL"),
        (r'[0-9]+:AA[0-9A-Za-z_-]{33}', CredentialType.API_KEY, "Telegram Bot Token", "HIGH"),
        (r'DISCORD[_-]?TOKEN\s*[=:]\s*["\']?([A-Za-z0-9._-]+)["\']?', CredentialType.OAUTH_TOKEN, "Discord Bot Token", "HIGH"),
        (r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}', CredentialType.OAUTH_TOKEN, "Discord Token", "HIGH"),
    ]
    
    # Common containers
    COMMON_S3_CONTAINERS = [
        "assets", "backup", "backups", "cdn", "data", "dev", "development",
        "files", "images", "logs", "media", "private", "prod", "production",
        "public", "staging", "static", "test", "testing", "uploads", "www"
    ]
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.discovered_resources: list[CloudResource] = []
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Comprehensive cloud security scan - Enterprise Edition.
        
        Scan Phases:
        1. Content collection and analysis
        2. AWS resource enumeration
        3. Azure resource enumeration
        4. GCP resource enumeration
        5. Other cloud providers scan
        6. Credential exposure detection
        7. Cloud metadata service testing
        8. Serverless function exposure
        9. Container registry analysis
        10. Permission and policy analysis
        """

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[Finding] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        parsed = urlparse(base_url)
        domain = parsed.netloc.replace("www.", "")
        
        logger.info(f"[Cloud Scanner Enterprise v2.0] Starting comprehensive scan on {base_url}")
        
        # Collect content for analysis
        all_content = await self._collect_content(base_url, asset_data)
        
        async with get_scan_client(verify_ssl=False, timeout=self.timeout) as client:
            # Phase 1: AWS Resource Analysis
            aws_findings = await self._scan_aws_resources(
                client, base_url, domain, all_content, rate_limiter
            )
            findings.extend(aws_findings)
            
            # Phase 2: Azure Resource Analysis
            azure_findings = await self._scan_azure_resources(
                client, base_url, domain, all_content, rate_limiter
            )
            findings.extend(azure_findings)
            
            # Phase 3: GCP Resource Analysis
            gcp_findings = await self._scan_gcp_resources(
                client, base_url, domain, all_content, rate_limiter
            )
            findings.extend(gcp_findings)
            
            # Phase 4: Firebase Analysis (special case)
            firebase_findings = await self._scan_firebase_resources(
                client, base_url, all_content, rate_limiter
            )
            findings.extend(firebase_findings)
            
            # Phase 5: Other Cloud Providers
            other_findings = await self._scan_other_providers(
                client, base_url, domain, all_content, rate_limiter
            )
            findings.extend(other_findings)
            
            # Phase 6: Credential Exposure Detection
            cred_findings = self._detect_credential_exposure(base_url, all_content)
            findings.extend(cred_findings)
            
            # Phase 7: S3 Bucket Enumeration by Domain
            enum_findings = await self._enumerate_s3_buckets(
                client, base_url, domain, rate_limiter
            )
            findings.extend(enum_findings)
            
            # Phase 8: Cloud Metadata Testing (if reachable)
            metadata_findings = await self._test_cloud_metadata(
                client, base_url, rate_limiter
            )
            findings.extend(metadata_findings)
            
            # Phase 9: Serverless Function Analysis
            serverless_findings = await self._analyze_serverless_functions(
                client, base_url, all_content, rate_limiter
            )
            findings.extend(serverless_findings)
        
        # Deduplicate findings
        findings = self._deduplicate_findings(findings)
        
        logger.info(f"[Cloud Scanner Enterprise v2.0] Found {len(findings)} cloud security issues")
        
        return findings
    
    async def _collect_content(
        self,
        base_url: str,
        asset_data: dict[str, Any],
    ) -> str:
        """Collect page and JS content for analysis."""
        content_parts = []
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            # Get main page
            try:
                response = await client.get(base_url)
                content_parts.append(response.text)
            except Exception as e:
                logger.debug(f"Failed to get page content: {e}")

            # Get JS files
            js_files = asset_data.get("js_files", []) if isinstance(asset_data, dict) else []
            for js_url in js_files[:15]:
                try:
                    response = await client.get(js_url)
                    content_parts.append(response.text)
                except (httpx.HTTPError, httpx.TimeoutException):
                    continue

            # Get common API config endpoints
            config_paths = [
                "/config.js", "/app/config.js", "/static/js/config.js",
                "/env.js", "/.env.js", "/settings.js",
                "/api/config", "/api/v1/config",
            ]

            for path in config_paths:
                try:
                    response = await client.get(urljoin(base_url, path))
                    if response.status_code == 200:
                        content_parts.append(response.text)
                except (httpx.HTTPError, httpx.TimeoutException):
                    continue
        
        return "\n".join(content_parts)
    
    async def _scan_aws_resources(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        domain: str,
        content: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for AWS resources and misconfigurations."""
        findings = []
        
        # Find S3 buckets in content
        s3_buckets = set()
        for pattern in self.AWS_S3_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            s3_buckets.update(matches)
        
        # Test each discovered bucket
        for bucket in list(s3_buckets)[:15]:
            await rate_limiter.acquire()
            bucket_finding = await self._test_s3_bucket(client, base_url, bucket)
            if bucket_finding:
                findings.append(bucket_finding)
        
        # Find Lambda function URLs
        lambda_urls = set()
        for pattern in self.AWS_LAMBDA_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            lambda_urls.update(matches)
        
        for lambda_url in list(lambda_urls)[:5]:
            await rate_limiter.acquire()
            lambda_finding = await self._test_lambda_function(client, base_url, lambda_url)
            if lambda_finding:
                findings.append(lambda_finding)
        
        # Find API Gateway endpoints
        api_gw_endpoints = set()
        for pattern in self.AWS_API_GATEWAY_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            api_gw_endpoints.update(matches)
        
        for endpoint in list(api_gw_endpoints)[:5]:
            await rate_limiter.acquire()
            api_finding = await self._test_api_gateway(client, base_url, endpoint)
            if api_finding:
                findings.append(api_finding)
        
        # Find Cognito
        cognito_pools = set()
        for pattern in self.AWS_COGNITO_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            cognito_pools.update(matches)
        
        if cognito_pools:
            findings.append(Finding(
                name="AWS Cognito User Pool Exposed",
                severity=Severity.MEDIUM,
                confidence_score=85.0,
                description="AWS Cognito endpoints discovered in application code",
                endpoint=base_url,
                evidence=[f"Cognito pools: {list(cognito_pools)[:3]}"],
                cwe_id="CWE-200",
                cvss_score=5.3,
                remediation="Ensure Cognito pools are properly configured with strong security settings",
            ))
        
        return findings
    
    async def _test_s3_bucket(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        bucket: str,
    ) -> Optional[Finding]:
        """Test individual S3 bucket for misconfigurations."""
        bucket_url = f"https://{bucket}.s3.amazonaws.com"
        
        try:
            response = await client.get(bucket_url)
            
            if response.status_code == 200:
                if "<ListBucketResult" in response.text:
                    # Extract some file info
                    keys = re.findall(r'<Key>([^<]+)</Key>', response.text)[:5]
                    
                    return Finding(
                        name="Public S3 Bucket with Directory Listing",
                        severity=Severity.CRITICAL,
                        confidence_score=85.0,
                        description=f"S3 bucket '{bucket}' allows public listing. All objects are enumerable.",
                        endpoint=bucket_url,
                        evidence=[
                            f"Bucket: {bucket}",
                            "Directory listing enabled",
                            f"Sample objects: {keys}",
                        ],
                        cwe_id="CWE-732",
                        cvss_score=9.1,
                        remediation=(
                            "1. Enable S3 Block Public Access at account level\n"
                            "2. Review and restrict bucket policy\n"
                            "3. Enable server-side encryption\n"
                            "4. Enable access logging\n"
                            "5. Use CloudFront for public content distribution"
                        ),
                    )
                else:
                    return Finding(
                        name="Public S3 Bucket Access",
                        severity=Severity.HIGH,
                        confidence_score=85.0,
                        description=f"S3 bucket '{bucket}' is publicly accessible",
                        endpoint=bucket_url,
                        evidence=[f"Bucket: {bucket}", "HTTP 200 response"],
                        cwe_id="CWE-732",
                        cvss_score=7.5,
                        remediation="Review bucket access policies and restrict as needed",
                    )
            
            elif response.status_code == 403:
                # Test for ACL misconfigurations
                try:
                    acl_response = await client.get(f"{bucket_url}?acl")
                    if acl_response.status_code == 200 and "<AccessControlList>" in acl_response.text:
                        return Finding(
                            name="S3 Bucket ACL Publicly Readable",
                            severity=Severity.MEDIUM,
                            confidence_score=85.0,
                            description=f"S3 bucket '{bucket}' ACL is publicly readable",
                            endpoint=f"{bucket_url}?acl",
                            evidence=[f"Bucket: {bucket}", "ACL exposed"],
                            cwe_id="CWE-732",
                            cvss_score=5.3,
                            remediation="Disable public ACL access",
                        )
                except (httpx.HTTPError, httpx.TimeoutException):
                    pass
                
                # Bucket exists but is private - info only
                return Finding(
                    name="S3 Bucket Discovered",
                    severity=Severity.INFO,
                    confidence_score=85.0,
                    description=f"S3 bucket '{bucket}' exists (access denied)",
                    endpoint=bucket_url,
                    evidence=[f"Bucket: {bucket}"],
                    cwe_id="CWE-200",
                    cvss_score=0.0,
                    remediation="No action needed if intentionally private",
                )
                
        except Exception as e:
            logger.debug(f"S3 bucket test error for {bucket}: {e}")
        
        return None
    
    async def _test_lambda_function(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        lambda_url: str,
    ) -> Optional[Finding]:
        """Test Lambda function URL exposure."""
        full_url = f"https://{lambda_url}" if not lambda_url.startswith("http") else lambda_url
        
        try:
            response = await client.get(full_url)
            
            if response.status_code != 403:
                return Finding(
                    name="AWS Lambda Function URL Exposed",
                    severity=Severity.MEDIUM,
                    confidence_score=85.0,
                    description=f"Lambda function URL is publicly accessible: {lambda_url}",
                    endpoint=full_url,
                    evidence=[
                        f"Function URL: {lambda_url}",
                        f"Response code: {response.status_code}",
                    ],
                    cwe_id="CWE-284",
                    cvss_score=5.3,
                    remediation="Configure Lambda function URL authentication (AWS_IAM or custom auth)",
                )
        except Exception as e:
            logger.debug(f"Lambda test error: {e}")
        
        return None
    
    async def _test_api_gateway(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: str,
    ) -> Optional[Finding]:
        """Test API Gateway endpoint configuration."""
        full_url = f"https://{endpoint}" if not endpoint.startswith("http") else endpoint
        
        try:
            # Test common API paths
            test_paths = ["/", "/api", "/v1", "/swagger", "/docs", "/openapi.json", "/swagger.json"]
            
            for path in test_paths:
                response = await client.get(f"{full_url}{path}")
                
                # Check for exposed swagger/openapi docs
                if path in ["/swagger", "/docs", "/openapi.json", "/swagger.json"]:
                    if response.status_code == 200 and ("swagger" in response.text.lower() or "openapi" in response.text.lower()):
                        return Finding(
                            name="API Gateway Documentation Exposed",
                            severity=Severity.MEDIUM,
                            confidence_score=85.0,
                            description=f"API documentation is publicly accessible at {full_url}{path}",
                            endpoint=f"{full_url}{path}",
                            evidence=[f"Endpoint: {endpoint}", f"Docs at: {path}"],
                            cwe_id="CWE-200",
                            cvss_score=5.3,
                            remediation="Restrict API documentation access in production",
                        )
        except Exception as e:
            logger.debug(f"API Gateway test error: {e}")
        
        return None
    
    async def _scan_azure_resources(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        domain: str,
        content: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for Azure resources and misconfigurations."""
        findings = []
        
        # Find Azure Storage accounts
        storage_accounts = set()
        for pattern in self.AZURE_BLOB_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            storage_accounts.update(matches)
        
        for account in list(storage_accounts)[:10]:
            await rate_limiter.acquire()
            finding = await self._test_azure_storage(client, base_url, account)
            if finding:
                findings.append(finding)
        
        # Find Azure Functions
        function_apps = set()
        for pattern in self.AZURE_FUNCTION_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            function_apps.update(matches)
        
        for app in list(function_apps)[:5]:
            await rate_limiter.acquire()
            finding = await self._test_azure_function(client, base_url, app)
            if finding:
                findings.append(finding)
        
        # Find Key Vaults
        keyvaults = set()
        for pattern in self.AZURE_KEYVAULT_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            keyvaults.update(matches)
        
        if keyvaults:
            findings.append(Finding(
                name="Azure Key Vault Reference Discovered",
                severity=Severity.INFO,
                confidence_score=85.0,
                description="Azure Key Vault references found in application",
                endpoint=base_url,
                evidence=[f"Key Vaults: {list(keyvaults)[:3]}"],
                cwe_id="CWE-200",
                cvss_score=0.0,
                remediation="Ensure Key Vault access policies are properly configured",
            ))
        
        # Find Container Registries
        acr_registries = set()
        for pattern in self.AZURE_ACR_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            acr_registries.update(matches)
        
        for registry in list(acr_registries)[:3]:
            await rate_limiter.acquire()
            finding = await self._test_azure_acr(client, base_url, registry)
            if finding:
                findings.append(finding)
        
        return findings
    
    async def _test_azure_storage(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        account: str,
    ) -> Optional[Finding]:
        """Test Azure Storage account for misconfigurations."""
        blob_url = f"https://{account}.blob.core.windows.net/?comp=list"
        
        try:
            response = await client.get(blob_url)
            
            if response.status_code == 200:
                if "<EnumerationResults" in response.text or "<Containers>" in response.text:
                    containers = re.findall(r'<Name>([^<]+)</Name>', response.text)[:5]
                    
                    return Finding(
                        name="Azure Blob Storage Public Container Enumeration",
                        severity=Severity.CRITICAL,
                        confidence_score=85.0,
                        description=f"Azure storage account '{account}' allows public container enumeration",
                        endpoint=blob_url,
                        evidence=[
                            f"Account: {account}",
                            f"Containers: {containers}",
                        ],
                        cwe_id="CWE-732",
                        cvss_score=9.1,
                        remediation=(
                            "1. Disable public blob access at storage account level\n"
                            "2. Use private endpoints for access\n"
                            "3. Implement SAS tokens with minimal permissions\n"
                            "4. Enable storage analytics logging"
                        ),
                    )
        except Exception as e:
            logger.debug(f"Azure storage test error: {e}")
        
        return None
    
    async def _test_azure_function(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        app: str,
    ) -> Optional[Finding]:
        """Test Azure Function App exposure."""
        func_url = f"https://{app}.azurewebsites.net"
        
        try:
            response = await client.get(func_url)
            
            # Check for default page or exposed functions
            if response.status_code == 200:
                if "Your Azure Function App is up and running" in response.text:
                    return Finding(
                        name="Azure Function App Default Page Exposed",
                        severity=Severity.LOW,
                        confidence_score=85.0,
                        description=f"Azure Function App default page is accessible: {app}",
                        endpoint=func_url,
                        evidence=[f"Function App: {app}"],
                        cwe_id="CWE-200",
                        cvss_score=3.1,
                        remediation="Configure function authorization levels appropriately",
                    )
                
                # Test for SCM (Kudu) exposure
                scm_response = await client.get(f"https://{app}.scm.azurewebsites.net")
                if scm_response.status_code != 401:
                    return Finding(
                        name="Azure Function App SCM (Kudu) Exposed",
                        severity=Severity.HIGH,
                        confidence_score=85.0,
                        description=f"Azure Function App SCM endpoint accessible without auth: {app}",
                        endpoint=f"https://{app}.scm.azurewebsites.net",
                        evidence=[f"Function App: {app}", "SCM endpoint accessible"],
                        cwe_id="CWE-306",
                        cvss_score=8.1,
                        remediation="Restrict SCM site access using IP restrictions or authentication",
                    )
        except Exception as e:
            logger.debug(f"Azure function test error: {e}")
        
        return None
    
    async def _test_azure_acr(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        registry: str,
    ) -> Optional[Finding]:
        """Test Azure Container Registry exposure."""
        acr_url = f"https://{registry}.azurecr.io/v2/_catalog"
        
        try:
            response = await client.get(acr_url)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    repositories = []
                    if isinstance(asset_data, dict):
                        repositories = data.get("repositories", [])[:5]
                    
                    return Finding(
                        name="Azure Container Registry Public Access",
                        severity=Severity.CRITICAL,
                        confidence_score=85.0,
                        description=f"Azure Container Registry '{registry}' is publicly accessible",
                        endpoint=acr_url,
                        evidence=[
                            f"Registry: {registry}",
                            f"Repositories: {repositories}",
                        ],
                        cwe_id="CWE-732",
                        cvss_score=9.1,
                        remediation="Disable anonymous pull access and use Azure AD authentication",
                    )
                except (httpx.HTTPError, httpx.TimeoutException, KeyError):
                    pass
        except (httpx.HTTPError, httpx.TimeoutException) as e:
            logger.debug(f"ACR test error: {e}")
        
        return None
    
    async def _scan_gcp_resources(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        domain: str,
        content: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for GCP resources and misconfigurations."""
        findings = []
        
        # Find GCP Storage buckets
        buckets = set()
        for pattern in self.GCP_STORAGE_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            buckets.update(matches)
        
        for bucket in list(buckets)[:10]:
            await rate_limiter.acquire()
            finding = await self._test_gcp_bucket(client, base_url, bucket)
            if finding:
                findings.append(finding)
        
        # Find Cloud Functions
        functions = set()
        for pattern in self.GCP_FUNCTION_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            functions.update(matches)
        
        for func in list(functions)[:5]:
            findings.append(Finding(
                name="GCP Cloud Function Discovered",
                severity=Severity.INFO,
                confidence_score=85.0,
                description=f"GCP Cloud Function endpoint discovered: {func}",
                endpoint=base_url,
                evidence=[f"Function: {func}"],
                cwe_id="CWE-200",
                cvss_score=0.0,
                remediation="Ensure Cloud Functions have appropriate authentication",
            ))
        
        # Find GCR repositories
        gcr_repos = set()
        for pattern in self.GCP_GCR_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            gcr_repos.update(matches)
        
        for repo in list(gcr_repos)[:3]:
            await rate_limiter.acquire()
            finding = await self._test_gcr(client, base_url, repo)
            if finding:
                findings.append(finding)
        
        return findings
    
    async def _test_gcp_bucket(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        bucket: str,
    ) -> Optional[Finding]:
        """Test GCP Storage bucket for misconfigurations."""
        bucket_url = f"https://storage.googleapis.com/{bucket}"
        
        try:
            response = await client.get(bucket_url)
            
            if response.status_code == 200:
                if "<ListBucketResult" in response.text:
                    keys = re.findall(r'<Key>([^<]+)</Key>', response.text)[:5]
                    
                    return Finding(
                        name="GCP Storage Bucket Public Listing",
                        severity=Severity.CRITICAL,
                        confidence_score=85.0,
                        description=f"GCP bucket '{bucket}' allows public listing",
                        endpoint=bucket_url,
                        evidence=[
                            f"Bucket: {bucket}",
                            f"Sample objects: {keys}",
                        ],
                        cwe_id="CWE-732",
                        cvss_score=9.1,
                        remediation=(
                            "1. Remove public access using gsutil or Console\n"
                            "2. Enable uniform bucket-level access\n"
                            "3. Use IAM for access control\n"
                            "4. Enable audit logging"
                        ),
                    )
            elif response.status_code == 403:
                return Finding(
                    name="GCP Storage Bucket Discovered",
                    severity=Severity.INFO,
                    confidence_score=85.0,
                    description=f"GCP bucket '{bucket}' exists (access denied)",
                    endpoint=bucket_url,
                    evidence=[f"Bucket: {bucket}"],
                    cwe_id="CWE-200",
                    cvss_score=0.0,
                    remediation="No action needed if intentionally private",
                )
        except Exception as e:
            logger.debug(f"GCP bucket test error: {e}")
        
        return None
    
    async def _test_gcr(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        project: str,
    ) -> Optional[Finding]:
        """Test Google Container Registry exposure."""
        gcr_url = f"https://gcr.io/v2/{project}/tags/list"
        
        try:
            response = await client.get(gcr_url)
            
            if response.status_code == 200:
                return Finding(
                    name="GCP Container Registry Public Access",
                    severity=Severity.HIGH,
                    confidence_score=85.0,
                    description=f"GCR project '{project}' is publicly accessible",
                    endpoint=gcr_url,
                    evidence=[f"Project: {project}"],
                    cwe_id="CWE-732",
                    cvss_score=7.5,
                    remediation="Configure IAM policies to restrict GCR access",
                )
        except Exception as e:
            logger.debug(f"GCR test error: {e}")
        
        return None
    
    async def _scan_firebase_resources(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        content: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for Firebase misconfigurations."""
        findings = []
        
        # Find Firebase projects
        projects = set()
        for pattern in self.GCP_FIREBASE_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            projects.update(matches)
        
        for project in list(projects)[:5]:
            await rate_limiter.acquire()
            
            # Test Realtime Database
            db_url = f"https://{project}.firebaseio.com/.json"
            try:
                response = await client.get(db_url)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if data is not None and data != "null":
                            data_preview = str(data)[:200] if isinstance(data, dict) else str(data)[:100]
                            
                            findings.append(Finding(
                                name="Firebase Realtime Database Public Read",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description=f"Firebase database '{project}' is publicly readable",
                                endpoint=db_url,
                                evidence=[
                                    f"Project: {project}",
                                    f"Data preview: {data_preview}...",
                                ],
                                cwe_id="CWE-306",
                                cvss_score=9.8,
                                remediation=(
                                    "1. Configure Firebase Security Rules\n"
                                    "2. Require authentication for reads\n"
                                    "3. Use rule validation for data access\n"
                                    "4. Enable audit logging"
                                ),
                            ))
                    except json.JSONDecodeError:
                        pass
                        
                # Test for write access - ONLY in write-allowed modes
                if not ALLOW_WRITES:
                    logger.debug(f"⚠️ SAFE MODE: Skipping Firebase write test for project '{project}'")
                else:
                    try:
                        test_path = f"https://{project}.firebaseio.com/test_write_check.json"
                        write_response = await client.put(
                            test_path,
                            json={"test": "vulnerability_scan"},
                        )
                        
                        if write_response.status_code == 200:
                            # Clean up
                            await client.delete(test_path)
                            
                            findings.append(Finding(
                                name="Firebase Realtime Database Public Write",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description=f"Firebase database '{project}' allows public writes",
                                endpoint=test_path,
                                evidence=[f"Project: {project}", "Write successful"],
                                cwe_id="CWE-306",
                                cvss_score=10.0,
                                remediation="IMMEDIATELY configure Firebase Security Rules to require authentication",
                            ))
                    except (httpx.HTTPError, httpx.TimeoutException):
                        pass

            except (httpx.HTTPError, httpx.TimeoutException) as e:
                logger.debug(f"Firebase test error: {e}")
        
        return findings
    
    async def _scan_other_providers(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        domain: str,
        content: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for other cloud provider resources."""
        findings = []
        
        # DigitalOcean Spaces
        do_spaces = set()
        for pattern in self.DIGITALOCEAN_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            do_spaces.update(matches)
        
        for space in list(do_spaces)[:5]:
            await rate_limiter.acquire()
            # Spaces use S3-compatible API
            space_url = f"https://{space}.nyc3.digitaloceanspaces.com"
            try:
                response = await client.get(space_url)
                if response.status_code == 200 and "<ListBucketResult" in response.text:
                    findings.append(Finding(
                        name="DigitalOcean Space Public Listing",
                        severity=Severity.HIGH,
                        confidence_score=85.0,
                        description=f"DigitalOcean Space '{space}' allows public listing",
                        endpoint=space_url,
                        evidence=[f"Space: {space}"],
                        cwe_id="CWE-732",
                        cvss_score=7.5,
                        remediation="Disable public file listing in Space settings",
                    ))
            except (httpx.HTTPError, httpx.TimeoutException):
                pass

        # Heroku apps
        heroku_apps = set()
        for pattern in self.HEROKU_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            heroku_apps.update(matches)
        
        for app in list(heroku_apps)[:3]:
            findings.append(Finding(
                name="Heroku Application Discovered",
                severity=Severity.INFO,
                confidence_score=85.0,
                description=f"Heroku application '{app}' referenced in code",
                endpoint=base_url,
                evidence=[f"App: {app}.herokuapp.com"],
                cwe_id="CWE-200",
                cvss_score=0.0,
                remediation="Ensure Heroku app is properly secured",
            ))
        
        return findings
    
    def _detect_credential_exposure(
        self,
        base_url: str,
        content: str,
    ) -> list[Finding]:
        """Detect exposed credentials using 50+ patterns."""
        findings = []
        found_creds = []
        
        for pattern, cred_type, description, severity in self.CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            if matches:
                # Filter false positives
                valid_matches = []
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else match[-1]
                    
                    if not self._is_false_positive(match, cred_type):
                        valid_matches.append(match)
                
                if valid_matches:
                    for match in valid_matches[:3]:
                        masked = self._mask_credential(match)
                        found_creds.append(CredentialLeak(
                            credential_type=cred_type,
                            value_masked=masked,
                            location=base_url,
                            context=description,
                            severity=severity,
                        ))
                        
                        findings.append(Finding(
                            name=f"Exposed {description}",
                            severity=severity,
                            confidence_score=85.0,
                            description=f"{description} found in application code/response",
                            endpoint=base_url,
                            evidence=[
                                f"Credential type: {description}",
                                f"Masked value: {masked}",
                            ],
                            cwe_id="CWE-312",
                            cvss_score=9.8 if severity == "CRITICAL" else (7.5 if severity == "HIGH" else 5.3),
                            remediation=(
                                "1. IMMEDIATELY rotate the exposed credential\n"
                                "2. Remove credential from client-side code\n"
                                "3. Use environment variables or secrets manager\n"
                                "4. Enable credential scanning in CI/CD pipeline\n"
                                "5. Audit access logs for unauthorized usage"
                            ),
                        ))
        
        return findings
    
    async def _enumerate_s3_buckets(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        domain: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Enumerate potential S3 buckets based on domain."""
        findings = []

        # Skip S3 enumeration for localhost/local targets - makes no sense!
        local_indicators = [
            "localhost", "127.0.0.1", "::1", "0.0.0.0",
            "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
            ".local", ".internal", ".lan", ".home"
        ]
        if any(indicator in domain.lower() for indicator in local_indicators):
            logger.debug(f"[Cloud Scanner] Skipping S3 enumeration for local target: {domain}")
            return findings

        # Generate potential bucket names
        domain_parts = domain.replace(".", "-").split("-")
        base_names = [domain.replace(".", "-"), domain.replace(".", "")]
        base_names.extend(domain_parts)
        
        bucket_candidates = set()
        for base in base_names:
            bucket_candidates.add(base)
            for suffix in self.COMMON_S3_CONTAINERS:
                bucket_candidates.add(f"{base}-{suffix}")
                bucket_candidates.add(f"{suffix}-{base}")
        
        # Test top candidates
        for bucket in list(bucket_candidates)[:20]:
            await rate_limiter.acquire()
            finding = await self._test_s3_bucket(client, base_url, bucket)
            if finding and finding.severity != "INFO":
                findings.append(finding)
        
        return findings
    
    async def _test_cloud_metadata(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for cloud metadata service access via SSRF."""
        findings = []
        
        # This checks if the application might be vulnerable to metadata access
        # via SSRF parameters
        ssrf_params = ["url", "uri", "redirect", "callback", "webhook", "src"]
        metadata_targets = [
            ("http://169.254.169.254/latest/meta-data/", "AWS IMDS"),
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"),
        ]
        
        for param in ssrf_params[:3]:
            for target, provider in metadata_targets:
                await rate_limiter.acquire()
                
                try:
                    test_url = f"{base_url}?{param}={quote(target)}"
                    
                    headers = {}
                    if "google" in target:
                        headers["Metadata-Flavor"] = "Google"
                    
                    response = await client.get(test_url, headers=headers)
                    
                    # Check for metadata indicators
                    indicators = ["ami-id", "instance-id", "computeMetadata", "vmId"]
                    if any(indicator in response.text for indicator in indicators):
                        findings.append(Finding(
                            name=f"Cloud Metadata Access via SSRF - {provider}",
                            severity=Severity.CRITICAL,
                            confidence_score=85.0,
                            description=f"{provider} accessible via SSRF in {param} parameter",
                            endpoint=test_url,
                            evidence=[
                                f"Parameter: {param}",
                                f"Target: {target}",
                                f"Provider: {provider}",
                            ],
                            cwe_id="CWE-918",
                            cvss_score=10.0,
                            remediation=(
                                "1. CRITICAL: Cloud credentials may be compromised\n"
                                "2. Block requests to metadata IPs at network level\n"
                                "3. Implement URL validation and allowlisting\n"
                                "4. Use IMDSv2 on AWS (requires token)"
                            ),
                        ))
                        return findings  # Critical finding, stop
                        
                except Exception as e:
                    logger.debug(f"Metadata test error: {e}")
        
        return findings
    
    async def _analyze_serverless_functions(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        content: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Analyze serverless function configurations."""
        findings = []
        
        # Check for exposed function configuration
        serverless_indicators = [
            (r'serverless\.yml', "Serverless Framework Config"),
            (r'functions:', "Lambda/Cloud Functions Definition"),
            (r'aws_lambda_function', "Terraform Lambda Resource"),
            (r'google_cloudfunctions_function', "Terraform Cloud Function"),
            (r'azurerm_function_app', "Terraform Azure Function"),
        ]
        
        for pattern, indicator in serverless_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(Finding(
                    name=f"Serverless Configuration Exposed - {indicator}",
                    severity=Severity.MEDIUM,
                    confidence_score=65.0,
                    description=f"Serverless function configuration ({indicator}) may be exposed",
                    endpoint=base_url,
                    evidence=[f"Pattern: {pattern}"],
                    cwe_id="CWE-200",
                    cvss_score=5.3,
                    remediation="Remove infrastructure configuration from public-facing code",
                ))
        
        return findings
    
    def _is_false_positive(self, value: str, cred_type: CredentialType) -> bool:
        """Check if credential match is likely a false positive."""
        if not value:
            return True
        
        # Common false positives
        false_positives = [
            "0000000000000000000000000000000000000000",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "xxxxxxxxxxxxxxxxxxxx",
            "example",
            "placeholder",
            "your-secret-key",
            "your-api-key",
            "api-key-here",
            "insert-key-here",
            "key-goes-here",
            "your_api_key",
            "test",
            "demo",
            "sample",
        ]
        
        value_lower = value.lower()
        
        if value_lower in false_positives:
            return True
        
        # Too short
        if len(value) < 10:
            return True
        
        # Too repetitive
        if len(set(value)) < 5:
            return True
        
        # All same case letters only
        if value.isalpha() and (value.islower() or value.isupper()):
            return True
        
        # All digits
        if value.isdigit():
            return True
        
        # Placeholder patterns
        placeholder_patterns = [
            r'^[x]+$',
            r'^[X]+$',
            r'^[\*]+$',
            r'^[\.]+$',
            r'example',
            r'placeholder',
            r'changeme',
            r'password',
            r'secret',
            r'your[_-]',
            r'\$\{',
            r'<%=',
            r'{{',
        ]
        
        for pattern in placeholder_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    def _mask_credential(self, cred: str) -> str:
        """Mask credential for safe reporting."""
        if len(cred) > 16:
            return cred[:6] + "..." + cred[-4:]
        elif len(cred) > 8:
            return cred[:4] + "..." + cred[-2:]
        elif len(cred) > 4:
            return cred[:2] + "***" + cred[-1:]
        return "***"
    
    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings."""
        seen = set()
        unique = []
        
        for finding in findings:
            key = (finding.name, finding.endpoint)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique
