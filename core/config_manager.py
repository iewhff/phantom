"""
Configuration Manager with Pydantic validation.
Provides type-safe configuration loading and validation.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings


class AIConfig(BaseModel):
    """AI model configuration."""
    
    provider: str = "ollama"
    model: str = "llama3.1:8b"
    base_url: str = "http://localhost:11434"
    temperature: float = Field(default=0.3, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=256)
    context_window: int = 128000
    top_p: float = Field(default=0.9, ge=0.0, le=1.0)
    max_retries: int = Field(default=3, ge=1)
    retry_delay: float = Field(default=1.0, ge=0.1)
    timeout: int = Field(default=120, ge=10)
    embedding_model: str = "nomic-embed-text"


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""
    
    requests_per_second: int = Field(default=10, ge=1)
    concurrent_scans: int = Field(default=5, ge=1)
    max_requests_per_minute: int = Field(default=500, ge=10)
    adaptive: bool = True
    backoff_factor: float = Field(default=2.0, ge=1.0)
    min_delay: float = Field(default=0.1, ge=0.01)
    max_delay: float = Field(default=60.0, ge=1.0)
    modules: dict[str, int] = Field(default_factory=lambda: {
        "nuclei": 50,
        "nmap": 100,
        "dirbrute": 30,
        "default": 10,
    })


class PhaseTimeoutsConfig(BaseModel):
    """Per-phase timeout configuration (L9 fix)."""
    discovery: int = Field(default=300, ge=30)
    auth_acquisition: int = Field(default=180, ge=30)
    module_execution: int = Field(default=7200, ge=60)
    proof_engine: int = Field(default=600, ge=30)
    chain_analysis: int = Field(default=300, ge=30)
    validation: int = Field(default=300, ge=30)


class TimeoutsConfig(BaseModel):
    """Timeout configuration."""

    connection: int = Field(default=15, ge=1)
    read: int = Field(default=45, ge=1)
    request_timeout: int = Field(default=45, ge=1)  # General request timeout
    subdomain_enum: int = Field(default=600, ge=30)
    port_scan: int = Field(default=900, ge=60)
    vuln_scan: int = Field(default=3600, ge=60)
    crawl: int = Field(default=900, ge=60)
    ai_analysis: int = Field(default=180, ge=30)
    ai_generation: int = Field(default=240, ge=30)
    # Per-module timeouts (configurable via settings.yaml)
    module_heavy: int = Field(default=900, ge=60)   # 15 min for sqli, xss, nosql, etc.
    module_normal: int = Field(default=600, ge=60)  # 10 min for normal modules
    # L9 fix: Per-phase timeouts
    phase_timeouts: PhaseTimeoutsConfig = Field(default_factory=PhaseTimeoutsConfig)


class StorageConfig(BaseModel):
    """Storage configuration."""
    
    database_url: str = "sqlite+aiosqlite:///data/pentest.db"
    vector_store_path: str = "data/knowledge_base"
    collection_name: str = "pentest_knowledge"
    encryption_key_file: str = ".secrets/encryption.key"
    auto_cleanup_days: int = Field(default=30, ge=1)
    max_scan_history: int = Field(default=100, ge=10)


class SubdomainConfig(BaseModel):
    """Subdomain enumeration configuration."""
    
    wordlist: str = "data/wordlists/subdomains-10k.txt"
    resolvers: str = "data/wordlists/resolvers.txt"
    concurrent_resolvers: int = Field(default=50, ge=1)
    use_crt_sh: bool = True
    use_virustotal: bool = False


class PortsConfig(BaseModel):
    """Port scanning configuration."""
    
    default_ports: str = "top1000"
    scan_type: str = "syn"
    timing: int = Field(default=4, ge=0, le=5)
    
    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        valid = {"syn", "connect", "udp"}
        if v.lower() not in valid:
            raise ValueError(f"scan_type must be one of {valid}")
        return v.lower()


class CrawlerConfig(BaseModel):
    """Crawler configuration - Enhanced for better endpoint discovery."""

    max_depth: int = Field(default=5, ge=1, le=15)
    max_pages: int = Field(default=2000, ge=1)
    respect_robots: bool = False  # Disabled for security testing
    follow_redirects: bool = True
    parse_forms: bool = True
    parse_javascript: bool = True
    parse_comments: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    excluded_extensions: list[str] = Field(
        default_factory=lambda: [".pdf", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot"]
    )
    include_extensions: list[str] = Field(
        default_factory=lambda: [".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".cgi", ".pl"]
    )
    interesting_params: list[str] = Field(
        default_factory=lambda: ["id", "user", "page", "file", "path", "url", "redirect", "next", "return", "callback", "data", "query", "search", "q", "cmd", "exec", "action"]
    )


class ReconnaissanceConfig(BaseModel):
    """Reconnaissance configuration."""
    
    subdomains: SubdomainConfig = Field(default_factory=SubdomainConfig)
    ports: PortsConfig = Field(default_factory=PortsConfig)
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)


class ModuleConfig(BaseModel):
    """Individual scanning module configuration."""
    
    enabled: bool = True
    extra: dict[str, Any] = Field(default_factory=dict)


class ScanningConfig(BaseModel):
    """Scanning configuration."""
    
    default_modules: list[str] = Field(
        default_factory=lambda: ["nuclei", "headers", "ssl", "cors"]
    )
    modules: dict[str, dict[str, Any]] = Field(default_factory=dict)


class FPFilterConfig(BaseModel):
    """False positive filter configuration."""
    
    enabled: bool = True
    confidence_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    use_signatures: bool = True
    use_ai: bool = True


class ChainDetectionConfig(BaseModel):
    """Exploit chain detection configuration."""
    
    enabled: bool = True
    max_chain_length: int = Field(default=5, ge=2)
    min_confidence: float = Field(default=0.7, ge=0.0, le=1.0)


class ExploitSuggestConfig(BaseModel):
    """Exploit suggestion configuration."""
    
    enabled: bool = True
    generate_poc: bool = True
    severity_threshold: str = "high"
    
    @field_validator("severity_threshold")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = {"critical", "high", "medium", "low"}
        if v.lower() not in valid:
            raise ValueError(f"severity_threshold must be one of {valid}")
        return v.lower()


class AnalysisConfig(BaseModel):
    """AI Analysis configuration."""
    
    fp_filter: FPFilterConfig = Field(default_factory=FPFilterConfig)
    chain_detection: ChainDetectionConfig = Field(default_factory=ChainDetectionConfig)
    exploit_suggest: ExploitSuggestConfig = Field(default_factory=ExploitSuggestConfig)


class ReportingConfig(BaseModel):
    """Reporting configuration."""
    
    default_format: str = "pdf"
    available_formats: list[str] = Field(
        default_factory=lambda: ["pdf", "html", "json", "markdown"]
    )
    include_raw_data: bool = False
    anonymize_sensitive: bool = True
    include_screenshots: bool = False
    cvss_threshold: float = Field(default=4.0, ge=0.0, le=10.0)
    default_template: str = "professional"
    templates_path: str = "reporting/templates"
    company_name: str = ""
    company_logo: str = ""


class LoggingFileConfig(BaseModel):
    """File logging configuration."""
    
    enabled: bool = True
    path: str = "data/logs"
    rotation: str = "10 MB"
    retention: int = Field(default=90, ge=1)


class LoggingConsoleConfig(BaseModel):
    """Console logging configuration."""
    
    enabled: bool = True
    colors: bool = True


class LoggingConfig(BaseModel):
    """Logging configuration."""
    
    level: str = "INFO"
    format: str = "json"
    file: LoggingFileConfig = Field(default_factory=LoggingFileConfig)
    console: LoggingConsoleConfig = Field(default_factory=LoggingConsoleConfig)
    mask_patterns: list[str] = Field(
        default_factory=lambda: ["password", "token", "api_key", "secret"]
    )
    
    @field_validator("level")
    @classmethod
    def validate_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid:
            raise ValueError(f"level must be one of {valid}")
        return v.upper()


class APIsConfig(BaseModel):
    """API keys configuration."""
    
    virustotal_key: str = ""
    shodan_key: str = ""
    censys_key: str = ""


class SecurityConfig(BaseModel):
    """Security configuration."""
    
    require_authorization: bool = True
    authorized_targets_file: str = "config/authorized_targets.enc"
    excluded_ips: list[str] = Field(
        default_factory=lambda: [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
    )
    exclude_private_ips: bool = False


class ToolsConfig(BaseModel):
    """External tools configuration."""
    
    nmap: str = "nmap"
    nuclei: str = "nuclei"
    subfinder: str = "subfinder"
    httpx: str = "httpx"
    masscan: str = "masscan"


# =============================================================================
# NETWORK PROTECTION CONFIGURATION
# =============================================================================

class ProxyNetworkConfig(BaseModel):
    """Proxy configuration for network protection."""
    
    enabled: bool = False
    type: str = "http"  # http, https, socks4, socks5, tor
    host: str = "127.0.0.1"
    port: int = 8080
    username: str | None = None
    password: str | None = None


class TorNetworkConfig(BaseModel):
    """Tor configuration for network protection."""
    
    enabled: bool = False
    socks_port: int = 9050
    control_port: int = 9051
    password: str | None = None
    rotate_circuit_every: int = 10


class UserAgentConfig(BaseModel):
    """User-Agent configuration."""
    
    rotate: bool = True
    use_realistic: bool = True
    custom: str | None = None


class HeadersProtectionConfig(BaseModel):
    """Headers randomization configuration."""
    
    randomize: bool = True
    add_dnt: bool = True


class LeakProtectionConfig(BaseModel):
    """IP/DNS leak protection configuration."""
    
    check_before_scan: bool = True
    abort_on_leak: bool = True


class DNSProtectionConfig(BaseModel):
    """DNS protection configuration."""
    
    use_proxy_dns: bool = True
    custom_servers: list[str] = Field(default_factory=list)


class NetworkProtectionConfig(BaseModel):
    """Network protection (OPSEC) configuration."""

    enabled: bool = False
    proxy: ProxyNetworkConfig = Field(default_factory=ProxyNetworkConfig)
    tor: TorNetworkConfig = Field(default_factory=TorNetworkConfig)
    user_agent: UserAgentConfig = Field(default_factory=UserAgentConfig)
    headers: HeadersProtectionConfig = Field(default_factory=HeadersProtectionConfig)
    leak_protection: LeakProtectionConfig = Field(default_factory=LeakProtectionConfig)
    dns: DNSProtectionConfig = Field(default_factory=DNSProtectionConfig)


# ═══════════════════════════════════════════════════════════════════════════
# BUG BOUNTY CONFIGURATION - Safety for HackerOne/Bugcrowd
# ═══════════════════════════════════════════════════════════════════════════

class BugBountyScopeConfig(BaseModel):
    """Scope enforcement configuration."""
    strict_enforcement: bool = True
    require_confirmation: bool = True
    block_redirects_out_of_scope: bool = True


class BugBountySSRFConfig(BaseModel):
    """SSRF protection configuration."""
    block_cloud_metadata: bool = True
    block_private_ips: bool = True
    block_localhost: bool = True
    block_dangerous_protocols: bool = True
    allowed_protocols: list[str] = Field(default_factory=lambda: ["http", "https"])


class BugBountyBruteForceConfig(BaseModel):
    """Brute force protection configuration."""
    block_login_attacks: bool = True
    block_otp_enumeration: bool = True
    max_auth_attempts: int = Field(default=5, ge=1)


class BugBountyDoSConfig(BaseModel):
    """DoS protection configuration."""
    block_large_payloads: bool = True
    max_payload_size_kb: int = Field(default=10, ge=1)
    block_recursive_requests: bool = True
    max_recursion_depth: int = Field(default=3, ge=1)
    block_slow_http: bool = True


class BugBountyRateLimitModeConfig(BaseModel):
    """Rate limit mode configuration."""
    requests_per_second: float = Field(default=1.5, ge=0.1)
    burst: int = Field(default=3, ge=1)
    min_delay_ms: int = Field(default=500, ge=10)


class BugBountyRateLimitsConfig(BaseModel):
    """Rate limits configuration for different modes."""
    safe: BugBountyRateLimitModeConfig = Field(default_factory=BugBountyRateLimitModeConfig)
    moderate: BugBountyRateLimitModeConfig = Field(
        default_factory=lambda: BugBountyRateLimitModeConfig(
            requests_per_second=3.0, burst=5, min_delay_ms=200
        )
    )
    aggressive: BugBountyRateLimitModeConfig = Field(
        default_factory=lambda: BugBountyRateLimitModeConfig(
            requests_per_second=10.0, burst=15, min_delay_ms=50
        )
    )


class BugBountyLoggingConfig(BaseModel):
    """Bug bounty audit logging configuration."""
    log_all_requests: bool = True
    log_blocked_requests: bool = True
    log_file: str = "logs/bug_bounty_audit.jsonl"
    include_timestamps: bool = True
    include_payloads: bool = False


class BugBountyKillSwitchConfig(BaseModel):
    """Kill switch configuration."""
    enabled: bool = True
    trigger_on_scope_violation: bool = True
    trigger_on_rate_limit_exceeded: bool = True
    trigger_on_dangerous_action: bool = True


class BugBountyDisclaimerConfig(BaseModel):
    """Legal disclaimer configuration."""
    show_before_scan: bool = True
    require_acceptance: bool = True
    text: str = """WARNING: This tool is for AUTHORIZED security testing only.
- You MUST have written permission to test the target
- You MUST respect the program's scope and rules
- You are LEGALLY responsible for your actions
- Unauthorized access is a CRIME

By continuing, you confirm you have authorization."""


class BugBountyPresetCampaignConfig(BaseModel):
    """Bug bounty campaign configuration."""
    active: bool = False
    multiplier: int = Field(default=1, ge=1)
    budget: int = Field(default=0, ge=0)
    type: str = "normal"


class BugBountyPresetAccountConfig(BaseModel):
    """Bug bounty account configuration."""
    email_domain: str = ""
    require_account: bool = False


class BugBountyPresetConfig(BaseModel):
    """Bug bounty program preset configuration."""
    name: str = ""
    url: str = ""
    required_headers: dict[str, str] = Field(default_factory=dict)
    rate_limit: float = Field(default=1.0, ge=0.1)
    max_requests_per_minute: int = Field(default=30, ge=1)
    tier_1: list[str] = Field(default_factory=list)
    tier_2: list[str] = Field(default_factory=list)
    tier_3: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    prohibited: list[str] = Field(default_factory=list)
    account: BugBountyPresetAccountConfig = Field(default_factory=BugBountyPresetAccountConfig)
    campaign: BugBountyPresetCampaignConfig = Field(default_factory=BugBountyPresetCampaignConfig)


class BugBountyConfig(BaseModel):
    """
    Bug bounty safety configuration.

    SECURITY: When enabled=True, critical safety settings are ENFORCED
    and cannot be disabled. This prevents accidental misconfiguration
    that could lead to legal issues or program bans.
    """
    enabled: bool = True
    mode: str = Field(default="safe")
    scope: BugBountyScopeConfig = Field(default_factory=BugBountyScopeConfig)
    ssrf_protection: BugBountySSRFConfig = Field(default_factory=BugBountySSRFConfig)
    brute_force: BugBountyBruteForceConfig = Field(default_factory=BugBountyBruteForceConfig)
    dos_protection: BugBountyDoSConfig = Field(default_factory=BugBountyDoSConfig)
    rate_limits: BugBountyRateLimitsConfig = Field(default_factory=BugBountyRateLimitsConfig)
    logging: BugBountyLoggingConfig = Field(default_factory=BugBountyLoggingConfig)
    kill_switch: BugBountyKillSwitchConfig = Field(default_factory=BugBountyKillSwitchConfig)
    disclaimer: BugBountyDisclaimerConfig = Field(default_factory=BugBountyDisclaimerConfig)
    presets: dict[str, BugBountyPresetConfig] = Field(default_factory=dict)

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        valid = {"safe", "moderate", "aggressive"}
        if v not in valid:
            raise ValueError(f"Invalid mode: {v}. Must be one of: {valid}")
        return v

    def model_post_init(self, __context: Any) -> None:
        """
        Enforce critical safety settings when bug bounty mode is enabled.

        SECURITY: These settings CANNOT be disabled in bug bounty mode
        to prevent accidental misconfiguration that could cause legal issues.
        """
        if not self.enabled:
            return

        # ENFORCE SSRF PROTECTION - Critical for legal safety
        enforced_ssrf = False
        if not self.ssrf_protection.block_cloud_metadata:
            self.ssrf_protection.block_cloud_metadata = True
            enforced_ssrf = True
        if not self.ssrf_protection.block_private_ips:
            self.ssrf_protection.block_private_ips = True
            enforced_ssrf = True
        if not self.ssrf_protection.block_localhost:
            self.ssrf_protection.block_localhost = True
            enforced_ssrf = True
        if not self.ssrf_protection.block_dangerous_protocols:
            self.ssrf_protection.block_dangerous_protocols = True
            enforced_ssrf = True

        # ENFORCE KILL SWITCH - Must be enabled for safety
        enforced_killswitch = False
        if not self.kill_switch.enabled:
            self.kill_switch.enabled = True
            enforced_killswitch = True
        if not self.kill_switch.trigger_on_scope_violation:
            self.kill_switch.trigger_on_scope_violation = True
            enforced_killswitch = True
        if not self.kill_switch.trigger_on_dangerous_action:
            self.kill_switch.trigger_on_dangerous_action = True
            enforced_killswitch = True

        # ENFORCE DoS PROTECTION - Must be enabled
        enforced_dos = False
        if not self.dos_protection.block_large_payloads:
            self.dos_protection.block_large_payloads = True
            enforced_dos = True
        if not self.dos_protection.block_slow_http:
            self.dos_protection.block_slow_http = True
            enforced_dos = True

        # ENFORCE SCOPE - Must be strict
        enforced_scope = False
        if not self.scope.strict_enforcement:
            self.scope.strict_enforcement = True
            enforced_scope = True

        # Log enforcement actions (imports are at module level, but we avoid logging import here)
        if any([enforced_ssrf, enforced_killswitch, enforced_dos, enforced_scope]):
            pass  # Note: Can't log here (circular imports), logged when settings loaded


# =============================================================================
# CLIENT ENGAGEMENT CONFIGURATION (Optional advanced features)
# =============================================================================

class EngagementTypeConfig(BaseModel):
    """Individual engagement type configuration."""
    name: str = ""
    description: str = ""
    duration_days: int = Field(default=5, ge=1)
    scope: list[str] = Field(default_factory=list)
    modules: list[str] = Field(default_factory=list)
    credentials: bool = False
    credential_level: str = ""
    internal_access: bool = False
    source_code_access: bool = False
    app_binary: str = ""
    stealth_mode: bool = False
    blue_team_notification: bool = True
    
    class Config:
        extra = "allow"  # Allow extra fields for flexibility


class EngagementTypesConfig(BaseModel):
    """All engagement types configuration."""
    external_blackbox: EngagementTypeConfig = Field(default_factory=EngagementTypeConfig)
    internal_graybox: EngagementTypeConfig = Field(default_factory=EngagementTypeConfig)
    webapp_whitebox: EngagementTypeConfig = Field(default_factory=EngagementTypeConfig)
    api_security: EngagementTypeConfig = Field(default_factory=EngagementTypeConfig)
    cloud_pentest: EngagementTypeConfig = Field(default_factory=EngagementTypeConfig)
    mobile_pentest: EngagementTypeConfig = Field(default_factory=EngagementTypeConfig)
    red_team: EngagementTypeConfig = Field(default_factory=EngagementTypeConfig)
    
    class Config:
        extra = "allow"


class PerformanceConfig(BaseModel):
    """Performance tuning configuration."""
    max_workers: int = Field(default=20, ge=1)
    max_threads_per_module: int = Field(default=10, ge=1)
    max_memory_percent: int = Field(default=80, ge=10, le=95)
    cache_size_mb: int = Field(default=1024, ge=64)
    db_connection_pool_size: int = Field(default=20, ge=1)
    db_pool_max_overflow: int = Field(default=10, ge=0)
    batch_size: int = Field(default=1000, ge=10)
    batch_commit_interval: int = Field(default=100, ge=1)


class EmailNotificationConfig(BaseModel):
    """Email notification configuration."""
    enabled: bool = False
    smtp_server: str = ""
    smtp_port: int = Field(default=587, ge=1)
    username: str = ""
    password: str = ""
    from_address: str = ""
    to_addresses: list[str] = Field(default_factory=list)
    notify_on: list[str] = Field(default_factory=lambda: ["scan_complete", "critical_finding", "error"])


class SlackNotificationConfig(BaseModel):
    """Slack notification configuration."""
    enabled: bool = False
    webhook_url: str = ""
    channel: str = ""
    notify_on: list[str] = Field(default_factory=lambda: ["scan_complete", "critical_finding"])


class DiscordNotificationConfig(BaseModel):
    """Discord notification configuration."""
    enabled: bool = False
    webhook_url: str = ""
    notify_on: list[str] = Field(default_factory=lambda: ["scan_complete", "critical_finding"])


class NotificationsConfig(BaseModel):
    """All notifications configuration."""
    enabled: bool = True
    email: EmailNotificationConfig = Field(default_factory=EmailNotificationConfig)
    slack: SlackNotificationConfig = Field(default_factory=SlackNotificationConfig)
    discord: DiscordNotificationConfig = Field(default_factory=DiscordNotificationConfig)


class PeerReviewConfig(BaseModel):
    """Peer review configuration."""
    enabled: bool = True
    require_second_opinion: bool = True


class FPTrackingConfig(BaseModel):
    """False positive tracking configuration."""
    enabled: bool = True
    learn_from_manual_reviews: bool = True


class QualityAssuranceConfig(BaseModel):
    """Quality assurance configuration."""
    verify_findings: bool = True
    retest_attempts: int = Field(default=3, ge=1)
    # Changed default to False: PHANTOM now has automatic verification
    # via ProofEngine, state mutation verification, and baseline comparison
    manual_verification_required: bool = False
    peer_review: PeerReviewConfig = Field(default_factory=PeerReviewConfig)
    fp_tracking: FPTrackingConfig = Field(default_factory=FPTrackingConfig)


class ComplianceConfig(BaseModel):
    """Compliance standards configuration."""
    standards: list[str] = Field(default_factory=lambda: [
        "OWASP Top 10",
        "OWASP API Security Top 10",
        "PCI DSS",
        "NIST",
        "CWE Top 25"
    ])
    map_findings_to_standards: bool = True
    include_compliance_gaps: bool = True


class ProjectConfig(BaseModel):
    """Project metadata configuration."""

    name: str = "AI-Pentest Framework"
    version: str = "2.0.0"
    environment: str = "production"


# =============================================================================
# SCANNER LIMITS CONFIGURATION
# =============================================================================

class IDORLimitsConfig(BaseModel):
    """IDOR/Access control testing limits."""
    max_ids_per_endpoint: int = Field(default=10, ge=1)
    max_id_variations: int = Field(default=5, ge=1)
    max_horizontal_ids: int = Field(default=5, ge=1)
    max_vertical_ids: int = Field(default=3, ge=1)


class BusinessLogicLimitsConfig(BaseModel):
    """Business logic testing limits."""
    max_negative_payloads: int = Field(default=14, ge=1)
    max_boundary_tests: int = Field(default=10, ge=1)
    max_flow_variations: int = Field(default=5, ge=1)


class InjectionLimitsConfig(BaseModel):
    """Injection testing limits."""
    max_payloads_per_param: int = Field(default=50, ge=1)
    max_extraction_attempts: int = Field(default=20, ge=1)
    max_tamper_variations: int = Field(default=10, ge=1)


class LFILimitsConfig(BaseModel):
    """LFI/Path traversal limits."""
    max_traversal_depth: int = Field(default=10, ge=1)
    max_wrapper_tests: int = Field(default=8, ge=1)
    max_encoding_variations: int = Field(default=6, ge=1)


class RaceConditionLimitsConfig(BaseModel):
    """Race condition testing limits."""
    concurrent_requests: int = Field(default=10, ge=2)
    max_race_attempts: int = Field(default=5, ge=1)
    timing_window_ms: int = Field(default=100, ge=10)


class AuthLimitsConfig(BaseModel):
    """Authentication testing limits."""
    max_login_attempts: int = Field(default=10, ge=1)
    max_token_variations: int = Field(default=20, ge=1)
    max_bypass_techniques: int = Field(default=15, ge=1)


class DiscoveryLimitsConfig(BaseModel):
    """Discovery/enumeration limits."""
    max_hidden_paths: int = Field(default=100, ge=1)
    max_endpoints_per_phase: int = Field(default=500, ge=1)
    max_parameters_per_endpoint: int = Field(default=50, ge=1)


class ProofEngineModeConfig(BaseModel):
    """Single proof engine mode configuration."""
    max_requests: int = Field(default=0, ge=0)
    allow_write: bool = False
    allow_auth: bool = False


class ProofEngineLimitsConfig(BaseModel):
    """Proof engine budget limits by safety mode."""
    safe: ProofEngineModeConfig = Field(
        default_factory=lambda: ProofEngineModeConfig(max_requests=0, allow_write=False, allow_auth=False)
    )
    cautious: ProofEngineModeConfig = Field(
        default_factory=lambda: ProofEngineModeConfig(max_requests=5, allow_write=False, allow_auth=False)
    )
    standard: ProofEngineModeConfig = Field(
        default_factory=lambda: ProofEngineModeConfig(max_requests=15, allow_write=False, allow_auth=True)
    )
    aggressive: ProofEngineModeConfig = Field(
        default_factory=lambda: ProofEngineModeConfig(max_requests=50, allow_write=True, allow_auth=True)
    )


class AmplificationLimitsConfig(BaseModel):
    """Amplification engine limits."""
    max_actions_per_finding: int = Field(default=10, ge=1)
    max_total_actions: int = Field(default=50, ge=1)
    max_depth: int = Field(default=3, ge=1)


class ChainLimitsConfig(BaseModel):
    """Chain analysis limits."""
    max_chain_length: int = Field(default=5, ge=2)
    max_chains_per_finding: int = Field(default=10, ge=1)
    min_confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)


class ValidationLimitsConfig(BaseModel):
    """Validation pipeline limits."""
    max_replay_attempts: int = Field(default=3, ge=1)
    max_negative_control_tests: int = Field(default=2, ge=1)
    timeout_per_test_ms: int = Field(default=5000, ge=100)


class ConcurrencyLimitsConfig(BaseModel):
    """General concurrency limits."""
    max_parallel_modules: int = Field(default=10, ge=1)
    max_requests_per_module: int = Field(default=1000, ge=1)
    max_findings_per_module: int = Field(default=500, ge=1)


class ScannerLimitsConfig(BaseModel):
    """
    Scanner limits configuration.

    Centralizes all hardcoded limits from scanner modules.
    Adjust based on target size, time budget, and thoroughness.
    """
    idor: IDORLimitsConfig = Field(default_factory=IDORLimitsConfig)
    business_logic: BusinessLogicLimitsConfig = Field(default_factory=BusinessLogicLimitsConfig)
    injection: InjectionLimitsConfig = Field(default_factory=InjectionLimitsConfig)
    lfi: LFILimitsConfig = Field(default_factory=LFILimitsConfig)
    race_condition: RaceConditionLimitsConfig = Field(default_factory=RaceConditionLimitsConfig)
    auth: AuthLimitsConfig = Field(default_factory=AuthLimitsConfig)
    discovery: DiscoveryLimitsConfig = Field(default_factory=DiscoveryLimitsConfig)
    proof_engine: ProofEngineLimitsConfig = Field(default_factory=ProofEngineLimitsConfig)
    amplification: AmplificationLimitsConfig = Field(default_factory=AmplificationLimitsConfig)
    chains: ChainLimitsConfig = Field(default_factory=ChainLimitsConfig)
    validation: ValidationLimitsConfig = Field(default_factory=ValidationLimitsConfig)
    concurrency: ConcurrencyLimitsConfig = Field(default_factory=ConcurrencyLimitsConfig)


# =============================================================================
# GDPR COMPLIANCE CONFIGURATION
# =============================================================================

class GDPRRetentionConfig(BaseModel):
    """GDPR data retention configuration."""
    scan_data_days: int = Field(default=30, ge=1)
    log_retention_days: int = Field(default=90, ge=1)
    report_retention_days: int = Field(default=365, ge=1)
    gdpr_records_days: int = Field(default=1095, ge=365)  # 3 years minimum


class GDPRCleanupConfig(BaseModel):
    """GDPR cleanup configuration."""
    enabled: bool = True
    run_on_startup: bool = True
    schedule: str = "weekly"


class GDPRPIIProtectionConfig(BaseModel):
    """GDPR PII protection configuration."""
    anonymize_in_logs: bool = True
    anonymize_in_reports: bool = False
    redact_sensitive_fields: bool = True
    detect_types: list[str] = Field(default_factory=lambda: [
        "email", "phone", "credit_card", "ip_address", "jwt", "password_field"
    ])


class GDPRDataMinimizationConfig(BaseModel):
    """GDPR data minimization configuration."""
    store_full_responses: bool = False
    max_evidence_length: int = Field(default=1000, ge=100)
    store_non_findings: bool = False


class GDPRSubjectRightsConfig(BaseModel):
    """GDPR subject rights configuration."""
    enabled: bool = True
    erasure_requires_confirmation: bool = True
    log_requests: bool = True


class GDPRProcessingRecordsConfig(BaseModel):
    """GDPR processing records configuration."""
    enabled: bool = True
    file: str = "data/gdpr/processing_records.jsonl"


class GDPRPathsConfig(BaseModel):
    """GDPR paths configuration."""
    data_root: str = "data"
    gdpr_records: str = "data/gdpr"
    exports: str = "data/gdpr/exports"


class GDPRLegalBasisConfig(BaseModel):
    """GDPR legal basis configuration."""
    default: str = "Legitimate interest / Authorized security testing"
    alternatives: list[str] = Field(default_factory=lambda: [
        "Contractual obligation",
        "Legal obligation"
    ])


class GDPRConfig(BaseModel):
    """
    GDPR compliance configuration.

    Implements requirements from Regulation (EU) 2016/679:
    - Art. 5: Data minimization, storage limitation
    - Art. 15: Right of access
    - Art. 17: Right to erasure
    - Art. 20: Right to data portability
    - Art. 25: Privacy by design
    - Art. 30: Processing records
    - Art. 32: Security of processing
    """
    enabled: bool = True
    retention: GDPRRetentionConfig = Field(default_factory=GDPRRetentionConfig)
    cleanup: GDPRCleanupConfig = Field(default_factory=GDPRCleanupConfig)
    pii_protection: GDPRPIIProtectionConfig = Field(default_factory=GDPRPIIProtectionConfig)
    data_minimization: GDPRDataMinimizationConfig = Field(default_factory=GDPRDataMinimizationConfig)
    subject_rights: GDPRSubjectRightsConfig = Field(default_factory=GDPRSubjectRightsConfig)
    processing_records: GDPRProcessingRecordsConfig = Field(default_factory=GDPRProcessingRecordsConfig)
    paths: GDPRPathsConfig = Field(default_factory=GDPRPathsConfig)
    legal_basis: GDPRLegalBasisConfig = Field(default_factory=GDPRLegalBasisConfig)


# =============================================================================
# L1-L3 Fix: Scan Execution Configuration
# =============================================================================

class JitterConfig(BaseModel):
    """Jitter configuration for module execution timing."""
    min: float = Field(default=0.1, ge=0.0)
    max: float = Field(default=0.5, ge=0.0)
    gaussian_sigma: float = Field(default=0.2, ge=0.0)


class CircuitBreakerConfig(BaseModel):
    """Circuit breaker configuration for rate limiting protection."""
    max_consecutive_blocks: int = Field(default=3, ge=1)
    pause_duration: int = Field(default=30, ge=1)
    max_backoff_multiplier: int = Field(default=8, ge=1)
    reset_on_success: bool = True


class ScanConcurrencyConfig(BaseModel):
    """Module concurrency configuration."""
    default: int = Field(default=5, ge=1)
    waf_reduction: int = Field(default=2, ge=1)


class ScanExecutionConfig(BaseModel):
    """Scan execution parameters (L1-L3 fix)."""
    jitter: JitterConfig = Field(default_factory=JitterConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    concurrency: ScanConcurrencyConfig = Field(default_factory=ScanConcurrencyConfig)


# =============================================================================
# L10 Fix: Module Categories Configuration
# =============================================================================

class ModuleCategoriesConfig(BaseModel):
    """
    Configurable module categories (L10 fix).

    Allows defining custom module presets in settings.yaml that override
    the hardcoded CATEGORIES in full_scanner.py.
    """
    # Custom categories - all optional
    custom: list[str] = Field(default_factory=list)
    fast_api: list[str] = Field(default_factory=list)
    legacy_web: list[str] = Field(default_factory=list)

    class Config:
        extra = "allow"  # Allow arbitrary category names


class Settings(BaseSettings):
    """
    Main settings class that loads and validates all configuration.
    
    Configuration is loaded from:
    1. config/settings.yaml (default)
    2. Environment variables (override)
    """
    
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    timeouts: TimeoutsConfig = Field(default_factory=TimeoutsConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    reconnaissance: ReconnaissanceConfig = Field(default_factory=ReconnaissanceConfig)
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    scanner_limits: ScannerLimitsConfig = Field(default_factory=ScannerLimitsConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    apis: APIsConfig = Field(default_factory=APIsConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    network_protection: NetworkProtectionConfig = Field(default_factory=NetworkProtectionConfig)
    bug_bounty: BugBountyConfig = Field(default_factory=BugBountyConfig)
    # Optional advanced features
    engagement_types: EngagementTypesConfig = Field(default_factory=EngagementTypesConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    quality_assurance: QualityAssuranceConfig = Field(default_factory=QualityAssuranceConfig)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    gdpr: GDPRConfig = Field(default_factory=GDPRConfig)

    # L1-L3 Fix: Scan execution parameters (jitter, circuit breaker, concurrency)
    scan_execution: ScanExecutionConfig | None = Field(default_factory=ScanExecutionConfig)

    # L10 Fix: Configurable module categories
    module_categories: ModuleCategoriesConfig | None = Field(default_factory=ModuleCategoriesConfig)

    @field_validator('scan_execution', mode='before')
    @classmethod
    def validate_scan_execution(cls, v):
        """Convert None to default config."""
        if v is None:
            return ScanExecutionConfig()
        return v

    @field_validator('module_categories', mode='before')
    @classmethod
    def validate_module_categories(cls, v):
        """Convert None to default config."""
        if v is None:
            return ModuleCategoriesConfig()
        return v

    class Config:
        env_prefix = "PENTEST_"
        env_nested_delimiter = "__"
    
    @classmethod
    def from_yaml(cls, path: str | Path) -> "Settings":
        """Load settings from YAML file."""
        path = Path(path)
        
        if not path.exists():
            # Return defaults if file doesn't exist
            return cls()
        
        with open(path) as f:
            yaml_data = yaml.safe_load(f) or {}
        
        # Expand environment variables
        yaml_data = cls._expand_env_vars(yaml_data)
        
        return cls(**yaml_data)
    
    @classmethod
    def _expand_env_vars(cls, data: Any) -> Any:
        """
        Recursively expand environment variables in config.

        Supports two formats:
        - ${VAR} - Returns empty string if not set
        - ${VAR:default} - Returns 'default' if VAR is not set

        Examples:
            ${HACKERONE_USERNAME} -> value of HACKERONE_USERNAME or ""
            ${OLLAMA_BASE_URL:http://localhost:11434} -> value or default
            ${HACKERONE_USERNAME:your-username}-twilio -> "username-twilio"
        """
        import re

        if isinstance(data, dict):
            return {k: cls._expand_env_vars(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [cls._expand_env_vars(item) for item in data]
        elif isinstance(data, str):
            # Pattern to match ${VAR} or ${VAR:default}
            pattern = r'\$\{([^}:]+)(?::([^}]*))?\}'

            def replace_var(match: re.Match) -> str:
                var_name = match.group(1)
                default = match.group(2) if match.group(2) is not None else ""
                return os.environ.get(var_name, default)

            # Replace all occurrences
            return re.sub(pattern, replace_var, data)
        return data
    
    def get_prompt_path(self, prompt_name: str) -> Path:
        """Get path to a prompt template file."""
        return Path("config/ai_prompts") / f"{prompt_name}.txt"
    
    def load_prompt(self, prompt_name: str) -> str:
        """Load a prompt template."""
        path = self.get_prompt_path(prompt_name)
        if path.exists():
            return path.read_text()
        raise FileNotFoundError(f"Prompt template not found: {path}")


@lru_cache()
def get_settings(config_path: str = "config/settings.yaml") -> Settings:
    """
    Get cached settings instance.

    Args:
        config_path: Path to configuration file

    Returns:
        Settings instance
    """
    return Settings.from_yaml(config_path)


def get_scanner_limits(config_path: str = "config/settings.yaml") -> ScannerLimitsConfig:
    """
    Get scanner limits configuration.

    Convenience function for scanner modules to access limits.

    Args:
        config_path: Path to configuration file

    Returns:
        ScannerLimitsConfig instance
    """
    return get_settings(config_path).scanner_limits


def get_limit(category: str, limit_name: str, default: int | float = 10) -> int | float:
    """
    Get a specific scanner limit by category and name.

    Convenience function for quick limit lookups.

    Args:
        category: Limit category (e.g., "idor", "business_logic", "proof_engine")
        limit_name: Specific limit name (e.g., "max_ids_per_endpoint")
        default: Default value if limit not found

    Returns:
        The configured limit value or default

    Examples:
        >>> get_limit("idor", "max_ids_per_endpoint")
        10
        >>> get_limit("proof_engine", "aggressive.max_requests")
        50
    """
    try:
        limits = get_scanner_limits()
        category_config = getattr(limits, category, None)
        if category_config is None:
            return default

        # Handle nested access (e.g., "aggressive.max_requests")
        if "." in limit_name:
            parts = limit_name.split(".")
            value = category_config
            for part in parts:
                value = getattr(value, part, None)
                if value is None:
                    return default
            return value

        return getattr(category_config, limit_name, default)
    except Exception:
        return default


def validate_configuration(settings: Settings) -> tuple[bool, list[str], list[str]]:
    """
    Validate configuration at startup.

    Checks:
    - Required directories exist/are writable
    - Environment variables for bug bounty are set
    - Critical settings are properly configured

    Args:
        settings: Settings instance to validate

    Returns:
        Tuple of (is_valid, errors, warnings)
        - is_valid: True if no critical errors
        - errors: List of critical error messages
        - warnings: List of warning messages
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Check output directories
    output_dirs = [
        Path(settings.storage.vector_store_path),
        Path(settings.logging.file.path) if settings.logging.file.enabled else None,
    ]

    for dir_path in output_dirs:
        if dir_path:
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                errors.append(f"Cannot create/write to directory: {dir_path}")
            except Exception as e:
                warnings.append(f"Directory check failed for {dir_path}: {e}")

    # Check encryption key directory
    key_dir = Path(settings.storage.encryption_key_file).parent
    try:
        key_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        warnings.append(f"Cannot create secrets directory: {e}")

    # Bug bounty specific validation
    if settings.bug_bounty.enabled:
        # Check for HackerOne username environment variable
        hackerone_user = os.environ.get("HACKERONE_USERNAME", "")
        if not hackerone_user or hackerone_user == "your-username":
            warnings.append(
                "HACKERONE_USERNAME environment variable not set. "
                "Set it before bug bounty scanning: export HACKERONE_USERNAME=your_username"
            )

        # Check that safety settings are enforced
        if not settings.bug_bounty.ssrf_protection.block_cloud_metadata:
            errors.append("BUG BOUNTY: SSRF cloud metadata protection MUST be enabled")
        if not settings.bug_bounty.ssrf_protection.block_private_ips:
            errors.append("BUG BOUNTY: SSRF private IP protection MUST be enabled")
        if not settings.bug_bounty.kill_switch.enabled:
            errors.append("BUG BOUNTY: Kill switch MUST be enabled")

    # Check AI configuration
    ollama_url = settings.ai.base_url
    if "${" in ollama_url:
        warnings.append(
            f"OLLAMA_BASE_URL environment variable not set, using default. "
            f"Current value contains unexpanded variable: {ollama_url}"
        )

    # Check for API keys (warnings only - not all are required)
    if settings.reconnaissance.subdomains.use_virustotal and not settings.apis.virustotal_key:
        warnings.append("VirusTotal API key not set but use_virustotal is enabled")

    return len(errors) == 0, errors, warnings


def validate_and_report(settings: Settings, console: Any = None) -> bool:
    """
    Validate configuration and print report.

    Args:
        settings: Settings to validate
        console: Optional Rich console for output

    Returns:
        True if configuration is valid
    """
    is_valid, errors, warnings = validate_configuration(settings)

    if console:
        from rich.panel import Panel

        if errors:
            console.print(Panel(
                "\n".join(f"[red]✗[/red] {e}" for e in errors),
                title="[red]Configuration Errors[/red]",
                border_style="red",
            ))

        if warnings:
            console.print(Panel(
                "\n".join(f"[yellow]⚠[/yellow] {w}" for w in warnings),
                title="[yellow]Configuration Warnings[/yellow]",
                border_style="yellow",
            ))

        if is_valid and not warnings:
            console.print("[green]✓[/green] Configuration validated successfully")
    else:
        # Print to stdout without Rich
        if errors:
            print("Configuration Errors:")
            for e in errors:
                print(f"  ✗ {e}")

        if warnings:
            print("Configuration Warnings:")
            for w in warnings:
                print(f"  ⚠ {w}")

    return is_valid
