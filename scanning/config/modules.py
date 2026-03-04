"""
Module Definitions and Mappings.

Contains:
- ALL_MODULES: Mapping of short names to module class paths
- SHORT_TO_REGISTRY_NAME: Mapping of short names to ModuleRegistry names

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

from typing import Optional


# All available scanner modules
# Maps short name → fully qualified class path
ALL_MODULES: dict[str, str] = {
    # Base Injection Scanners
    "sqli": "scanning.modules.sqli_scanner.SQLiScanner",
    "xss": "scanning.modules.xss_scanner.XSSScanner",
    "cmdi": "scanning.modules.cmdi_scanner.CommandInjectionScanner",
    "xxe": "scanning.modules.xxe_scanner.XXEScanner",
    "ssrf": "scanning.modules.ssrf_scanner.SSRFScanner",
    "lfi": "scanning.modules.lfi_scanner.LFIScanner",

    # Authentication & Authorization
    "auth": "scanning.modules.auth_scanner.AuthScanner",
    "oauth": "scanning.modules.oauth_scanner.OAuthScanner",
    "saml": "scanning.modules.saml_scanner.SAMLScanner",
    "mfa": "scanning.modules.mfa_bypass_scanner.MFABypassScanner",
    "authz": "scanning.modules.authorization_engine.AuthorizationEngine",

    # API Security
    "api": "scanning.modules.api_scanner.APIScanner",
    "graphql": "scanning.modules.graphql_advanced_scanner.GraphQLAdvancedScanner",
    "grpc": "scanning.modules.grpc_scanner.GRPCScanner",
    "websocket": "scanning.modules.websocket_scanner.WebSocketScanner",
    "sse": "scanning.modules.sse_scanner.SSEScanner",

    # Infrastructure
    "ssl": "scanning.modules.ssl_checker.SSLChecker",
    "headers": "scanning.modules.header_security.HeaderSecurityChecker",
    "cors": "scanning.modules.cors_checker.CORSChecker",
    "cloud": "scanning.modules.cloud_scanner.CloudScanner",
    "k8s": "scanning.modules.kubernetes_scanner.KubernetesContainerScanner",

    # CMS & Discovery
    "cms": "scanning.modules.cms_scanner.CMSScanner",
    "dir": "scanning.modules.dir_scanner.DirectoryScanner",
    "nuclei": "scanning.modules.nuclei_runner.NucleiRunner",

    # Advanced Attacks
    "nosql": "scanning.modules.nosql_scanner.NoSQLScanner",
    "ssti": "scanning.modules.ssti_scanner.SSTIScanner",
    "deser": "scanning.modules.deserialization_scanner.DeserializationScanner",
    "smuggling": "scanning.modules.smuggling_scanner.HTTPSmugglingScanner",
    "prototype": "scanning.modules.prototype_pollution_scanner.PrototypePollutionScanner",
    "crlf": "scanning.modules.crlf_scanner.CRLFScanner",
    "cache": "scanning.modules.cache_poisoning_scanner.CachePoisoningScanner",
    "dns_rebind": "scanning.modules.dns_rebinding_scanner.DNSRebindingScanner",

    # Specialized
    "ldap": "scanning.modules.ldap_xpath_scanner.LDAPXPathScanner",
    "mobile": "scanning.modules.mobile_api_scanner.MobileAPIScanner",
    "email": "scanning.modules.email_security_scanner.EmailSecurityScanner",
    "ratelimit": "scanning.modules.rate_limit_scanner.RateLimitScanner",
    "business": "scanning.modules.business_logic_scanner.BusinessLogicScanner",
    "postexploit": "scanning.modules.post_exploitation.PostExploitationModule",

    # TOP TIER BOUNTY MODULES
    "dom_xss": "scanning.modules.dom_xss_scanner.DOMXSSScanner",
    "idor": "scanning.modules.api_logic_profiler.APILogicProfiler",
    "csrf": "scanning.modules.csrf_scanner.CSRFScanner",
    "mass_assign": "scanning.modules.mass_assignment_scanner.MassAssignmentScanner",

    # BaaS Security (Supabase, Firebase)
    "supabase": "scanning.modules.supabase_scanner.SupabaseScanner",
    "firebase": "scanning.modules.firebase_scanner.FirebaseScanner",
    "rls_bypass": "scanning.modules.advanced_rls_bypass_scanner.AdvancedRLSBypassScanner",

    # Discovery & Fingerprinting
    "backend": "scanning.modules.backend_detector.BackendDetector",
    "third_party": "scanning.modules.third_party_scanner.ThirdPartyScanner",

    # Credential Detection & Verification
    "credential_verifier": "scanning.modules.credential_verifier.CredentialVerifier",

    # PortSwigger Coverage Modules
    "jwt": "scanning.modules.jwt_scanner.JWTScanner",
    "race": "scanning.modules.race_condition_scanner.RaceConditionScanner",
    "host_header": "scanning.modules.host_header_scanner.HostHeaderScanner",
    "clickjacking": "scanning.modules.clickjacking_scanner.ClickjackingScanner",
    "info_disclosure": "scanning.modules.info_disclosure_scanner.InfoDisclosureScanner",
    "cache_deception": "scanning.modules.cache_deception_scanner.CacheDeceptionScanner",
    "open_redirect": "scanning.modules.open_redirect_scanner.OpenRedirectScanner",
    "file_upload": "scanning.modules.file_upload_scanner.FileUploadScanner",
    "cookie": "scanning.modules.cookie_security_scanner.CookieSecurityScanner",
    "subdomain_takeover": "scanning.modules.subdomain_takeover_scanner.SubdomainTakeoverScanner",
    "llm": "scanning.modules.llm_security_scanner.LLMSecurityScanner",

    # Communications API Security (Twilio, SendGrid)
    "comms": "scanning.modules.communications_api_scanner.CommunicationsAPIScanner",

    # Session & Token Abuse
    "session_abuse": "scanning.modules.session_abuse_scanner.SessionAbuseScanner",

    # Creative Exploiter
    "creative_exploiter": "scanning.modules.creative_exploiter.CreativeExploiterScanner",

    # Configuration & Environment Security
    "config_exposure": "scanning.modules.config_exposure_scanner.ConfigExposureScanner",
    "secrets_pattern": "scanning.modules.secrets_pattern_scanner.SecretsPatternScanner",

    # Concurrency & Stress Testing
    "concurrency_stress": "scanning.modules.concurrency_stress_scanner.ConcurrencyStressScanner",
    "concurrency_state": "scanning.modules.concurrency_state_modeler.ConcurrencyStateModeler",

    # Integration Security
    "webhook_security": "scanning.modules.webhook_security_scanner.WebhookSecurityScanner",

    # Cross-Surface Analysis
    "cross_surface": "scanning.cross_surface_analyzer.CrossSurfaceAnalyzer",

    # Advanced Business Logic & Workflow Testing
    "workflow_inference": "scanning.modules.workflow_inference_engine.WorkflowInferenceEngine",

    # ABAC & Context-Based Access Control Testing
    "abac_context": "scanning.modules.abac_context_tester.ABACContextTester",

    # Token Binding & Session Security
    "token_binding": "scanning.modules.token_binding_validator.TokenBindingValidator",

    # Client-Side Security Hardening
    "client_hardening": "scanning.modules.client_hardening_scanner.ClientHardeningScanner",

    # Permission Matrix & Authorization Logic
    "permission_matrix": "scanning.modules.permission_matrix_scanner.PermissionMatrixScanner",

    # Integration Exploitation
    "integration_exploiter": "scanning.modules.integration_exploiter.IntegrationExploiter",

    # Defensive Evasion
    "defensive_evasion": "scanning.modules.defensive_evasion_scanner.DefensiveEvasionScanner",

    # WebAssembly Security Analysis
    "wasm": "scanning.modules.wasm_scanner.WasmScanner",

    # Logic Chain Analysis
    "logic_chain": "scanning.modules.logic_chain_scanner.LogicChainScanner",

    # Stateful Flow Fuzzer
    "stateful_flow": "scanning.modules.stateful_flow_scanner.StatefulFlowScanner",
}


# Short name → ModuleRegistry name mapping
# Maps legacy short names to centralized ModuleRegistry names
SHORT_TO_REGISTRY_NAME: dict[str, Optional[str]] = {
    # Injection
    "sqli": "sqli_scanner",
    "xss": "xss_scanner",
    "dom_xss": "dom_xss_scanner",
    "cmdi": "cmdi_scanner",
    "xxe": "xxe_scanner",
    "ssrf": "ssrf_scanner",
    "lfi": "lfi_scanner",
    "nosql": "nosql_scanner",
    "ssti": "ssti_scanner",
    "ldap": "ldap_xpath_scanner",
    "crlf": "crlf_scanner",
    # Auth
    "auth": "auth_scanner",
    "oauth": "oauth_scanner",
    "saml": "saml_scanner",
    "mfa": "mfa_bypass_scanner",
    "authz": "authorization_engine",
    "jwt": "jwt_scanner",
    "session_abuse": "session_abuse_scanner",
    "csrf": "csrf_scanner",
    "cookie": "cookie_security_scanner",
    "credential_verifier": "credential_verifier",
    "token_binding": "token_binding_validator",
    # API
    "api": "api_scanner",
    "idor": "api_logic_profiler",
    "graphql": "graphql_advanced_scanner",
    "grpc": "grpc_scanner",
    "websocket": "websocket_scanner",
    "sse": "sse_scanner",
    "cors": "cors_checker",
    "comms": "communications_api_scanner",
    "webhook_security": "webhook_security_scanner",
    # Infrastructure
    "ssl": "ssl_checker",
    "headers": "header_security_checker",
    "cloud": "cloud_scanner",
    "k8s": "kubernetes_scanner",
    "supabase": "supabase_scanner",
    "firebase": "firebase_scanner",
    "email": "email_security_scanner",
    "third_party": "third_party_scanner",
    # Network
    "smuggling": "smuggling_scanner",
    "dns_rebind": "dns_rebinding_scanner",
    "host_header": "host_header_scanner",
    "subdomain_takeover": "subdomain_takeover_scanner",
    # Business Logic
    "business": "business_logic_scanner",
    "race": "race_condition_scanner",
    "ratelimit": "rate_limit_scanner",
    "logic_chain": "logic_chain_scanner",
    "workflow_inference": "workflow_inference_engine",
    "stateful_flow": "stateful_flow_scanner",
    # Access Control
    "mass_assign": "mass_assignment_scanner",
    "permission_matrix": "permission_matrix_scanner",
    "abac_context": "abac_context_tester",
    "rls_bypass": "advanced_rls_bypass_scanner",
    # Client-Side
    "clickjacking": "clickjacking_scanner",
    "prototype": "prototype_pollution_scanner",
    "wasm": "wasm_scanner",
    "client_hardening": "client_hardening_scanner",
    # Discovery
    "dir": "dir_scanner",
    "cms": "cms_scanner",
    "backend": "backend_detector",
    "info_disclosure": "info_disclosure_scanner",
    "config_exposure": "config_exposure_scanner",
    "secrets_pattern": "secrets_pattern_scanner",
    # Advanced
    "deser": "deserialization_scanner",
    "cache": "cache_poisoning_scanner",
    "cache_deception": "cache_deception_scanner",
    "file_upload": "file_upload_scanner",
    "open_redirect": "open_redirect_scanner",
    "creative_exploiter": "creative_exploiter",
    "postexploit": "post_exploitation",
    "integration_exploiter": "integration_exploiter",
    "defensive_evasion": "defensive_evasion_scanner",
    "llm": "llm_security_scanner",
    # Concurrency
    "concurrency_stress": "concurrency_stress_scanner",
    "concurrency_state": "concurrency_state_modeler",
    # External
    "nuclei": "nuclei_runner",
    "mobile": "mobile_api_scanner",
    # Cross-surface (special - not in registry)
    "cross_surface": None,  # Handled separately
}


def get_module_path(short_name: str) -> Optional[str]:
    """Get the fully qualified module path for a short name."""
    return ALL_MODULES.get(short_name)


def get_registry_name(short_name: str) -> Optional[str]:
    """Get the ModuleRegistry name for a short name."""
    return SHORT_TO_REGISTRY_NAME.get(short_name)


def get_all_module_names() -> list[str]:
    """Get all available module short names."""
    return list(ALL_MODULES.keys())
