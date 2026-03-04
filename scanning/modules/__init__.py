"""
Scanning modules package.
All vulnerability scanning modules - Complete Enterprise Coverage 100%.
"""

from scanning.modules.nuclei_runner import NucleiRunner
from scanning.modules.header_security import HeaderSecurityChecker
from scanning.modules.ssl_checker import SSLChecker
from scanning.modules.cors_checker import CORSChecker
from scanning.modules.sqli_scanner import SQLiScanner
from scanning.modules.xss_scanner import XSSScanner
from scanning.modules.auth_scanner import AuthScanner
from scanning.modules.api_scanner import APIScanner
from scanning.modules.ssrf_scanner import SSRFScanner, SSRF_SCANNER_VERSION
from scanning.modules.lfi_scanner import LFIScanner, LFI_SCANNER_VERSION
from scanning.modules.dir_scanner import DirectoryScanner
from scanning.modules.cms_scanner import CMSScanner
from scanning.modules.xxe_scanner import XXEScanner, XXE_SCANNER_VERSION
from scanning.modules.cmdi_scanner import CommandInjectionScanner, CMDI_SCANNER_VERSION
from scanning.modules.cloud_scanner import CloudScanner
# Enterprise-level modules
from scanning.modules.business_logic_scanner import BusinessLogicScanner
from scanning.modules.authorization_engine import AuthorizationEngine
from scanning.modules.post_exploitation import PostExploitationModule
# Advanced vulnerability scanners (Gap Analysis additions)
from scanning.modules.oauth_scanner import OAuthScanner
from scanning.modules.ssti_scanner import SSTIScanner
from scanning.modules.deserialization_scanner import DeserializationScanner
from scanning.modules.websocket_scanner import WebSocketScanner
from scanning.modules.mfa_bypass_scanner import MFABypassScanner
from scanning.modules.nosql_scanner import NoSQLScanner, NOSQL_SCANNER_VERSION
from scanning.modules.smuggling_scanner import HTTPSmugglingScanner
from scanning.modules.prototype_pollution_scanner import PrototypePollutionScanner
from scanning.modules.crlf_scanner import CRLFScanner
from scanning.modules.mobile_api_scanner import MobileAPIScanner
from scanning.modules.saml_scanner import SAMLScanner
# 100% Coverage - Additional scanners
from scanning.modules.cache_poisoning_scanner import CachePoisoningScanner
from scanning.modules.graphql_advanced_scanner import GraphQLAdvancedScanner
from scanning.modules.ldap_xpath_scanner import LDAPXPathScanner
from scanning.modules.kubernetes_scanner import KubernetesContainerScanner
from scanning.modules.grpc_scanner import GRPCScanner
from scanning.modules.dns_rebinding_scanner import DNSRebindingScanner
from scanning.modules.email_security_scanner import EmailSecurityScanner
from scanning.modules.sse_scanner import SSEScanner
from scanning.modules.rate_limit_scanner import RateLimitScanner
# Coverage Gaps v2.0 (2026-02-19)
from scanning.modules.graphql_subscription_scanner import GraphQLSubscriptionScanner
from scanning.modules.llm_security_scanner import LLMSecurityScanner
from scanning.modules.rsc_scanner import RSCScanner
from scanning.modules.edge_function_scanner import EdgeFunctionScanner
from scanning.modules.grpc_web_scanner import GRPCWebScanner
from scanning.modules.http3_scanner import HTTP3Scanner
from scanning.modules.webtransport_scanner import WebTransportScanner

__all__ = [
    # Original modules
    "NucleiRunner",
    "HeaderSecurityChecker",
    "SSLChecker",
    "CORSChecker",
    # Active vulnerability scanners (OWASP Top 10)
    "SQLiScanner",
    "XSSScanner",
    "AuthScanner",
    "APIScanner",
    "SSRFScanner",
    "SSRF_SCANNER_VERSION",
    "LFIScanner",
    "LFI_SCANNER_VERSION",
    "DirectoryScanner",
    "CMSScanner",
    "XXEScanner",
    "CommandInjectionScanner",
    "CloudScanner",
    # Enterprise-level scanners
    "BusinessLogicScanner",
    "AuthorizationEngine",
    "PostExploitationModule",
    # Advanced vulnerability scanners
    "OAuthScanner",
    "SSTIScanner",
    "DeserializationScanner",
    "WebSocketScanner",
    "MFABypassScanner",
    "NoSQLScanner",
    "NOSQL_SCANNER_VERSION",
    "HTTPSmugglingScanner",
    "PrototypePollutionScanner",
    "CRLFScanner",
    # Mobile and SSO scanners
    "MobileAPIScanner",
    "SAMLScanner",
    # 100% Coverage scanners
    "CachePoisoningScanner",
    "GraphQLAdvancedScanner",
    "LDAPXPathScanner",
    "KubernetesContainerScanner",
    "GRPCScanner",
    "DNSRebindingScanner",
    "EmailSecurityScanner",
    "SSEScanner",
    "RateLimitScanner",
    # Coverage Gaps v2.0 (2026-02-19)
    "GraphQLSubscriptionScanner",
    "LLMSecurityScanner",
    "RSCScanner",
    "EdgeFunctionScanner",
    "GRPCWebScanner",
    "HTTP3Scanner",
    "WebTransportScanner",
]
