"""
Scope Guard v1.0.0-ENTERPRISE
==============================

Proteção de escopo e guardrails legais!

Bloqueia automaticamente:
- IPs internos (RFC1918, loopback, link-local)
- Subdomínios fora do scope
- Caminhos proibidos
- Hosts não autorizados

Princípio: Isto é OBRIGATÓRIO se algum dia sair do teu PC!
"""

import ipaddress
import re
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Optional, List, Dict, Any, Set, Pattern
from urllib.parse import urlparse, urljoin
from pathlib import Path
import fnmatch


class ScopeViolationType(Enum):
    """Types of scope violations"""
    INTERNAL_IP = "internal_ip"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    OUT_OF_SCOPE_DOMAIN = "out_of_scope_domain"
    OUT_OF_SCOPE_SUBDOMAIN = "out_of_scope_subdomain"
    FORBIDDEN_PATH = "forbidden_path"
    FORBIDDEN_PORT = "forbidden_port"
    CLOUD_METADATA = "cloud_metadata"
    SENSITIVE_ENDPOINT = "sensitive_endpoint"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    EXPLICIT_EXCLUSION = "explicit_exclusion"


class ScopeMode(Enum):
    """Scope enforcement modes"""
    STRICT = "strict"         # Block all out-of-scope
    PERMISSIVE = "permissive" # Warn but allow
    AUDIT = "audit"           # Log only


@dataclass
class ScopeViolation:
    """
    Record of a scope violation attempt
    """
    timestamp: datetime
    violation_type: ScopeViolationType
    target: str
    reason: str
    blocked: bool
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "violation_type": self.violation_type.value,
            "target": self.target,
            "reason": self.reason,
            "blocked": self.blocked,
            "context": self.context
        }


@dataclass
class ScopeDefinition:
    """
    Defines the allowed scope for testing
    """
    # Allowed targets
    allowed_domains: List[str] = field(default_factory=list)
    allowed_ips: List[str] = field(default_factory=list)  # Can be CIDR notation
    allowed_ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8443])
    
    # Inclusions (override exclusions)
    include_subdomains: bool = True
    include_patterns: List[str] = field(default_factory=list)
    
    # Exclusions
    excluded_domains: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    excluded_patterns: List[str] = field(default_factory=list)
    
    # Safety settings
    block_internal_ips: bool = True
    block_cloud_metadata: bool = True
    block_localhost: bool = True
    
    # Sensitive paths (always blocked)
    sensitive_paths: List[str] = field(default_factory=lambda: [
        "/admin/delete*",
        "/api/*/delete",
        "*/drop*",
        "*/truncate*",
        "/system/shutdown",
        "/actuator/shutdown",
        "/debug/pprof",
    ])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed_domains": self.allowed_domains,
            "allowed_ips": self.allowed_ips,
            "allowed_ports": self.allowed_ports,
            "include_subdomains": self.include_subdomains,
            "include_patterns": self.include_patterns,
            "excluded_domains": self.excluded_domains,
            "excluded_paths": self.excluded_paths,
            "excluded_patterns": self.excluded_patterns,
            "block_internal_ips": self.block_internal_ips,
            "block_cloud_metadata": self.block_cloud_metadata,
            "block_localhost": self.block_localhost,
            "sensitive_paths": self.sensitive_paths
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScopeDefinition':
        """Create ScopeDefinition from dictionary"""
        return cls(**data)
    
    @classmethod
    def from_target(cls, target: str, include_subdomains: bool = True) -> 'ScopeDefinition':
        """Create ScopeDefinition from a target URL"""
        parsed = urlparse(target)
        domain = parsed.netloc.split(':')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        return cls(
            allowed_domains=[domain],
            allowed_ports=[port, 80, 443, 8080, 8443],
            include_subdomains=include_subdomains
        )


class ScopeGuard:
    """
    Scope Guard - Legal and Safety Enforcement
    
    Protects against:
    1. Testing internal/private IPs
    2. Testing out-of-scope domains
    3. Accessing sensitive/destructive endpoints
    4. Cloud metadata access
    """
    
    VERSION = "1.0.0-ENTERPRISE"
    
    # RFC1918 private IP ranges
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
    ]
    
    # Loopback
    LOOPBACK_RANGES = [
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('::1/128'),
    ]
    
    # Link-local
    LINK_LOCAL_RANGES = [
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('fe80::/10'),
    ]
    
    # Cloud metadata IPs
    CLOUD_METADATA_IPS = [
        '169.254.169.254',  # AWS, GCP, Azure
        '100.100.100.200',  # Alibaba
        '169.254.170.2',    # Azure Instance Metadata
        'metadata.google.internal',
        'metadata.gcp.internal',
    ]
    
    # Cloud metadata paths
    CLOUD_METADATA_PATHS = [
        '/latest/meta-data/',
        '/latest/user-data/',
        '/metadata/v1/',
        '/computeMetadata/v1/',
        '/metadata/instance',
        '/openstack/',
        '/2009-04-04/',
        '/opc/v1/',
    ]
    
    def __init__(
        self,
        scope: Optional[ScopeDefinition] = None,
        mode: ScopeMode = ScopeMode.STRICT
    ):
        """
        Initialize Scope Guard
        
        Args:
            scope: Scope definition
            mode: Enforcement mode
        """
        self.scope = scope or ScopeDefinition()
        self.mode = mode
        self.violations: List[ScopeViolation] = []
        
        # Compile patterns for performance
        self._compiled_patterns: Dict[str, List[Pattern]] = {
            "include": [],
            "exclude": [],
            "sensitive": []
        }
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile glob patterns to regex"""
        for pattern in self.scope.include_patterns:
            try:
                regex = fnmatch.translate(pattern)
                self._compiled_patterns["include"].append(re.compile(regex, re.IGNORECASE))
            except Exception:
                pass
        
        for pattern in self.scope.excluded_patterns:
            try:
                regex = fnmatch.translate(pattern)
                self._compiled_patterns["exclude"].append(re.compile(regex, re.IGNORECASE))
            except Exception:
                pass
        
        for pattern in self.scope.sensitive_paths:
            try:
                regex = fnmatch.translate(pattern)
                self._compiled_patterns["sensitive"].append(re.compile(regex, re.IGNORECASE))
            except Exception:
                pass
    
    def is_allowed(self, url: str) -> tuple:
        """
        Check if URL is allowed by scope
        
        Returns:
            (allowed: bool, violation: Optional[ScopeViolation])
        """
        try:
            parsed = urlparse(url)
            host = parsed.netloc.split(':')[0]
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            path = parsed.path or '/'
            
            # 1. Check for internal/private IPs
            violation = self._check_ip_restrictions(host, url)
            if violation:
                return self._handle_violation(violation)
            
            # 2. Check cloud metadata
            if self.scope.block_cloud_metadata:
                violation = self._check_cloud_metadata(host, path, url)
                if violation:
                    return self._handle_violation(violation)
            
            # 3. Check domain scope
            violation = self._check_domain_scope(host, url)
            if violation:
                return self._handle_violation(violation)
            
            # 4. Check port
            violation = self._check_port(port, url)
            if violation:
                return self._handle_violation(violation)
            
            # 5. Check path exclusions
            violation = self._check_path_exclusions(path, url)
            if violation:
                return self._handle_violation(violation)
            
            # 6. Check sensitive paths
            violation = self._check_sensitive_paths(path, url)
            if violation:
                return self._handle_violation(violation)
            
            return (True, None)
            
        except Exception as e:
            return (False, ScopeViolation(
                timestamp=datetime.now(),
                violation_type=ScopeViolationType.EXPLICIT_EXCLUSION,
                target=url,
                reason=f"Parse error: {str(e)}",
                blocked=True
            ))
    
    def _check_ip_restrictions(self, host: str, url: str) -> Optional[ScopeViolation]:
        """Check IP-based restrictions"""
        # Check localhost hostname FIRST (before IP check)
        if self.scope.block_localhost:
            if host.lower() in ('localhost', 'localhost.localdomain', 'local'):
                return ScopeViolation(
                    timestamp=datetime.now(),
                    violation_type=ScopeViolationType.LOOPBACK,
                    target=url,
                    reason=f"Localhost hostname not allowed: {host}",
                    blocked=True
                )
        
        try:
            ip = ipaddress.ip_address(host)
            
            # Check loopback
            if self.scope.block_localhost:
                for net in self.LOOPBACK_RANGES:
                    if ip in net:
                        return ScopeViolation(
                            timestamp=datetime.now(),
                            violation_type=ScopeViolationType.LOOPBACK,
                            target=url,
                            reason=f"Loopback IP not allowed: {host}",
                            blocked=True
                        )
            
            # Check private ranges
            if self.scope.block_internal_ips:
                for net in self.PRIVATE_RANGES:
                    if ip in net:
                        return ScopeViolation(
                            timestamp=datetime.now(),
                            violation_type=ScopeViolationType.INTERNAL_IP,
                            target=url,
                            reason=f"Private/Internal IP not allowed: {host}",
                            blocked=True
                        )
            
            # Check link-local
            for net in self.LINK_LOCAL_RANGES:
                if ip in net:
                    return ScopeViolation(
                        timestamp=datetime.now(),
                        violation_type=ScopeViolationType.LINK_LOCAL,
                        target=url,
                        reason=f"Link-local IP not allowed: {host}",
                        blocked=True
                    )
            
            # Check if IP is explicitly allowed
            if self.scope.allowed_ips:
                ip_allowed = False
                for allowed in self.scope.allowed_ips:
                    try:
                        if '/' in allowed:
                            if ip in ipaddress.ip_network(allowed, strict=False):
                                ip_allowed = True
                                break
                        elif ip == ipaddress.ip_address(allowed):
                            ip_allowed = True
                            break
                    except ValueError:
                        pass
                
                if not ip_allowed:
                    return ScopeViolation(
                        timestamp=datetime.now(),
                        violation_type=ScopeViolationType.OUT_OF_SCOPE_DOMAIN,
                        target=url,
                        reason=f"IP not in allowed list: {host}",
                        blocked=True
                    )
            
        except ValueError:
            # Not an IP address, that's fine
            pass
        
        return None
    
    def _check_cloud_metadata(self, host: str, path: str, url: str) -> Optional[ScopeViolation]:
        """Check for cloud metadata access attempts"""
        # Check metadata IPs
        if host in self.CLOUD_METADATA_IPS:
            return ScopeViolation(
                timestamp=datetime.now(),
                violation_type=ScopeViolationType.CLOUD_METADATA,
                target=url,
                reason=f"Cloud metadata IP blocked: {host}",
                blocked=True,
                context={"type": "metadata_ip"}
            )
        
        # Check metadata paths
        path_lower = path.lower()
        for meta_path in self.CLOUD_METADATA_PATHS:
            if meta_path.lower() in path_lower:
                return ScopeViolation(
                    timestamp=datetime.now(),
                    violation_type=ScopeViolationType.CLOUD_METADATA,
                    target=url,
                    reason=f"Cloud metadata path blocked: {path}",
                    blocked=True,
                    context={"type": "metadata_path", "pattern": meta_path}
                )
        
        return None
    
    def _check_domain_scope(self, host: str, url: str) -> Optional[ScopeViolation]:
        """Check if domain is in scope"""
        if not self.scope.allowed_domains:
            return None  # No domain restrictions
        
        host_lower = host.lower()
        
        for allowed in self.scope.allowed_domains:
            allowed_lower = allowed.lower()
            
            # Exact match
            if host_lower == allowed_lower:
                # Check exclusions
                if host_lower in [d.lower() for d in self.scope.excluded_domains]:
                    return ScopeViolation(
                        timestamp=datetime.now(),
                        violation_type=ScopeViolationType.EXPLICIT_EXCLUSION,
                        target=url,
                        reason=f"Domain explicitly excluded: {host}",
                        blocked=True
                    )
                return None
            
            # Subdomain match
            if self.scope.include_subdomains:
                if host_lower.endswith('.' + allowed_lower):
                    # Check excluded subdomains
                    if host_lower in [d.lower() for d in self.scope.excluded_domains]:
                        return ScopeViolation(
                            timestamp=datetime.now(),
                            violation_type=ScopeViolationType.EXPLICIT_EXCLUSION,
                            target=url,
                            reason=f"Subdomain explicitly excluded: {host}",
                            blocked=True
                        )
                    return None
        
        # Not in any allowed domain
        return ScopeViolation(
            timestamp=datetime.now(),
            violation_type=ScopeViolationType.OUT_OF_SCOPE_DOMAIN,
            target=url,
            reason=f"Domain not in scope: {host}",
            blocked=True
        )
    
    def _check_port(self, port: int, url: str) -> Optional[ScopeViolation]:
        """Check if port is allowed"""
        if self.scope.allowed_ports and port not in self.scope.allowed_ports:
            return ScopeViolation(
                timestamp=datetime.now(),
                violation_type=ScopeViolationType.FORBIDDEN_PORT,
                target=url,
                reason=f"Port not in allowed list: {port}",
                blocked=True
            )
        return None
    
    def _check_path_exclusions(self, path: str, url: str) -> Optional[ScopeViolation]:
        """Check path exclusions"""
        # Check explicit exclusions
        for excluded in self.scope.excluded_paths:
            if excluded.lower() in path.lower():
                return ScopeViolation(
                    timestamp=datetime.now(),
                    violation_type=ScopeViolationType.FORBIDDEN_PATH,
                    target=url,
                    reason=f"Path excluded: {path} (matches {excluded})",
                    blocked=True
                )
        
        # Check pattern exclusions
        for pattern in self._compiled_patterns["exclude"]:
            if pattern.match(path):
                return ScopeViolation(
                    timestamp=datetime.now(),
                    violation_type=ScopeViolationType.FORBIDDEN_PATH,
                    target=url,
                    reason=f"Path matches exclusion pattern: {path}",
                    blocked=True
                )
        
        return None
    
    def _check_sensitive_paths(self, path: str, url: str) -> Optional[ScopeViolation]:
        """Check for sensitive/destructive paths"""
        for pattern in self._compiled_patterns["sensitive"]:
            if pattern.match(path):
                return ScopeViolation(
                    timestamp=datetime.now(),
                    violation_type=ScopeViolationType.SENSITIVE_ENDPOINT,
                    target=url,
                    reason=f"Sensitive endpoint blocked: {path}",
                    blocked=True
                )
        return None
    
    def _handle_violation(self, violation: ScopeViolation) -> tuple:
        """Handle a scope violation based on mode"""
        self.violations.append(violation)
        
        if self.mode == ScopeMode.STRICT:
            return (False, violation)
        elif self.mode == ScopeMode.PERMISSIVE:
            violation.blocked = False
            return (True, violation)  # Allow but return violation for logging
        else:  # AUDIT
            violation.blocked = False
            return (True, violation)
    
    def add_to_scope(
        self,
        domains: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        ports: Optional[List[int]] = None
    ):
        """Add targets to allowed scope"""
        if domains:
            self.scope.allowed_domains.extend(domains)
        if ips:
            self.scope.allowed_ips.extend(ips)
        if ports:
            self.scope.allowed_ports.extend(ports)
    
    def exclude(
        self,
        domains: Optional[List[str]] = None,
        paths: Optional[List[str]] = None,
        patterns: Optional[List[str]] = None
    ):
        """Add exclusions to scope"""
        if domains:
            self.scope.excluded_domains.extend(domains)
        if paths:
            self.scope.excluded_paths.extend(paths)
        if patterns:
            self.scope.excluded_patterns.extend(patterns)
            self._compile_patterns()
    
    def get_violations(self) -> List[ScopeViolation]:
        """Get all recorded violations"""
        return self.violations
    
    def get_violations_by_type(self, vtype: ScopeViolationType) -> List[ScopeViolation]:
        """Get violations of a specific type"""
        return [v for v in self.violations if v.violation_type == vtype]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scope guard statistics"""
        by_type = {}
        for v in self.violations:
            vtype = v.violation_type.value
            by_type[vtype] = by_type.get(vtype, 0) + 1
        
        blocked_count = sum(1 for v in self.violations if v.blocked)
        
        return {
            "version": self.VERSION,
            "mode": self.mode.value,
            "total_violations": len(self.violations),
            "blocked_count": blocked_count,
            "allowed_count": len(self.violations) - blocked_count,
            "by_type": by_type,
            "scope_summary": {
                "allowed_domains": len(self.scope.allowed_domains),
                "excluded_domains": len(self.scope.excluded_domains),
                "excluded_paths": len(self.scope.excluded_paths)
            }
        }
    
    def generate_audit_report(self) -> str:
        """Generate audit report of all scope checks"""
        stats = self.get_statistics()
        
        report = f"""# Scope Guard Audit Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Mode:** {self.mode.value.upper()}

## Summary

| Metric | Count |
|--------|-------|
| Total Violations | {stats['total_violations']} |
| Blocked | {stats['blocked_count']} |
| Allowed (warnings) | {stats['allowed_count']} |

## Violations by Type

"""
        for vtype, count in stats['by_type'].items():
            report += f"- **{vtype}**: {count}\n"
        
        if self.violations:
            report += "\n## Detailed Violations\n\n"
            for v in self.violations[-50:]:  # Last 50
                status = "🚫 BLOCKED" if v.blocked else "⚠️ ALLOWED"
                report += f"- {status} `{v.target[:60]}` - {v.reason}\n"
        
        return report
    
    def export_config(self) -> Dict[str, Any]:
        """Export scope configuration"""
        return {
            "version": self.VERSION,
            "mode": self.mode.value,
            "scope": self.scope.to_dict()
        }
    
    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> 'ScopeGuard':
        """Create ScopeGuard from exported config"""
        scope = ScopeDefinition.from_dict(config.get("scope", {}))
        mode = ScopeMode(config.get("mode", "strict"))
        return cls(scope=scope, mode=mode)


class ScopeGuardMiddleware:
    """
    Middleware to wrap HTTP clients with scope enforcement
    """
    
    def __init__(self, guard: ScopeGuard):
        self.guard = guard
    
    def check_request(self, url: str) -> bool:
        """
        Check if request should be allowed
        
        Raises ScopeViolationError if blocked
        """
        allowed, violation = self.guard.is_allowed(url)
        
        if not allowed:
            raise ScopeViolationError(violation)
        
        return True


class ScopeViolationError(Exception):
    """Exception raised when scope is violated"""
    
    def __init__(self, violation: ScopeViolation):
        self.violation = violation
        super().__init__(f"Scope violation: {violation.reason}")


# Convenience functions
def create_scope_from_url(url: str, include_subdomains: bool = True) -> ScopeGuard:
    """Create a scope guard from a single URL"""
    scope = ScopeDefinition.from_target(url, include_subdomains)
    return ScopeGuard(scope=scope)


def is_safe_target(url: str) -> tuple:
    """Quick check if URL is safe to test (no scope restrictions)"""
    guard = ScopeGuard(ScopeDefinition(), mode=ScopeMode.STRICT)
    return guard.is_allowed(url)


# Export
__all__ = [
    "ScopeGuard",
    "ScopeDefinition",
    "ScopeViolation",
    "ScopeViolationType",
    "ScopeMode",
    "ScopeGuardMiddleware",
    "ScopeViolationError",
    "create_scope_from_url",
    "is_safe_target"
]
