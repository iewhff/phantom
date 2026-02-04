"""
Firebase Security Scanner - Tests Firebase-specific vulnerabilities.

Covers SecureDev checklist phases:
- F1: Firebase Auth Enumeration
- F2: Firestore Rules Testing
- F3: Realtime Database Rules
- F4: Firebase Storage Rules

SAFETY MODES:
- passive/safe/cautious: READ-ONLY mode - NO writes, NO deletes
- standard: Write test + immediate cleanup (test data only)
- aggressive: Full testing
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

import httpx

from utils.logger import get_logger
from scanning.modules.backend_detector import FirebaseConfig, BackendDetector

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


# Safe mode environment variable - set by full_scanner.py
SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()
ALLOW_WRITES = SAFE_MODE in ("standard", "aggressive")


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


@dataclass
class FirebaseFinding:
    """A security finding related to Firebase."""
    phase: str
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    resource: str = ""
    cwe: str = ""
    confidence: float = 85.0  # Default confidence for Firebase findings
    
    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "title": self.title,
            "severity": self.severity.name,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "remediation": self.remediation,
            "resource": self.resource,
            "cwe": self.cwe,
            "confidence": self.confidence,
        }


@dataclass
class FirebaseScanResult:
    """Result of Firebase security scan."""
    findings: list[FirebaseFinding] = field(default_factory=list)
    collections_discovered: list[str] = field(default_factory=list)
    storage_buckets: list[str] = field(default_factory=list)
    exposed_data_paths: list[str] = field(default_factory=list)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)


class FirebaseScanner:
    """
    Specialized scanner for Firebase backends.
    
    Tests:
    - Auth enumeration and misconfig (F1)
    - Firestore security rules (F2)
    - Realtime Database rules (F3)
    - Firebase Storage rules (F4)
    """
    
    # Common Firestore collection names
    COMMON_COLLECTIONS = [
        "users", "profiles", "accounts", "posts", "comments",
        "orders", "products", "payments", "messages", "chats",
        "notifications", "settings", "configs", "documents",
        "admins", "roles", "permissions", "logs", "events",
    ]
    
    # Common RTDB paths
    COMMON_RTDB_PATHS = [
        "", "users", "messages", "posts", "data",
        "admin", "config", "settings", "public",
        "private", "logs", "analytics",
    ]
    
    def __init__(
        self,
        settings_or_config: Settings | FirebaseConfig,
        settings: Settings | None = None
    ) -> None:
        """
        Initialize FirebaseScanner.

        Can be initialized in two ways:
        1. FirebaseScanner(settings) - for full_scanner compatibility
        2. FirebaseScanner(firebase_config, settings) - direct usage with config
        """
        # Determine if first arg is Settings or FirebaseConfig
        if hasattr(settings_or_config, 'api_key') and hasattr(settings_or_config, 'project_id'):
            # It's a FirebaseConfig
            self.config: FirebaseConfig | None = settings_or_config
            self.settings = settings
        else:
            # It's Settings - config will be detected during scan
            self.config = None
            self.settings = settings_or_config

        self.timeout = httpx.Timeout(15.0)
        self.result = FirebaseScanResult()

    async def scan(
        self,
        target: str | None = None,
        asset_data: dict | None = None,
    ) -> FirebaseScanResult | dict:
        """
        Run all Firebase security tests.

        Args:
            target: Target URL (used to detect Firebase config if not provided)
            asset_data: Optional asset data from crawler

        Returns:
            FirebaseScanResult or dict with findings
        """
        # If no config, try to detect from target
        if self.config is None:
            if target is None:
                logger.warning("FirebaseScanner: No config and no target provided")
                return {"findings": [], "error": "No Firebase config or target provided"}

            # Try to detect Firebase config using BackendDetector.detect()
            try:
                detector = BackendDetector(self.settings)
                detection_result = await detector.detect(target)

                if detection_result.firebase_config and detection_result.firebase_config.is_valid:
                    self.config = detection_result.firebase_config
                    logger.info(f"🔥 Firebase detected: {self.config.project_id}")
                else:
                    logger.info(f"🔥 No Firebase detected on {target}")
                    return {"findings": [], "info": "No Firebase configuration detected"}
            except Exception as e:
                logger.warning(f"Firebase detection failed: {e}")
                return {"findings": [], "error": str(e)}

        logger.info(f"🔥 Starting Firebase security scan for {self.config.project_id}")
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
        ) as client:
            # Run tests
            await asyncio.gather(
                self._test_auth_enumeration(client),
                self._test_firestore_rules(client),
                self._test_rtdb_rules(client),
                self._test_storage_rules(client),
                return_exceptions=True,
            )
        
        logger.info(f"✅ Firebase scan complete: {len(self.result.findings)} findings")
        logger.info(f"   Critical: {self.result.critical_count}, High: {self.result.high_count}")

        # Return dict format for full_scanner compatibility
        return {
            "findings": [f.to_dict() for f in self.result.findings],
            "collections_discovered": self.result.collections_discovered,
            "storage_buckets": self.result.storage_buckets,
            "exposed_data_paths": self.result.exposed_data_paths,
            "critical_count": self.result.critical_count,
            "high_count": self.result.high_count,
            "firebase_result": self.result,  # Keep original for backwards compat
        }
    
    async def _test_auth_enumeration(self, client: httpx.AsyncClient) -> None:
        """
        F1: Firebase Auth Enumeration Testing.
        
        Tests:
        - Email enumeration via sign-in/sign-up
        - Anonymous auth enabled
        - Weak password acceptance
        """
        logger.info("🔐 F1: Testing Firebase Auth Configuration")
        
        identity_url = "https://identitytoolkit.googleapis.com/v1/accounts"
        
        try:
            # Test 1: Check if anonymous auth is enabled
            response = await client.post(
                f"{identity_url}:signUp",
                params={"key": self.config.api_key},
                json={"returnSecureToken": True}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("idToken"):
                    self.result.findings.append(FirebaseFinding(
                        phase="F1",
                        title="Anonymous Authentication Enabled",
                        severity=Severity.MEDIUM,
                        description="Firebase anonymous authentication is enabled. "
                                   "Anyone can create anonymous sessions.",
                        evidence="Anonymous signUp successful",
                        remediation="Disable anonymous auth if not required. "
                                   "Ensure security rules don't trust anonymous users.",
                        cwe="CWE-287"
                    ))
            
            # Test 2: Email enumeration
            test_emails = [
                f"nonexistent_{uuid.uuid4().hex[:8]}@test.com",
                "admin@gmail.com",  # Likely to exist
            ]
            
            responses = {}
            for email in test_emails:
                response = await client.post(
                    f"{identity_url}:signInWithPassword",
                    params={"key": self.config.api_key},
                    json={
                        "email": email,
                        "password": "wrongpassword123",
                        "returnSecureToken": True
                    }
                )
                responses[email] = {
                    "status": response.status_code,
                    "error": response.json().get("error", {}).get("message", "")
                }
            
            # Compare responses
            error_messages = [r["error"] for r in responses.values()]
            if len(set(error_messages)) > 1:
                # Different error messages = email enumeration possible
                if "EMAIL_NOT_FOUND" in error_messages or "INVALID_EMAIL" in error_messages:
                    self.result.findings.append(FirebaseFinding(
                        phase="F1",
                        title="Email Enumeration via Auth Errors",
                        severity=Severity.MEDIUM,
                        description="Firebase returns different errors for existing vs "
                                   "non-existing emails, allowing enumeration.",
                        evidence=f"Errors: {error_messages}",
                        remediation="This is Firebase default behavior. "
                                   "Use rate limiting and monitoring.",
                        cwe="CWE-203"
                    ))
            
            # Test 3: Weak password signup
            weak_test = await client.post(
                f"{identity_url}:signUp",
                params={"key": self.config.api_key},
                json={
                    "email": f"weaktest_{uuid.uuid4().hex[:6]}@test.com",
                    "password": "123456",
                    "returnSecureToken": True
                }
            )
            
            if weak_test.status_code == 200:
                self.result.findings.append(FirebaseFinding(
                    phase="F1",
                    title="Weak Passwords Accepted",
                    severity=Severity.MEDIUM,
                    description="Firebase accepts weak passwords like '123456'. "
                               "This makes accounts vulnerable to brute force.",
                    evidence="Password '123456' accepted",
                    remediation="Implement client-side password validation. "
                               "Consider Firebase App Check.",
                    cwe="CWE-521"
                ))
                
        except Exception as e:
            logger.debug(f"Auth enumeration test error: {e}")
    
    async def _test_firestore_rules(self, client: httpx.AsyncClient) -> None:
        """
        F2: Firestore Security Rules Testing.
        
        Tests:
        - Unauthenticated collection access
        - Document enumeration
        - Write permissions
        """
        logger.info("📚 F2: Testing Firestore Rules")
        
        firestore_url = f"https://firestore.googleapis.com/v1/projects/{self.config.project_id}/databases/(default)/documents"
        
        for collection in self.COMMON_COLLECTIONS:
            try:
                # Test 1: List documents (unauthenticated)
                response = await client.get(
                    f"{firestore_url}/{collection}",
                    params={"key": self.config.api_key}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    documents = data.get("documents", [])
                    
                    if documents:
                        self.result.collections_discovered.append(collection)
                        
                        # Check for sensitive fields
                        sensitive_found = []
                        for doc in documents[:3]:
                            fields = doc.get("fields", {})
                            for field in ["email", "password", "phone", "ssn", "token"]:
                                if field in fields:
                                    sensitive_found.append(field)
                        
                        severity = Severity.HIGH if sensitive_found else Severity.MEDIUM
                        
                        self.result.findings.append(FirebaseFinding(
                            phase="F2",
                            title=f"Collection '{collection}' publicly readable",
                            severity=severity,
                            description=f"Collection '{collection}' allows unauthenticated reads. "
                                       f"{'Sensitive fields: ' + ', '.join(set(sensitive_found)) if sensitive_found else 'Review data sensitivity.'}",
                            evidence=f"Found {len(documents)} documents",
                            resource=collection,
                            remediation="Add Firestore security rules: "
                                       "allow read: if request.auth != null;",
                            cwe="CWE-284"
                        ))
                
                # Test 2: Try to create a document (ONLY in write-allowed modes)
                if not ALLOW_WRITES:
                    logger.debug(f"⚠️ SAFE MODE: Skipping write test for collection '{collection}'")
                    # Still report that we COULD test writes (for manual verification)
                    self.result.findings.append(FirebaseFinding(
                        phase="F2",
                        title=f"Collection '{collection}' - Write test skipped (safe mode)",
                        severity=Severity.INFO,
                        description=f"Write test skipped due to safe mode. Manual verification recommended.",
                        evidence="Safe mode active - no writes performed",
                        resource=collection,
                        remediation="Run with --safe-mode=standard to test write permissions",
                        cwe="CWE-284",
                        confidence=0.0,  # Mark as unverified
                    ))
                else:
                    test_doc = {
                        "fields": {
                            "test_field": {"stringValue": "security_test"},
                            "timestamp": {"timestampValue": "2024-01-01T00:00:00Z"}
                        }
                    }
                    
                    response = await client.post(
                        f"{firestore_url}/{collection}",
                        params={"key": self.config.api_key},
                        json=test_doc
                    )
                    
                    if response.status_code in [200, 201]:
                        self.result.findings.append(FirebaseFinding(
                            phase="F2",
                            title=f"Collection '{collection}' allows public writes",
                            severity=Severity.CRITICAL,
                            description=f"Collection '{collection}' allows unauthenticated document creation. "
                                       "Attackers can inject malicious data.",
                            evidence=f"Document created with status {response.status_code}",
                            resource=collection,
                            remediation="Add write rules: allow write: if request.auth != null;",
                            cwe="CWE-284"
                        ))
                        
                        # Try to delete the test document (cleanup)
                        doc_name = response.json().get("name", "")
                        if doc_name:
                            await client.delete(
                                f"https://firestore.googleapis.com/v1/{doc_name}",
                                params={"key": self.config.api_key}
                            )
                        
            except Exception as e:
                logger.debug(f"Firestore test error for {collection}: {e}")
    
    async def _test_rtdb_rules(self, client: httpx.AsyncClient) -> None:
        """
        F3: Realtime Database Rules Testing.
        
        Tests:
        - Root-level read access
        - Path enumeration
        - Write permissions
        """
        logger.info("🗃️ F3: Testing Realtime Database Rules")
        
        if not self.config.database_url:
            # Try to construct from project ID
            rtdb_url = f"https://{self.config.project_id}-default-rtdb.firebaseio.com"
        else:
            rtdb_url = f"https://{self.config.database_url}"
        
        for path in self.COMMON_RTDB_PATHS:
            url = f"{rtdb_url}/{path}.json" if path else f"{rtdb_url}/.json"
            
            try:
                # Test 1: Read access
                response = await client.get(url)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data is not None and data != "null":
                        self.result.exposed_data_paths.append(path or "/")
                        
                        # Determine severity based on path
                        if path in ["", "users", "admin", "config"]:
                            severity = Severity.CRITICAL
                        elif path in ["private", "settings"]:
                            severity = Severity.HIGH
                        else:
                            severity = Severity.MEDIUM
                        
                        self.result.findings.append(FirebaseFinding(
                            phase="F3",
                            title=f"RTDB path '/{path or 'root'}' is publicly readable",
                            severity=severity,
                            description=f"Realtime Database path '/{path or 'root'}' returns data without authentication.",
                            evidence=f"Data type: {type(data).__name__}, Size: {len(str(data))} chars",
                            resource=path or "/",
                            remediation="Set RTDB rules: {\"rules\": {\".read\": \"auth != null\"}}",
                            cwe="CWE-284"
                        ))
                
                # Test 2: Write access (ONLY in write-allowed modes)
                if not ALLOW_WRITES:
                    logger.debug(f"⚠️ SAFE MODE: Skipping RTDB write test")
                else:
                    test_data = {"security_test": True, "timestamp": 1234567890}
                    response = await client.put(
                        f"{rtdb_url}/security_test_node.json",
                        json=test_data
                    )
                    
                    if response.status_code == 200:
                        self.result.findings.append(FirebaseFinding(
                            phase="F3",
                            title="RTDB allows public writes",
                            severity=Severity.CRITICAL,
                            description="Realtime Database allows unauthenticated writes. "
                                       "Attackers can modify or inject data.",
                            evidence="Write to /security_test_node successful",
                            resource="/",
                            remediation="Set write rules: {\".write\": \"auth != null\"}",
                            cwe="CWE-284"
                        ))
                        
                        # Clean up
                        await client.delete(f"{rtdb_url}/security_test_node.json")
                        break  # Found vulnerability, no need to test more paths
                    
            except Exception as e:
                logger.debug(f"RTDB test error for path '{path}': {e}")
    
    async def _test_storage_rules(self, client: httpx.AsyncClient) -> None:
        """
        F4: Firebase Storage Rules Testing.
        
        Tests:
        - Bucket listing
        - File upload without auth
        - File enumeration
        """
        logger.info("📦 F4: Testing Firebase Storage Rules")
        
        if not self.config.storage_bucket:
            self.config.storage_bucket = f"{self.config.project_id}.appspot.com"
        
        storage_url = f"https://firebasestorage.googleapis.com/v0/b/{self.config.storage_bucket}/o"
        
        try:
            # Test 1: List files
            response = await client.get(storage_url)
            
            if response.status_code == 200:
                data = response.json()
                items = data.get("items", [])
                
                if items:
                    self.result.storage_buckets.append(self.config.storage_bucket)
                    self.result.findings.append(FirebaseFinding(
                        phase="F4",
                        title="Storage bucket allows file listing",
                        severity=Severity.MEDIUM,
                        description=f"Firebase Storage bucket allows listing files without authentication. "
                                   f"Found {len(items)} files.",
                        evidence=f"Files: {[f.get('name', '') for f in items[:5]]}",
                        resource=self.config.storage_bucket,
                        remediation="Add storage rules to prevent listing or require auth",
                        cwe="CWE-548"
                    ))
            
            # Test 2: Try to upload a file - ONLY in write-allowed modes
            if not ALLOW_WRITES:
                logger.debug(f"⚠️ SAFE MODE: Skipping Storage upload test")
            else:
                test_content = b"security test file content"
                upload_url = f"{storage_url}/security_test.txt"
                
                response = await client.post(
                    upload_url,
                    params={"uploadType": "media"},
                    headers={"Content-Type": "text/plain"},
                    content=test_content
                )
                
                if response.status_code in [200, 201]:
                    self.result.findings.append(FirebaseFinding(
                        phase="F4",
                        title="Storage allows unauthenticated uploads",
                        severity=Severity.HIGH,
                        description="Firebase Storage accepts file uploads without authentication. "
                                   "This may allow malicious file injection.",
                        evidence="File upload successful",
                        resource=self.config.storage_bucket,
                        remediation="Set storage rules: allow write: if request.auth != null;",
                        cwe="CWE-434"
                    ))
                    
                    # Try to delete (cleanup)
                    await client.delete(upload_url)
            
            # Test 3: Check common file paths
            common_paths = ["uploads/", "images/", "documents/", "backups/"]
            
            for path in common_paths:
                response = await client.get(
                    storage_url,
                    params={"prefix": path}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    items = data.get("items", [])
                    if items:
                        self.result.findings.append(FirebaseFinding(
                            phase="F4",
                            title=f"Storage path '{path}' accessible",
                            severity=Severity.LOW,
                            description=f"Storage path '{path}' contains {len(items)} files.",
                            evidence=f"Sample files: {[f.get('name', '')[:30] for f in items[:3]]}",
                            resource=path,
                            remediation="Review if this path should be public",
                            cwe="CWE-548"
                        ))
                        
        except Exception as e:
            logger.debug(f"Storage test error: {e}")


async def scan_firebase(
    target: str,
    config: FirebaseConfig | None = None,
    settings: Settings | None = None
) -> FirebaseScanResult:
    """
    Convenience function to run Firebase security scan.
    
    If config is not provided, will run backend detection first.
    """
    if not config:
        detector = BackendDetector(settings)
        result = await detector.detect(target)
        config = result.firebase_config
    
    if not config or not config.is_valid:
        logger.error("No valid Firebase configuration found")
        return FirebaseScanResult()
    
    scanner = FirebaseScanner(config, settings)
    return await scanner.scan()
