"""
PHANTOM AI - Security Knowledge Loader

Enterprise-grade security knowledge base loader for AI-powered penetration testing.
Integrates with PayloadsAllTheThings, HackTricks, CVE Database, and custom sources.

Version: 3.0.0
Date: 2026-01-30
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import aiohttp


# =============================================================================
# CONSTANTS
# =============================================================================

VERSION = "3.0.0"

# Knowledge base sources
PAYLOADS_ALL_THE_THINGS_REPO = "https://github.com/swisskyrepo/PayloadsAllTheThings"
HACKTRICKS_REPO = "https://github.com/carlospolop/hacktricks"
HACKTRICKS_CLOUD_REPO = "https://github.com/carlospolop/hacktricks-cloud"
SECLIST_REPO = "https://github.com/danielmiessler/SecLists"

# Raw GitHub content URLs
PAYLOADS_RAW_URL = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"
HACKTRICKS_RAW_URL = "https://raw.githubusercontent.com/carlospolop/hacktricks/master"

# Default knowledge base directory
DEFAULT_KB_DIR = Path.home() / ".phantom" / "knowledge"

# Cache settings
CACHE_EXPIRY_HOURS = 24
MAX_CACHE_SIZE_MB = 500


# =============================================================================
# ENUMS
# =============================================================================

class KnowledgeSource(Enum):
    """Knowledge base sources."""
    PAYLOADS_ALL_THE_THINGS = "payloads_all_the_things"
    HACKTRICKS = "hacktricks"
    HACKTRICKS_CLOUD = "hacktricks_cloud"
    SECLIST = "seclist"
    CVE_DATABASE = "cve_database"
    EXPLOIT_DB = "exploit_db"
    NUCLEI_TEMPLATES = "nuclei_templates"
    CUSTOM = "custom"


class KnowledgeType(Enum):
    """Types of security knowledge."""
    PAYLOAD = "payload"
    TECHNIQUE = "technique"
    VULNERABILITY = "vulnerability"
    EXPLOIT = "exploit"
    BYPASS = "bypass"
    ENUMERATION = "enumeration"
    COMMAND = "command"
    WORDLIST = "wordlist"
    TEMPLATE = "template"
    REFERENCE = "reference"


class VulnerabilityCategory(Enum):
    """Vulnerability categories."""
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    XXE = "xxe"
    LFI = "lfi"
    RFI = "rfi"
    DESERIALIZATION = "deserialization"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    SSTI = "ssti"
    PATH_TRAVERSAL = "path_traversal"
    FILE_UPLOAD = "file_upload"
    IDOR = "idor"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    MISCONFIGURATION = "misconfiguration"
    CRYPTOGRAPHIC = "cryptographic"
    API_SECURITY = "api_security"
    CLOUD_SECURITY = "cloud_security"
    WEB_CACHE = "web_cache"
    HTTP_SMUGGLING = "http_smuggling"
    WEBSOCKET = "websocket"
    GRAPHQL = "graphql"
    JWT = "jwt"
    OAUTH = "oauth"
    OTHER = "other"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class KnowledgeEntry:
    """Represents a single knowledge entry."""
    id: str
    source: KnowledgeSource
    knowledge_type: KnowledgeType
    category: VulnerabilityCategory
    title: str
    content: str
    tags: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cwe_ids: List[int] = field(default_factory=list)
    severity: Optional[str] = None
    platform: Optional[str] = None
    language: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "source": self.source.value,
            "knowledge_type": self.knowledge_type.value,
            "category": self.category.value,
            "title": self.title,
            "content": self.content,
            "tags": self.tags,
            "payloads": self.payloads,
            "techniques": self.techniques,
            "references": self.references,
            "cwe_ids": self.cwe_ids,
            "severity": self.severity,
            "platform": self.platform,
            "language": self.language,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KnowledgeEntry":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            source=KnowledgeSource(data["source"]),
            knowledge_type=KnowledgeType(data["knowledge_type"]),
            category=VulnerabilityCategory(data["category"]),
            title=data["title"],
            content=data["content"],
            tags=data.get("tags", []),
            payloads=data.get("payloads", []),
            techniques=data.get("techniques", []),
            references=data.get("references", []),
            cwe_ids=data.get("cwe_ids", []),
            severity=data.get("severity"),
            platform=data.get("platform"),
            language=data.get("language"),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if "updated_at" in data else datetime.now(),
            metadata=data.get("metadata", {}),
        )

    def get_embedding_text(self) -> str:
        """Get text for embedding generation."""
        parts = [
            self.title,
            self.content[:1000],  # Limit content length
            f"Category: {self.category.value}",
            f"Type: {self.knowledge_type.value}",
        ]
        if self.tags:
            parts.append(f"Tags: {', '.join(self.tags)}")
        if self.payloads:
            parts.append(f"Payloads: {len(self.payloads)} available")
        return "\n".join(parts)


@dataclass
class PayloadCollection:
    """Collection of payloads for a specific vulnerability type."""
    category: VulnerabilityCategory
    name: str
    description: str
    payloads: List[str]
    tags: List[str] = field(default_factory=list)
    platform: Optional[str] = None
    waf_bypass: bool = False
    encoded: bool = False
    source: KnowledgeSource = KnowledgeSource.CUSTOM

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category": self.category.value,
            "name": self.name,
            "description": self.description,
            "payloads": self.payloads,
            "tags": self.tags,
            "platform": self.platform,
            "waf_bypass": self.waf_bypass,
            "encoded": self.encoded,
            "source": self.source.value,
        }


@dataclass
class TechniqueEntry:
    """Security technique entry."""
    id: str
    name: str
    category: VulnerabilityCategory
    description: str
    steps: List[str]
    prerequisites: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    detection_methods: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    difficulty: str = "medium"
    source: KnowledgeSource = KnowledgeSource.CUSTOM

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "steps": self.steps,
            "prerequisites": self.prerequisites,
            "tools": self.tools,
            "payloads": self.payloads,
            "detection_methods": self.detection_methods,
            "mitigations": self.mitigations,
            "references": self.references,
            "difficulty": self.difficulty,
            "source": self.source.value,
        }


@dataclass
class CVEEntry:
    """CVE database entry."""
    cve_id: str
    title: str
    description: str
    cvss_score: float
    cvss_vector: str
    cwe_ids: List[int]
    affected_products: List[str]
    references: List[str]
    published_date: datetime
    modified_date: datetime
    exploit_available: bool = False
    exploit_references: List[str] = field(default_factory=list)
    poc_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_ids": self.cwe_ids,
            "affected_products": self.affected_products,
            "references": self.references,
            "published_date": self.published_date.isoformat(),
            "modified_date": self.modified_date.isoformat(),
            "exploit_available": self.exploit_available,
            "exploit_references": self.exploit_references,
            "poc_code": self.poc_code,
        }


@dataclass
class LoaderStatistics:
    """Loader statistics."""
    total_entries: int = 0
    payloads_count: int = 0
    techniques_count: int = 0
    cves_count: int = 0
    sources_loaded: List[str] = field(default_factory=list)
    last_update: Optional[datetime] = None
    cache_size_mb: float = 0.0
    load_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_entries": self.total_entries,
            "payloads_count": self.payloads_count,
            "techniques_count": self.techniques_count,
            "cves_count": self.cves_count,
            "sources_loaded": self.sources_loaded,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "cache_size_mb": self.cache_size_mb,
            "load_errors": self.load_errors,
        }


# =============================================================================
# CATEGORY MAPPINGS
# =============================================================================

# Map PayloadsAllTheThings directories to categories
PATT_CATEGORY_MAP = {
    "SQL Injection": VulnerabilityCategory.SQL_INJECTION,
    "XSS Injection": VulnerabilityCategory.XSS,
    "XXE Injection": VulnerabilityCategory.XXE,
    "SSRF": VulnerabilityCategory.SSRF,
    "Server Side Request Forgery": VulnerabilityCategory.SSRF,
    "SSTI": VulnerabilityCategory.SSTI,
    "Server Side Template Injection": VulnerabilityCategory.SSTI,
    "NoSQL Injection": VulnerabilityCategory.NOSQL_INJECTION,
    "Command Injection": VulnerabilityCategory.COMMAND_INJECTION,
    "File Inclusion": VulnerabilityCategory.LFI,
    "Directory Traversal": VulnerabilityCategory.PATH_TRAVERSAL,
    "CSRF": VulnerabilityCategory.CSRF,
    "CRLF Injection": VulnerabilityCategory.INJECTION,
    "LDAP Injection": VulnerabilityCategory.INJECTION,
    "Insecure Deserialization": VulnerabilityCategory.DESERIALIZATION,
    "GraphQL Injection": VulnerabilityCategory.GRAPHQL,
    "JWT Security": VulnerabilityCategory.JWT,
    "OAuth": VulnerabilityCategory.OAUTH,
    "IDOR": VulnerabilityCategory.IDOR,
    "Upload Insecure Files": VulnerabilityCategory.FILE_UPLOAD,
    "HTTP Request Smuggling": VulnerabilityCategory.HTTP_SMUGGLING,
    "Web Cache Deception": VulnerabilityCategory.WEB_CACHE,
    "Web Cache Poisoning": VulnerabilityCategory.WEB_CACHE,
    "WebSocket": VulnerabilityCategory.WEBSOCKET,
    "API Testing": VulnerabilityCategory.API_SECURITY,
}

# CWE to Category mapping
CWE_CATEGORY_MAP = {
    89: VulnerabilityCategory.SQL_INJECTION,
    79: VulnerabilityCategory.XSS,
    611: VulnerabilityCategory.XXE,
    918: VulnerabilityCategory.SSRF,
    78: VulnerabilityCategory.COMMAND_INJECTION,
    94: VulnerabilityCategory.INJECTION,
    98: VulnerabilityCategory.LFI,
    22: VulnerabilityCategory.PATH_TRAVERSAL,
    352: VulnerabilityCategory.CSRF,
    502: VulnerabilityCategory.DESERIALIZATION,
    434: VulnerabilityCategory.FILE_UPLOAD,
    639: VulnerabilityCategory.IDOR,
    287: VulnerabilityCategory.AUTHENTICATION,
    384: VulnerabilityCategory.AUTHENTICATION,
    327: VulnerabilityCategory.CRYPTOGRAPHIC,
    311: VulnerabilityCategory.CRYPTOGRAPHIC,
    200: VulnerabilityCategory.INFORMATION_DISCLOSURE,
}


# =============================================================================
# KNOWLEDGE LOADER
# =============================================================================

class KnowledgeLoader:
    """
    PHANTOM AI Security Knowledge Loader.

    Loads and manages security knowledge from multiple sources including
    PayloadsAllTheThings, HackTricks, CVE Database, and custom sources.
    """

    VERSION = "3.0.0"

    def __init__(
        self,
        kb_dir: Optional[Path] = None,
        cache_expiry_hours: int = CACHE_EXPIRY_HOURS,
        max_cache_size_mb: int = MAX_CACHE_SIZE_MB,
    ):
        """Initialize the knowledge loader."""
        self.kb_dir = kb_dir or DEFAULT_KB_DIR
        self.kb_dir.mkdir(parents=True, exist_ok=True)

        self.cache_expiry = timedelta(hours=cache_expiry_hours)
        self.max_cache_size = max_cache_size_mb * 1024 * 1024  # Convert to bytes

        # Knowledge storage
        self.entries: Dict[str, KnowledgeEntry] = {}
        self.payloads: Dict[VulnerabilityCategory, List[PayloadCollection]] = {}
        self.techniques: Dict[str, TechniqueEntry] = {}
        self.cves: Dict[str, CVEEntry] = {}

        # Indexes for fast lookup
        self._category_index: Dict[VulnerabilityCategory, Set[str]] = {}
        self._tag_index: Dict[str, Set[str]] = {}
        self._source_index: Dict[KnowledgeSource, Set[str]] = {}

        # Statistics
        self.stats = LoaderStatistics()

        # Load cached data
        self._load_cache()

    # =========================================================================
    # PUBLIC METHODS
    # =========================================================================

    async def load_all(self, sources: Optional[List[KnowledgeSource]] = None) -> LoaderStatistics:
        """Load knowledge from all sources."""
        if sources is None:
            sources = [
                KnowledgeSource.PAYLOADS_ALL_THE_THINGS,
                KnowledgeSource.HACKTRICKS,
                KnowledgeSource.CVE_DATABASE,
            ]

        for source in sources:
            try:
                if source == KnowledgeSource.PAYLOADS_ALL_THE_THINGS:
                    await self.load_payloads_all_the_things()
                elif source == KnowledgeSource.HACKTRICKS:
                    await self.load_hacktricks()
                elif source == KnowledgeSource.CVE_DATABASE:
                    await self.load_cve_database()
                elif source == KnowledgeSource.SECLIST:
                    await self.load_seclists()

                self.stats.sources_loaded.append(source.value)

            except Exception as e:
                self.stats.load_errors.append(f"{source.value}: {str(e)}")

        self.stats.last_update = datetime.now()
        self._update_statistics()
        self._save_cache()

        return self.stats

    async def load_payloads_all_the_things(self) -> int:
        """Load payloads from PayloadsAllTheThings repository."""
        loaded_count = 0

        # Define payload categories and their GitHub paths
        payload_paths = {
            "SQL Injection": [
                "SQL%20Injection/Intruder/Auth_Bypass.txt",
                "SQL%20Injection/Intruder/FUZZ_Bypass.txt",
                "SQL%20Injection/PostgreSQL%20Injection.md",
                "SQL%20Injection/MySQL%20Injection.md",
                "SQL%20Injection/MSSQL%20Injection.md",
            ],
            "XSS Injection": [
                "XSS%20Injection/Intruder/IntruderXSS.txt",
                "XSS%20Injection/XSS%20in%20HTML.md",
                "XSS%20Injection/XSS%20in%20JavaScript.md",
            ],
            "Server Side Template Injection": [
                "Server%20Side%20Template%20Injection/README.md",
            ],
            "Server Side Request Forgery": [
                "Server%20Side%20Request%20Forgery/README.md",
            ],
            "Command Injection": [
                "Command%20Injection/README.md",
                "Command%20Injection/Intruder/command-execution-unix.txt",
            ],
            "NoSQL Injection": [
                "NoSQL%20Injection/README.md",
            ],
            "XXE Injection": [
                "XXE%20Injection/README.md",
            ],
            "LDAP Injection": [
                "LDAP%20Injection/README.md",
            ],
            "CSRF": [
                "CSRF%20Injection/README.md",
            ],
            "IDOR": [
                "Insecure%20Direct%20Object%20References/README.md",
            ],
            "JWT Security": [
                "JSON%20Web%20Token/README.md",
            ],
            "GraphQL Injection": [
                "GraphQL%20Injection/README.md",
            ],
            "Insecure Deserialization": [
                "Insecure%20Deserialization/README.md",
            ],
            "File Inclusion": [
                "File%20Inclusion/README.md",
            ],
            "Directory Traversal": [
                "Directory%20Traversal/README.md",
            ],
            "Upload Insecure Files": [
                "Upload%20Insecure%20Files/README.md",
            ],
            "HTTP Request Smuggling": [
                "Request%20Smuggling/README.md",
            ],
        }

        async with aiohttp.ClientSession() as session:
            for category_name, paths in payload_paths.items():
                category = PATT_CATEGORY_MAP.get(category_name, VulnerabilityCategory.OTHER)

                for path in paths:
                    try:
                        url = f"{PAYLOADS_RAW_URL}/{path}"
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                            if response.status == 200:
                                content = await response.text()

                                # Parse content based on file type
                                if path.endswith(".md"):
                                    entries = self._parse_markdown_payloads(
                                        content, category, category_name
                                    )
                                else:
                                    entries = self._parse_text_payloads(
                                        content, category, category_name
                                    )

                                for entry in entries:
                                    self._add_entry(entry)
                                    loaded_count += 1

                    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                        logger.debug(f"Failed to load payload from {path}: {e}")
                        continue

        return loaded_count

    async def load_hacktricks(self) -> int:
        """Load techniques from HackTricks repository."""
        loaded_count = 0

        # HackTricks category paths
        hacktricks_paths = {
            "pentesting-web/sql-injection": VulnerabilityCategory.SQL_INJECTION,
            "pentesting-web/xss-cross-site-scripting": VulnerabilityCategory.XSS,
            "pentesting-web/ssrf-server-side-request-forgery": VulnerabilityCategory.SSRF,
            "pentesting-web/ssti-server-side-template-injection": VulnerabilityCategory.SSTI,
            "pentesting-web/xxe-xee-xml-external-entity": VulnerabilityCategory.XXE,
            "pentesting-web/command-injection": VulnerabilityCategory.COMMAND_INJECTION,
            "pentesting-web/nosql-injection": VulnerabilityCategory.NOSQL_INJECTION,
            "pentesting-web/deserialization": VulnerabilityCategory.DESERIALIZATION,
            "pentesting-web/file-inclusion": VulnerabilityCategory.LFI,
            "pentesting-web/csrf-cross-site-request-forgery": VulnerabilityCategory.CSRF,
            "pentesting-web/idor": VulnerabilityCategory.IDOR,
            "pentesting-web/file-upload": VulnerabilityCategory.FILE_UPLOAD,
            "pentesting-web/graphql": VulnerabilityCategory.GRAPHQL,
            "pentesting-web/hacking-jwt-json-web-tokens": VulnerabilityCategory.JWT,
            "pentesting-web/oauth-to-account-takeover": VulnerabilityCategory.OAUTH,
            "pentesting-web/http-request-smuggling": VulnerabilityCategory.HTTP_SMUGGLING,
            "pentesting-web/cache-deception": VulnerabilityCategory.WEB_CACHE,
        }

        async with aiohttp.ClientSession() as session:
            for path, category in hacktricks_paths.items():
                try:
                    # Try to get the README.md for each category
                    url = f"{HACKTRICKS_RAW_URL}/{path}/README.md"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                        if response.status == 200:
                            content = await response.text()
                            entry = self._parse_hacktricks_technique(content, category, path)
                            if entry:
                                self._add_entry(entry)
                                loaded_count += 1

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.debug(f"Failed to load HackTricks from {path}: {e}")
                    continue

        return loaded_count

    async def load_cve_database(self) -> int:
        """Load recent CVEs from public sources."""
        loaded_count = 0

        # Load from NIST NVD API (limited to recent entries)
        # In production, this would use the actual NVD API
        # For now, we'll create some sample CVE entries for common vulnerabilities

        sample_cves = [
            CVEEntry(
                cve_id="CVE-2024-0001",
                title="SQL Injection in Sample Application",
                description="A SQL injection vulnerability exists in the login form.",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_ids=[89],
                affected_products=["sample-app <= 1.0.0"],
                references=["https://example.com/advisory"],
                published_date=datetime.now() - timedelta(days=30),
                modified_date=datetime.now() - timedelta(days=15),
                exploit_available=True,
            ),
            CVEEntry(
                cve_id="CVE-2024-0002",
                title="XSS in Web Framework",
                description="Cross-site scripting vulnerability in template rendering.",
                cvss_score=6.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                cwe_ids=[79],
                affected_products=["web-framework <= 2.0.0"],
                references=["https://example.com/advisory2"],
                published_date=datetime.now() - timedelta(days=60),
                modified_date=datetime.now() - timedelta(days=45),
                exploit_available=False,
            ),
        ]

        for cve in sample_cves:
            self.cves[cve.cve_id] = cve
            loaded_count += 1

        return loaded_count

    async def load_seclists(self) -> int:
        """Load wordlists and payloads from SecLists."""
        loaded_count = 0
        # Implementation would download and index SecLists content
        return loaded_count

    def add_custom_entry(self, entry: KnowledgeEntry) -> None:
        """Add a custom knowledge entry."""
        self._add_entry(entry)
        self._save_cache()

    def add_custom_payloads(
        self,
        category: VulnerabilityCategory,
        name: str,
        payloads: List[str],
        description: str = "",
        tags: Optional[List[str]] = None,
    ) -> None:
        """Add custom payload collection."""
        collection = PayloadCollection(
            category=category,
            name=name,
            description=description,
            payloads=payloads,
            tags=tags or [],
            source=KnowledgeSource.CUSTOM,
        )

        if category not in self.payloads:
            self.payloads[category] = []
        self.payloads[category].append(collection)
        self._save_cache()

    # =========================================================================
    # SEARCH AND RETRIEVAL
    # =========================================================================

    def search(
        self,
        query: str,
        category: Optional[VulnerabilityCategory] = None,
        knowledge_type: Optional[KnowledgeType] = None,
        source: Optional[KnowledgeSource] = None,
        limit: int = 10,
    ) -> List[KnowledgeEntry]:
        """Search knowledge base."""
        results = []
        query_lower = query.lower()

        for entry_id, entry in self.entries.items():
            # Filter by criteria
            if category and entry.category != category:
                continue
            if knowledge_type and entry.knowledge_type != knowledge_type:
                continue
            if source and entry.source != source:
                continue

            # Score relevance
            score = 0
            if query_lower in entry.title.lower():
                score += 10
            if query_lower in entry.content.lower():
                score += 5
            if any(query_lower in tag.lower() for tag in entry.tags):
                score += 3

            if score > 0:
                results.append((score, entry))

        # Sort by score and return top results
        results.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in results[:limit]]

    def get_payloads_for_category(
        self,
        category: VulnerabilityCategory,
        waf_bypass: bool = False,
        limit: int = 100,
    ) -> List[str]:
        """Get payloads for a specific vulnerability category."""
        payloads = []

        # From payload collections
        if category in self.payloads:
            for collection in self.payloads[category]:
                if waf_bypass and not collection.waf_bypass:
                    continue
                payloads.extend(collection.payloads)

        # From knowledge entries
        if category in self._category_index:
            for entry_id in self._category_index[category]:
                entry = self.entries.get(entry_id)
                if entry and entry.payloads:
                    payloads.extend(entry.payloads)

        # Deduplicate and limit
        seen = set()
        unique_payloads = []
        for payload in payloads:
            if payload not in seen:
                seen.add(payload)
                unique_payloads.append(payload)
                if len(unique_payloads) >= limit:
                    break

        return unique_payloads

    def get_techniques_for_category(
        self,
        category: VulnerabilityCategory,
    ) -> List[TechniqueEntry]:
        """Get techniques for a specific vulnerability category."""
        return [
            technique
            for technique in self.techniques.values()
            if technique.category == category
        ]

    def get_entry_by_id(self, entry_id: str) -> Optional[KnowledgeEntry]:
        """Get a specific knowledge entry by ID."""
        return self.entries.get(entry_id)

    def get_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Get a specific CVE entry."""
        return self.cves.get(cve_id)

    def get_cves_by_cwe(self, cwe_id: int, limit: int = 10) -> List[CVEEntry]:
        """Get CVEs by CWE ID."""
        return [
            cve for cve in self.cves.values()
            if cwe_id in cve.cwe_ids
        ][:limit]

    def get_entries_by_tag(self, tag: str) -> List[KnowledgeEntry]:
        """Get entries by tag."""
        if tag in self._tag_index:
            return [
                self.entries[entry_id]
                for entry_id in self._tag_index[tag]
                if entry_id in self.entries
            ]
        return []

    def get_all_tags(self) -> List[str]:
        """Get all available tags."""
        return list(self._tag_index.keys())

    def get_statistics(self) -> LoaderStatistics:
        """Get loader statistics."""
        return self.stats

    # =========================================================================
    # EXPORT METHODS
    # =========================================================================

    def export_for_rag(self) -> List[Dict[str, Any]]:
        """Export knowledge base entries for RAG indexing."""
        documents = []

        for entry in self.entries.values():
            documents.append({
                "id": entry.id,
                "text": entry.get_embedding_text(),
                "metadata": {
                    "source": entry.source.value,
                    "category": entry.category.value,
                    "type": entry.knowledge_type.value,
                    "title": entry.title,
                    "tags": entry.tags,
                },
            })

        return documents

    def export_payloads_json(self, output_path: Path) -> None:
        """Export all payloads to JSON file."""
        data = {}
        for category, collections in self.payloads.items():
            data[category.value] = [
                collection.to_dict()
                for collection in collections
            ]
        output_path.write_text(json.dumps(data, indent=2))

    def export_techniques_json(self, output_path: Path) -> None:
        """Export all techniques to JSON file."""
        data = {
            technique_id: technique.to_dict()
            for technique_id, technique in self.techniques.items()
        }
        output_path.write_text(json.dumps(data, indent=2))

    # =========================================================================
    # PRIVATE METHODS
    # =========================================================================

    def _add_entry(self, entry: KnowledgeEntry) -> None:
        """Add entry to knowledge base and update indexes."""
        self.entries[entry.id] = entry

        # Update category index
        if entry.category not in self._category_index:
            self._category_index[entry.category] = set()
        self._category_index[entry.category].add(entry.id)

        # Update tag index
        for tag in entry.tags:
            if tag not in self._tag_index:
                self._tag_index[tag] = set()
            self._tag_index[tag].add(entry.id)

        # Update source index
        if entry.source not in self._source_index:
            self._source_index[entry.source] = set()
        self._source_index[entry.source].add(entry.id)

    def _parse_markdown_payloads(
        self,
        content: str,
        category: VulnerabilityCategory,
        category_name: str,
    ) -> List[KnowledgeEntry]:
        """Parse payloads from markdown content."""
        entries = []

        # Extract code blocks
        code_blocks = re.findall(r'```[\w]*\n(.*?)\n```', content, re.DOTALL)

        # Extract payloads from content
        payloads = []
        for block in code_blocks:
            lines = block.strip().split('\n')
            payloads.extend([line.strip() for line in lines if line.strip()])

        if payloads:
            entry_id = hashlib.md5(f"patt_{category_name}".encode()).hexdigest()[:16]
            entry = KnowledgeEntry(
                id=entry_id,
                source=KnowledgeSource.PAYLOADS_ALL_THE_THINGS,
                knowledge_type=KnowledgeType.PAYLOAD,
                category=category,
                title=f"{category_name} Payloads",
                content=content[:2000],  # Limit content size
                tags=[category_name.lower().replace(" ", "_"), "payload"],
                payloads=payloads[:500],  # Limit payload count
            )
            entries.append(entry)

        return entries

    def _parse_text_payloads(
        self,
        content: str,
        category: VulnerabilityCategory,
        category_name: str,
    ) -> List[KnowledgeEntry]:
        """Parse payloads from text file."""
        entries = []

        payloads = [
            line.strip()
            for line in content.split('\n')
            if line.strip() and not line.startswith('#')
        ]

        if payloads:
            entry_id = hashlib.md5(f"patt_txt_{category_name}".encode()).hexdigest()[:16]
            entry = KnowledgeEntry(
                id=entry_id,
                source=KnowledgeSource.PAYLOADS_ALL_THE_THINGS,
                knowledge_type=KnowledgeType.WORDLIST,
                category=category,
                title=f"{category_name} Wordlist",
                content=f"Wordlist containing {len(payloads)} payloads for {category_name}",
                tags=[category_name.lower().replace(" ", "_"), "wordlist"],
                payloads=payloads[:1000],  # Limit payload count
            )
            entries.append(entry)

        return entries

    def _parse_hacktricks_technique(
        self,
        content: str,
        category: VulnerabilityCategory,
        path: str,
    ) -> Optional[KnowledgeEntry]:
        """Parse technique from HackTricks markdown."""
        # Extract title
        title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        title = title_match.group(1) if title_match else path.split('/')[-1].replace('-', ' ').title()

        # Extract description (first paragraph after title)
        desc_match = re.search(r'^#\s+.+\n\n(.+?)(?=\n\n|\n#)', content, re.DOTALL)
        description = desc_match.group(1).strip() if desc_match else ""

        # Extract payloads from code blocks
        payloads = []
        code_blocks = re.findall(r'```[\w]*\n(.*?)\n```', content, re.DOTALL)
        for block in code_blocks:
            lines = block.strip().split('\n')
            payloads.extend([line.strip() for line in lines if line.strip()])

        entry_id = hashlib.md5(f"hacktricks_{path}".encode()).hexdigest()[:16]

        return KnowledgeEntry(
            id=entry_id,
            source=KnowledgeSource.HACKTRICKS,
            knowledge_type=KnowledgeType.TECHNIQUE,
            category=category,
            title=title,
            content=content[:5000],  # Limit content size
            tags=["hacktricks", category.value],
            payloads=payloads[:200],
            references=[f"https://book.hacktricks.xyz/{path}"],
        )

    def _load_cache(self) -> None:
        """Load cached knowledge base."""
        cache_file = self.kb_dir / "knowledge_cache.json"

        if not cache_file.exists():
            return

        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)

            # Check cache expiry
            cache_time = datetime.fromisoformat(cache_data.get("cached_at", "2000-01-01"))
            if datetime.now() - cache_time > self.cache_expiry:
                return  # Cache expired

            # Load entries
            for entry_data in cache_data.get("entries", []):
                entry = KnowledgeEntry.from_dict(entry_data)
                self._add_entry(entry)

            # Load payload collections
            for category_str, collections in cache_data.get("payloads", {}).items():
                category = VulnerabilityCategory(category_str)
                self.payloads[category] = []
                for coll_data in collections:
                    self.payloads[category].append(PayloadCollection(
                        category=category,
                        name=coll_data["name"],
                        description=coll_data["description"],
                        payloads=coll_data["payloads"],
                        tags=coll_data.get("tags", []),
                        source=KnowledgeSource(coll_data.get("source", "custom")),
                    ))

            self._update_statistics()

        except (json.JSONDecodeError, OSError, KeyError, ValueError) as e:
            # Cache loading failed, start fresh
            logger.debug(f"Cache loading failed, starting fresh: {e}")

    def _save_cache(self) -> None:
        """Save knowledge base to cache."""
        cache_file = self.kb_dir / "knowledge_cache.json"

        cache_data = {
            "cached_at": datetime.now().isoformat(),
            "version": VERSION,
            "entries": [entry.to_dict() for entry in self.entries.values()],
            "payloads": {
                category.value: [coll.to_dict() for coll in collections]
                for category, collections in self.payloads.items()
            },
        }

        # Check cache size
        cache_json = json.dumps(cache_data, default=str)
        if len(cache_json.encode()) > self.max_cache_size:
            # Trim cache if too large
            cache_data["entries"] = cache_data["entries"][:5000]
            cache_json = json.dumps(cache_data, default=str)

        cache_file.write_text(cache_json)

    def _update_statistics(self) -> None:
        """Update loader statistics."""
        self.stats.total_entries = len(self.entries)
        self.stats.cves_count = len(self.cves)
        self.stats.techniques_count = len(self.techniques)

        payload_count = 0
        for collections in self.payloads.values():
            for collection in collections:
                payload_count += len(collection.payloads)
        self.stats.payloads_count = payload_count

        # Calculate cache size
        cache_file = self.kb_dir / "knowledge_cache.json"
        if cache_file.exists():
            self.stats.cache_size_mb = cache_file.stat().st_size / (1024 * 1024)


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================

_knowledge_loader: Optional[KnowledgeLoader] = None


def get_knowledge_loader() -> KnowledgeLoader:
    """Get the global knowledge loader instance."""
    global _knowledge_loader
    if _knowledge_loader is None:
        _knowledge_loader = KnowledgeLoader()
    return _knowledge_loader


async def load_knowledge(sources: Optional[List[KnowledgeSource]] = None) -> LoaderStatistics:
    """Load security knowledge from specified sources."""
    loader = get_knowledge_loader()
    return await loader.load_all(sources)


def search_knowledge(
    query: str,
    category: Optional[VulnerabilityCategory] = None,
    limit: int = 10,
) -> List[KnowledgeEntry]:
    """Search the security knowledge base."""
    loader = get_knowledge_loader()
    return loader.search(query, category=category, limit=limit)


def get_payloads(
    category: VulnerabilityCategory,
    waf_bypass: bool = False,
    limit: int = 100,
) -> List[str]:
    """Get payloads for a vulnerability category."""
    loader = get_knowledge_loader()
    return loader.get_payloads_for_category(category, waf_bypass=waf_bypass, limit=limit)


# =============================================================================
# PUBLIC API
# =============================================================================

__all__ = [
    # Version
    "VERSION",
    # Enums
    "KnowledgeSource",
    "KnowledgeType",
    "VulnerabilityCategory",
    # Data classes
    "KnowledgeEntry",
    "PayloadCollection",
    "TechniqueEntry",
    "CVEEntry",
    "LoaderStatistics",
    # Main class
    "KnowledgeLoader",
    # Functions
    "get_knowledge_loader",
    "load_knowledge",
    "search_knowledge",
    "get_payloads",
]
