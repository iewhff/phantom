"""
PHANTOM AI - Configuration & Secrets Exposure Scanner

Comprehensive scanner for detecting exposed configuration files, secrets,
source code, and sensitive data that should never be publicly accessible.

Coverage:
- Version control exposure (.git, .svn, .hg, .bzr)
- Environment files (.env, .env.local, .env.production)
- Configuration files (config.yml, settings.json, database.yml)
- Backup files (.bak, .old, .orig, ~)
- Source maps and build artifacts
- IDE and editor files (.idea, .vscode, .DS_Store)
- Package manager files with dependencies
- Debug/development endpoints
- API documentation exposure
- Database dumps and exports

Works generically for ALL web applications regardless of tech stack.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from scanning.findings import Finding, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.scan_client import get_scan_client
from scanning.scan_context import ScanContext

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# SENSITIVE FILE PATTERNS - Organized by category and risk level
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SensitiveFile:
    """Definition of a sensitive file to check."""
    path: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    indicators: list[str] = field(default_factory=list)  # Content indicators to confirm
    anti_indicators: list[str] = field(default_factory=list)  # Content that disproves finding
    min_size: int = 0  # Minimum response size to be valid
    max_size: int = 10_000_000  # Maximum response size (10MB)


# Version Control Systems - CRITICAL (source code exposure)
VCS_FILES = [
    SensitiveFile("/.git/config", "Git repository configuration exposed", "CRITICAL",
                  indicators=["[core]", "[remote", "repositoryformatversion"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.git/HEAD", "Git HEAD reference exposed", "CRITICAL",
                  indicators=["ref: refs/", "refs/heads/"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.git/index", "Git index file exposed (binary)", "CRITICAL",
                  indicators=["DIRC"],  # Git index magic bytes
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.git/logs/HEAD", "Git commit history exposed", "HIGH",
                  indicators=["commit", "checkout:", "clone:"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.svn/entries", "SVN repository entries exposed", "CRITICAL",
                  indicators=["dir", "svn:"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.svn/wc.db", "SVN working copy database exposed", "CRITICAL",
                  indicators=["SQLite"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.hg/hgrc", "Mercurial repository config exposed", "CRITICAL",
                  indicators=["[paths]", "[ui]", "default ="],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.hg/store/fncache", "Mercurial file cache exposed", "CRITICAL",
                  indicators=["data/"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.bzr/branch/branch.conf", "Bazaar branch config exposed", "CRITICAL",
                  indicators=["parent_location", "push_location"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/CVS/Root", "CVS root file exposed", "HIGH",
                  indicators=[":pserver:", ":ext:", "/cvsroot"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/CVS/Entries", "CVS entries file exposed", "HIGH",
                  indicators=["/"],
                  anti_indicators=["<!DOCTYPE", "<html"], min_size=5),
]

# Environment Files - CRITICAL (credentials, API keys)
ENV_FILES = [
    SensitiveFile("/.env", "Environment file exposed", "CRITICAL",
                  indicators=["=", "DB_", "API_", "SECRET", "KEY", "PASSWORD", "TOKEN"],
                  anti_indicators=["<!DOCTYPE", "<html", "<?xml"]),
    SensitiveFile("/.env.local", "Local environment file exposed", "CRITICAL",
                  indicators=["=", "DB_", "API_", "SECRET"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.env.development", "Development environment file exposed", "HIGH",
                  indicators=["=", "DB_", "API_"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.env.production", "Production environment file exposed", "CRITICAL",
                  indicators=["=", "DB_", "API_", "SECRET"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.env.staging", "Staging environment file exposed", "HIGH",
                  indicators=["=", "DB_", "API_"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.env.backup", "Environment backup file exposed", "CRITICAL",
                  indicators=["=", "DB_", "API_"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.env.example", "Environment example file exposed", "LOW",
                  indicators=["="],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.env.sample", "Environment sample file exposed", "LOW",
                  indicators=["="],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/env.js", "Environment JS config exposed", "HIGH",
                  indicators=["process.env", "API_", "KEY"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
]

# Configuration Files - HIGH to CRITICAL
CONFIG_FILES = [
    # Generic configs
    SensitiveFile("/config.json", "JSON configuration exposed", "HIGH",
                  indicators=["{", "}", "database", "password", "secret", "key"],
                  anti_indicators=["<!DOCTYPE"], min_size=10),
    SensitiveFile("/config.yml", "YAML configuration exposed", "HIGH",
                  indicators=[":", "database", "password", "secret"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/config.yaml", "YAML configuration exposed", "HIGH",
                  indicators=[":", "database", "password", "secret"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/settings.json", "Settings file exposed", "HIGH",
                  indicators=["{", "}"],
                  anti_indicators=["<!DOCTYPE"], min_size=10),
    SensitiveFile("/settings.yml", "Settings file exposed", "HIGH",
                  indicators=[":"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/configuration.json", "Configuration file exposed", "HIGH",
                  indicators=["{", "}"],
                  anti_indicators=["<!DOCTYPE"], min_size=10),

    # Framework-specific configs
    SensitiveFile("/config/database.yml", "Rails database config exposed", "CRITICAL",
                  indicators=["adapter:", "database:", "username:", "password:"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/config/secrets.yml", "Rails secrets config exposed", "CRITICAL",
                  indicators=["secret_key_base:", "production:"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/config/credentials.yml.enc", "Rails encrypted credentials", "MEDIUM",
                  indicators=[],  # Encrypted, but still shouldn't be exposed
                  anti_indicators=["<!DOCTYPE", "<html"], min_size=50),
    SensitiveFile("/config/master.key", "Rails master key exposed", "CRITICAL",
                  indicators=[],
                  anti_indicators=["<!DOCTYPE", "<html"], min_size=32, max_size=64),
    SensitiveFile("/wp-config.php", "WordPress config exposed", "CRITICAL",
                  indicators=["DB_NAME", "DB_USER", "DB_PASSWORD", "<?php"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/wp-config.php.bak", "WordPress config backup exposed", "CRITICAL",
                  indicators=["DB_NAME", "DB_USER", "DB_PASSWORD"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/wp-config.php~", "WordPress config backup exposed", "CRITICAL",
                  indicators=["DB_NAME", "DB_USER", "DB_PASSWORD"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/configuration.php", "Joomla config exposed", "CRITICAL",
                  indicators=["$host", "$user", "$password", "$db"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/sites/default/settings.php", "Drupal settings exposed", "CRITICAL",
                  indicators=["$databases", "password"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/app/etc/local.xml", "Magento config exposed", "CRITICAL",
                  indicators=["<connection>", "<username>", "<password>"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/app/etc/env.php", "Magento 2 env config exposed", "CRITICAL",
                  indicators=["'db'", "'password'", "<?php"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/LocalSettings.php", "MediaWiki config exposed", "CRITICAL",
                  indicators=["$wgDBpassword", "$wgSecretKey"],
                  anti_indicators=["<!DOCTYPE", "<html"]),

    # Node.js / JavaScript
    SensitiveFile("/package.json", "Package.json exposed (dependency info)", "LOW",
                  indicators=["name", "version", "dependencies"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/package-lock.json", "Package lock exposed (exact versions)", "LOW",
                  indicators=["lockfileVersion", "dependencies"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/yarn.lock", "Yarn lock file exposed", "LOW",
                  indicators=["# yarn lockfile"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/npm-shrinkwrap.json", "NPM shrinkwrap exposed", "LOW",
                  indicators=["lockfileVersion"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.npmrc", "NPM config exposed (may contain tokens)", "HIGH",
                  indicators=["registry", "//"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/nodemon.json", "Nodemon config exposed", "LOW",
                  indicators=["watch", "ext"],
                  anti_indicators=["<!DOCTYPE", "<html"]),

    # Python
    SensitiveFile("/requirements.txt", "Python requirements exposed", "LOW",
                  indicators=["==", ">="],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/Pipfile", "Pipfile exposed", "LOW",
                  indicators=["[packages]", "[dev-packages]"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/Pipfile.lock", "Pipfile.lock exposed", "LOW",
                  indicators=["_meta", "default"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/pyproject.toml", "Python project config exposed", "LOW",
                  indicators=["[tool.", "[project]"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.python-version", "Python version file exposed", "LOW",
                  indicators=["3.", "2."],
                  anti_indicators=["<!DOCTYPE", "<html"]),

    # PHP
    SensitiveFile("/composer.json", "Composer config exposed", "LOW",
                  indicators=["require", "autoload"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/composer.lock", "Composer lock exposed", "LOW",
                  indicators=["packages", "content-hash"],
                  anti_indicators=["<!DOCTYPE", "<html"]),

    # Java/Kotlin
    SensitiveFile("/pom.xml", "Maven POM exposed", "LOW",
                  indicators=["<project", "<groupId>", "<artifactId>"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/build.gradle", "Gradle build file exposed", "LOW",
                  indicators=["dependencies", "plugins"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/application.properties", "Spring properties exposed", "HIGH",
                  indicators=["spring.", "server.", "database"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/application.yml", "Spring YAML config exposed", "HIGH",
                  indicators=["spring:", "server:", "datasource:"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/application-prod.properties", "Spring prod config exposed", "CRITICAL",
                  indicators=["spring.", "password"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/application-prod.yml", "Spring prod YAML exposed", "CRITICAL",
                  indicators=["spring:", "password:"],
                  anti_indicators=["<!DOCTYPE", "<html"]),

    # Ruby
    SensitiveFile("/Gemfile", "Gemfile exposed", "LOW",
                  indicators=["source", "gem "],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/Gemfile.lock", "Gemfile.lock exposed", "LOW",
                  indicators=["GEM", "BUNDLED"],
                  anti_indicators=["<!DOCTYPE", "<html"]),

    # Go
    SensitiveFile("/go.mod", "Go module file exposed", "LOW",
                  indicators=["module", "go "],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/go.sum", "Go checksum file exposed", "LOW",
                  indicators=["h1:"],
                  anti_indicators=["<!DOCTYPE", "<html"]),

    # .NET
    SensitiveFile("/web.config", "ASP.NET config exposed", "HIGH",
                  indicators=["<configuration>", "<connectionStrings>", "<appSettings>"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/appsettings.json", ".NET app settings exposed", "HIGH",
                  indicators=["ConnectionStrings", "Logging"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/appsettings.Development.json", ".NET dev settings exposed", "HIGH",
                  indicators=["ConnectionStrings"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/appsettings.Production.json", ".NET prod settings exposed", "CRITICAL",
                  indicators=["ConnectionStrings"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
]

# Backup and Temporary Files - HIGH to CRITICAL
BACKUP_FILES = [
    SensitiveFile("/backup.sql", "SQL backup exposed", "CRITICAL",
                  indicators=["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/backup.zip", "Backup archive exposed", "CRITICAL",
                  indicators=["PK"],  # ZIP magic bytes
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/backup.tar.gz", "Backup archive exposed", "CRITICAL",
                  indicators=[],
                  anti_indicators=["<!DOCTYPE", "<html"], min_size=100),
    SensitiveFile("/db.sql", "Database dump exposed", "CRITICAL",
                  indicators=["CREATE TABLE", "INSERT INTO"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/database.sql", "Database dump exposed", "CRITICAL",
                  indicators=["CREATE TABLE", "INSERT INTO"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/dump.sql", "Database dump exposed", "CRITICAL",
                  indicators=["CREATE TABLE", "INSERT INTO"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/data.sql", "Data SQL file exposed", "HIGH",
                  indicators=["INSERT INTO", "VALUES"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/mysql.sql", "MySQL dump exposed", "CRITICAL",
                  indicators=["CREATE TABLE", "ENGINE="],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/localhost.sql", "Local database dump exposed", "CRITICAL",
                  indicators=["CREATE TABLE", "INSERT INTO"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
]

# Source Maps and Build Artifacts - MEDIUM to HIGH
BUILD_FILES = [
    SensitiveFile("/main.js.map", "JavaScript source map exposed", "MEDIUM",
                  indicators=["mappings", "sources", "sourcesContent"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/app.js.map", "JavaScript source map exposed", "MEDIUM",
                  indicators=["mappings", "sources"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/bundle.js.map", "Webpack source map exposed", "MEDIUM",
                  indicators=["mappings", "sources", "webpack"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/vendor.js.map", "Vendor source map exposed", "MEDIUM",
                  indicators=["mappings", "sources"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/main.css.map", "CSS source map exposed", "LOW",
                  indicators=["mappings", "sources"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/webpack.config.js", "Webpack config exposed", "MEDIUM",
                  indicators=["module.exports", "entry", "output"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/vite.config.js", "Vite config exposed", "MEDIUM",
                  indicators=["defineConfig", "plugins"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/tsconfig.json", "TypeScript config exposed", "LOW",
                  indicators=["compilerOptions", "include"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.babelrc", "Babel config exposed", "LOW",
                  indicators=["presets", "plugins"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/Dockerfile", "Dockerfile exposed", "MEDIUM",
                  indicators=["FROM", "RUN", "COPY", "CMD"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/docker-compose.yml", "Docker Compose exposed", "HIGH",
                  indicators=["services:", "volumes:", "environment:"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/docker-compose.yaml", "Docker Compose exposed", "HIGH",
                  indicators=["services:", "volumes:", "environment:"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.dockerignore", "Docker ignore file exposed", "LOW",
                  indicators=[],
                  anti_indicators=["<!DOCTYPE", "<html"], min_size=5),
    SensitiveFile("/Makefile", "Makefile exposed", "LOW",
                  indicators=[":", "\t"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
]

# IDE and Editor Files - LOW to MEDIUM
IDE_FILES = [
    SensitiveFile("/.idea/workspace.xml", "IntelliJ workspace exposed", "MEDIUM",
                  indicators=["<?xml", "<project"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/.idea/modules.xml", "IntelliJ modules exposed", "LOW",
                  indicators=["<?xml", "<module"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/.vscode/settings.json", "VS Code settings exposed", "LOW",
                  indicators=["{", "}"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.vscode/launch.json", "VS Code launch config exposed", "MEDIUM",
                  indicators=["configurations", "program"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.sublime-project", "Sublime project exposed", "LOW",
                  indicators=["folders"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.editorconfig", "Editor config exposed", "LOW",
                  indicators=["root", "indent_style"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.DS_Store", "macOS DS_Store exposed", "LOW",
                  indicators=["Bud1"],  # DS_Store magic bytes
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/Thumbs.db", "Windows Thumbs.db exposed", "LOW",
                  indicators=[],
                  anti_indicators=["<!DOCTYPE", "<html"], min_size=100),
]

# Debug and Development Endpoints - HIGH to CRITICAL
DEBUG_ENDPOINTS = [
    SensitiveFile("/debug", "Debug endpoint exposed", "HIGH",
                  indicators=["debug", "stack", "trace", "error"],
                  anti_indicators=[]),
    SensitiveFile("/debug/", "Debug endpoint exposed", "HIGH",
                  indicators=["debug", "stack", "trace"],
                  anti_indicators=[]),
    SensitiveFile("/_debug", "Debug endpoint exposed", "HIGH",
                  indicators=["debug", "stack", "trace"],
                  anti_indicators=[]),
    SensitiveFile("/phpinfo.php", "PHP info exposed", "HIGH",
                  indicators=["PHP Version", "phpinfo()", "Configuration"],
                  anti_indicators=[]),
    SensitiveFile("/info.php", "PHP info exposed", "HIGH",
                  indicators=["PHP Version", "phpinfo()"],
                  anti_indicators=[]),
    SensitiveFile("/test.php", "PHP test file exposed", "MEDIUM",
                  indicators=["<?php"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/elmah.axd", "ELMAH error log exposed", "HIGH",
                  indicators=["Error Log", "ELMAH"],
                  anti_indicators=[]),
    SensitiveFile("/trace.axd", "ASP.NET trace exposed", "HIGH",
                  indicators=["Trace Information", "Request Details"],
                  anti_indicators=[]),
    SensitiveFile("/__debug__/", "Debug toolbar exposed", "HIGH",
                  indicators=["debug", "toolbar"],
                  anti_indicators=[]),
    SensitiveFile("/rails/info", "Rails info exposed", "MEDIUM",
                  indicators=["Rails", "Ruby"],
                  anti_indicators=[]),
    SensitiveFile("/rails/info/routes", "Rails routes exposed", "MEDIUM",
                  indicators=["GET", "POST", "Prefix"],
                  anti_indicators=[]),
    SensitiveFile("/_profiler", "Symfony profiler exposed", "HIGH",
                  indicators=["profiler", "symfony"],
                  anti_indicators=[]),
    SensitiveFile("/actuator", "Spring Actuator exposed", "HIGH",
                  indicators=["_links", "self", "href"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/actuator/health", "Spring health endpoint", "MEDIUM",
                  indicators=["status", "UP", "DOWN"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/actuator/env", "Spring environment exposed", "CRITICAL",
                  indicators=["propertySources", "activeProfiles"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/actuator/configprops", "Spring config props exposed", "CRITICAL",
                  indicators=["beans", "properties"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/actuator/mappings", "Spring mappings exposed", "MEDIUM",
                  indicators=["dispatcherServlets", "contexts"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/actuator/beans", "Spring beans exposed", "MEDIUM",
                  indicators=["contexts", "beans"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/actuator/heapdump", "Spring heap dump exposed", "CRITICAL",
                  indicators=[],  # Binary file
                  anti_indicators=["<!DOCTYPE html"], min_size=1000),
    SensitiveFile("/metrics", "Metrics endpoint exposed", "MEDIUM",
                  indicators=["counter", "gauge", "histogram"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/health", "Health endpoint exposed", "LOW",
                  indicators=["status", "healthy", "ok"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/status", "Status endpoint exposed", "LOW",
                  indicators=["status", "version"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/server-status", "Apache server status exposed", "HIGH",
                  indicators=["Apache Server Status", "Server Version"],
                  anti_indicators=[]),
    SensitiveFile("/server-info", "Apache server info exposed", "HIGH",
                  indicators=["Apache Server Information", "Server Settings"],
                  anti_indicators=[]),
    SensitiveFile("/nginx_status", "Nginx status exposed", "MEDIUM",
                  indicators=["Active connections", "server accepts"],
                  anti_indicators=["<!DOCTYPE html"]),
]

# API Documentation - LOW to MEDIUM (information disclosure)
API_DOCS = [
    SensitiveFile("/swagger.json", "Swagger API spec exposed", "MEDIUM",
                  indicators=["swagger", "paths", "definitions"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/swagger.yaml", "Swagger API spec exposed", "MEDIUM",
                  indicators=["swagger:", "paths:", "definitions:"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/openapi.json", "OpenAPI spec exposed", "MEDIUM",
                  indicators=["openapi", "paths", "components"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/openapi.yaml", "OpenAPI spec exposed", "MEDIUM",
                  indicators=["openapi:", "paths:", "components:"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/api-docs", "API documentation exposed", "MEDIUM",
                  indicators=["swagger", "openapi", "paths"],
                  anti_indicators=[]),
    SensitiveFile("/api/docs", "API documentation exposed", "MEDIUM",
                  indicators=["swagger", "openapi", "paths"],
                  anti_indicators=[]),
    SensitiveFile("/v1/api-docs", "API v1 documentation exposed", "MEDIUM",
                  indicators=["swagger", "paths"],
                  anti_indicators=[]),
    SensitiveFile("/v2/api-docs", "API v2 documentation exposed", "MEDIUM",
                  indicators=["swagger", "paths"],
                  anti_indicators=[]),
    SensitiveFile("/graphql/schema", "GraphQL schema exposed", "MEDIUM",
                  indicators=["type", "Query", "Mutation"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/graphiql", "GraphiQL interface exposed", "MEDIUM",
                  indicators=["GraphiQL", "graphql"],
                  anti_indicators=[]),
    SensitiveFile("/.well-known/openapi.json", "Well-known OpenAPI exposed", "MEDIUM",
                  indicators=["openapi", "paths"],
                  anti_indicators=["<!DOCTYPE html"]),
]

# Security-related files - HIGH to CRITICAL
SECURITY_FILES = [
    SensitiveFile("/.htpasswd", "Apache password file exposed", "CRITICAL",
                  indicators=[":$", ":{SHA}"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.htaccess", "Apache htaccess exposed", "MEDIUM",
                  indicators=["RewriteRule", "Deny", "Allow", "Redirect"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/id_rsa", "SSH private key exposed", "CRITICAL",
                  indicators=["-----BEGIN", "PRIVATE KEY"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/id_rsa.pub", "SSH public key exposed", "LOW",
                  indicators=["ssh-rsa", "ssh-ed25519"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.ssh/id_rsa", "SSH private key exposed", "CRITICAL",
                  indicators=["-----BEGIN", "PRIVATE KEY"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/private.key", "Private key exposed", "CRITICAL",
                  indicators=["-----BEGIN", "PRIVATE KEY"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/server.key", "Server private key exposed", "CRITICAL",
                  indicators=["-----BEGIN", "PRIVATE KEY"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/ssl.key", "SSL private key exposed", "CRITICAL",
                  indicators=["-----BEGIN", "PRIVATE KEY"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.pgpass", "PostgreSQL password file exposed", "CRITICAL",
                  indicators=[":"],
                  anti_indicators=["<!DOCTYPE", "<html"], min_size=10),
    SensitiveFile("/.my.cnf", "MySQL config file exposed", "CRITICAL",
                  indicators=["[client]", "password"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/.netrc", "FTP credentials file exposed", "CRITICAL",
                  indicators=["machine", "login", "password"],
                  anti_indicators=["<!DOCTYPE", "<html"]),
    SensitiveFile("/crossdomain.xml", "Flash crossdomain policy exposed", "MEDIUM",
                  indicators=["cross-domain-policy", "allow-access-from"],
                  anti_indicators=["<!DOCTYPE html"]),
    SensitiveFile("/clientaccesspolicy.xml", "Silverlight access policy exposed", "MEDIUM",
                  indicators=["access-policy", "cross-domain-access"],
                  anti_indicators=["<!DOCTYPE html"]),
]

# Combine all categories
ALL_SENSITIVE_FILES = (
    VCS_FILES +
    ENV_FILES +
    CONFIG_FILES +
    BACKUP_FILES +
    BUILD_FILES +
    IDE_FILES +
    DEBUG_ENDPOINTS +
    API_DOCS +
    SECURITY_FILES
)


class ConfigExposureScanner(ScanModule):
    """
    Comprehensive scanner for exposed configuration files, secrets, and sensitive data.

    Works generically for ALL web applications by checking hundreds of common
    sensitive file paths across all major frameworks and languages.
    """

    name = "config_exposure"
    description = "Detects exposed configuration files, .env, .git, backups"
    version = "1.0.0"
    author = "PHANTOM AI"
    tags = ["config", "exposure", "secrets", "discovery"]

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = 10.0
        self.max_concurrent = 20  # Parallel requests
        self._homepage_hash: str = ""
        self._homepage_size: int = 0

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any] | None = None,
        rate_limiter: Any | None = None,
    ) -> dict[str, Any]:
        """Scan for exposed configuration files and secrets."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[Finding] = []
        asset_data = asset_data or {}

        # Normalize host to base URL
        if not host.startswith(("http://", "https://")):
            # Use http:// for localhost/local IPs, https:// for external
            is_local = any(host.startswith(p) for p in ("localhost", "127.", "192.168.", "10.", "172."))
            host = f"http://{host}" if is_local else f"https://{host}"
        base_url = host.rstrip("/")

        logger.info(f"[CONFIG] Starting configuration exposure scan on {base_url}")

        try:
            async with get_scan_client(
                timeout=self.timeout,
                verify_ssl=False,
                follow_redirects=True,
                limits=httpx.Limits(max_connections=self.max_concurrent),
            ) as client:
                # First, get homepage hash for comparison (to avoid SPA false positives)
                await self._capture_homepage_baseline(client, base_url)

                # Check all sensitive files in parallel batches
                semaphore = asyncio.Semaphore(self.max_concurrent)

                async def check_with_semaphore(sf: SensitiveFile) -> Finding | None:
                    async with semaphore:
                        if rate_limiter:
                            await rate_limiter.acquire()
                        return await self._check_sensitive_file(client, base_url, sf)

                tasks = [check_with_semaphore(sf) for sf in ALL_SENSITIVE_FILES]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, Finding):
                        findings.append(result)
                    elif isinstance(result, Exception):
                        logger.debug(f"[CONFIG] Check failed: {result}")

        except Exception as e:
            logger.error(f"[CONFIG] Scan error: {e}")

        logger.info(f"[CONFIG] Found {len(findings)} exposed files/endpoints")

        return {
            "findings": findings,
            "files_checked": len(ALL_SENSITIVE_FILES),
            "exposed_count": len(findings),
        }

    async def _capture_homepage_baseline(
        self,
        client: httpx.AsyncClient,
        base_url: str,
    ) -> None:
        """Capture homepage hash for SPA false positive detection."""
        try:
            resp = await client.get(base_url, timeout=self.timeout)
            if resp.status_code == 200:
                content = resp.text[:5000]  # First 5KB
                self._homepage_hash = hashlib.md5(content.encode()).hexdigest()
                self._homepage_size = len(resp.text)
        except Exception:
            pass

    async def _check_sensitive_file(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        sf: SensitiveFile,
    ) -> Finding | None:
        """Check if a sensitive file is exposed."""
        url = urljoin(base_url, sf.path)

        try:
            resp = await client.get(url, timeout=self.timeout)

            # Must be 200 OK
            if resp.status_code != 200:
                return None

            content = resp.text
            content_lower = content.lower()
            content_len = len(content)

            # Size checks
            if content_len < sf.min_size:
                return None
            if content_len > sf.max_size:
                return None

            # SPA false positive check: same as homepage
            if self._homepage_hash:
                content_hash = hashlib.md5(content[:5000].encode()).hexdigest()
                if content_hash == self._homepage_hash:
                    return None
                # Also check if response is within 5% of homepage size and looks like HTML
                if abs(content_len - self._homepage_size) / max(self._homepage_size, 1) < 0.05:
                    if "<!doctype" in content_lower[:500] or "<html" in content_lower[:500]:
                        return None

            # Anti-indicators check (content that disproves the finding)
            for anti in sf.anti_indicators:
                if anti.lower() in content_lower:
                    return None

            # Indicators check (content that confirms the finding)
            if sf.indicators:
                matched_indicators = sum(1 for ind in sf.indicators if ind.lower() in content_lower)
                if matched_indicators == 0:
                    return None
                # Require at least 1 indicator match, or 50% for files with many indicators
                min_matches = max(1, len(sf.indicators) // 2)
                if matched_indicators < min_matches and len(sf.indicators) > 2:
                    return None

            # Extract a preview of the content (redact sensitive values)
            preview = self._extract_preview(content, sf)

            return Finding(
                vuln_type=VulnType.INFO_DISCLOSURE,
                severity=sf.severity,
                host=urlparse(base_url).netloc,
                endpoint=url,
                name=f"Sensitive File Exposed: {sf.path}",
                description=(
                    f"{sf.description}\n\n"
                    f"The file at `{sf.path}` is publicly accessible and may contain "
                    f"sensitive configuration data, credentials, or internal information.\n\n"
                    f"**Response size:** {content_len:,} bytes\n"
                    f"**Content preview:** {preview}"
                ),
                evidence=[
                    f"URL: {url}",
                    f"Status: 200 OK",
                    f"Size: {content_len:,} bytes",
                    f"Content-Type: {resp.headers.get('content-type', 'unknown')}",
                ],
                confidence_score=95.0 if sf.indicators else 85.0,
                metadata={
                    "url": url,
                    "path": sf.path,
                    "category": self._categorize_file(sf),
                    "response_size": content_len,
                    "content_type": resp.headers.get("content-type", ""),
                    "preview": preview,
                    "module_name": "config_exposure",
                },
            )

        except httpx.TimeoutException:
            return None
        except Exception as e:
            logger.debug(f"[CONFIG] Error checking {sf.path}: {e}")
            return None

    def _extract_preview(self, content: str, sf: SensitiveFile) -> str:
        """Extract a safe preview of the content, redacting sensitive values."""
        # Take first 500 chars
        preview = content[:500].strip()

        # Redact common sensitive patterns
        patterns = [
            (r'(password\s*[=:]\s*)[^\s\n"\']+', r'\1[REDACTED]'),
            (r'(secret\s*[=:]\s*)[^\s\n"\']+', r'\1[REDACTED]'),
            (r'(api_key\s*[=:]\s*)[^\s\n"\']+', r'\1[REDACTED]'),
            (r'(token\s*[=:]\s*)[^\s\n"\']+', r'\1[REDACTED]'),
            (r'(DB_PASSWORD\s*=\s*)[^\s\n]+', r'\1[REDACTED]'),
            (r'(AWS_SECRET[^\s]*\s*=\s*)[^\s\n]+', r'\1[REDACTED]'),
            (r'-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----', '[PRIVATE KEY REDACTED]'),
        ]

        for pattern, replacement in patterns:
            preview = re.sub(pattern, replacement, preview, flags=re.IGNORECASE)

        if len(content) > 500:
            preview += "\n... [truncated]"

        return preview

    def _categorize_file(self, sf: SensitiveFile) -> str:
        """Categorize the sensitive file for reporting."""
        if sf in VCS_FILES:
            return "Version Control"
        elif sf in ENV_FILES:
            return "Environment Configuration"
        elif sf in CONFIG_FILES:
            return "Application Configuration"
        elif sf in BACKUP_FILES:
            return "Backup / Database Dump"
        elif sf in BUILD_FILES:
            return "Build Artifacts"
        elif sf in IDE_FILES:
            return "IDE / Editor Files"
        elif sf in DEBUG_ENDPOINTS:
            return "Debug / Development Endpoint"
        elif sf in API_DOCS:
            return "API Documentation"
        elif sf in SECURITY_FILES:
            return "Security / Credentials"
        return "Other"
