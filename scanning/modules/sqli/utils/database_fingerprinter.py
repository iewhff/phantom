"""
SQL Injection Scanner - Database Fingerprinter.

Provides precise database type and version detection from error messages
and response content.

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanning.modules.sqli.sqli_base import DatabaseType


class DatabaseFingerprinter:
    """Precise database type and version detection."""

    # Import DatabaseType locally to avoid circular import at module level
    @staticmethod
    def _get_database_type():
        from scanning.modules.sqli.sqli_base import DatabaseType
        return DatabaseType

    ERROR_SIGNATURES: dict = {}  # Populated in _init_signatures

    @classmethod
    def _init_signatures(cls) -> None:
        """Initialize error signatures lazily to avoid circular imports."""
        if cls.ERROR_SIGNATURES:
            return

        DatabaseType = cls._get_database_type()

        cls.ERROR_SIGNATURES = {
            DatabaseType.MYSQL: [
                (r"You have an error in your SQL syntax.*MySQL", 100),
                (r"MySQL.*server version.*for the right syntax", 100),
                (r"Warning.*mysql[i]?_", 95),
                (r"MySqlException", 95),
                (r"com\.mysql\.jdbc", 95),
                (r"Column count doesn't match", 90),
                (r"Unknown column.*in.*clause", 85),
                (r"mysql_fetch", 80),
                (r"SQLSTATE\[HY000\].*MySQL", 90),
                # Additional MySQL patterns
                (r"You have an error in your SQL syntax", 95),
                (r"supplied argument is not a valid MySQL", 90),
                (r"mysql_num_rows\(\)", 85),
                (r"mysql_result\(\)", 85),
                (r"Warning:.*mysql_", 85),
                (r"Error:.*mysql_", 85),
                (r"SQL syntax.*error", 80),
                (r"check the manual that corresponds to your MySQL server version", 95),
                # FIX 2026-02-16: Classic PHP mysql_* function errors (legacy apps)
                (r"mysql_query\(\)", 90),
                (r"mysql_connect\(\)", 90),
                (r"mysql_select_db\(\)", 85),
                (r"mysql_db_query\(\)", 85),
                (r"mysql_real_escape_string\(\)", 80),
                (r"mysqli_query\(\)", 90),
                (r"mysqli_connect\(\)", 90),
                (r"mysqli_error\(\)", 85),
                (r"mysqli_real_escape_string\(\)", 80),
                (r"mysql_error\(\)", 90),
                (r"Call to undefined function mysql_", 85),
                (r"Access denied for user.*@", 80),  # MySQL auth error reveals DB
                (r"Can't connect to MySQL server", 80),
                (r"Too many connections", 70),
                (r"Lost connection to MySQL server", 75),
                (r"Table '.*' doesn't exist", 85),
                (r"Duplicate entry.*for key", 80),
                (r"Data truncated for column", 75),
                (r"Incorrect.*value.*for column", 80),
                (r"Field.*doesn't have a default value", 75),
                # PHP PDO MySQL errors
                (r"PDOStatement::execute\(\)", 85),
                (r"PDO::query\(\)", 85),
                (r"PDOException", 90),
                (r"SQLSTATE\[42000\]", 85),  # Syntax error
                (r"SQLSTATE\[42S02\]", 85),  # Table not found
                (r"SQLSTATE\[42S22\]", 85),  # Column not found
                (r"SQLSTATE\[23000\]", 80),  # Integrity constraint
                # WordPress/Drupal/Joomla specific MySQL errors
                (r"WordPress database error", 90),
                (r"wpdb->query", 85),
                (r"Drupal.*Database.*error", 90),
                (r"Joomla.*Database.*error", 90),
            ],
            DatabaseType.MARIADB: [
                # Theme 11: Extended MariaDB 10.5+ patterns
                (r"MariaDB.*server version", 100),
                (r"You have an error.*MariaDB", 100),
                (r"MariaDB Connection Error", 95),
                (r"MariaDB.*Error \d+", 90),
                (r"ER_PARSE_ERROR.*MariaDB", 90),
                (r"mariadb-connector", 85),
                (r"libmysqlclient.*MariaDB", 85),
                (r"HY000.*MariaDB", 80),
                (r"COLLATION.*utf8mb4_uca1400", 75),  # MariaDB 10.10+ specific collation
                (r"Aria storage engine", 70),  # MariaDB-specific storage engine
            ],
            DatabaseType.POSTGRESQL: [
                # Theme 11: Extended PostgreSQL 15+ patterns
                (r"PostgreSQL.*ERROR", 100),
                (r"ERROR:\s+syntax error at or near", 100),
                (r"pg_query\(\)", 95),
                (r"Npgsql\.PostgresException", 95),
                (r"org\.postgresql", 95),
                (r"PSQLException", 90),
                (r"unterminated quoted string", 85),
                (r"invalid input syntax for type", 80),
                (r"pg_exec\(\)", 85),
                (r"Warning:.*pg_", 85),
                # PostgreSQL 14+ / 15+
                (r"SQLSTATE\s+\d{5}", 85),  # PostgreSQL error codes
                (r"DETAIL:\s+", 80),  # Error detail prefix
                (r"HINT:\s+", 75),  # Error hint prefix
                (r"permission denied for relation", 80),
                (r"violates.*constraint", 75),
                # CockroachDB (PostgreSQL-compatible)
                (r"CockroachDB.*error", 95),
                (r"cockroachdb.*syntax", 90),
                (r"crdb_internal", 85),  # CockroachDB internal schema
                # Neon (serverless Postgres)
                (r"neon\.tech.*error", 85),
                # Supabase PostgreSQL
                (r"supabase.*pg_error", 85),
                (r"PostgREST.*error", 80),
            ],
            DatabaseType.MSSQL: [
                (r"Microsoft SQL Server.*Driver", 100),
                (r"Unclosed quotation mark", 100),
                (r"SQLServer JDBC Driver", 95),
                (r"com\.microsoft\.sqlserver", 95),
                (r"System\.Data\.SqlClient", 95),
                (r"\[SQL Server\]", 90),
                (r"ODBC SQL Server", 90),
                (r"Incorrect syntax near", 85),
                (r"Conversion failed when converting", 80),
            ],
            DatabaseType.ORACLE: [
                (r"ORA-[0-9]{5}:", 100),
                (r"Oracle.*error", 95),
                (r"oracle\.jdbc", 95),
                (r"OracleException", 95),
                (r"quoted string not properly terminated", 90),
                (r"SQL command not properly ended", 85),
                (r"PLS-[0-9]{5}:", 90),
            ],
            DatabaseType.SQLITE: [
                # Theme 11: Extended SQLite 3.37+ patterns
                (r"sqlite3\.OperationalError", 100),
                (r"SQLITE_ERROR", 95),
                (r"SQLite error", 95),
                (r"System\.Data\.SQLite", 95),
                (r'near ".*": syntax error', 90),
                (r"unrecognized token", 85),
                # SQLite 3.37+ (strict tables, RETURNING clause errors)
                (r"SQLITE_CONSTRAINT", 90),
                (r"SQLITE_MISMATCH", 85),
                (r"SQLITE_RANGE", 80),
                (r"cannot store .* in .* column", 85),  # Strict tables (3.37+)
                (r"RETURNING.*not supported", 80),  # Old SQLite with RETURNING
                (r"JSON1 extension", 75),  # SQLite JSON extension
                (r"FTS\d+ syntax error", 80),  # Full-text search errors
                # SQLite WASM / browser-based
                (r"sql\.js.*error", 85),  # sql.js (WASM SQLite)
                (r"better-sqlite3", 80),  # Node.js better-sqlite3
                (r"sqlite-wasm", 80),  # SQLite WASM builds
                (r"@libsql", 80),  # Turso/libSQL (SQLite fork)
            ],
        }

    # Generic SQL error patterns (used when no specific DB detected)
    GENERIC_SQL_ERRORS = [
        (r"SQL syntax.*?error", 75),
        (r"Warning:.*SQL", 70),
        (r"Error.*SQL", 70),
        (r"syntax error", 65),
        (r"unclosed.*quote", 70),
        (r"quoted string", 65),
        (r"unexpected.*token", 60),
        (r"Query failed", 70),
        (r"DB Error", 70),
        (r"Database Error", 75),
        (r"ODBC.*Error", 75),
    ]

    VERSION_PATTERNS: dict = {}  # Populated in _init_version_patterns

    @classmethod
    def _init_version_patterns(cls) -> None:
        """Initialize version patterns lazily to avoid circular imports."""
        if cls.VERSION_PATTERNS:
            return

        DatabaseType = cls._get_database_type()

        cls.VERSION_PATTERNS = {
            DatabaseType.MYSQL: [
                (r"MySQL.*?([0-9]+\.[0-9]+\.[0-9]+)", "version"),
                (r"MariaDB.*?([0-9]+\.[0-9]+\.[0-9]+)", "version"),
            ],
            DatabaseType.POSTGRESQL: [
                (r"PostgreSQL.*?([0-9]+\.[0-9]+)", "version"),
            ],
            DatabaseType.MSSQL: [
                (r"Microsoft SQL Server.*?([0-9]{4})", "year"),
                (r"SQL Server.*?([0-9]+\.[0-9]+)", "version"),
            ],
            DatabaseType.ORACLE: [
                (r"Oracle.*?([0-9]+[cgi]?)", "version"),
                (r"ORA-.*?([0-9]+\.[0-9]+)", "version"),
            ],
            DatabaseType.SQLITE: [
                (r"sqlite.*?([0-9]+\.[0-9]+\.[0-9]+)", "version"),
            ],
        }

    @classmethod
    def detect(cls, content: str) -> tuple["DatabaseType", int, str]:
        """
        Detect database type from error message.
        Returns (db_type, confidence, matched_pattern)
        """
        cls._init_signatures()
        DatabaseType = cls._get_database_type()

        best = (DatabaseType.UNKNOWN, 0, "")

        # First try specific database patterns
        for db_type, patterns in cls.ERROR_SIGNATURES.items():
            for pattern, confidence in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    if confidence > best[1]:
                        best = (db_type, confidence, pattern)

        # If no specific DB detected, try generic patterns
        if best[0] == DatabaseType.UNKNOWN:
            for pattern, confidence in cls.GENERIC_SQL_ERRORS:
                if re.search(pattern, content, re.IGNORECASE):
                    if confidence > best[1]:
                        # Report as MYSQL (most common) but with confidence
                        best = (DatabaseType.MYSQL, confidence, pattern)
                        break

        return best

    @classmethod
    def extract_version(cls, content: str, db_type: "DatabaseType") -> str:
        """Extract exact database version from content."""
        cls._init_version_patterns()

        if db_type not in cls.VERSION_PATTERNS:
            return ""

        for pattern, _ in cls.VERSION_PATTERNS[db_type]:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)

        return ""


__all__ = ["DatabaseFingerprinter"]
