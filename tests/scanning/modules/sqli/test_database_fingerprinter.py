"""
Tests for DatabaseFingerprinter utility.

Tests cover:
- Database type detection from error messages
- Version extraction from error messages
- Generic SQL error detection
- Edge cases and false positives
"""

import pytest

from scanning.modules.sqli.utils.database_fingerprinter import DatabaseFingerprinter
from scanning.modules.sqli.sqli_base import DatabaseType


class TestDatabaseFingerprinterDetection:
    """Tests for database type detection."""

    def test_mysql_error_detection(self):
        """Test MySQL error message detection."""
        mysql_errors = [
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            "Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result",
            "MySqlException: Unknown column 'foo' in 'where clause'",
            "SQLSTATE[HY000]: MySQL server has gone away",
        ]

        for error in mysql_errors:
            db_type, confidence, pattern = DatabaseFingerprinter.detect(error)
            assert db_type == DatabaseType.MYSQL, f"Failed to detect MySQL in: {error[:50]}..."
            assert confidence >= 70

    def test_postgresql_error_detection(self):
        """Test PostgreSQL error message detection."""
        pg_errors = [
            "PostgreSQL ERROR: syntax error at or near 'SELECT'",
            "ERROR:  syntax error at or near \"'\"",
            "pg_query(): Query failed: ERROR: invalid input syntax",
            "Npgsql.PostgresException: 42601: syntax error",
            "PSQLException: ERROR: relation \"users\" does not exist",
        ]

        for error in pg_errors:
            db_type, confidence, pattern = DatabaseFingerprinter.detect(error)
            assert db_type == DatabaseType.POSTGRESQL, f"Failed to detect PostgreSQL in: {error[:50]}..."
            assert confidence >= 70

    def test_mssql_error_detection(self):
        """Test MSSQL error message detection."""
        mssql_errors = [
            "Microsoft SQL Server 2019 Driver: Unclosed quotation mark",
            "[SQL Server] Incorrect syntax near 'SELECT'",
            "ODBC SQL Server Driver: Conversion failed when converting",
            "System.Data.SqlClient.SqlException: Invalid column name",
            "SQLServer JDBC Driver Error: Unclosed quotation mark",
        ]

        for error in mssql_errors:
            db_type, confidence, pattern = DatabaseFingerprinter.detect(error)
            assert db_type == DatabaseType.MSSQL, f"Failed to detect MSSQL in: {error[:50]}..."
            assert confidence >= 70

    def test_oracle_error_detection(self):
        """Test Oracle error message detection."""
        oracle_errors = [
            "ORA-00942: table or view does not exist",
            "ORA-01756: quoted string not properly terminated",
            "oracle.jdbc.driver.OracleDriver: ORA-00904",
            "OracleException: SQL command not properly ended",
            "PLS-00103: Encountered the symbol 'SELECT'",
        ]

        for error in oracle_errors:
            db_type, confidence, pattern = DatabaseFingerprinter.detect(error)
            assert db_type == DatabaseType.ORACLE, f"Failed to detect Oracle in: {error[:50]}..."
            assert confidence >= 70

    def test_sqlite_error_detection(self):
        """Test SQLite error message detection."""
        sqlite_errors = [
            "sqlite3.OperationalError: near \"SELECT\": syntax error",
            "SQLITE_ERROR: unrecognized token",
            "SQLite error: near \"'\": syntax error",
            "System.Data.SQLite.SQLiteException: SQL logic error",
        ]

        for error in sqlite_errors:
            db_type, confidence, pattern = DatabaseFingerprinter.detect(error)
            assert db_type == DatabaseType.SQLITE, f"Failed to detect SQLite in: {error[:50]}..."
            assert confidence >= 70

    def test_mariadb_error_detection(self):
        """Test MariaDB error message detection."""
        mariadb_errors = [
            "MariaDB server version for the right syntax",
            "You have an error in your SQL syntax... MariaDB",
            "MariaDB Connection Error: Host is blocked",
            "ER_PARSE_ERROR in MariaDB 10.5",
        ]

        for error in mariadb_errors:
            db_type, confidence, pattern = DatabaseFingerprinter.detect(error)
            assert db_type == DatabaseType.MARIADB, f"Failed to detect MariaDB in: {error[:50]}..."
            assert confidence >= 70


class TestDatabaseFingerprinterGeneric:
    """Tests for generic SQL error detection."""

    def test_generic_sql_error_detection(self):
        """Test generic SQL error fallback detection."""
        generic_errors = [
            "SQL syntax error near line 1",
            "Warning: SQL Error",
            "Database Error: Query failed",
            "ODBC Error: Connection failed",
        ]

        for error in generic_errors:
            db_type, confidence, pattern = DatabaseFingerprinter.detect(error)
            # Generic errors default to MYSQL as most common
            assert db_type != DatabaseType.UNKNOWN or confidence == 0
            if db_type != DatabaseType.UNKNOWN:
                assert confidence >= 60

    def test_no_sql_error_returns_unknown(self):
        """Test non-SQL content returns UNKNOWN."""
        non_errors = [
            "Welcome to our website",
            "<html><body>Hello World</body></html>",
            '{"status": "ok", "data": []}',
            "Page not found",
            "Internal server error",
        ]

        for content in non_errors:
            db_type, confidence, pattern = DatabaseFingerprinter.detect(content)
            # Either UNKNOWN or very low confidence
            assert db_type == DatabaseType.UNKNOWN or confidence < 60


class TestDatabaseFingerprinterVersion:
    """Tests for version extraction."""

    def test_mysql_version_extraction(self):
        """Test MySQL version extraction."""
        content = "MySQL server version 8.0.33 for the right syntax"
        version = DatabaseFingerprinter.extract_version(content, DatabaseType.MYSQL)
        assert version == "8.0.33"

    def test_mysql_version_from_mariadb(self):
        """Test MySQL version extraction from MariaDB string."""
        content = "MariaDB 10.6.12 server version"
        version = DatabaseFingerprinter.extract_version(content, DatabaseType.MYSQL)
        assert version == "10.6.12"

    def test_postgresql_version_extraction(self):
        """Test PostgreSQL version extraction."""
        content = "PostgreSQL 15.2 on x86_64-pc-linux-gnu"
        version = DatabaseFingerprinter.extract_version(content, DatabaseType.POSTGRESQL)
        assert version == "15.2"

    def test_mssql_version_extraction(self):
        """Test MSSQL version extraction."""
        content = "Microsoft SQL Server 2019 (RTM)"
        version = DatabaseFingerprinter.extract_version(content, DatabaseType.MSSQL)
        assert version == "2019"

    def test_oracle_version_extraction(self):
        """Test Oracle version extraction."""
        content = "Oracle Database 19c Enterprise Edition"
        version = DatabaseFingerprinter.extract_version(content, DatabaseType.ORACLE)
        assert version == "19c"

    def test_sqlite_version_extraction(self):
        """Test SQLite version extraction."""
        content = "SQLite version 3.40.1"
        version = DatabaseFingerprinter.extract_version(content, DatabaseType.SQLITE)
        assert version == "3.40.1"

    def test_version_not_found(self):
        """Test version extraction when not present."""
        content = "SQL syntax error"
        version = DatabaseFingerprinter.extract_version(content, DatabaseType.MYSQL)
        assert version == ""

    def test_version_unsupported_db(self):
        """Test version extraction for unsupported database type."""
        content = "Some content"
        version = DatabaseFingerprinter.extract_version(content, DatabaseType.UNKNOWN)
        assert version == ""


class TestDatabaseFingerprinterConfidence:
    """Tests for confidence scoring."""

    def test_high_confidence_specific_errors(self):
        """Test that specific errors get high confidence."""
        high_confidence_errors = [
            ("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", 95),
            ("ORA-00942: table or view does not exist", 100),
            ("PostgreSQL ERROR: syntax error", 100),
            ("Unclosed quotation mark after the character string", 100),
        ]

        for error, min_confidence in high_confidence_errors:
            _, confidence, _ = DatabaseFingerprinter.detect(error)
            assert confidence >= min_confidence, f"Expected >= {min_confidence} for: {error[:50]}..."

    def test_medium_confidence_generic_errors(self):
        """Test that generic errors get medium confidence."""
        medium_confidence_errors = [
            "mysql_fetch_array",
            "pg_query()",
            "Warning: SQL",
        ]

        for error in medium_confidence_errors:
            _, confidence, _ = DatabaseFingerprinter.detect(error)
            assert 60 <= confidence <= 95


class TestDatabaseFingerprinterEdgeCases:
    """Tests for edge cases and potential false positives."""

    def test_case_insensitive_detection(self):
        """Test that detection is case-insensitive."""
        # These error messages should be detected regardless of case
        errors = [
            ("Warning: MYSQL_FETCH_ARRAY(): supplied argument", DatabaseType.MYSQL),
            ("You Have An Error In Your SQL Syntax", DatabaseType.MYSQL),
            ("POSTGRESQL ERROR: syntax error", DatabaseType.POSTGRESQL),
            ("ORA-00942: table or view does not exist", DatabaseType.ORACLE),
        ]

        for error, expected_db in errors:
            db_type, confidence, _ = DatabaseFingerprinter.detect(error)
            assert db_type == expected_db, f"Failed for: {error}"
            assert confidence >= 60

    def test_html_embedded_errors(self):
        """Test detection of errors embedded in HTML."""
        html_errors = [
            "<div class='error'>You have an error in your SQL syntax</div>",
            "<p>Error: mysql_fetch_array() expects parameter 1</p>",
            "<!DOCTYPE html><html><body><pre>ORA-00942: table or view does not exist</pre></body></html>",
        ]

        for html in html_errors:
            db_type, confidence, _ = DatabaseFingerprinter.detect(html)
            assert db_type != DatabaseType.UNKNOWN
            assert confidence >= 60

    def test_json_embedded_errors(self):
        """Test detection of errors in JSON responses."""
        json_errors = [
            '{"error": "You have an error in your SQL syntax"}',
            '{"message": "ORA-00942: table or view does not exist", "status": 500}',
        ]

        for json_str in json_errors:
            db_type, confidence, _ = DatabaseFingerprinter.detect(json_str)
            assert db_type != DatabaseType.UNKNOWN
            assert confidence >= 60

    def test_false_positive_sql_keywords(self):
        """Test that SQL keywords in normal content don't trigger detection."""
        normal_content = [
            "Learn SQL basics in this tutorial",
            "SELECT the best option for your needs",
            "Join our newsletter to get updates",
            "Error handling in JavaScript",
            "Warning: This page uses cookies",
        ]

        for content in normal_content:
            db_type, confidence, _ = DatabaseFingerprinter.detect(content)
            # Should either be UNKNOWN or have very low confidence
            if db_type != DatabaseType.UNKNOWN:
                assert confidence < 70

    def test_empty_content(self):
        """Test handling of empty content."""
        db_type, confidence, pattern = DatabaseFingerprinter.detect("")
        assert db_type == DatabaseType.UNKNOWN
        assert confidence == 0

    def test_long_content(self):
        """Test handling of very long content."""
        # Simulate a large page with an error somewhere
        long_content = "x" * 100000 + "You have an error in your SQL syntax" + "y" * 100000
        db_type, confidence, _ = DatabaseFingerprinter.detect(long_content)
        assert db_type == DatabaseType.MYSQL
        assert confidence >= 80


class TestDatabaseFingerprinterPHPLegacy:
    """Tests for PHP legacy function error detection."""

    def test_php_mysql_functions(self):
        """Test PHP mysql_* function errors are detected."""
        php_errors = [
            "Warning: mysql_query(): supplied argument is not a valid MySQL-Link resource",
            "Fatal error: Call to undefined function mysql_connect()",
            "Warning: mysql_fetch_array() expects parameter 1",
            "Warning: mysql_num_rows(): supplied argument is not",
            "Warning: mysql_real_escape_string(): A link to the server could not be established",
        ]

        for error in php_errors:
            db_type, confidence, _ = DatabaseFingerprinter.detect(error)
            assert db_type == DatabaseType.MYSQL, f"Failed for: {error[:50]}..."
            assert confidence >= 80

    def test_php_mysqli_functions(self):
        """Test PHP mysqli_* function errors are detected."""
        mysqli_errors = [
            "Warning: mysqli_query() expects parameter 1 to be mysqli",
            "Warning: mysqli_connect(): (HY000/1045)",
            "Warning: mysqli_error() expects parameter 1",
        ]

        for error in mysqli_errors:
            db_type, confidence, _ = DatabaseFingerprinter.detect(error)
            assert db_type == DatabaseType.MYSQL
            assert confidence >= 80

    def test_pdo_errors(self):
        """Test PDO error detection."""
        pdo_errors = [
            "PDOException: SQLSTATE[42000]: Syntax error or access violation",
            "PDOStatement::execute(): SQLSTATE[HY093]: Invalid parameter number",
            "PDO::query(): SQLSTATE[42S02]: Table not found",
        ]

        for error in pdo_errors:
            db_type, confidence, _ = DatabaseFingerprinter.detect(error)
            assert db_type == DatabaseType.MYSQL
            assert confidence >= 80


class TestDatabaseFingerprinterModernDB:
    """Tests for modern database variant detection."""

    def test_cockroachdb_detection(self):
        """Test CockroachDB error detection (PostgreSQL-compatible)."""
        cockroach_errors = [
            "CockroachDB error: syntax error at or near",
            "cockroachdb syntax error in statement",
        ]

        for error in cockroach_errors:
            db_type, confidence, _ = DatabaseFingerprinter.detect(error)
            assert db_type == DatabaseType.POSTGRESQL  # CockroachDB is PG-compatible
            assert confidence >= 80

    def test_supabase_detection(self):
        """Test Supabase/PostgREST error detection."""
        supabase_errors = [
            "PostgREST error: Could not find the function",
        ]

        for error in supabase_errors:
            db_type, confidence, _ = DatabaseFingerprinter.detect(error)
            assert db_type == DatabaseType.POSTGRESQL
            assert confidence >= 70

    def test_turso_libsql_detection(self):
        """Test Turso/libSQL error detection (SQLite-compatible)."""
        libsql_errors = [
            "@libsql error: near \"SELECT\": syntax error",
        ]

        for error in libsql_errors:
            db_type, confidence, _ = DatabaseFingerprinter.detect(error)
            assert db_type == DatabaseType.SQLITE
            assert confidence >= 70
