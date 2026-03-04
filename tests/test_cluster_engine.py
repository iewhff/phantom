"""Tests for scanning/result_processor/cluster.py — Root-Cause Clustering."""

import pytest

from scanning.result_processor.cluster import (
    cluster_findings,
    generate_cluster_key,
    get_cluster_summary,
    get_clustered_findings,
)


# ═════════════════════════════════════════════════════════════════════════════
# Cluster Key Generation
# ═════════════════════════════════════════════════════════════════════════════


class TestClusterKey:
    """Test cluster key generation."""

    def test_same_param_different_detection_same_key(self):
        """Union and boolean SQLi on same param → same cluster key."""
        f1 = {
            "vuln_type": "sqli",
            "host": "example.com",
            "endpoint": "/api/users",
            "parameter": "id",
            "metadata": {"detection_method": "union_based"},
        }
        f2 = {
            "vuln_type": "sqli",
            "host": "example.com",
            "endpoint": "/api/users",
            "parameter": "id",
            "metadata": {"detection_method": "boolean_blind"},
        }
        assert generate_cluster_key(f1) == generate_cluster_key(f2)

    def test_different_param_different_key(self):
        f1 = {
            "vuln_type": "sqli",
            "host": "example.com",
            "endpoint": "/api/users",
            "parameter": "id",
        }
        f2 = {
            "vuln_type": "sqli",
            "host": "example.com",
            "endpoint": "/api/users",
            "parameter": "name",
        }
        assert generate_cluster_key(f1) != generate_cluster_key(f2)

    def test_host_wide_type_collapses_endpoints(self):
        """Missing headers at different endpoints → same cluster key."""
        f1 = {
            "vuln_type": "missing_headers",
            "host": "example.com",
            "endpoint": "/api/users",
        }
        f2 = {
            "vuln_type": "missing_headers",
            "host": "example.com",
            "endpoint": "/api/admin",
        }
        assert generate_cluster_key(f1) == generate_cluster_key(f2)

    def test_cors_variants_same_key(self):
        """CORS wildcard and CORS null at same host → same cluster."""
        f1 = {"vuln_type": "cors_wildcard", "host": "example.com", "endpoint": "/a"}
        f2 = {"vuln_type": "cors_null", "host": "example.com", "endpoint": "/b"}
        assert generate_cluster_key(f1) == generate_cluster_key(f2)

    def test_canonical_endpoint_strips_query(self):
        f1 = {
            "vuln_type": "xss",
            "host": "example.com",
            "endpoint": "/search?q=test",
            "parameter": "q",
        }
        f2 = {
            "vuln_type": "xss",
            "host": "example.com",
            "endpoint": "/search?q=other",
            "parameter": "q",
        }
        assert generate_cluster_key(f1) == generate_cluster_key(f2)

    def test_different_hosts_different_key(self):
        f1 = {"vuln_type": "xss", "host": "a.com", "endpoint": "/", "parameter": "q"}
        f2 = {"vuln_type": "xss", "host": "b.com", "endpoint": "/", "parameter": "q"}
        assert generate_cluster_key(f1) != generate_cluster_key(f2)

    def test_different_types_different_key(self):
        f1 = {
            "vuln_type": "sqli",
            "host": "example.com",
            "endpoint": "/api",
            "parameter": "id",
        }
        f2 = {
            "vuln_type": "xss",
            "host": "example.com",
            "endpoint": "/api",
            "parameter": "id",
        }
        assert generate_cluster_key(f1) != generate_cluster_key(f2)

    def test_oauth_variants_same_endpoint_same_key(self):
        """OAuth sub-types at same endpoint → same cluster."""
        f1 = {
            "vuln_type": "oauth_misconfiguration",
            "host": "example.com",
            "endpoint": "/openid/authorize",
        }
        f2 = {
            "vuln_type": "oauth_redirect_bypass",
            "host": "example.com",
            "endpoint": "/openid/authorize",
        }
        assert generate_cluster_key(f1) == generate_cluster_key(f2)

    def test_trailing_slash_normalized(self):
        f1 = {"vuln_type": "idor", "host": "example.com", "endpoint": "/api/users/"}
        f2 = {"vuln_type": "idor", "host": "example.com", "endpoint": "/api/users"}
        assert generate_cluster_key(f1) == generate_cluster_key(f2)

    def test_no_metadata_doesnt_crash(self):
        f = {"vuln_type": "sqli", "host": "example.com", "endpoint": "/api"}
        key = generate_cluster_key(f)
        assert "sqli" in key

    def test_saml_host_only(self):
        """SAML variants at different guessed paths → same cluster."""
        f1 = {"vuln_type": "saml_vulnerability", "host": "example.com", "endpoint": "/saml/acs"}
        f2 = {"vuln_type": "saml_xsw", "host": "example.com", "endpoint": "/saml/consume"}
        assert generate_cluster_key(f1) == generate_cluster_key(f2)

    def test_http_method_ignored(self):
        """GET and POST to same endpoint → same cluster key."""
        f1 = {
            "vuln_type": "sqli",
            "host": "example.com",
            "endpoint": "/api",
            "parameter": "id",
            "method": "GET",
        }
        f2 = {
            "vuln_type": "sqli",
            "host": "example.com",
            "endpoint": "/api",
            "parameter": "id",
            "method": "POST",
        }
        assert generate_cluster_key(f1) == generate_cluster_key(f2)


# ═════════════════════════════════════════════════════════════════════════════
# Cluster Findings
# ═════════════════════════════════════════════════════════════════════════════


class TestClusterFindings:
    """Test cluster_findings() annotation."""

    def test_three_sqli_same_param(self):
        """Three SQLi findings on same param → 1 cluster with size 3."""
        findings = [
            {
                "vuln_type": "sqli",
                "host": "example.com",
                "endpoint": "/api",
                "parameter": "id",
                "severity": "CRITICAL",
                "confidence_score": 95,
                "metadata": {"detection_method": "union_based"},
            },
            {
                "vuln_type": "sqli",
                "host": "example.com",
                "endpoint": "/api",
                "parameter": "id",
                "severity": "HIGH",
                "confidence_score": 80,
                "metadata": {"detection_method": "boolean_blind"},
            },
            {
                "vuln_type": "sqli",
                "host": "example.com",
                "endpoint": "/api",
                "parameter": "id",
                "severity": "HIGH",
                "confidence_score": 70,
                "metadata": {"detection_method": "time_blind"},
            },
        ]
        result = cluster_findings(findings)
        assert len(result) == 3  # No findings removed

        # All share the same cluster_id
        cluster_ids = {f["metadata"]["cluster"]["cluster_id"] for f in result}
        assert len(cluster_ids) == 1

        # Cluster size is 3
        assert result[0]["metadata"]["cluster"]["cluster_size"] == 3

        # One representative
        reps = [f for f in result if f["metadata"]["cluster"]["is_representative"]]
        assert len(reps) == 1
        # Representative should be the CRITICAL one
        assert reps[0]["severity"] == "CRITICAL"

    def test_two_oauth_same_endpoint(self):
        findings = [
            {
                "vuln_type": "oauth_misconfiguration",
                "host": "example.com",
                "endpoint": "/openid/authorize",
                "severity": "HIGH",
                "confidence_score": 85,
            },
            {
                "vuln_type": "oauth_csrf",
                "host": "example.com",
                "endpoint": "/openid/authorize",
                "severity": "MEDIUM",
                "confidence_score": 75,
            },
        ]
        cluster_findings(findings)
        ids = {f["metadata"]["cluster"]["cluster_id"] for f in findings}
        assert len(ids) == 1
        assert findings[0]["metadata"]["cluster"]["cluster_size"] == 2

    def test_different_hosts_separate_clusters(self):
        findings = [
            {
                "vuln_type": "xss",
                "host": "a.com",
                "endpoint": "/",
                "parameter": "q",
                "severity": "HIGH",
            },
            {
                "vuln_type": "xss",
                "host": "b.com",
                "endpoint": "/",
                "parameter": "q",
                "severity": "HIGH",
            },
        ]
        cluster_findings(findings)
        ids = {f["metadata"]["cluster"]["cluster_id"] for f in findings}
        assert len(ids) == 2

    def test_mixed_clustered_and_standalone(self):
        findings = [
            {
                "vuln_type": "sqli",
                "host": "example.com",
                "endpoint": "/api",
                "parameter": "id",
                "severity": "CRITICAL",
                "confidence_score": 95,
                "metadata": {},
            },
            {
                "vuln_type": "sqli",
                "host": "example.com",
                "endpoint": "/api",
                "parameter": "id",
                "severity": "HIGH",
                "confidence_score": 80,
                "metadata": {},
            },
            {
                "vuln_type": "xss",
                "host": "example.com",
                "endpoint": "/search",
                "parameter": "q",
                "severity": "MEDIUM",
                "confidence_score": 70,
                "metadata": {},
            },
        ]
        cluster_findings(findings)

        # SQLi pair = 1 cluster, XSS = 1 cluster
        ids = {f["metadata"]["cluster"]["cluster_id"] for f in findings}
        assert len(ids) == 2

        # SQLi cluster size = 2
        sqli_findings = [f for f in findings if f["vuln_type"] == "sqli"]
        assert sqli_findings[0]["metadata"]["cluster"]["cluster_size"] == 2

        # XSS standalone cluster size = 1
        xss_finding = [f for f in findings if f["vuln_type"] == "xss"][0]
        assert xss_finding["metadata"]["cluster"]["cluster_size"] == 1
        assert xss_finding["metadata"]["cluster"]["is_representative"] is True

    def test_single_finding(self):
        findings = [
            {
                "vuln_type": "xss",
                "host": "example.com",
                "endpoint": "/search",
                "parameter": "q",
                "severity": "MEDIUM",
            }
        ]
        cluster_findings(findings)
        cl = findings[0]["metadata"]["cluster"]
        assert cl["cluster_size"] == 1
        assert cl["is_representative"] is True
        assert cl["cluster_id"].startswith("CLU-")

    def test_empty_list(self):
        result = cluster_findings([])
        assert result == []

    def test_no_metadata_key(self):
        """Finding without metadata dict gets one created."""
        findings = [{"vuln_type": "xss", "host": "a.com", "endpoint": "/", "severity": "LOW"}]
        cluster_findings(findings)
        assert "cluster" in findings[0]["metadata"]

    def test_cluster_metadata_shape(self):
        """Verify all expected fields are present."""
        findings = [
            {
                "vuln_type": "sqli",
                "host": "example.com",
                "endpoint": "/api",
                "parameter": "id",
                "severity": "CRITICAL",
                "confidence_score": 90,
                "metadata": {},
            }
        ]
        cluster_findings(findings)
        cl = findings[0]["metadata"]["cluster"]
        assert "cluster_id" in cl
        assert "cluster_key" in cl
        assert "root_cause" in cl
        assert "is_representative" in cl
        assert "cluster_size" in cl
        assert "cluster_severity" in cl
        assert "cluster_confidence" in cl
        assert "evidence_fingerprint" in cl
        assert "member_index" in cl


# ═════════════════════════════════════════════════════════════════════════════
# Cluster Severity & Representative Selection
# ═════════════════════════════════════════════════════════════════════════════


class TestClusterSeverity:
    """Test severity/confidence calculations and representative selection."""

    def test_representative_is_highest_severity(self):
        findings = [
            {
                "vuln_type": "sqli",
                "host": "h",
                "endpoint": "/a",
                "parameter": "id",
                "severity": "HIGH",
                "confidence_score": 95,
                "metadata": {},
            },
            {
                "vuln_type": "sqli",
                "host": "h",
                "endpoint": "/a",
                "parameter": "id",
                "severity": "CRITICAL",
                "confidence_score": 80,
                "metadata": {},
            },
        ]
        cluster_findings(findings)
        rep = next(f for f in findings if f["metadata"]["cluster"]["is_representative"])
        assert rep["severity"] == "CRITICAL"

    def test_representative_tiebreak_by_confidence(self):
        findings = [
            {
                "vuln_type": "sqli",
                "host": "h",
                "endpoint": "/a",
                "parameter": "id",
                "severity": "HIGH",
                "confidence_score": 70,
                "metadata": {},
            },
            {
                "vuln_type": "sqli",
                "host": "h",
                "endpoint": "/a",
                "parameter": "id",
                "severity": "HIGH",
                "confidence_score": 95,
                "metadata": {},
            },
        ]
        cluster_findings(findings)
        rep = next(f for f in findings if f["metadata"]["cluster"]["is_representative"])
        assert rep["confidence_score"] == 95

    def test_cluster_severity_is_max(self):
        findings = [
            {
                "vuln_type": "oauth_misconfiguration",
                "host": "h",
                "endpoint": "/oauth",
                "severity": "MEDIUM",
                "confidence_score": 70,
            },
            {
                "vuln_type": "oauth_csrf",
                "host": "h",
                "endpoint": "/oauth",
                "severity": "HIGH",
                "confidence_score": 85,
            },
        ]
        cluster_findings(findings)
        for f in findings:
            assert f["metadata"]["cluster"]["cluster_severity"] == "HIGH"

    def test_cluster_confidence_is_max(self):
        findings = [
            {
                "vuln_type": "sqli",
                "host": "h",
                "endpoint": "/a",
                "parameter": "id",
                "severity": "CRITICAL",
                "confidence_score": 60,
                "metadata": {},
            },
            {
                "vuln_type": "sqli",
                "host": "h",
                "endpoint": "/a",
                "parameter": "id",
                "severity": "HIGH",
                "confidence_score": 95,
                "metadata": {},
            },
        ]
        cluster_findings(findings)
        for f in findings:
            assert f["metadata"]["cluster"]["cluster_confidence"] == 95.0

    def test_word_confidence_handling(self):
        findings = [
            {
                "vuln_type": "missing_headers",
                "host": "h",
                "endpoint": "/a",
                "severity": "LOW",
                "confidence": "high",
            },
            {
                "vuln_type": "missing_headers",
                "host": "h",
                "endpoint": "/b",
                "severity": "LOW",
                "confidence": "medium",
            },
        ]
        cluster_findings(findings)
        assert findings[0]["metadata"]["cluster"]["cluster_confidence"] == 85.0


# ═════════════════════════════════════════════════════════════════════════════
# get_clustered_findings (reordering)
# ═════════════════════════════════════════════════════════════════════════════


class TestGetClusteredFindings:
    """Test get_clustered_findings() reordering for reports."""

    def test_representatives_first_in_group(self):
        findings = [
            {
                "vuln_type": "sqli",
                "host": "h",
                "endpoint": "/a",
                "parameter": "id",
                "severity": "HIGH",
                "confidence_score": 70,
                "metadata": {},
            },
            {
                "vuln_type": "sqli",
                "host": "h",
                "endpoint": "/a",
                "parameter": "id",
                "severity": "CRITICAL",
                "confidence_score": 95,
                "metadata": {},
            },
        ]
        cluster_findings(findings)
        ordered = get_clustered_findings(findings)
        # First in the output should be the representative (CRITICAL)
        assert ordered[0]["metadata"]["cluster"]["is_representative"] is True
        assert ordered[0]["severity"] == "CRITICAL"

    def test_multi_member_before_standalone(self):
        findings = [
            # Standalone HIGH
            {
                "vuln_type": "xss",
                "host": "h",
                "endpoint": "/search",
                "parameter": "q",
                "severity": "HIGH",
                "confidence_score": 80,
                "metadata": {},
            },
            # Cluster: 2 x MEDIUM sqli
            {
                "vuln_type": "sqli",
                "host": "h",
                "endpoint": "/a",
                "parameter": "id",
                "severity": "MEDIUM",
                "confidence_score": 70,
                "metadata": {},
            },
            {
                "vuln_type": "sqli",
                "host": "h",
                "endpoint": "/a",
                "parameter": "id",
                "severity": "MEDIUM",
                "confidence_score": 60,
                "metadata": {},
            },
        ]
        cluster_findings(findings)
        ordered = get_clustered_findings(findings)

        # Multi-member cluster comes first (even though MEDIUM < HIGH standalone)
        assert ordered[0]["metadata"]["cluster"]["cluster_size"] == 2
        # Standalone comes last
        assert ordered[-1]["metadata"]["cluster"]["cluster_size"] == 1

    def test_empty_list(self):
        assert get_clustered_findings([]) == []

    def test_all_standalone(self):
        findings = [
            {"vuln_type": "xss", "host": "h", "endpoint": "/a", "parameter": "q", "severity": "HIGH", "metadata": {}},
            {"vuln_type": "sqli", "host": "h", "endpoint": "/b", "parameter": "id", "severity": "CRITICAL", "metadata": {}},
        ]
        cluster_findings(findings)
        ordered = get_clustered_findings(findings)
        # CRITICAL first
        assert ordered[0]["severity"] == "CRITICAL"
        assert ordered[1]["severity"] == "HIGH"

    def test_multiple_clusters_sorted_by_severity(self):
        findings = [
            # LOW cluster (2 findings)
            {"vuln_type": "missing_headers", "host": "h", "endpoint": "/a", "severity": "LOW", "confidence_score": 80},
            {"vuln_type": "missing_headers", "host": "h", "endpoint": "/b", "severity": "LOW", "confidence_score": 70},
            # CRITICAL cluster (2 findings)
            {"vuln_type": "sqli", "host": "h", "endpoint": "/api", "parameter": "id", "severity": "CRITICAL", "confidence_score": 95, "metadata": {}},
            {"vuln_type": "sqli", "host": "h", "endpoint": "/api", "parameter": "id", "severity": "HIGH", "confidence_score": 80, "metadata": {}},
        ]
        cluster_findings(findings)
        ordered = get_clustered_findings(findings)
        # CRITICAL cluster first
        assert ordered[0]["metadata"]["cluster"]["cluster_severity"] == "CRITICAL"


# ═════════════════════════════════════════════════════════════════════════════
# get_cluster_summary
# ═════════════════════════════════════════════════════════════════════════════


class TestClusterSummary:
    """Test get_cluster_summary() statistics."""

    def test_summary_stats(self):
        findings = [
            {"vuln_type": "sqli", "host": "h", "endpoint": "/a", "parameter": "id", "severity": "CRITICAL", "confidence_score": 95, "metadata": {}},
            {"vuln_type": "sqli", "host": "h", "endpoint": "/a", "parameter": "id", "severity": "HIGH", "confidence_score": 80, "metadata": {}},
            {"vuln_type": "sqli", "host": "h", "endpoint": "/a", "parameter": "id", "severity": "HIGH", "confidence_score": 70, "metadata": {}},
            {"vuln_type": "xss", "host": "h", "endpoint": "/search", "parameter": "q", "severity": "MEDIUM", "confidence_score": 65, "metadata": {}},
        ]
        cluster_findings(findings)
        summary = get_cluster_summary(findings)
        assert summary["total_clusters"] == 2
        assert summary["multi_member_clusters"] == 1
        assert summary["largest_cluster"] == 3
        assert summary["findings_in_multi_clusters"] == 3

    def test_summary_all_standalone(self):
        findings = [
            {"vuln_type": "xss", "host": "a", "endpoint": "/", "parameter": "q", "severity": "HIGH", "metadata": {}},
            {"vuln_type": "sqli", "host": "b", "endpoint": "/", "parameter": "id", "severity": "CRITICAL", "metadata": {}},
        ]
        cluster_findings(findings)
        summary = get_cluster_summary(findings)
        assert summary["total_clusters"] == 2
        assert summary["multi_member_clusters"] == 0
        assert summary["findings_in_multi_clusters"] == 0

    def test_summary_empty(self):
        summary = get_cluster_summary([])
        assert summary["total_clusters"] == 0
