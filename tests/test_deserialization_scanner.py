"""
Tests for scanning/modules/deserialization_scanner.py

Covers:
- DeserVulnType enum (23 types)
- GadgetChainType enum (60+ chains)
- SerializationFormat enum (20 formats)
- FP mitigation constants (STATIC_EXTENSIONS, SPA_TRIVIAL_ENDPOINTS, etc.)
- DESER_SPECIFIC_PATTERNS per language
- DeserTestResult dataclass
- FrameworkSignature dataclass
- DeserializationScanner class attributes (magic bytes, patterns)
- JAVA_GADGET_PAYLOADS
"""

import pytest
import re
from scanning.modules.deserialization_scanner import (
    DeserVulnType,
    GadgetChainType,
    SerializationFormat,
    STATIC_EXTENSIONS,
    SPA_TRIVIAL_ENDPOINTS,
    GENERIC_ERROR_PATTERNS,
    DESER_SPECIFIC_PATTERNS,
    SAFE_CONTENT_TYPES,
    SEVERITY_SIGNAL_REQUIREMENTS,
    DeserTestResult,
    FrameworkSignature,
    DeserializationScanner,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestDeserVulnType:
    def test_count(self):
        assert len(DeserVulnType) == 23

    def test_java_object(self):
        assert DeserVulnType.JAVA_OBJECT.value == "java_object_deserialization"

    def test_java_rmi(self):
        assert DeserVulnType.JAVA_RMI.value == "java_rmi_deserialization"

    def test_java_t3(self):
        assert DeserVulnType.JAVA_T3.value == "weblogic_t3_deserialization"

    def test_php_object(self):
        assert DeserVulnType.PHP_OBJECT.value == "php_object_injection"

    def test_php_phar(self):
        assert DeserVulnType.PHP_PHAR.value == "php_phar_deserialization"

    def test_python_pickle(self):
        assert DeserVulnType.PYTHON_PICKLE.value == "python_pickle_deserialization"

    def test_python_yaml(self):
        assert DeserVulnType.PYTHON_YAML.value == "python_yaml_deserialization"

    def test_dotnet_viewstate(self):
        assert DeserVulnType.DOTNET_VIEWSTATE.value == "dotnet_viewstate_deserialization"

    def test_dotnet_binary(self):
        assert DeserVulnType.DOTNET_BINARY.value == "dotnet_binaryformatter_deserialization"

    def test_ruby_marshal(self):
        assert DeserVulnType.RUBY_MARSHAL.value == "ruby_marshal_deserialization"

    def test_node_serialize(self):
        assert DeserVulnType.NODE_SERIALIZE.value == "node_serialize_deserialization"


class TestGadgetChainType:
    def test_has_many_chains(self):
        assert len(GadgetChainType) >= 50

    # Java ysoserial
    def test_has_commons_collections(self):
        assert GadgetChainType.COMMONS_COLLECTIONS.value == "CommonsCollections"

    def test_has_commons_beanutils(self):
        assert GadgetChainType.COMMONS_BEANUTILS.value == "CommonsBeanutils"

    def test_has_spring(self):
        assert GadgetChainType.SPRING_CORE.value == "Spring"

    def test_has_hibernate(self):
        assert GadgetChainType.HIBERNATE_1 is not None

    def test_has_urldns(self):
        assert GadgetChainType.URLDNS.value == "URLDNS"

    def test_has_jrmpclient(self):
        assert GadgetChainType.JRMPCLIENT.value == "JRMPClient"

    def test_has_rome(self):
        assert GadgetChainType.ROME.value == "ROME"

    # PHP PHPGGC
    def test_has_guzzle(self):
        assert GadgetChainType.GUZZLE_RCE1.value == "Guzzle/RCE1"

    def test_has_monolog(self):
        assert GadgetChainType.MONOLOG_RCE1.value == "Monolog/RCE1"

    def test_has_symfony(self):
        assert GadgetChainType.SYMFONY_RCE1.value == "Symfony/RCE1"

    def test_has_laravel(self):
        assert GadgetChainType.LARAVEL_RCE1.value == "Laravel/RCE1"

    def test_has_doctrine(self):
        assert GadgetChainType.DOCTRINE_RCE1.value == "Doctrine/RCE1"

    def test_has_wordpress(self):
        assert GadgetChainType.WORDPRESS_RCE1.value == "WordPress/RCE1"

    # .NET ysoserial.net
    def test_has_typeconfuse(self):
        assert GadgetChainType.TYPECONFUSE.value == "TypeConfuseDelegate"

    def test_has_viewstate(self):
        assert GadgetChainType.VIEWSTATE_RCE.value == "ViewState"

    # Ruby
    def test_has_gem_installer(self):
        assert GadgetChainType.GEM_INSTALLER.value == "Gem::Installer"

    def test_has_erb(self):
        assert GadgetChainType.ERB_TEMPLATE.value == "ERB"


class TestSerializationFormat:
    def test_count(self):
        assert len(SerializationFormat) == 20

    def test_java_native(self):
        assert SerializationFormat.JAVA_NATIVE.value == "java_native_serialization"

    def test_php_serialize(self):
        assert SerializationFormat.PHP_SERIALIZE.value == "php_native_serialize"

    def test_python_pickle(self):
        assert SerializationFormat.PYTHON_PICKLE.value == "python_pickle"

    def test_dotnet_binary(self):
        assert SerializationFormat.DOTNET_BINARY.value == "dotnet_binaryformatter"

    def test_ruby_marshal(self):
        assert SerializationFormat.RUBY_MARSHAL.value == "ruby_marshal"

    def test_msgpack(self):
        assert SerializationFormat.MSGPACK.value == "msgpack"

    def test_protobuf(self):
        assert SerializationFormat.PROTOBUF.value == "protobuf"


# =============================================================================
# FP MITIGATION CONSTANTS
# =============================================================================

class TestStaticExtensions:
    def test_not_empty(self):
        assert len(STATIC_EXTENSIONS) > 0

    def test_has_common_static(self):
        assert ".js" in STATIC_EXTENSIONS
        assert ".css" in STATIC_EXTENSIONS
        assert ".png" in STATIC_EXTENSIONS
        assert ".jpg" in STATIC_EXTENSIONS

    def test_is_frozenset(self):
        assert isinstance(STATIC_EXTENSIONS, frozenset)


class TestSPATrivialEndpoints:
    def test_not_empty(self):
        assert len(SPA_TRIVIAL_ENDPOINTS) > 0

    def test_has_root(self):
        assert "/" in SPA_TRIVIAL_ENDPOINTS

    def test_has_login(self):
        assert "/login" in SPA_TRIVIAL_ENDPOINTS

    def test_has_static_dirs(self):
        assert "/static/" in SPA_TRIVIAL_ENDPOINTS


class TestGenericErrorPatterns:
    def test_not_empty(self):
        assert len(GENERIC_ERROR_PATTERNS) > 0

    def test_has_404(self):
        assert "404" in GENERIC_ERROR_PATTERNS or "not found" in GENERIC_ERROR_PATTERNS

    def test_has_500(self):
        assert any("500" in p or "internal server error" in p for p in GENERIC_ERROR_PATTERNS)


class TestDeserSpecificPatterns:
    def test_has_java(self):
        assert "java" in DESER_SPECIFIC_PATTERNS
        assert len(DESER_SPECIFIC_PATTERNS["java"]) > 0

    def test_has_php(self):
        assert "php" in DESER_SPECIFIC_PATTERNS
        assert len(DESER_SPECIFIC_PATTERNS["php"]) > 0

    def test_has_python(self):
        assert "python" in DESER_SPECIFIC_PATTERNS
        assert len(DESER_SPECIFIC_PATTERNS["python"]) > 0

    def test_has_dotnet(self):
        assert "dotnet" in DESER_SPECIFIC_PATTERNS
        assert len(DESER_SPECIFIC_PATTERNS["dotnet"]) > 0

    def test_has_ruby(self):
        assert "ruby" in DESER_SPECIFIC_PATTERNS

    def test_has_node(self):
        assert "node" in DESER_SPECIFIC_PATTERNS

    def test_java_patterns_compile(self):
        for pattern in DESER_SPECIFIC_PATTERNS["java"]:
            re.compile(pattern)

    def test_php_patterns_compile(self):
        for pattern in DESER_SPECIFIC_PATTERNS["php"]:
            re.compile(pattern)

    def test_python_patterns_compile(self):
        for pattern in DESER_SPECIFIC_PATTERNS["python"]:
            re.compile(pattern)

    def test_java_has_objectinputstream(self):
        patterns_text = " ".join(DESER_SPECIFIC_PATTERNS["java"])
        assert "ObjectInputStream" in patterns_text

    def test_php_has_unserialize(self):
        patterns_text = " ".join(DESER_SPECIFIC_PATTERNS["php"])
        assert "unserialize" in patterns_text

    def test_python_has_pickle(self):
        patterns_text = " ".join(DESER_SPECIFIC_PATTERNS["python"])
        assert "pickle" in patterns_text.lower()


class TestSafeContentTypes:
    def test_not_empty(self):
        assert len(SAFE_CONTENT_TYPES) > 0

    def test_has_html(self):
        assert "text/html" in SAFE_CONTENT_TYPES

    def test_has_javascript(self):
        assert "application/javascript" in SAFE_CONTENT_TYPES


class TestSeveritySignalRequirements:
    def test_critical_requires_most(self):
        assert SEVERITY_SIGNAL_REQUIREMENTS["CRITICAL"] > SEVERITY_SIGNAL_REQUIREMENTS["MEDIUM"]

    def test_high_requires_more_than_medium(self):
        assert SEVERITY_SIGNAL_REQUIREMENTS["HIGH"] > SEVERITY_SIGNAL_REQUIREMENTS["MEDIUM"]


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestDeserTestResult:
    def test_basic_creation(self):
        result = DeserTestResult(
            vuln_type=DeserVulnType.JAVA_OBJECT,
        )
        assert result.vuln_type == DeserVulnType.JAVA_OBJECT
        assert result.gadget_chain is None
        assert result.rce_confirmed is False
        assert result.evidence == []

    def test_full_creation(self):
        result = DeserTestResult(
            vuln_type=DeserVulnType.JAVA_OBJECT,
            gadget_chain=GadgetChainType.COMMONS_COLLECTIONS,
            serialization_format=SerializationFormat.JAVA_NATIVE,
            parameter="data",
            endpoint="/api/process",
            evidence=["StreamCorruptedException in response"],
            rce_confirmed=True,
            dns_callback=True,
            cve_ids=["CVE-2015-7501"],
        )
        assert result.rce_confirmed is True
        assert result.dns_callback is True
        assert len(result.cve_ids) == 1


class TestFrameworkSignature:
    def test_basic_creation(self):
        sig = FrameworkSignature(name="Spring Boot")
        assert sig.name == "Spring Boot"
        assert sig.version_pattern is None
        assert sig.headers == {}
        assert sig.gadget_chains == []

    def test_full_creation(self):
        sig = FrameworkSignature(
            name="Laravel",
            version_pattern=r"Laravel/\d+",
            headers={"X-Powered-By": "PHP"},
            cookies=["laravel_session"],
            body_patterns=[r"IlluminateException"],
            gadget_chains=[GadgetChainType.LARAVEL_RCE1],
            cves=["CVE-2021-3129"],
        )
        assert len(sig.gadget_chains) == 1
        assert len(sig.cves) == 1


# =============================================================================
# SCANNER CLASS ATTRIBUTES
# =============================================================================

class TestDeserializationScannerClass:
    def test_name(self):
        assert DeserializationScanner.name == "deserialization_scanner"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(DeserializationScanner, ScanModule)

    # Magic bytes
    def test_java_magic(self):
        assert DeserializationScanner.JAVA_MAGIC == b'\xac\xed\x00\x05'

    def test_java_magic_b64(self):
        assert DeserializationScanner.JAVA_MAGIC_B64 == "rO0AB"

    def test_php_phar_magic(self):
        assert b"__HALT_COMPILER" in DeserializationScanner.PHP_PHAR_MAGIC

    def test_pickle_v2_magic(self):
        assert DeserializationScanner.PICKLE_MAGIC_V2 == b'\x80\x02'

    def test_pickle_v5_magic(self):
        assert DeserializationScanner.PICKLE_MAGIC_V5 == b'\x80\x05'

    def test_dotnet_binary_magic(self):
        assert len(DeserializationScanner.DOTNET_BINARY_MAGIC) > 0

    def test_ruby_marshal_magic(self):
        assert DeserializationScanner.RUBY_MARSHAL_MAGIC == b'\x04\x08'

    # PHP pattern
    def test_php_serialize_pattern(self):
        pattern = DeserializationScanner.PHP_SERIALIZE_PATTERN
        assert pattern.search('O:4:"test":1:{s:3:"foo";s:3:"bar";}')
        assert pattern.search('a:2:{i:0;s:5:"hello";i:1;s:5:"world";}')

    # ViewState patterns
    def test_viewstate_pattern(self):
        pattern = DeserializationScanner.VIEWSTATE_PATTERN
        assert pattern.search('__VIEWSTATE" value="/wEPDwUK"')

    # Java gadget payloads
    def test_has_java_gadgets(self):
        assert len(DeserializationScanner.JAVA_GADGET_PAYLOADS) > 0

    def test_has_urldns_gadget(self):
        assert GadgetChainType.URLDNS in DeserializationScanner.JAVA_GADGET_PAYLOADS

    def test_urldns_is_safe(self):
        urldns = DeserializationScanner.JAVA_GADGET_PAYLOADS[GadgetChainType.URLDNS]
        assert urldns.get("safe_detection") is True

    def test_has_commons_collections_gadget(self):
        assert GadgetChainType.COMMONS_COLLECTIONS in DeserializationScanner.JAVA_GADGET_PAYLOADS

    def test_commons_collections_has_cves(self):
        cc = DeserializationScanner.JAVA_GADGET_PAYLOADS[GadgetChainType.COMMONS_COLLECTIONS]
        assert len(cc.get("cves", [])) > 0

    def test_has_spring_gadget(self):
        assert GadgetChainType.SPRING_CORE in DeserializationScanner.JAVA_GADGET_PAYLOADS

    def test_has_jboss_gadget(self):
        assert GadgetChainType.JBOSS in DeserializationScanner.JAVA_GADGET_PAYLOADS


# =============================================================================
# ATTACK SCENARIOS
# =============================================================================

class TestAttackScenarios:
    def test_java_rce_scenario(self):
        result = DeserTestResult(
            vuln_type=DeserVulnType.JAVA_OBJECT,
            gadget_chain=GadgetChainType.COMMONS_COLLECTIONS,
            serialization_format=SerializationFormat.JAVA_NATIVE,
            parameter="viewstate",
            endpoint="/faces/javax.faces.resource",
            evidence=["RCE confirmed: uid=0(root)"],
            rce_confirmed=True,
            cve_ids=["CVE-2015-7501"],
        )
        assert result.rce_confirmed is True

    def test_php_phar_scenario(self):
        result = DeserTestResult(
            vuln_type=DeserVulnType.PHP_PHAR,
            serialization_format=SerializationFormat.PHP_PHAR,
            parameter="file",
            endpoint="/upload",
            evidence=["phar:// wrapper triggered deserialization"],
        )
        assert result.vuln_type == DeserVulnType.PHP_PHAR

    def test_python_pickle_scenario(self):
        result = DeserTestResult(
            vuln_type=DeserVulnType.PYTHON_PICKLE,
            serialization_format=SerializationFormat.PYTHON_PICKLE,
            parameter="session",
            endpoint="/api/load",
            evidence=["pickle.loads() executed on user input"],
            rce_confirmed=True,
        )
        assert result.rce_confirmed is True

    def test_dotnet_viewstate_scenario(self):
        result = DeserTestResult(
            vuln_type=DeserVulnType.DOTNET_VIEWSTATE,
            serialization_format=SerializationFormat.DOTNET_OBJECTSTATE,
            parameter="__VIEWSTATE",
            endpoint="/Default.aspx",
            evidence=["ViewState deserialization without MAC validation"],
            cve_ids=["CVE-2020-0688"],
        )
        assert "CVE-2020-0688" in result.cve_ids


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_all_vuln_types_unique(self):
        values = [t.value for t in DeserVulnType]
        assert len(values) == len(set(values))

    def test_all_formats_unique(self):
        values = [f.value for f in SerializationFormat]
        assert len(values) == len(set(values))

    def test_all_gadget_chains_unique(self):
        values = [g.value for g in GadgetChainType]
        assert len(values) == len(set(values))
