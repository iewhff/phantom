"""
Test Targets - Database of Known Vulnerable Applications.

Provides information about test targets, their vulnerabilities,
and how to set them up for validation testing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


class TargetType(Enum):
    """Types of test targets."""
    DOCKER = "docker"
    VM = "vm"
    CLOUD = "cloud"
    LOCAL = "local"
    SAAS = "saas"


class DifficultyLevel(Enum):
    """Difficulty levels for test targets."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


@dataclass
class SetupInstructions:
    """Instructions to set up a test target."""
    docker_compose: str | None = None
    docker_run: str | None = None
    download_url: str | None = None
    documentation_url: str | None = None
    requirements: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    notes: str = ""


@dataclass  
class TestTarget:
    """A test target for validation."""
    name: str
    target_type: TargetType
    difficulty: DifficultyLevel
    description: str
    vulnerabilities: list[str]
    owasp_categories: list[str]
    setup: SetupInstructions
    default_url: str = ""
    default_credentials: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "target_type": self.target_type.value,
            "difficulty": self.difficulty.value,
            "description": self.description,
            "vulnerabilities": self.vulnerabilities,
            "owasp_categories": self.owasp_categories,
            "default_url": self.default_url,
            "default_credentials": self.default_credentials,
            "tags": self.tags,
            "setup": {
                "docker_compose": self.setup.docker_compose,
                "docker_run": self.setup.docker_run,
                "download_url": self.setup.download_url,
                "documentation_url": self.setup.documentation_url,
                "requirements": self.setup.requirements,
                "ports": self.setup.ports,
                "notes": self.setup.notes,
            },
        }


class VulnerabilityDatabase:
    """
    Database of test targets and their known vulnerabilities.
    
    Used for:
    - Setting up test environments
    - Validating scanner accuracy
    - Training and education
    """
    
    # Pre-configured test targets
    TARGETS: dict[str, TestTarget] = {
        "dvwa": TestTarget(
            name="Damn Vulnerable Web Application (DVWA)",
            target_type=TargetType.DOCKER,
            difficulty=DifficultyLevel.BEGINNER,
            description="PHP/MySQL web application with intentional vulnerabilities",
            vulnerabilities=[
                "sql_injection",
                "xss_reflected",
                "xss_stored",
                "command_injection",
                "lfi",
                "rfi",
                "file_upload",
                "csrf",
                "brute_force",
                "captcha_bypass",
                "weak_session_ids",
            ],
            owasp_categories=["A03:2021", "A07:2021", "A01:2021", "A05:2021"],
            setup=SetupInstructions(
                docker_run="docker run -d -p 80:80 vulnerables/web-dvwa",
                docker_compose="""
version: '3'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "80:80"
    environment:
      - RECAPTCHA_PRIV_KEY=''
      - RECAPTCHA_PUB_KEY=''
                """,
                documentation_url="https://github.com/digininja/DVWA",
                requirements=["Docker"],
                ports=[80],
                notes="Login with admin/password, then setup database",
            ),
            default_url="http://localhost:80",
            default_credentials={"username": "admin", "password": "password"},
            tags=["php", "mysql", "beginner", "owasp-top10"],
        ),
        
        "juice_shop": TestTarget(
            name="OWASP Juice Shop",
            target_type=TargetType.DOCKER,
            difficulty=DifficultyLevel.INTERMEDIATE,
            description="Modern JavaScript vulnerable application with 100+ challenges",
            vulnerabilities=[
                "sql_injection",
                "xss_dom",
                "xss_reflected",
                "nosql_injection",
                "xxe",
                "idor",
                "jwt_vulnerabilities",
                "broken_authentication",
                "sensitive_data_exposure",
                "broken_access_control",
                "security_misconfiguration",
                "ssrf",
            ],
            owasp_categories=["A01:2021", "A02:2021", "A03:2021", "A05:2021", "A07:2021"],
            setup=SetupInstructions(
                docker_run="docker run -d -p 3000:3000 bkimminich/juice-shop",
                documentation_url="https://owasp.org/www-project-juice-shop/",
                requirements=["Docker"],
                ports=[3000],
                notes="Angular/Node.js app with REST API",
            ),
            default_url="http://localhost:3000",
            default_credentials={},
            tags=["javascript", "nodejs", "angular", "rest-api", "owasp"],
        ),
        
        "webgoat": TestTarget(
            name="OWASP WebGoat",
            target_type=TargetType.DOCKER,
            difficulty=DifficultyLevel.INTERMEDIATE,
            description="Java-based deliberately insecure application",
            vulnerabilities=[
                "sql_injection",
                "xxe",
                "deserialization",
                "jwt_vulnerabilities",
                "path_traversal",
                "authentication_bypass",
                "access_control",
                "crypto_failures",
                "request_forgery",
            ],
            owasp_categories=["A01:2021", "A02:2021", "A03:2021", "A08:2021"],
            setup=SetupInstructions(
                docker_run="docker run -d -p 8080:8080 -p 9090:9090 webgoat/webgoat",
                documentation_url="https://owasp.org/www-project-webgoat/",
                requirements=["Docker"],
                ports=[8080, 9090],
                notes="WebGoat on 8080, WebWolf helper on 9090",
            ),
            default_url="http://localhost:8080/WebGoat",
            default_credentials={},
            tags=["java", "spring", "educational", "owasp"],
        ),
        
        "hackable": TestTarget(
            name="Hackable Docker Targets",
            target_type=TargetType.DOCKER,
            difficulty=DifficultyLevel.ADVANCED,
            description="Collection of hackable Docker containers",
            vulnerabilities=[
                "multiple",
            ],
            owasp_categories=["A01:2021", "A03:2021", "A05:2021"],
            setup=SetupInstructions(
                docker_compose="""
version: '3'
services:
  # Various vulnerable containers
  tiredful-api:
    image: tuxotron/tiredful-api
    ports:
      - "8000:8000"
  
  nodegoat:
    image: owasp/nodegoat
    ports:
      - "4000:4000"
      
  vulnado:
    image: vulnerables/vulnado
    ports:
      - "1337:1337"
                """,
                documentation_url="https://github.com/vulhub/vulhub",
                requirements=["Docker", "docker-compose"],
                ports=[8000, 4000, 1337],
            ),
            default_url="http://localhost:8000",
            tags=["docker", "multiple", "advanced"],
        ),
        
        "vulnerable_graphql": TestTarget(
            name="Damn Vulnerable GraphQL Application",
            target_type=TargetType.DOCKER,
            difficulty=DifficultyLevel.INTERMEDIATE,
            description="GraphQL-specific vulnerabilities",
            vulnerabilities=[
                "graphql_injection",
                "graphql_introspection",
                "graphql_dos",
                "graphql_authorization",
                "graphql_batching_attack",
            ],
            owasp_categories=["A01:2021", "A03:2021"],
            setup=SetupInstructions(
                docker_run="docker run -d -p 5013:5013 dolevf/dvga",
                documentation_url="https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application",
                requirements=["Docker"],
                ports=[5013],
            ),
            default_url="http://localhost:5013",
            tags=["graphql", "api", "intermediate"],
        ),
        
        "vulnerable_api": TestTarget(
            name="VAmPI (Vulnerable API)",
            target_type=TargetType.DOCKER,
            difficulty=DifficultyLevel.INTERMEDIATE,
            description="Vulnerable REST API for API security testing",
            vulnerabilities=[
                "broken_authentication",
                "broken_authorization",
                "excessive_data_exposure",
                "lack_of_rate_limiting",
                "mass_assignment",
                "injection",
                "improper_assets_management",
            ],
            owasp_categories=["A01:2021", "A02:2021", "A03:2021", "A04:2021"],
            setup=SetupInstructions(
                docker_run="docker run -d -p 5000:5000 erev0s/vampi",
                documentation_url="https://github.com/erev0s/VAmPI",
                requirements=["Docker"],
                ports=[5000],
                notes="Based on OWASP API Security Top 10",
            ),
            default_url="http://localhost:5000",
            tags=["api", "rest", "owasp-api-top10"],
        ),
        
        "kubernetes_goat": TestTarget(
            name="Kubernetes Goat",
            target_type=TargetType.DOCKER,
            difficulty=DifficultyLevel.ADVANCED,
            description="Kubernetes security vulnerabilities",
            vulnerabilities=[
                "kubernetes_misconfiguration",
                "container_escape",
                "secrets_exposure",
                "rbac_misconfiguration",
                "network_policies",
            ],
            owasp_categories=["A05:2021", "A07:2021"],
            setup=SetupInstructions(
                documentation_url="https://github.com/madhuakula/kubernetes-goat",
                requirements=["Kubernetes cluster", "kubectl", "helm"],
                notes="Requires running Kubernetes cluster",
            ),
            default_url="",
            tags=["kubernetes", "cloud", "containers", "advanced"],
        ),
        
        "cloudgoat": TestTarget(
            name="CloudGoat",
            target_type=TargetType.CLOUD,
            difficulty=DifficultyLevel.ADVANCED,
            description="AWS security vulnerabilities",
            vulnerabilities=[
                "iam_misconfiguration",
                "s3_exposure",
                "ec2_ssrf",
                "lambda_privilege_escalation",
                "secrets_in_metadata",
            ],
            owasp_categories=["A01:2021", "A05:2021"],
            setup=SetupInstructions(
                documentation_url="https://github.com/RhinoSecurityLabs/cloudgoat",
                requirements=["AWS account", "Terraform", "AWS CLI"],
                notes="Creates vulnerable AWS resources - USE SANDBOX ACCOUNT",
            ),
            default_url="",
            tags=["aws", "cloud", "iam", "advanced"],
        ),
    }
    
    @classmethod
    def get_target(cls, name: str) -> TestTarget | None:
        """Get a test target by name."""
        return cls.TARGETS.get(name.lower())
    
    @classmethod
    def list_targets(cls) -> list[str]:
        """List all available test targets."""
        return list(cls.TARGETS.keys())
    
    @classmethod
    def get_targets_by_vulnerability(cls, vuln_type: str) -> list[TestTarget]:
        """Get targets that have a specific vulnerability."""
        return [
            target for target in cls.TARGETS.values()
            if vuln_type in target.vulnerabilities
        ]
    
    @classmethod
    def get_targets_by_difficulty(cls, difficulty: DifficultyLevel) -> list[TestTarget]:
        """Get targets by difficulty level."""
        return [
            target for target in cls.TARGETS.values()
            if target.difficulty == difficulty
        ]
    
    @classmethod
    def get_targets_by_owasp(cls, owasp_category: str) -> list[TestTarget]:
        """Get targets that cover a specific OWASP category."""
        return [
            target for target in cls.TARGETS.values()
            if owasp_category in target.owasp_categories
        ]
    
    @classmethod
    def generate_docker_compose(cls, targets: list[str]) -> str:
        """Generate docker-compose.yml for multiple targets."""
        compose = "version: '3'\nservices:\n"
        
        port_offset = 0
        for target_name in targets:
            target = cls.get_target(target_name)
            if target and target.setup.docker_run:
                # Extract image from docker run command
                parts = target.setup.docker_run.split()
                image = parts[-1] if parts else ""
                
                if image:
                    compose += f"""
  {target_name}:
    image: {image}
    ports:
"""
                    for port in target.setup.ports:
                        compose += f"      - \"{port + port_offset}:{port}\"\n"
                    port_offset += 1000
        
        return compose
    
    @classmethod
    def get_coverage_report(cls) -> dict:
        """Get vulnerability coverage report across all targets."""
        all_vulns: dict[str, list[str]] = {}
        
        for name, target in cls.TARGETS.items():
            for vuln in target.vulnerabilities:
                if vuln not in all_vulns:
                    all_vulns[vuln] = []
                all_vulns[vuln].append(name)
        
        return {
            "total_targets": len(cls.TARGETS),
            "total_vulnerability_types": len(all_vulns),
            "coverage": {
                vuln: {
                    "count": len(targets),
                    "targets": targets,
                }
                for vuln, targets in sorted(all_vulns.items())
            },
        }
