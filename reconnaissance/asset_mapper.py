"""
Asset mapper for consolidating reconnaissance data.
Creates a unified view of discovered assets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings
    from reconnaissance.port_scanner import PortInfo
    from reconnaissance.tech_detection import Technology

logger = get_logger(__name__)


@dataclass
class Asset:
    """Represents a discovered asset."""
    
    hostname: str
    ip_addresses: list[str] = field(default_factory=list)
    ports: list[dict] = field(default_factory=list)
    technologies: list[dict] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hostname": self.hostname,
            "ip_addresses": self.ip_addresses,
            "ports": self.ports,
            "technologies": self.technologies,
            "urls": self.urls,
            "forms": self.forms,
            "metadata": self.metadata,
        }
    
    @property
    def has_web_service(self) -> bool:
        """Check if asset has web service."""
        web_ports = {80, 443, 8080, 8443}
        return any(p.get("port") in web_ports for p in self.ports)
    
    @property
    def attack_surface_score(self) -> float:
        """Calculate attack surface score (0-10)."""
        score = 0.0
        
        # Ports
        score += min(len(self.ports) * 0.5, 3.0)
        
        # URLs
        score += min(len(self.urls) * 0.01, 2.0)
        
        # Forms (input points)
        score += min(len(self.forms) * 0.3, 2.0)
        
        # Technologies (known vulnerable techs could increase score)
        score += min(len(self.technologies) * 0.2, 1.5)
        
        # Web services
        if self.has_web_service:
            score += 1.5
        
        return min(score, 10.0)


class AssetMapper:
    """
    Consolidates reconnaissance data into unified asset view.
    
    Aggregates:
    - Subdomain data
    - Port scan results
    - Technology detection
    - Crawler results
    """
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize mapper.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.assets: dict[str, Asset] = {}
    
    def add_host(self, hostname: str) -> Asset:
        """
        Add or get a host asset.
        
        Args:
            hostname: Host identifier
            
        Returns:
            Asset object
        """
        if hostname not in self.assets:
            self.assets[hostname] = Asset(hostname=hostname)
        return self.assets[hostname]
    
    def add_ports(self, hostname: str, ports: list[PortInfo]) -> None:
        """
        Add port scan results.
        
        Args:
            hostname: Host identifier
            ports: Port scan results
        """
        asset = self.add_host(hostname)
        asset.ports = [p.to_dict() if hasattr(p, 'to_dict') else p for p in ports]
        logger.debug(f"Added {len(ports)} ports to {hostname}")
    
    def add_technologies(self, hostname: str, technologies: list[Technology]) -> None:
        """
        Add technology detection results.
        
        Args:
            hostname: Host identifier
            technologies: Detected technologies
        """
        asset = self.add_host(hostname)
        asset.technologies = [
            t.to_dict() if hasattr(t, 'to_dict') else t
            for t in technologies
        ]
        logger.debug(f"Added {len(technologies)} technologies to {hostname}")
    
    def add_urls(self, hostname: str, urls: list[str]) -> None:
        """
        Add discovered URLs.
        
        Args:
            hostname: Host identifier
            urls: Discovered URLs
        """
        asset = self.add_host(hostname)
        asset.urls = urls
        logger.debug(f"Added {len(urls)} URLs to {hostname}")
    
    def add_forms(self, hostname: str, forms: list[dict]) -> None:
        """
        Add discovered forms.
        
        Args:
            hostname: Host identifier
            forms: Discovered forms
        """
        asset = self.add_host(hostname)
        asset.forms = forms
        logger.debug(f"Added {len(forms)} forms to {hostname}")
    
    def set_metadata(self, hostname: str, key: str, value: Any) -> None:
        """
        Set asset metadata.
        
        Args:
            hostname: Host identifier
            key: Metadata key
            value: Metadata value
        """
        asset = self.add_host(hostname)
        asset.metadata[key] = value
    
    def get_asset(self, hostname: str) -> Asset | None:
        """
        Get asset by hostname.
        
        Args:
            hostname: Host identifier
            
        Returns:
            Asset or None
        """
        return self.assets.get(hostname)
    
    def get_all_assets(self) -> list[Asset]:
        """Get all assets."""
        return list(self.assets.values())
    
    def get_summary(self) -> dict[str, Any]:
        """
        Get summary of all assets.
        
        Returns:
            Summary dictionary
        """
        total_ports = sum(len(a.ports) for a in self.assets.values())
        total_urls = sum(len(a.urls) for a in self.assets.values())
        total_forms = sum(len(a.forms) for a in self.assets.values())
        
        all_techs: set[str] = set()
        for asset in self.assets.values():
            for tech in asset.technologies:
                all_techs.add(tech.get("name", "Unknown"))
        
        web_assets = [a for a in self.assets.values() if a.has_web_service]
        
        avg_attack_surface = (
            sum(a.attack_surface_score for a in self.assets.values()) / len(self.assets)
            if self.assets else 0
        )
        
        return {
            "total_assets": len(self.assets),
            "web_assets": len(web_assets),
            "total_ports": total_ports,
            "total_urls": total_urls,
            "total_forms": total_forms,
            "unique_technologies": len(all_techs),
            "technologies": list(all_techs),
            "average_attack_surface": round(avg_attack_surface, 2),
        }
    
    def to_dict(self) -> dict[str, Any]:
        """
        Convert all assets to dictionary.
        
        Returns:
            Dictionary with all assets
        """
        return {
            hostname: asset.to_dict()
            for hostname, asset in self.assets.items()
        }
    
    def get_high_value_targets(self, min_score: float = 6.0) -> list[Asset]:
        """
        Get high-value targets based on attack surface.
        
        Args:
            min_score: Minimum attack surface score
            
        Returns:
            List of high-value assets
        """
        return [
            asset for asset in self.assets.values()
            if asset.attack_surface_score >= min_score
        ]
    
    def get_assets_by_technology(self, tech_name: str) -> list[Asset]:
        """
        Get assets using a specific technology.
        
        Args:
            tech_name: Technology name to search
            
        Returns:
            List of matching assets
        """
        matching = []
        tech_lower = tech_name.lower()
        
        for asset in self.assets.values():
            for tech in asset.technologies:
                if tech_lower in tech.get("name", "").lower():
                    matching.append(asset)
                    break
        
        return matching
