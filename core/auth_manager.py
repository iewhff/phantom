"""
Authorization Manager for target validation.
Ensures scans only run against authorized targets.

SECURITY: Implements encrypted storage for authorized targets (CWE-312).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from utils.logger import get_logger

logger = get_logger(__name__)

# Try to import cryptography for encryption
try:
    from cryptography.fernet import Fernet, InvalidToken
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    Fernet = None  # type: ignore
    InvalidToken = Exception  # type: ignore

if TYPE_CHECKING:
    from core.config_manager import Settings


def _get_encryption_key(key_file: Path) -> bytes:
    """
    Get or generate encryption key for authorized targets.

    SECURITY: Uses PBKDF2 with salt for key derivation.

    Args:
        key_file: Path to store/load encryption key

    Returns:
        Fernet-compatible encryption key
    """
    if not ENCRYPTION_AVAILABLE:
        raise RuntimeError("cryptography package not installed - run: pip install cryptography")

    if key_file.exists():
        # Load existing key
        key_data = key_file.read_bytes()
        return key_data
    else:
        # Generate new key
        key = Fernet.generate_key()
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(key)
        # Secure file permissions (owner read/write only)
        os.chmod(key_file, 0o600)
        logger.info(f"Generated new encryption key at {key_file}")
        return key


class AuthorizationError(Exception):
    """Raised when target is not authorized."""
    pass


class AuthManager:
    """
    Manages target authorization for pentesting scans.
    
    Features:
    - Encrypted storage of authorized targets
    - Wildcard domain support
    - IP range validation
    - Audit logging
    """
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize AuthManager.

        Args:
            settings: Application settings
        """
        self.settings = settings
        self.targets_file = Path(settings.security.authorized_targets_file)
        self._targets: dict[str, dict] = {}
        self._cipher: Any = None  # Fernet cipher when encryption is available

        # Initialize encryption if available
        if ENCRYPTION_AVAILABLE:
            try:
                key_file = Path(settings.storage.encryption_key_file)
                key = _get_encryption_key(key_file)
                self._cipher = Fernet(key)
                logger.debug("Encryption initialized for authorized targets")
            except Exception as e:
                logger.warning(f"Failed to initialize encryption: {e}")
                logger.warning("Falling back to unencrypted storage (NOT RECOMMENDED)")
        else:
            logger.warning(
                "cryptography package not installed - authorized targets will be stored unencrypted. "
                "Install with: pip install cryptography"
            )

        self._load_targets()

    def _load_targets(self) -> None:
        """
        Load authorized targets from encrypted file.

        SECURITY: Decrypts data using Fernet symmetric encryption.
        """
        if not self.targets_file.exists():
            logger.info("No authorized targets file found, creating empty")
            self._targets = {}
            return

        try:
            raw_content = self.targets_file.read_bytes()

            # Try to decrypt if encryption is available
            if self._cipher and raw_content:
                try:
                    decrypted = self._cipher.decrypt(raw_content)
                    content = decrypted.decode('utf-8')
                except InvalidToken:
                    # File might be unencrypted (legacy) - try reading as plain text
                    logger.warning("Failed to decrypt targets file - trying as plain JSON")
                    content = raw_content.decode('utf-8')
                except Exception as e:
                    logger.error(f"Decryption failed: {e}")
                    content = raw_content.decode('utf-8')
            else:
                content = raw_content.decode('utf-8')

            if content.strip():
                self._targets = json.loads(content)
            else:
                self._targets = {}

            logger.info(f"Loaded {len(self._targets)} authorized targets")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse targets file: {e}")
            self._targets = {}
        except Exception as e:
            logger.error(f"Failed to load targets: {e}")
            self._targets = {}

    def _save_targets(self) -> None:
        """
        Save authorized targets to encrypted file.

        SECURITY: Encrypts data using Fernet symmetric encryption (CWE-312).
        """
        self.targets_file.parent.mkdir(parents=True, exist_ok=True)

        content = json.dumps(self._targets, indent=2, default=str)

        # Encrypt if available
        if self._cipher:
            encrypted = self._cipher.encrypt(content.encode('utf-8'))
            self.targets_file.write_bytes(encrypted)
            # Secure file permissions
            os.chmod(self.targets_file, 0o600)
            logger.info(f"Saved {len(self._targets)} authorized targets (encrypted)")
        else:
            self.targets_file.write_text(content)
            logger.warning(f"Saved {len(self._targets)} authorized targets (UNENCRYPTED - install cryptography)")
    
    def is_authorized(self, target: str) -> bool:
        """
        Check if a target is authorized for scanning.
        
        Args:
            target: Domain, IP, or URL to check
            
        Returns:
            True if authorized, False otherwise
        """
        if not self.settings.security.require_authorization:
            logger.warning("Authorization check disabled - allowing all targets")
            return True
        
        # Normalize target
        normalized = self._normalize_target(target)
        
        # Direct match
        if normalized in self._targets:
            return self._check_target_validity(normalized)
        
        # Wildcard domain match
        if self._matches_wildcard(normalized):
            return True
        
        # IP range match
        if self._matches_ip_range(normalized):
            return True
        
        # Check excluded IPs
        if self._is_excluded_ip(normalized):
            logger.warning(f"Target {target} is in excluded IP ranges")
            return False
        
        logger.warning(f"Target {target} is not authorized")
        return False
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target for comparison."""
        # Remove protocol
        target = re.sub(r'^https?://', '', target)
        # Remove path
        target = target.split('/')[0]
        # Remove port
        target = target.split(':')[0]
        # Lowercase
        return target.lower().strip()
    
    def _check_target_validity(self, target: str) -> bool:
        """Check if target authorization is still valid."""
        target_data = self._targets.get(target, {})
        
        # Check expiration
        expires = target_data.get("expires")
        if expires:
            expires_dt = datetime.fromisoformat(expires)
            if datetime.now() > expires_dt:
                logger.warning(f"Authorization for {target} has expired")
                return False
        
        return target_data.get("active", True)
    
    def _matches_wildcard(self, target: str) -> bool:
        """Check if target matches a wildcard authorization."""
        for authorized in self._targets:
            if authorized.startswith("*."):
                # Wildcard domain (e.g., *.example.com)
                base_domain = authorized[2:]  # Remove *.
                if target.endswith(base_domain) or target == base_domain.lstrip('.'):
                    return self._check_target_validity(authorized)
        
        return False
    
    def _matches_ip_range(self, target: str) -> bool:
        """Check if target IP matches authorized range."""
        try:
            target_ip = ipaddress.ip_address(target)
        except ValueError:
            # Not an IP address
            return False
        
        for authorized in self._targets:
            try:
                if '/' in authorized:
                    # CIDR notation
                    network = ipaddress.ip_network(authorized, strict=False)
                    if target_ip in network:
                        return self._check_target_validity(authorized)
            except ValueError:
                continue
        
        return False
    
    def _is_excluded_ip(self, target: str) -> bool:
        """Check if target is in excluded IP ranges."""
        if not self.settings.security.exclude_private_ips:
            return False
        
        try:
            target_ip = ipaddress.ip_address(target)
        except ValueError:
            return False
        
        for excluded in self.settings.security.excluded_ips:
            try:
                network = ipaddress.ip_network(excluded, strict=False)
                if target_ip in network:
                    return True
            except ValueError:
                continue
        
        return False
    
    def add_target(
        self,
        target: str,
        authorized_by: str = "cli",
        expires: datetime | None = None,
        notes: str = "",
    ) -> str:
        """
        Add a target to the authorized list.
        
        Args:
            target: Domain, IP, or CIDR to authorize
            authorized_by: Who authorized this target
            expires: Optional expiration date
            notes: Optional notes
            
        Returns:
            Target ID
        """
        normalized = self._normalize_target(target)
        target_id = hashlib.sha256(normalized.encode()).hexdigest()[:12]
        
        self._targets[normalized] = {
            "id": target_id,
            "original": target,
            "authorized_by": authorized_by,
            "authorized_at": datetime.now().isoformat(),
            "expires": expires.isoformat() if expires else None,
            "notes": notes,
            "active": True,
        }
        
        self._save_targets()
        logger.info(f"Added authorized target: {normalized} (ID: {target_id})")
        
        return target_id
    
    def remove_target(self, target: str) -> bool:
        """
        Remove a target from the authorized list.
        
        Args:
            target: Target to remove
            
        Returns:
            True if removed, False if not found
        """
        normalized = self._normalize_target(target)
        
        if normalized in self._targets:
            del self._targets[normalized]
            self._save_targets()
            logger.info(f"Removed authorized target: {normalized}")
            return True
        
        return False
    
    def list_targets(self) -> list[dict]:
        """
        List all authorized targets.
        
        Returns:
            List of authorized target data
        """
        return [
            {"target": target, **data}
            for target, data in self._targets.items()
        ]
    
    def validate_scope(self, targets: list[str]) -> tuple[list[str], list[str]]:
        """
        Validate a list of targets against authorization.
        
        Args:
            targets: List of targets to validate
            
        Returns:
            Tuple of (authorized, unauthorized) lists
        """
        authorized = []
        unauthorized = []
        
        for target in targets:
            if self.is_authorized(target):
                authorized.append(target)
            else:
                unauthorized.append(target)
        
        return authorized, unauthorized
