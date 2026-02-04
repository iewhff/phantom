"""
Subdomain enumeration using multiple techniques.
Combines passive and active methods for comprehensive discovery.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import aiohttp
import dns.resolver
from tenacity import retry, stop_after_attempt, wait_exponential

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class SubdomainEnumerator:
    """
    Enumerate subdomains using multiple techniques:
    - Certificate Transparency logs (crt.sh)
    - DNS brute force
    - Public APIs (optional)
    
    Results are validated by DNS resolution.
    """
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize enumerator.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.config = settings.reconnaissance.subdomains
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5
    
    async def enumerate(self, domain: str) -> set[str]:
        """
        Enumerate all subdomains for a domain.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of discovered subdomains
        """
        logger.info(f"Starting subdomain enumeration for {domain}")
        subdomains: set[str] = set()
        
        # Run enumeration techniques in parallel
        tasks = [
            self._crt_sh(domain),
            self._dns_bruteforce(domain),
        ]
        
        # Optional: VirusTotal
        if self.config.use_virustotal and self.settings.apis.virustotal_key:
            tasks.append(self._virustotal(domain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"Subdomain enumeration method failed: {result}")
                continue
            subdomains.update(result)
        
        # Validate subdomains resolve
        valid = await self._validate_subdomains(list(subdomains))
        
        logger.info(f"Found {len(valid)} valid subdomains for {domain}")
        return valid
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def _crt_sh(self, domain: str) -> set[str]:
        """
        Query Certificate Transparency logs via crt.sh.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of discovered subdomains
        """
        if not self.config.use_crt_sh:
            return set()
        
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subdomains: set[str] = set()
        
        timeout = aiohttp.ClientTimeout(total=30)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        logger.warning(f"crt.sh returned status {resp.status}")
                        return set()
                    
                    data = await resp.json()
                    
                    for entry in data:
                        name = entry.get("name_value", "")
                        # Skip wildcards and extract all names
                        for subdomain in name.split("\n"):
                            subdomain = subdomain.strip().lower()
                            if subdomain and not subdomain.startswith("*"):
                                if subdomain.endswith(domain):
                                    subdomains.add(subdomain)
            
            logger.info(f"crt.sh found {len(subdomains)} subdomains")
            return subdomains
            
        except asyncio.TimeoutError:
            logger.warning("crt.sh request timed out")
            raise
        except Exception as e:
            logger.warning(f"crt.sh query failed: {e}")
            raise
    
    async def _dns_bruteforce(self, domain: str) -> set[str]:
        """
        Brute force subdomains using wordlist.

        Args:
            domain: Target domain

        Returns:
            Set of discovered subdomains
        """
        from pathlib import Path

        wordlist_path = Path(self.config.wordlist)

        # Try fallback wordlist if main doesn't exist
        if not wordlist_path.exists():
            logger.warning(f"Wordlist not found: {wordlist_path}")
            # Try fallback if available
            fallback = getattr(self.config, 'wordlist_fallback', None)
            if fallback:
                wordlist_path = Path(fallback)
                if wordlist_path.exists():
                    logger.info(f"Using fallback wordlist: {wordlist_path}")
                else:
                    logger.warning(f"Fallback wordlist not found: {wordlist_path}")
                    return set()
            else:
                return set()
        
        # Read wordlist
        with open(wordlist_path) as f:
            words = [line.strip() for line in f if line.strip()]
        
        logger.info(f"DNS bruteforce with {len(words)} words")
        
        # Limit concurrency
        semaphore = asyncio.Semaphore(self.config.concurrent_resolvers)
        found: set[str] = set()
        
        async def check_subdomain(word: str) -> str | None:
            async with semaphore:
                subdomain = f"{word}.{domain}"
                try:
                    # Run DNS query in executor
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None,
                        self.resolver.resolve,
                        subdomain,
                        "A",
                    )
                    return subdomain
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers, dns.resolver.Timeout):
                    return None
                except Exception:
                    return None
        
        # Process in batches
        batch_size = 500
        for i in range(0, len(words), batch_size):
            batch = words[i:i + batch_size]
            tasks = [check_subdomain(word) for word in batch]
            results = await asyncio.gather(*tasks)
            
            for result in results:
                if result:
                    found.add(result)
        
        logger.info(f"DNS bruteforce found {len(found)} subdomains")
        return found
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def _virustotal(self, domain: str) -> set[str]:
        """
        Query VirusTotal for subdomains.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of discovered subdomains
        """
        api_key = self.settings.apis.virustotal_key
        if not api_key:
            return set()
        
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        headers = {"x-apikey": api_key}
        
        subdomains: set[str] = set()
        timeout = aiohttp.ClientTimeout(total=30)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status != 200:
                        return set()
                    
                    data = await resp.json()
                    
                    for item in data.get("data", []):
                        subdomain = item.get("id", "")
                        if subdomain:
                            subdomains.add(subdomain)
            
            logger.info(f"VirusTotal found {len(subdomains)} subdomains")
            return subdomains
            
        except Exception as e:
            logger.warning(f"VirusTotal query failed: {e}")
            return set()
    
    async def _validate_subdomains(self, subdomains: list[str]) -> set[str]:
        """
        Validate subdomains by DNS resolution.
        
        Args:
            subdomains: List of subdomains to validate
            
        Returns:
            Set of valid (resolving) subdomains
        """
        semaphore = asyncio.Semaphore(100)
        valid: set[str] = set()
        
        async def validate(subdomain: str) -> str | None:
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None,
                        self.resolver.resolve,
                        subdomain,
                        "A",
                    )
                    return subdomain
                except Exception:
                    return None
        
        tasks = [validate(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                valid.add(result)
        
        return valid
