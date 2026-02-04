"""
Port scanner with nmap and masscan integration.
Provides async port scanning with flexible options.

Features:
- nmap: Comprehensive port scanning with service detection
- masscan: Ultra-fast port scanning (1000+ ports/sec)
- Hybrid mode: masscan for discovery, nmap for service detection
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)

# Check for masscan availability
_MASSCAN_AVAILABLE = shutil.which("masscan") is not None


class PortState(str, Enum):
    """Port state enumeration."""
    
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


@dataclass
class PortInfo:
    """Information about a discovered port."""
    
    port: int
    state: PortState
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "port": self.port,
            "state": self.state.value,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "product": self.product,
            "extra_info": self.extra_info,
        }


class PortScanner:
    """
    Async port scanner using nmap.
    
    Supports:
    - TCP SYN scan (requires root)
    - TCP connect scan
    - UDP scan
    - Service/version detection
    - Configurable timing and ports
    """
    
    # Common port sets
    TOP_100 = "1-100,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443"
    TOP_1000 = "1-1000,1433,1521,3306,3389,5432,5900,8000,8080,8443,8888"
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize scanner.

        Args:
            settings: Application settings
        """
        self.settings = settings
        self.config = settings.reconnaissance.ports
        self.nmap_path = settings.tools.nmap
        self.masscan_available = _MASSCAN_AVAILABLE
        self.use_masscan = getattr(settings, 'use_masscan_fast_scan', True) and self.masscan_available
    
    async def scan(
        self,
        host: str,
        ports: str = "top1000",
        scan_type: str | None = None,
    ) -> list[PortInfo]:
        """
        Scan ports on a host.
        
        Args:
            host: Target hostname or IP
            ports: Port specification (top100, top1000, all, or custom)
            scan_type: Override scan type (syn, connect, udp)
            
        Returns:
            List of PortInfo for open ports
        """
        # Resolve port specification
        port_spec = self._resolve_ports(ports)
        scan_type = scan_type or self.config.scan_type
        
        logger.info(f"Scanning {host} - ports: {ports}, type: {scan_type}")
        
        # Build nmap command
        cmd = self._build_command(host, port_spec, scan_type)
        
        # Execute scan
        try:
            result = await self._execute_scan(cmd)
            ports_found = self._parse_output(result)
            
            logger.info(f"Found {len(ports_found)} open ports on {host}")
            return ports_found
            
        except Exception as e:
            logger.error(f"Port scan failed for {host}: {e}")
            raise
    
    def _resolve_ports(self, ports: str) -> str:
        """Resolve port specification to nmap format."""
        ports_lower = ports.lower()
        
        if ports_lower == "top100":
            return self.TOP_100
        elif ports_lower == "top1000":
            return self.TOP_1000
        elif ports_lower == "all":
            return "1-65535"
        else:
            # Custom specification, validate
            if re.match(r'^[\d,\-\s]+$', ports):
                return ports
            else:
                logger.warning(f"Invalid port spec: {ports}, using top1000")
                return self.TOP_1000
    
    def _build_command(
        self,
        host: str,
        ports: str,
        scan_type: str,
    ) -> list[str]:
        """Build nmap command."""
        cmd = [self.nmap_path]
        
        # Scan type
        if scan_type == "syn":
            cmd.append("-sS")
        elif scan_type == "udp":
            cmd.append("-sU")
        else:  # connect
            cmd.append("-sT")
        
        # Timing
        cmd.append(f"-T{self.config.timing}")
        
        # Service detection
        cmd.append("-sV")
        cmd.append("--version-light")
        
        # Output format
        cmd.extend(["-oG", "-"])  # Grepable output to stdout
        
        # Ports
        cmd.extend(["-p", ports])
        
        # No DNS resolution
        cmd.append("-n")
        
        # Host
        cmd.append(host)
        
        return cmd
    
    async def _execute_scan(self, cmd: list[str]) -> str:
        """Execute nmap scan."""
        timeout = self.settings.timeouts.port_scan
        
        logger.debug(f"Executing: {' '.join(cmd)}")
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise TimeoutError(f"Port scan timed out after {timeout}s")
        
        if proc.returncode != 0:
            error = stderr.decode().strip()
            # Nmap returns 1 sometimes for no open ports, check if output exists
            if not stdout:
                raise RuntimeError(f"nmap failed: {error}")
        
        return stdout.decode()
    
    def _parse_output(self, output: str) -> list[PortInfo]:
        """Parse nmap grepable output."""
        ports: list[PortInfo] = []
        
        # Grepable format: Host: 1.2.3.4 ()  Ports: 22/open/tcp//ssh//
        port_pattern = re.compile(
            r'(\d+)/(\w+)/(\w+)//([^/]*)/([^/]*)/([^/]*)'
        )
        
        for line in output.split('\n'):
            if 'Ports:' not in line:
                continue
            
            # Extract ports section
            ports_section = line.split('Ports:')[-1].strip()
            
            for match in port_pattern.finditer(ports_section):
                port_num = int(match.group(1))
                state_str = match.group(2)
                protocol = match.group(3)
                service = match.group(4)
                product = match.group(5)
                version = match.group(6)
                
                state = PortState(state_str) if state_str in PortState._value2member_map_ else PortState.UNKNOWN
                
                # Only include open ports
                if state == PortState.OPEN:
                    ports.append(PortInfo(
                        port=port_num,
                        state=state,
                        protocol=protocol,
                        service=service,
                        product=product,
                        version=version,
                    ))
        
        return ports

    async def scan_with_masscan(
        self,
        host: str,
        ports: str = "1-65535",
        rate: int = 1000,
    ) -> list[PortInfo]:
        """
        Fast port scan using masscan.

        Masscan is much faster than nmap for port discovery but
        doesn't provide service detection. Use hybrid_scan() for
        fast discovery + service detection.

        Args:
            host: Target hostname or IP
            ports: Port specification (default: all ports)
            rate: Packets per second (default: 1000)

        Returns:
            List of PortInfo for open ports (no service info)
        """
        if not self.masscan_available:
            logger.warning("[PortScanner] masscan not available, falling back to nmap")
            return await self.scan(host, ports)

        logger.info(f"[PortScanner] Fast masscan on {host} - rate: {rate} pps")

        # Build masscan command
        cmd = [
            "masscan",
            host,
            "-p", self._resolve_ports(ports),
            "--rate", str(rate),
            "-oJ", "-",  # JSON output to stdout
            "--wait", "3",  # Wait 3 seconds for responses
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300,  # 5 min timeout for full scan
            )

            return self._parse_masscan_output(stdout.decode())

        except asyncio.TimeoutError:
            logger.warning("[PortScanner] masscan timed out")
            return []
        except Exception as e:
            logger.error(f"[PortScanner] masscan error: {e}")
            return []

    def _parse_masscan_output(self, output: str) -> list[PortInfo]:
        """Parse masscan JSON output."""
        ports: list[PortInfo] = []

        # Masscan JSON has trailing commas, fix and parse
        try:
            # Clean up masscan's malformed JSON
            output = output.strip()
            if output.endswith(","):
                output = output[:-1]
            if not output.startswith("["):
                output = "[" + output
            if not output.endswith("]"):
                output = output + "]"

            # Fix internal trailing commas
            output = re.sub(r',\s*\]', ']', output)
            output = re.sub(r',\s*\}', '}', output)

            data = json.loads(output) if output.strip() not in ["", "[]"] else []

            for entry in data:
                ip = entry.get("ip", "")
                for port_info in entry.get("ports", []):
                    port_num = port_info.get("port", 0)
                    status = port_info.get("status", "")
                    proto = port_info.get("proto", "tcp")

                    if status == "open":
                        ports.append(PortInfo(
                            port=port_num,
                            state=PortState.OPEN,
                            protocol=proto,
                            service="",  # masscan doesn't detect services
                            version="",
                            product="",
                            extra_info=f"Discovered by masscan on {ip}",
                        ))

        except json.JSONDecodeError as e:
            logger.debug(f"[PortScanner] masscan JSON parse error: {e}")

        return ports

    async def hybrid_scan(
        self,
        host: str,
        ports: str = "1-65535",
        masscan_rate: int = 1000,
    ) -> list[PortInfo]:
        """
        Hybrid scan: masscan for fast discovery, nmap for service detection.

        This combines the speed of masscan with the accuracy of nmap:
        1. Use masscan to quickly find all open ports
        2. Use nmap to detect services on discovered ports

        Args:
            host: Target hostname or IP
            ports: Port specification for masscan
            masscan_rate: Masscan packets per second

        Returns:
            List of PortInfo with service information
        """
        if not self.masscan_available:
            logger.info("[PortScanner] masscan not available, using nmap only")
            return await self.scan(host, ports)

        logger.info(f"[PortScanner] Hybrid scan on {host}")

        # Phase 1: Fast port discovery with masscan
        logger.info("[PortScanner] Phase 1: Fast port discovery with masscan")
        discovered_ports = await self.scan_with_masscan(host, ports, masscan_rate)

        if not discovered_ports:
            logger.info("[PortScanner] No open ports found")
            return []

        # Phase 2: Service detection with nmap on discovered ports
        port_list = ",".join(str(p.port) for p in discovered_ports)
        logger.info(f"[PortScanner] Phase 2: Service detection on {len(discovered_ports)} ports")

        detailed_ports = await self.scan(host, port_list, scan_type="connect")

        logger.info(f"[PortScanner] Hybrid scan complete: {len(detailed_ports)} ports with services")
        return detailed_ports

    async def quick_scan(self, host: str) -> list[int]:
        """
        Quick scan for common ports.
        
        Args:
            host: Target host
            
        Returns:
            List of open port numbers
        """
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                       3306, 3389, 5432, 8080, 8443]
        
        open_ports: list[int] = []
        
        async def check_port(port: int) -> int | None:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=3,
                )
                writer.close()
                await writer.wait_closed()
                return port
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
        
        tasks = [check_port(p) for p in common_ports]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                open_ports.append(result)
        
        return open_ports
