"""Port scanning module"""
import asyncio
import socket
from typing import List, Dict, Optional
import struct


class PortScanner:
    """Advanced port scanner with service detection"""
    
    # Common ports and their services
    COMMON_PORTS = {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
        53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap', 443: 'https',
        445: 'smb', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
        5900: 'vnc', 6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
        27017: 'mongodb', 9200: 'elasticsearch'
    }
    
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        scanning = config.get('scanning', {})
        # Port connection timeouts should be short and independent from the
        # slower HTTP response timeout; otherwise a filtered port range can
        # make a vulnerability-only scan appear to hang.
        self.timeout = scanning.get('port_timeout', min(scanning.get('timeout', 5), 5))
        self.threads = config.get('scanning', {}).get('threads', 50)
    
    async def scan(self, target: str, port_range: str) -> List[Dict]:
        """Scan ports on target"""
        self.logger.info(f"Starting port scan on {target}")
        
        # Parse port range
        ports = self._parse_port_range(port_range)
        
        # Resolve target to IP
        try:
            ip = socket.gethostbyname(target)
            self.logger.info(f"Resolved {target} to {ip}")
        except socket.gaierror:
            self.logger.error(f"Failed to resolve {target}")
            return []
        
        # Create scanning tasks
        semaphore = asyncio.Semaphore(self.threads)
        tasks = [self._scan_port(ip, port, semaphore) for port in ports]
        
        # Execute scans
        results = await asyncio.gather(*tasks)
        
        # Filter open ports
        open_ports = [r for r in results if r and r.get('state') == 'open']
        
        return open_ports
    
    async def _scan_port(self, ip: str, port: int, semaphore: asyncio.Semaphore) -> Optional[Dict]:
        """Scan a single port"""
        async with semaphore:
            try:
                # Create connection
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                
                # Grab banner
                banner = await self._grab_banner(reader, writer)
                
                # Detect service
                service = self._detect_service(port, banner)
                
                writer.close()
                await writer.wait_closed()
                
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner,
                    # A port number is only a service hint. Do not present
                    # the IANA default as proof that FTP/Telnet/etc. is
                    # actually running; many hosts accept TCP and expose no
                    # application banner (and proxies can make this worse).
                    'service_confidence': 'high' if banner else 'low',
                    'service_source': 'banner' if banner else 'port mapping only',
                    'protocol': 'tcp'
                }
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
    
    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> str:
        """Attempt to grab service banner"""
        try:
            # Try to read banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return ''
    
    def _detect_service(self, port: int, banner: str) -> str:
        """Detect service based on port and banner"""
        # Check common ports
        service = self.COMMON_PORTS.get(port, 'unknown')
        
        # Refine based on banner
        if banner:
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                service = 'ssh'
            elif 'http' in banner_lower or 'html' in banner_lower:
                service = 'http'
            elif 'ftp' in banner_lower:
                service = 'ftp'
            elif 'smtp' in banner_lower:
                service = 'smtp'
            elif 'mysql' in banner_lower:
                service = 'mysql'
        
        return service
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range string to list of ports"""
        ports = []
        
        for part in port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        return sorted(set(ports))
