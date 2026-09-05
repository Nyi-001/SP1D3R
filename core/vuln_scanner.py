"""Vulnerability scanning module"""
import asyncio
import aiohttp
from typing import List, Dict
import re
import ssl
import certifi


class VulnerabilityScanner:
    """Vulnerability detection and CVE checking"""
    
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
    
    async def scan(self, target: str, cve_check: bool = False) -> Dict:
        """Scan for vulnerabilities"""
        self.logger.info("Starting vulnerability scan")
        
        findings = []
        
        # Run vulnerability checks
        tasks = [
            self._check_common_misconfigs(target),
            self._check_default_credentials(target),
            self._check_directory_listing(target)
        ]
        
        if cve_check:
            tasks.append(self._check_known_cves(target))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect findings
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
        
        return {'findings': findings}
    
    async def _check_common_misconfigs(self, target: str) -> List[Dict]:
        """Check for common misconfigurations"""
        findings = []
        
        # Add protocol if missing
        if not target.startswith('http'):
            target = f"http://{target}"
        
        try:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            async with aiohttp.ClientSession() as session:
                # Check for exposed .git directory
                async with session.get(f"{target}/.git/config", ssl=ssl_context, timeout=10) as response:
                    if response.status == 200:
                        findings.append({
                            'type': 'Information Disclosure',
                            'severity': 'high',
                            'title': 'Exposed .git directory',
                            'description': 'Git repository is publicly accessible',
                            'location': f"{target}/.git/",
                            'remediation': 'Block access to .git directory in web server configuration'
                        })
        except:
            pass
        
        return findings
    
    async def _check_default_credentials(self, target: str) -> List[Dict]:
        """Check for default credentials"""
        findings = []
        
        # Common default credential pairs
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'root'),
            ('admin', ''),
        ]
        
        # This is a placeholder - actual implementation would test login endpoints
        # with proper rate limiting and error handling
        
        return findings
    
    async def _check_directory_listing(self, target: str) -> List[Dict]:
        """Check for directory listing vulnerabilities"""
        findings = []
        
        common_dirs = ['/uploads', '/files', '/backup', '/admin', '/test']
        
        if not target.startswith('http'):
            target = f"http://{target}"
        
        try:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            async with aiohttp.ClientSession() as session:
                for directory in common_dirs:
                    try:
                        async with session.get(f"{target}{directory}/", ssl=ssl_context, timeout=10) as response:
                            text = await response.text()
                            if 'Index of' in text or 'Directory listing' in text:
                                findings.append({
                                    'type': 'Information Disclosure',
                                    'severity': 'medium',
                                    'title': f'Directory listing enabled: {directory}',
                                    'description': f'Directory {directory} shows file listing',
                                    'location': f"{target}{directory}/",
                                    'remediation': 'Disable directory listing in web server configuration'
                                })
                    except:
                        pass
        except Exception as e:
            self.logger.debug(f"Directory listing check error: {e}")
        
        return findings
    
    async def _check_known_cves(self, target: str) -> List[Dict]:
        """Keep the optional legacy hook non-invasive.

        Version-aware CVE correlation is performed by ``CVESuggestionMatcher``
        after fingerprinting and port discovery complete. It is intentionally
        kept separate from confirmed findings.
        """
        self.logger.info("Version-based CVE suggestions are generated from discovered fingerprints")
        return []
