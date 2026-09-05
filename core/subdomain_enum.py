"""Subdomain enumeration module"""
import asyncio
import aiohttp
import aiodns
import shutil
import socket
from typing import List, Set, Optional, Dict
import ssl
import certifi
from core.scope import ScopePolicy


class SubdomainEnumerator:
    """Advanced subdomain enumeration tool"""
    
    # Common subdomain wordlist
    DEFAULT_WORDLIST = [
        'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'staging', 'test',
        'api', 'app', 'portal', 'secure', 'vpn', 'remote', 'shop', 'store',
        'support', 'help', 'cdn', 'static', 'media', 'images', 'files',
        'download', 'uploads', 'beta', 'demo', 'mobile', 'webmail', 'mx',
        'ns1', 'ns2', 'dns', 'cpanel', 'whm', 'forum', 'community'
    ]
    
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        self.resolver = aiodns.DNSResolver()
        self.found_subdomains: Set[str] = set()
        self.subdomain_sources: Dict[str, Set[str]] = {}
        self._verification_semaphore = asyncio.Semaphore(50)
        scope = config.get('scope', {})
        self.scope = ScopePolicy(scope.get('allowed_hosts', []), scope.get('excluded_paths', []))
    
    async def enumerate(self, domain: str, wordlist_file: Optional[str] = None) -> List[str]:
        """Enumerate subdomains using multiple techniques"""
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        self.found_subdomains = set()
        self.subdomain_sources = {}
        self._verification_semaphore = asyncio.Semaphore(50)
        
        # Load wordlist
        wordlist = await self._load_wordlist(wordlist_file)
        
        # Run enumeration techniques
        tasks = [
            self._assetfinder(domain),
            self._dns_bruteforce(domain, wordlist),
            self._certificate_transparency(domain),
            self._dns_dumpster(domain)
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.logger.info(f"Found {len(self.found_subdomains)} subdomains")
        return sorted(list(self.found_subdomains))

    def source_details(self) -> Dict[str, List[str]]:
        """Return reproducible discovery sources for report generation."""
        return {host: sorted(sources) for host, sources in sorted(self.subdomain_sources.items())}
    
    async def _load_wordlist(self, wordlist_file: Optional[str]) -> List[str]:
        """Load subdomain wordlist"""
        if wordlist_file:
            try:
                with open(wordlist_file, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.logger.warning(f"Failed to load wordlist: {e}")
        
        return self.DEFAULT_WORDLIST
    
    async def _dns_bruteforce(self, domain: str, wordlist: List[str]):
        """Brute-force subdomains using DNS queries"""
        self.logger.info("[*] DNS brute-force enumeration...")
        
        semaphore = asyncio.Semaphore(50)
        tasks = [self._check_subdomain(f"{word}.{domain}", semaphore) for word in wordlist]
        
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _assetfinder(self, domain: str):
        """Use Assetfinder as the default passive source when installed.

        Assetfinder output is treated as a candidate list only: every hostname
        is normalized, scope-checked, and DNS-verified before persistence.
        """
        self.logger.info("[*] Assetfinder passive subdomain enumeration...")
        executable = shutil.which("assetfinder")
        if not executable:
            self.logger.warning("Assetfinder is not installed; continuing with built-in passive sources")
            return
        try:
            process = await asyncio.create_subprocess_exec(
                executable, "--subs-only", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=float(self.config.get('scanning', {}).get('tool_timeout', 120)),
            )
            if process.returncode != 0:
                self.logger.warning(f"Assetfinder exited with status {process.returncode}")
            for line in stdout.decode(errors='replace').splitlines():
                candidate = line.strip().lower().rstrip('.')
                if self._is_candidate(candidate, domain):
                    await self._verify_and_record(candidate, domain, "assetfinder")
        except asyncio.TimeoutError:
            self.logger.warning("Assetfinder timed out")
        except Exception as exc:
            self.logger.warning(f"Assetfinder failed: {exc}")

    @staticmethod
    def _is_candidate(candidate: str, domain: str) -> bool:
        domain = domain.lower().rstrip('.')
        if not candidate or candidate == domain or not candidate.endswith('.' + domain):
            return False
        return all(part and part.replace('-', '').isalnum() for part in candidate.split('.'))

    async def _verify_and_record(self, subdomain: str, parent: str, source: str):
        if not self.scope.is_allowed_discovered_host(subdomain, parent):
            return
        async with self._verification_semaphore:
            if await self._resolves(subdomain):
                self.found_subdomains.add(subdomain)
                self.subdomain_sources.setdefault(subdomain, set()).add(source)
                # Individual candidates are useful in the verbose audit log,
                # but are noise in normal mode; the phase summary remains
                # visible to all users.
                self.logger.debug(f"[+] Found ({source}): {subdomain}")

    async def _resolves(self, hostname: str) -> bool:
        for record_type in ('A', 'AAAA', 'CNAME'):
            try:
                if await self.resolver.query(hostname, record_type):
                    return True
            except Exception:
                continue
        # Local labs commonly define subdomains in /etc/hosts rather than DNS.
        try:
            loop = asyncio.get_running_loop()
            await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            return True
        except Exception:
            return False
    
    async def _check_subdomain(self, subdomain: str, semaphore: asyncio.Semaphore):
        """Check if subdomain exists via DNS lookup"""
        parent = subdomain.split('.', 1)[1]
        if not self.scope.is_allowed_discovered_host(subdomain, parent):
            return
        async with semaphore:
            await self._verify_and_record(subdomain, parent, "dns-bruteforce")
    
    async def _certificate_transparency(self, domain: str):
        """Query certificate transparency logs"""
        self.logger.info("[*] Checking certificate transparency logs...")
        
        try:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url, ssl=ssl_context, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry.get('name_value', '')
                            for subdomain in name.split('\n'):
                                subdomain = subdomain.strip()
                                subdomain = subdomain.lower().rstrip('.')
                                if self._is_candidate(subdomain, domain):
                                    await self._verify_and_record(subdomain, domain, "crt.sh")
        except Exception as e:
            self.logger.warning(f"Certificate transparency check failed: {e}")
    
    async def _dns_dumpster(self, domain: str):
        """Query DNSDumpster API"""
        # Note: This is a placeholder. Actual implementation would require
        # proper DNSDumpster API integration or web scraping
        self.logger.info("[*] Checking additional sources...")
        pass
