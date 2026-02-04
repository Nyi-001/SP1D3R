"""Subdomain enumeration module"""
import asyncio
import aiohttp
import aiodns
from typing import List, Set, Optional
import ssl
import certifi


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
    
    async def enumerate(self, domain: str, wordlist_file: Optional[str] = None) -> List[str]:
        """Enumerate subdomains using multiple techniques"""
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        
        # Load wordlist
        wordlist = await self._load_wordlist(wordlist_file)
        
        # Run enumeration techniques
        tasks = [
            self._dns_bruteforce(domain, wordlist),
            self._certificate_transparency(domain),
            self._dns_dumpster(domain)
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.logger.info(f"Found {len(self.found_subdomains)} subdomains")
        return sorted(list(self.found_subdomains))
    
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
    
    async def _check_subdomain(self, subdomain: str, semaphore: asyncio.Semaphore):
        """Check if subdomain exists via DNS lookup"""
        async with semaphore:
            try:
                result = await self.resolver.query(subdomain, 'A')
                if result:
                    self.found_subdomains.add(subdomain)
                    self.logger.info(f"[+] Found: {subdomain}")
            except:
                pass
    
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
                                if subdomain and domain in subdomain and '*' not in subdomain:
                                    self.found_subdomains.add(subdomain)
                                    self.logger.info(f"[+] Found (CT): {subdomain}")
        except Exception as e:
            self.logger.warning(f"Certificate transparency check failed: {e}")
    
    async def _dns_dumpster(self, domain: str):
        """Query DNSDumpster API"""
        # Note: This is a placeholder. Actual implementation would require
        # proper DNSDumpster API integration or web scraping
        self.logger.info("[*] Checking additional sources...")
        pass