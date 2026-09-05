"""WAF Detection Module"""
import asyncio
import aiohttp
import ssl
import certifi
from typing import Dict, Any, Optional


class WAFDetector:
    """Web Application Firewall detector"""
    
    # Common WAF signatures
    WAF_SIGNATURES = {
        'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
        'AWS WAF': ['awswaf', 'x-amzn-requestid', 'x-amz-cf-id'],
        'Akamai': ['akamai', 'ak-bmsc'],
        'Incapsula': ['incapsula', 'x-iinfo', 'visid_incap'],
        'ModSecurity': ['mod_security', 'naxsi'],
        'F5 BIG-IP': ['bigip', 'f5-', 'tmui'],
        'Sucuri': ['sucuri', 'x-sucuri'],
        'Barracuda': ['barracuda', 'barra_counter_session'],
        'Fortinet': ['fortigate', 'fortiweb'],
        'Imperva': ['imperva', 'x-cdn'],
    }
    
    # Test payloads to trigger WAF
    TEST_PAYLOADS = [
        "' OR '1'='1",
        "<script>alert('xss')</script>",
        "../../../etc/passwd",
        "UNION SELECT NULL--",
    ]
    
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        self.timeout = config.get('scanning', {}).get('timeout', 10)

    def _ssl_context(self):
        """Use trusted TLS by default; allow bypass only by explicit flag."""
        if self.config.get('scanning', {}).get('insecure_tls', False):
            return False
        return ssl.create_default_context(cafile=certifi.where())
    
    async def detect(self, target: str) -> Dict[str, Any]:
        """Detect if target is protected by a WAF"""
        self.logger.info(f"Detecting WAF for {target}")
        
        if not target.startswith('http'):
            target = f"http://{target}"
        
        # Perform detection
        waf_info = {
            'detected': False,
            'name': None,
            'confidence': 'low',
            'signatures': [],
            'behavior': []
        }
        
        try:
            # Check headers and cookies
            header_waf = await self._check_headers(target)
            if header_waf:
                waf_info['detected'] = True
                waf_info['name'] = header_waf
                waf_info['confidence'] = 'high'
                waf_info['signatures'].append(f"Header signature: {header_waf}")
            
            # Check behavior with test payloads
            if not waf_info['detected']:
                behavior_waf = await self._check_behavior(target)
                if behavior_waf:
                    waf_info['detected'] = True
                    waf_info['name'] = behavior_waf.get('name', 'Unknown WAF')
                    waf_info['confidence'] = behavior_waf.get('confidence', 'medium')
                    waf_info['behavior'] = behavior_waf.get('patterns', [])
        
        except Exception as e:
            self.logger.debug(f"WAF detection error: {e}")
        
        return waf_info
    
    async def _check_headers(self, target: str) -> Optional[str]:
        """Check response headers for WAF signatures"""
        try:
            ssl_context = self._ssl_context()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    target,
                    ssl=ssl_context,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=False
                ) as response:
                    headers_str = ' '.join([f"{k}:{v}" for k, v in response.headers.items()]).lower()
                    cookies_str = ' '.join(response.cookies.keys()).lower()
                    
                    # Check for WAF signatures in headers and cookies
                    for waf_name, signatures in self.WAF_SIGNATURES.items():
                        for sig in signatures:
                            if sig.lower() in headers_str or sig.lower() in cookies_str:
                                self.logger.info(f"[+] WAF detected via headers: {waf_name}")
                                return waf_name
        
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.logger.debug(f"Header check error: {e}")
        except Exception as e:
            self.logger.debug(f"Unexpected error in header check: {e}")
        
        return None
    
    async def _check_behavior(self, target: str) -> Optional[Dict[str, Any]]:
        """Check WAF behavior by sending test payloads"""
        try:
            ssl_context = self._ssl_context()
            
            # Get baseline response
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        target,
                        ssl=ssl_context,
                        timeout=aiohttp.ClientTimeout(total=self.timeout)
                    ) as baseline_response:
                        baseline_status = baseline_response.status
                        baseline_text = await baseline_response.text()
                except:
                    return None
                
                # Test with payloads
                blocked_count = 0
                block_patterns = []
                
                for payload in self.TEST_PAYLOADS:
                    try:
                        test_url = f"{target}?test={payload}"
                        async with session.get(
                            test_url,
                            ssl=ssl_context,
                            timeout=aiohttp.ClientTimeout(total=self.timeout)
                        ) as test_response:
                            status = test_response.status
                            text = await test_response.text()
                            
                            # Check for blocking behavior
                            if status in [403, 406, 419, 429, 503]:
                                blocked_count += 1
                                block_patterns.append(f"Status {status} for payload")
                            
                            # Check for WAF-specific block pages
                            text_lower = text.lower()
                            if any(word in text_lower for word in ['blocked', 'forbidden', 'access denied', 'firewall']):
                                blocked_count += 1
                                block_patterns.append("WAF block page detected")
                    
                    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                        self.logger.debug(f"Payload test error: {e}")
                    except Exception as e:
                        self.logger.debug(f"Unexpected error in payload test: {e}")
                
                # If multiple payloads were blocked, likely a WAF
                if blocked_count >= 2:
                    self.logger.info(f"[+] WAF detected via behavior ({blocked_count} payloads blocked)")
                    return {
                        'name': 'Unknown WAF',
                        'confidence': 'medium' if blocked_count >= 3 else 'low',
                        'patterns': block_patterns
                    }
        
        except Exception as e:
            self.logger.debug(f"Behavior check error: {e}")
        
        return None
