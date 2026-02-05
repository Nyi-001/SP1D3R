"""Web Application Security Testing Module"""
import asyncio
import aiohttp
import ssl
import certifi
import re
from typing import Dict, Any, List, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup


class WebScanner:
    """Web application vulnerability scanner"""
    
    # SQL Injection test payloads
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "1' AND '1'='2",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(5)--",
    ]
    
    # XSS test payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "'><script>alert(String.fromCharCode(88,83,83))</script>",
    ]
    
    # Common vulnerable parameters
    COMMON_PARAMS = [
        'id', 'page', 'query', 'search', 'file', 'path', 'redirect',
        'url', 'view', 'cat', 'action', 'item', 'pid', 'user'
    ]
    
    # Directory traversal payloads
    TRAVERSAL_PAYLOADS = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    ]
    
    # SQL error signatures
    SQL_ERRORS = [
        r'SQL syntax.*MySQL',
        r'Warning.*mysql_.*',
        r'MySQLSyntaxErrorException',
        r'valid MySQL result',
        r'PostgreSQL.*ERROR',
        r'Warning.*pg_.*',
        r'valid PostgreSQL result',
        r'Npgsql\.',
        r'Driver.*SQL[\-\_\ ]*Server',
        r'OLE DB.*SQL Server',
        r'(\bSQL Server\b).*(\bDriver\b)',
        r'Warning.*mssql_.*',
        r'Microsoft SQL Native Client error',
        r'ODBC SQL Server Driver',
        r'SQLServer JDBC Driver',
        r'Oracle error',
        r'Oracle.*Driver',
        r'Warning.*oci_.*',
        r'Warning.*ora_.*',
    ]
    
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        self.timeout = config.get('scanning', {}).get('timeout', 10)
        self.user_agent = config.get('scanning', {}).get('user_agent', 'Mozilla/5.0')
        self.crawled_urls: Set[str] = set()
        self.findings = []
    
    async def scan(self, target: str, test_sqli: bool = False, test_xss: bool = False) -> Dict[str, Any]:
        """Perform comprehensive web application scan"""
        self.logger.info(f"Starting web application scan on {target}")
        
        if not target.startswith('http'):
            target = f"http://{target}"
        
        self.findings = []
        
        # Always run these tests
        await self._check_security_headers(target)
        await self._check_ssl_configuration(target)
        
        # Crawl the site to find pages and forms
        pages_and_forms = await self._crawl_site(target)
        
        # Run optional vulnerability tests
        if test_sqli:
            await self._test_sql_injection(target, pages_and_forms)
        
        if test_xss:
            await self._test_xss(target, pages_and_forms)
        
        # Always test for common vulnerabilities
        await self._test_directory_traversal(target, pages_and_forms)
        await self._check_common_files(target)
        await self._test_csrf(target, pages_and_forms)
        
        return {'findings': self.findings}
    
    async def _crawl_site(self, target: str, max_depth: int = 2) -> Dict[str, Any]:
        """Crawl website to discover pages and forms"""
        self.logger.info("[*] Crawling website...")
        
        pages = []
        forms = []
        
        try:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            async with aiohttp.ClientSession() as session:
                pages_to_crawl = [(target, 0)]
                
                while pages_to_crawl:
                    url, depth = pages_to_crawl.pop(0)
                    
                    if url in self.crawled_urls or depth > max_depth:
                        continue
                    
                    self.crawled_urls.add(url)
                    
                    try:
                        async with session.get(
                            url,
                            ssl=ssl_context,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            headers={'User-Agent': self.user_agent}
                        ) as response:
                            if response.status != 200:
                                continue
                            
                            html = await response.text()
                            soup = BeautifulSoup(html, 'html.parser')
                            
                            # Extract forms
                            for form in soup.find_all('form'):
                                form_data = self._extract_form_data(form, url)
                                if form_data:
                                    forms.append(form_data)
                            
                            # Extract links for further crawling
                            if depth < max_depth:
                                for link in soup.find_all('a', href=True):
                                    href = link.get('href')
                                    absolute_url = urljoin(url, href)
                                    
                                    # Only crawl same domain
                                    if urlparse(absolute_url).netloc == urlparse(target).netloc:
                                        if absolute_url not in self.crawled_urls:
                                            pages_to_crawl.append((absolute_url, depth + 1))
                            
                            pages.append(url)
                    
                    except Exception as e:
                        self.logger.debug(f"Error crawling {url}: {e}")
        
        except Exception as e:
            self.logger.debug(f"Crawling error: {e}")
        
        self.logger.info(f"[+] Crawled {len(pages)} pages, found {len(forms)} forms")
        return {'pages': pages, 'forms': forms}
    
    def _extract_form_data(self, form, page_url: str) -> Dict[str, Any]:
        """Extract form details for testing"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        action_url = urljoin(page_url, action)
        
        inputs = []
        for input_field in form.find_all(['input', 'textarea', 'select']):
            input_name = input_field.get('name')
            input_type = input_field.get('type', 'text')
            if input_name:
                inputs.append({
                    'name': input_name,
                    'type': input_type
                })
        
        if not inputs:
            return None
        
        return {
            'url': action_url,
            'method': method,
            'inputs': inputs,
            'page': page_url
        }
    
    async def _check_security_headers(self, target: str):
        """Check for missing security headers"""
        self.logger.info("[*] Checking security headers...")
        
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME-sniffing protection',
            'X-XSS-Protection': 'XSS filter',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content Security Policy',
        }
        
        try:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    target,
                    ssl=ssl_context,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    headers = response.headers
                    
                    for header, description in security_headers.items():
                        if header not in headers:
                            self.findings.append({
                                'type': 'Missing Security Header',
                                'severity': 'low',
                                'title': f'Missing {header} header',
                                'description': f'The {header} header is not set ({description})',
                                'location': target,
                                'remediation': f'Add the {header} header to improve security'
                            })
        
        except Exception as e:
            self.logger.debug(f"Security headers check error: {e}")
    
    async def _check_ssl_configuration(self, target: str):
        """Check SSL/TLS configuration"""
        if not target.startswith('https'):
            self.findings.append({
                'type': 'Insecure Protocol',
                'severity': 'medium',
                'title': 'Website not using HTTPS',
                'description': 'The website is accessible over HTTP without encryption',
                'location': target,
                'remediation': 'Implement HTTPS and redirect all HTTP traffic to HTTPS'
            })
    
    async def _test_sql_injection(self, target: str, crawl_data: Dict[str, Any]):
        """Test for SQL injection vulnerabilities"""
        self.logger.info("[*] Testing for SQL injection...")
        
        forms = crawl_data.get('forms', [])
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async with aiohttp.ClientSession() as session:
            # Test forms
            for form in forms[:5]:  # Limit to first 5 forms
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'hidden']:
                        await self._test_sqli_on_input(
                            session, ssl_context, form, input_field['name']
                        )
    
    async def _test_sqli_on_input(self, session, ssl_context, form: Dict, param_name: str):
        """Test SQL injection on a specific input"""
        for payload in self.SQLI_PAYLOADS[:3]:  # Test first 3 payloads
            try:
                data = {inp['name']: 'test' for inp in form['inputs']}
                data[param_name] = payload
                
                if form['method'] == 'get':
                    url = f"{form['url']}?{urlencode(data)}"
                    async with session.get(
                        url,
                        ssl=ssl_context,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        headers={'User-Agent': self.user_agent}
                    ) as response:
                        text = await response.text()
                        if self._check_sql_errors(text):
                            self.findings.append({
                                'type': 'SQL Injection',
                                'severity': 'critical',
                                'title': f'SQL Injection vulnerability in {param_name}',
                                'description': f'Parameter "{param_name}" appears vulnerable to SQL injection',
                                'location': form['url'],
                                'remediation': 'Use parameterized queries and input validation',
                                'payload': payload
                            })
                            return  # Found vulnerability, no need to test more payloads
                else:
                    async with session.post(
                        form['url'],
                        data=data,
                        ssl=ssl_context,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        headers={'User-Agent': self.user_agent}
                    ) as response:
                        text = await response.text()
                        if self._check_sql_errors(text):
                            self.findings.append({
                                'type': 'SQL Injection',
                                'severity': 'critical',
                                'title': f'SQL Injection vulnerability in {param_name}',
                                'description': f'Parameter "{param_name}" appears vulnerable to SQL injection',
                                'location': form['url'],
                                'remediation': 'Use parameterized queries and input validation',
                                'payload': payload
                            })
                            return
            
            except Exception as e:
                self.logger.debug(f"SQLi test error: {e}")
    
    def _check_sql_errors(self, text: str) -> bool:
        """Check if response contains SQL error messages"""
        for error_pattern in self.SQL_ERRORS:
            if re.search(error_pattern, text, re.IGNORECASE):
                return True
        return False
    
    async def _test_xss(self, target: str, crawl_data: Dict[str, Any]):
        """Test for XSS vulnerabilities"""
        self.logger.info("[*] Testing for XSS...")
        
        forms = crawl_data.get('forms', [])
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async with aiohttp.ClientSession() as session:
            # Test forms
            for form in forms[:5]:  # Limit to first 5 forms
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'textarea']:
                        await self._test_xss_on_input(
                            session, ssl_context, form, input_field['name']
                        )
    
    async def _test_xss_on_input(self, session, ssl_context, form: Dict, param_name: str):
        """Test XSS on a specific input"""
        test_payload = "<script>alert('XSS')</script>"
        
        try:
            data = {inp['name']: 'test' for inp in form['inputs']}
            data[param_name] = test_payload
            
            if form['method'] == 'get':
                url = f"{form['url']}?{urlencode(data)}"
                async with session.get(
                    url,
                    ssl=ssl_context,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={'User-Agent': self.user_agent}
                ) as response:
                    text = await response.text()
                    if test_payload in text:
                        self.findings.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'high',
                            'title': f'XSS vulnerability in {param_name}',
                            'description': f'Parameter "{param_name}" reflects unfiltered user input',
                            'location': form['url'],
                            'remediation': 'Implement proper input validation and output encoding',
                            'payload': test_payload
                        })
            else:
                async with session.post(
                    form['url'],
                    data=data,
                    ssl=ssl_context,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={'User-Agent': self.user_agent}
                ) as response:
                    text = await response.text()
                    if test_payload in text:
                        self.findings.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'high',
                            'title': f'XSS vulnerability in {param_name}',
                            'description': f'Parameter "{param_name}" reflects unfiltered user input',
                            'location': form['url'],
                            'remediation': 'Implement proper input validation and output encoding',
                            'payload': test_payload
                        })
        
        except Exception as e:
            self.logger.debug(f"XSS test error: {e}")
    
    async def _test_directory_traversal(self, target: str, crawl_data: Dict[str, Any]):
        """Test for directory traversal vulnerabilities"""
        self.logger.info("[*] Testing for directory traversal...")
        
        pages = crawl_data.get('pages', [])
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async with aiohttp.ClientSession() as session:
            for page in pages[:5]:  # Test first 5 pages
                parsed = urlparse(page)
                params = parse_qs(parsed.query)
                
                for param in params:
                    if any(keyword in param.lower() for keyword in ['file', 'path', 'page', 'view']):
                        for payload in self.TRAVERSAL_PAYLOADS[:2]:
                            try:
                                test_params = params.copy()
                                test_params[param] = [payload]
                                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                                
                                async with session.get(
                                    test_url,
                                    ssl=ssl_context,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                                    headers={'User-Agent': self.user_agent}
                                ) as response:
                                    text = await response.text()
                                    
                                    # Check for common file content indicators
                                    if 'root:' in text or 'localhost' in text or '[extensions]' in text:
                                        self.findings.append({
                                            'type': 'Directory Traversal',
                                            'severity': 'high',
                                            'title': f'Directory traversal vulnerability in {param}',
                                            'description': f'Parameter "{param}" allows file system access',
                                            'location': page,
                                            'remediation': 'Implement proper path validation and restrict file access',
                                            'payload': payload
                                        })
                                        break
                            
                            except Exception as e:
                                self.logger.debug(f"Directory traversal test error: {e}")
    
    async def _check_common_files(self, target: str):
        """Check for common sensitive files"""
        self.logger.info("[*] Checking for sensitive files...")
        
        sensitive_files = [
            '.git/config',
            '.env',
            'config.php',
            'wp-config.php',
            'config.yml',
            'settings.py',
            'web.config',
            '.htaccess',
            'phpinfo.php',
            'info.php',
            'robots.txt',
            'sitemap.xml',
        ]
        
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async with aiohttp.ClientSession() as session:
            for file in sensitive_files:
                try:
                    url = urljoin(target, file)
                    async with session.get(
                        url,
                        ssl=ssl_context,
                        timeout=aiohttp.ClientTimeout(total=5),
                        headers={'User-Agent': self.user_agent}
                    ) as response:
                        if response.status == 200:
                            text = await response.text()
                            if len(text) > 0:
                                severity = 'high' if file in ['.git/config', '.env', 'config.php', 'wp-config.php'] else 'medium'
                                self.findings.append({
                                    'type': 'Information Disclosure',
                                    'severity': severity,
                                    'title': f'Sensitive file exposed: {file}',
                                    'description': f'The file {file} is publicly accessible',
                                    'location': url,
                                    'remediation': 'Restrict access to sensitive configuration files'
                                })
                
                except Exception as e:
                    self.logger.debug(f"File check error for {file}: {e}")
    
    async def _test_csrf(self, target: str, crawl_data: Dict[str, Any]):
        """Check for CSRF protection"""
        self.logger.info("[*] Checking CSRF protection...")
        
        forms = crawl_data.get('forms', [])
        
        for form in forms:
            if form['method'] == 'post':
                # Check if form has CSRF token
                has_csrf_token = any(
                    'csrf' in inp['name'].lower() or 'token' in inp['name'].lower()
                    for inp in form['inputs']
                )
                
                if not has_csrf_token:
                    self.findings.append({
                        'type': 'CSRF',
                        'severity': 'medium',
                        'title': 'Missing CSRF protection',
                        'description': f'Form at {form["page"]} lacks CSRF token',
                        'location': form['url'],
                        'remediation': 'Implement CSRF tokens for all state-changing operations'
                    })
