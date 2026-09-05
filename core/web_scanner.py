"""Web Application Security Testing Module"""
import asyncio
import aiohttp
import ssl
import certifi
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Any, List, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunsplit
from bs4 import BeautifulSoup
from core.scope import ScopePolicy, normalize_url
from core.attack_surface import build_attack_surface
from core.verification_engine import VerificationEngine


class WebScanner:
    """Web application vulnerability scanner"""
    
    # SQL Injection test payloads
    SQLI_PAYLOADS = [
        "1'-- -",
        "' OR '1'='1'-- -",
        "' AND '1'='2'-- -",
        "1 OR 1=1-- -",
        "1 AND 1=2-- -",
        "' UNION SELECT NULL-- -",
    ]

    SQLI_BOOLEAN_TRUE = "' OR '1'='1'-- -"
    SQLI_BOOLEAN_FALSE = "' AND '1'='2'-- -"
    
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
        '../../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    ]

    SSTI_PROBES = [
        ('{{7*7}}', '49'),
        ('${7*7}', '49'),
        ('<%= 7*7 %>', '49'),
        ('{{8*8}}', '64'),
    ]

    REDIRECT_PARAMETER_NAMES = {
        'url', 'uri', 'next', 'redirect', 'redirect_url', 'return',
        'return_url', 'callback',
    }

    COMMAND_PARAMETER_NAMES = {
        'cmd', 'command', 'exec', 'execute', 'shell', 'run', 'process',
        'ping', 'host', 'hostname', 'ip', 'input', 'code', 'query',
    }
    FILE_PARAMETER_NAMES = {
        'file', 'filename', 'filepath', 'path', 'page', 'include',
        'template', 'doc', 'document', 'folder', 'dir', 'view', 'resource',
    }
    COMMAND_PAYLOADS = (
        ';printf \'{marker}\'',
        '&&printf \'{marker}\'',
        '|printf \'{marker}\'',
        '$(printf \'{marker}\')',
    )
    FILE_PAYLOADS = (
        '../../../../etc/passwd',
        '..%2f..%2f..%2f..%2fetc%2fpasswd',
        '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
    )
    
    # SQL error signatures
    SQL_ERRORS = [
        r'You have an error in your SQL syntax',
        r'Warning.*mysql_.*',
        r'Fatal error.*(?:mysql|mysqli|PDO)',
        r'mysqli?_fetch_.*',
        r'SQL syntax.*MySQL',
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
        self.request_log: List[Dict[str, Any]] = []
        self.request_count = 0
        scanning = config.get('scanning', {})
        self.max_requests = int(scanning.get('max_requests', 500))
        self.payload_limit = max(1, int(scanning.get('payload_limit', 50)))
        self.crawl_request_limit = max(1, int(self.max_requests * 0.4))
        self.request_delay = float(scanning.get('request_delay', 0))
        self.rate_limit = float(scanning.get('rate_limit', 0) or 0)
        self._last_request_at = 0.0
        self._budget_warning_emitted = False
        self._crawl_budget_warning_emitted = False
        self.attack_checks: List[Dict[str, Any]] = []
        # Headers imported from a Burp request are used as the authenticated
        # session context for the scan.  Hop-by-hop headers are deliberately
        # excluded when the request file is loaded below.
        self.request_headers: Dict[str, str] = {}
        self.api_detected = False
        self.api_signals: List[str] = []
        self.api_endpoints: List[Dict[str, Any]] = []
        self.api_docs: List[str] = []
        self.js_urls: List[str] = []
        self._analyzed_js: Set[str] = set()
        scope_config = config.get('scope', {})
        self.scope = ScopePolicy(scope_config.get('allowed_hosts', []), scope_config.get('excluded_paths', []))
        self.verifier = VerificationEngine()

    def _ssl_context(self):
        """Use trusted TLS by default; permit an explicit assessment override."""
        if self.config.get('scanning', {}).get('insecure_tls', False):
            return False
        return ssl.create_default_context(cafile=certifi.where())

    def _session_headers(self):
        headers = dict(self.config.get('scanning', {}).get('headers', {}))
        headers.update(self.request_headers)
        headers.setdefault('User-Agent', self.user_agent)
        cookie = self.config.get('scanning', {}).get('cookie')
        if cookie:
            headers['Cookie'] = cookie
        return headers

    @staticmethod
    def _form_request_kwargs(form: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
        """Encode a replayed form according to the captured Content-Type."""
        content_type = str(form.get('content_type', '')).lower()
        if 'application/json' in content_type:
            return {'json': data}
        return {'data': data}

    def _load_payload_file(self, filename: str, fallback) -> List[str]:
        """Load a bounded editable payload list.

        Payload files may be sourced from large community collections. A
        scanner should not turn those collections into an unbounded request
        loop, so the first configured number of entries is used per check.
        The limit is intentionally applied by the caller's configuration and
        remains easy to raise for a dedicated lab run.
        """
        payload_path = Path(__file__).resolve().parents[1] / 'payloads' / filename
        limit = self.payload_limit
        try:
            payloads = []
            with payload_path.open(encoding='utf-8', errors='replace') as payload_file:
                for line in payload_file:
                    value = line.strip()
                    if not value or value.startswith('#'):
                        continue
                    payloads.append(value)
                    if len(payloads) >= limit:
                        break
            return payloads or list(fallback)[:limit]
        except (OSError, UnicodeError):
            return list(fallback)[:limit]

    def _sqli_comment_payloads(self) -> List[str]:
        """Return bounded SQLi probes that include a real SQL comment.

        A lone quote is only a parser-error probe. It is not enough to call a
        parameter injectable because WAFs, validation layers, and unrelated
        application errors can all react to it. Active SQLi verification uses
        comment-terminated probes plus a true/false pair instead.
        """
        loaded = self._load_payload_file('sqli_payloads.txt', self.SQLI_PAYLOADS)
        candidates = list(self.SQLI_PAYLOADS) + loaded
        probes: List[str] = []
        for raw in candidates:
            payload = str(raw).strip()
            if not payload or not re.search(r'(--|#|/\*)', payload):
                continue
            # MySQL requires whitespace/control after --. Payload files often
            # omit it, so make the comment syntactically usable in a lab.
            if re.search(r'--\s*$', payload):
                payload = payload.rstrip() + ' -'
            if payload not in probes:
                probes.append(payload)
            if len(probes) >= min(self.payload_limit, 8):
                break
        return probes or list(self.SQLI_PAYLOADS)

    def _log_finding(self, finding: Dict[str, Any]) -> None:
        """Print concise finding telemetry in verbose terminal mode."""
        if not self.config.get('scanning', {}).get('verbose', False):
            return
        severity = str(finding.get('severity', 'info')).upper()
        confidence = str(finding.get('confidence', 'medium')).lower()
        title = finding.get('title', 'Unnamed finding')
        location = finding.get('location', '')
        self.logger.info(f"[FINDING] {severity} | confidence={confidence} | {title} | {location}")

    @staticmethod
    def _form_data(form: Dict[str, Any], override_name: str = None, override_value: Any = None) -> Dict[str, Any]:
        """Build a request from the form's original values, changing one field."""
        data: Dict[str, Any] = {}
        for field in form.get('inputs', []):
            name = field.get('name')
            if not name:
                continue
            field_type = str(field.get('type', 'text')).lower()
            if field_type in {'checkbox', 'radio'} and not field.get('checked', False):
                continue
            value = field.get('value', '')
            if value in (None, '') and field_type in {'text', 'search', 'textarea'}:
                value = 'test'
            data[name] = value
        if override_name:
            data[override_name] = override_value
        return data

    async def _reserve_request(self, phase: str = '') -> bool:
        """Apply one shared request budget and pacing rule to every probe."""
        if self.request_count >= self.max_requests:
            if not self._budget_warning_emitted:
                self.logger.warning(f"[!] Request budget reached ({self.max_requests}); remaining checks skipped")
                self._budget_warning_emitted = True
            return False
        if phase == 'crawl' and self.request_count >= self.crawl_request_limit:
            if not self._crawl_budget_warning_emitted:
                self.logger.warning(f"[!] Crawl budget reached ({self.crawl_request_limit}); continuing with active verification budget")
                self._crawl_budget_warning_emitted = True
            return False
        interval = max(self.request_delay, (1.0 / self.rate_limit) if self.rate_limit > 0 else 0.0)
        now = time.monotonic()
        wait_for = interval - (now - self._last_request_at)
        if wait_for > 0:
            await asyncio.sleep(wait_for)
        self._last_request_at = time.monotonic()
        self.request_count += 1
        return True

    @asynccontextmanager
    async def _request(self, session, method: str, url: str, phase: str, **kwargs):
        """Make a scoped, budgeted request and retain minimal coverage metadata."""
        if not await self._reserve_request(phase):
            yield None
            return
        try:
            async with session.request(method, url, **kwargs) as response:
                location = response.headers.get('Location', '')
                self.request_log.append({
                    'method': method.upper(),
                    'url': url,
                    'phase': phase,
                    'status': response.status,
                    'content_type': response.headers.get('Content-Type', ''),
                    'redirect_location': location,
                    'auth_gate': self._is_auth_gate_response(response.status, location),
                })
                yield response
        except Exception as exc:
            self.request_log.append({'method': method.upper(), 'url': url, 'phase': phase, 'error': str(exc)})
            raise
    
    async def scan(
        self,
        target: str,
        test_sqli: bool = False,
        test_xss: bool = False,
        seed_urls: List[str] = None,
        request_spec: Dict[str, Any] = None,
        discovery_assets: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Perform comprehensive web application scan"""
        self.logger.info(f"Starting web application scan on {target}")
        
        if not target.startswith('http'):
            target = f"https://{target}"
        target = self.scope.assert_allowed(normalize_url(target))
        
        self.findings = []
        self.crawled_urls = set()
        self.request_log = []
        self.request_count = 0
        self._last_request_at = 0.0
        self.attack_checks = []
        self._budget_warning_emitted = False
        self._crawl_budget_warning_emitted = False
        self.api_detected = False
        self.api_signals = []
        self.api_endpoints = []
        self.api_docs = []
        self.js_urls = []
        self._analyzed_js = set()

        self.request_headers = {}
        if request_spec:
            hop_by_hop = {'host', 'content-length', 'connection', 'transfer-encoding'}
            self.request_headers = {
                str(name): str(value)
                for name, value in request_spec.get('headers', {}).items()
                if str(name).lower() not in hop_by_hop
            }
        else:
            self.request_headers = {
                str(name): str(value)
                for name, value in self.config.get('scanning', {}).get('headers', {}).items()
                if str(name).lower() not in {'host', 'content-length', 'connection', 'transfer-encoding'}
            }
        
        # Always run these tests
        await self._check_security_headers(target)
        await self._check_ssl_configuration(target)
        
        # Crawl the site to find pages and forms. A Burp API request often
        # points back to the SPA through Referer; include that same-origin
        # page before crawling so its scripts and additional API routes are
        # actually fetched, not merely listed after the crawl completes.
        request_seed_data = self._request_spec_crawl_data(request_spec) if request_spec else {'pages': [], 'forms': []}
        crawl_seeds = list(seed_urls or []) + [
            page for page in request_seed_data.get('pages', []) if page != target
        ]
        pages_and_forms = await self._crawl_site(target, seed_urls=crawl_seeds)
        self._inspect_discovery_assets(discovery_assets or {}, pages_and_forms)
        if pages_and_forms.get('api_detected'):
            await self._discover_api_documentation(target, pages_and_forms)
        if request_spec:
            seed_data = request_seed_data
            scoped_seed_pages = []
            for page in seed_data['pages']:
                try:
                    normalized_page = normalize_url(page)
                except (TypeError, ValueError):
                    continue
                if self.scope.is_allowed(normalized_page):
                    scoped_seed_pages.append(normalized_page)
            pages_and_forms['pages'] = list(dict.fromkeys(pages_and_forms.get('pages', []) + scoped_seed_pages))
            existing_forms = {
                (str(form.get('method', 'get')).upper(), form.get('url', ''),
                 tuple(sorted(str(field.get('name', '')) for field in form.get('inputs', []))))
                for form in pages_and_forms.get('forms', [])
            }
            for form in seed_data['forms']:
                fingerprint = (
                    str(form.get('method', 'get')).upper(), form.get('url', ''),
                    tuple(sorted(str(field.get('name', '')) for field in form.get('inputs', []))),
                )
                if fingerprint not in existing_forms:
                    pages_and_forms.setdefault('forms', []).append(form)
                    existing_forms.add(fingerprint)
            pages_and_forms['request_seed'] = {
                'source': request_spec.get('source', ''),
                'method': request_spec.get('method', ''),
                'url': request_spec.get('url', ''),
            }
        
        # Run optional vulnerability tests
        active_checks = self.config.get('scope', {}).get('active_checks', False)

        all_active_tests = bool(self.config.get('scanning', {}).get('all_active_tests', False))

        attack_plan = [
            ('SQL injection', test_sqli or all_active_tests, self._test_sql_injection),
            ('Cross-site scripting', test_xss or all_active_tests, self._test_xss),
            ('Server-side template injection', all_active_tests, self._test_ssti),
            ('Command injection', all_active_tests, self._test_command_injection),
            ('Path traversal / LFI', True, self._test_directory_traversal),
            ('File inclusion', all_active_tests, self._test_file_inclusion),
            ('Open redirect', True, self._test_open_redirect),
            ('Sensitive file exposure', True, lambda scan_target, _crawl: self._check_common_files(scan_target)),
            ('CSRF protection', True, self._test_csrf),
        ]
        if pages_and_forms.get('api_detected'):
            attack_plan.append(('API surface verification', True, self._test_api_surface))
        for method_name, selected, checker in attack_plan:
            if not active_checks:
                self.attack_checks.append({'method': method_name, 'status': 'skipped', 'findings': 0, 'requests': 0, 'reason': 'active mode is disabled'})
                continue
            # A supplied Burp request is an explicit authenticated request
            # seed.  The general crawl may still hit a login page (for
            # example when the application serves different routes or the
            # seed is POST-only), so do not discard the captured request's
            # parameters solely because the crawl gate was inconclusive.
            if pages_and_forms.get('auth_state') == 'authentication_required' and not request_spec:
                self.attack_checks.append({
                    'method': method_name,
                    'status': 'skipped',
                    'findings': 0,
                    'requests': 0,
                    'reason': 'authenticated session was not accepted; login page detected on application route',
                })
                continue
            if not selected:
                self.attack_checks.append({'method': method_name, 'status': 'skipped', 'findings': 0, 'requests': 0, 'reason': 'not selected; use --all-tests to run the full matrix'})
                continue
            before_findings = len(self.findings)
            before_requests = self.request_count
            if self.request_count >= self.max_requests:
                self.attack_checks.append({'method': method_name, 'status': 'skipped', 'findings': 0, 'requests': 0, 'reason': 'request budget exhausted'})
                continue
            self.logger.info(f"[*] Attack method: {method_name}")
            try:
                await checker(target, pages_and_forms)
                for finding in self.findings[before_findings:]:
                    self._log_finding(finding)
                self.attack_checks.append({
                    'method': method_name,
                    'status': 'completed',
                    'findings': len(self.findings) - before_findings,
                    'requests': self.request_count - before_requests,
                    'reason': 'No finding recorded' if len(self.findings) == before_findings else 'Evidence recorded in findings section',
                })
            except Exception as exc:
                self.logger.error(f"[!] {method_name} check failed: {exc}")
                self.attack_checks.append({
                    'method': method_name,
                    'status': 'failed',
                    'findings': len(self.findings) - before_findings,
                    'requests': self.request_count - before_requests,
                    'reason': str(exc),
                })

        attack_surface = build_attack_surface(pages_and_forms)
        site_profile = self._classify_site(pages_and_forms, discovery_assets or {})
        unique_requests = {(entry.get('method'), entry.get('url')) for entry in self.request_log}
        
        return {
            'findings': self.findings,
            'attack_surface': attack_surface,
            'crawl': pages_and_forms,
            'site_profile': site_profile,
            'coverage': {
                'discovered_pages': len(pages_and_forms.get('pages', [])),
                'discovered_forms': len(pages_and_forms.get('forms', [])),
                'discovered_endpoints': attack_surface.get('endpoint_count', 0),
                'tested_requests': len(self.request_log),
                'unique_tested_requests': len(unique_requests),
                'request_budget': self.max_requests,
                'budget_exhausted': self.request_count >= self.max_requests,
                'request_log': self.request_log,
                'attack_checks': self.attack_checks,
                'auth_state': pages_and_forms.get('auth_state', 'unknown'),
                'auth_gate_urls': pages_and_forms.get('auth_gate_urls', []),
                'request_seed': pages_and_forms.get('request_seed', {}),
                'api_detected': bool(pages_and_forms.get('api_detected')),
                'api_signals': pages_and_forms.get('api_signals', []),
                'api_endpoints': pages_and_forms.get('api_endpoints', []),
                'api_docs': pages_and_forms.get('api_docs', []),
                'js_urls': pages_and_forms.get('js_urls', []),
                'site_profile': site_profile,
            },
        }

    def _inspect_discovery_assets(self, assets: Dict[str, Any], crawl_data: Dict[str, Any]) -> None:
        """Use content-discovery evidence to classify API/GraphQL surfaces."""
        for item in assets.get('directories', []) if isinstance(assets, dict) else []:
            if not isinstance(item, dict):
                continue
            url = str(item.get('url', ''))
            path = urlparse(url).path.lower()
            if re.search(r'/(?:graphql)(?:/|$)', path):
                self._mark_api(f'GraphQL route from content discovery: {url}')
                self._register_api_endpoint(url, 'POST', 'dirsearch')
            elif re.search(r'/(?:api|swagger|openapi)(?:/|\.|$)', path):
                self._mark_api(f'API route from content discovery: {url}')
                self._register_api_endpoint(url, 'GET', 'dirsearch')
        crawl_data['api_detected'] = self.api_detected
        crawl_data['api_signals'] = list(dict.fromkeys(self.api_signals))
        crawl_data['api_endpoints'] = self.api_endpoints

    @staticmethod
    def _classify_site(crawl_data: Dict[str, Any], assets: Dict[str, Any]) -> Dict[str, Any]:
        signals = list(dict.fromkeys(crawl_data.get('api_signals', [])))
        endpoints = crawl_data.get('api_endpoints', [])
        paths = [str(item.get('url', '')).lower() for item in assets.get('directories', []) if isinstance(item, dict)] if isinstance(assets, dict) else []
        graphql = any('/graphql' in str(item.get('url', '')).lower() for item in endpoints if isinstance(item, dict)) or any('/graphql' in path for path in paths)
        api = bool(crawl_data.get('api_detected') or endpoints or any('/api' in path or 'openapi' in path or 'swagger' in path for path in paths))
        pages = len(crawl_data.get('pages', []))
        forms = len(crawl_data.get('forms', []))
        if graphql and (pages or forms):
            kind = 'hybrid web + GraphQL'
        elif graphql:
            kind = 'GraphQL API'
        elif api and (pages or forms):
            kind = 'hybrid web + API'
        elif api:
            kind = 'REST/API service'
        else:
            kind = 'normal web application'
        if graphql:
            recommendations = ['schema and introspection review', 'resolver authorization / BOLA', 'query depth, batching, and rate limits', 'argument injection checks']
        elif api:
            recommendations = ['authentication and token handling', 'BOLA/IDOR with two authorized identities', 'HTTP method and mass-assignment review', 'JSON input injection and excessive data exposure', 'rate-limit verification']
        else:
            recommendations = ['input validation and output encoding', 'authentication and session review', 'access-control review', 'configuration and content-discovery review']
        return {
            'kind': kind,
            'confidence': 'high' if (graphql or len(endpoints) >= 2) else ('medium' if api else 'low'),
            'api_detected': api,
            'graphql_detected': graphql,
            'pages': pages,
            'forms': forms,
            'api_endpoint_count': len(endpoints),
            'signals': signals[:20],
            'recommended_reviews': recommendations,
        }

    @staticmethod
    def _request_spec_crawl_data(request_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Represent the captured request as one crawl page or replayable form."""
        url = request_spec.get('url', '')
        method = str(request_spec.get('method', 'GET')).upper()
        # An API request captured from a browser normally carries a Referer
        # (and sometimes Origin) pointing at the SPA that loads the API. Use
        # those same-origin pages as passive crawl seeds; otherwise a request
        # file scan is incorrectly limited to one endpoint and never sees the
        # JavaScript route inventory.
        pages = [url]
        headers = request_spec.get('headers', {}) or {}
        for name, value in headers.items():
            if str(name).lower() not in {'referer', 'origin'} or not value:
                continue
            candidate = str(value).strip()
            if candidate.startswith(('http://', 'https://')) and candidate not in pages:
                pages.append(candidate)
        if method == 'GET':
            return {'pages': pages, 'forms': []}
        inputs = request_spec.get('inputs', [])
        if not inputs:
            return {'pages': pages, 'forms': []}
        return {
            'pages': pages,
            'forms': [{
                'url': url,
                'method': method.lower(),
                'inputs': inputs,
                'page': url,
                'content_type': request_spec.get('content_type', ''),
            }],
        }
    
    async def _crawl_site(self, target: str, max_depth: int = None, seed_urls: List[str] = None) -> Dict[str, Any]:
        """Crawl website to discover pages and forms"""
        self.logger.info("[*] Crawling website...")

        if max_depth is None:
            max_depth = int(self.config.get('modules', {}).get('web_scanner', {}).get('depth', 2))
        
        pages = []
        forms = []
        auth_gate_urls = []
        
        try:
            ssl_context = self._ssl_context()
            
            async with aiohttp.ClientSession(headers=self._session_headers()) as session:
                pages_to_crawl = [(target, 0)]
                for seed_url in seed_urls or []:
                    try:
                        normalized_seed = normalize_url(seed_url)
                    except ValueError:
                        continue
                    if self.scope.is_allowed(normalized_seed) and normalized_seed != target:
                        pages_to_crawl.append((normalized_seed, 0))
                
                while pages_to_crawl:
                    url, depth = pages_to_crawl.pop(0)
                    
                    if url in self.crawled_urls or depth > max_depth:
                        continue
                    
                    if not self.scope.is_allowed(url):
                        continue
                    self.crawled_urls.add(url)
                    # GraphQL commonly rejects ordinary GET requests with
                    # 400/405, so classify the route before status handling.
                    # Otherwise a valid GraphQL endpoint disappears from the
                    # attack surface before the protocol-aware probe runs.
                    if re.search(r'/graphql(?:/|$)', urlparse(url).path.lower()):
                        self._mark_api(f'GraphQL route: {url}')
                        self._register_api_endpoint(url, 'POST', 'graphql-route')
                    
                    try:
                        async with self._request(
                            session, 'GET', url, 'crawl',
                            ssl=ssl_context,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            headers=self._session_headers(),
                            allow_redirects=False,
                        ) as response:
                            if response is None:
                                break
                            redirect_location = response.headers.get('Location', '')
                            if self._is_auth_gate_response(response.status, redirect_location):
                                auth_gate_urls.append(url)
                                pages.append(url)
                                self.logger.warning(
                                    f"[!] Authentication gate detected at {url}; "
                                    "active input tests are disabled until a valid session is supplied"
                                )
                                continue
                            # Follow ordinary in-scope redirects as crawl seeds,
                            # but never follow login redirects or external hosts.
                            if 300 <= response.status < 400:
                                redirected = urljoin(url, redirect_location)
                                try:
                                    redirected = normalize_url(redirected)
                                except ValueError:
                                    redirected = ''
                                if redirected and self.scope.is_allowed(redirected) and depth < max_depth:
                                    pages_to_crawl.append((redirected, depth))
                                pages.append(url)
                                continue
                            if response.status != 200:
                                continue
                            
                            html = await response.text()
                            soup = BeautifulSoup(html, 'html.parser')
                            self._inspect_api_response(url, response.headers.get('Content-Type', ''), html)

                            if self._looks_like_login_page(html) and not self._is_login_endpoint(url):
                                auth_gate_urls.append(url)
                                pages.append(url)
                                self.logger.warning(f"[!] Authentication gate detected at {url}; active input tests will not treat the login form as an application endpoint")
                                continue
                            
                            # Extract forms
                            for form in soup.find_all('form'):
                                form_data = self._extract_form_data(form, url)
                                if form_data:
                                    forms.append(form_data)

                            script_urls = []
                            for script in soup.find_all('script', src=True):
                                try:
                                    script_url = normalize_url(urljoin(url, script.get('src')))
                                except (TypeError, ValueError):
                                    continue
                                if self.scope.is_allowed(script_url):
                                    script_urls.append(script_url)
                            for script_url in script_urls:
                                if script_url not in self.js_urls:
                                    self.js_urls.append(script_url)
                            for script_url in script_urls[:20]:
                                await self._analyze_javascript(session, script_url, ssl_context)
                            
                            # Extract links for further crawling
                            if depth < max_depth:
                                for link in soup.find_all('a', href=True):
                                    href = link.get('href')
                                    try:
                                        absolute_url = normalize_url(urljoin(url, href))
                                    except ValueError:
                                        continue
                                    
                                    # Only crawl same domain
                                    if self.scope.is_allowed(absolute_url):
                                        if absolute_url not in self.crawled_urls:
                                            pages_to_crawl.append((absolute_url, depth + 1))
                            
                            pages.append(url)
                    
                    except Exception as e:
                        self.logger.debug(f"Error crawling {url}: {e}")
        
        except Exception as e:
            self.logger.debug(f"Crawling error: {e}")
        
        self.logger.info(f"[+] Crawled {len(pages)} pages, found {len(forms)} forms")
        return {
            'pages': pages,
            'forms': forms,
            'auth_state': 'authentication_required' if auth_gate_urls else 'authenticated_or_public',
            'auth_gate_urls': list(dict.fromkeys(auth_gate_urls)),
            'api_detected': self.api_detected,
            'api_signals': list(dict.fromkeys(self.api_signals)),
            'api_endpoints': self.api_endpoints,
            'api_docs': list(dict.fromkeys(self.api_docs)),
            'js_urls': list(dict.fromkeys(self.js_urls)),
        }

    def _mark_api(self, signal: str) -> None:
        self.api_detected = True
        if signal not in self.api_signals:
            self.api_signals.append(signal)

    def _register_api_endpoint(self, url: str, method: str = 'GET', source: str = 'discovery', parameters=None) -> None:
        try:
            normalized = normalize_url(url)
        except ValueError:
            return
        if not self.scope.is_allowed(normalized):
            return
        method = str(method or 'GET').upper()
        params = [str(p) for p in (parameters or []) if str(p)]
        key = (normalized, method)
        for endpoint in self.api_endpoints:
            if (endpoint.get('url'), endpoint.get('method')) == key:
                for param in params:
                    if param not in endpoint.setdefault('parameters', []):
                        endpoint['parameters'].append(param)
                return
        self.api_endpoints.append({
            'url': normalized,
            'method': method,
            'source': source,
            'parameters': params,
        })

    def _inspect_api_response(self, url: str, content_type: str, body: str) -> None:
        lowered_url = url.lower()
        lowered_type = str(content_type).lower()
        if 'json' in lowered_type:
            self._mark_api(f'JSON response: {url}')
            self._register_api_endpoint(url, 'GET', 'json-response', list(parse_qs(urlparse(url).query)))
        if re.search(r'/(?:api|graphql|swagger|openapi)(?:[/?]|$)', urlparse(url).path.lower()):
            self._mark_api(f'API-like route: {url}')
            self._register_api_endpoint(url, 'GET', 'route-pattern', list(parse_qs(urlparse(url).query)))
        if re.search(r'\b(?:fetch|axios|XMLHttpRequest)\s*\(', body, re.I) or 'application/json' in body.lower():
            self._mark_api(f'JavaScript/API client behavior: {url}')

    async def _analyze_javascript(self, session, script_url: str, ssl_context) -> None:
        if script_url in self._analyzed_js:
            return
        self._analyzed_js.add(script_url)
        try:
            async with self._request(
                session, 'GET', script_url, 'js-analysis', ssl=ssl_context,
                timeout=aiohttp.ClientTimeout(total=min(self.timeout, 8)),
                headers=self._session_headers(), allow_redirects=False,
            ) as response:
                if response is None or response.status != 200:
                    return
                body = await response.text()
                # Webpack bundles commonly escape slashes and construct API
                # URLs inside axios/fetch calls instead of keeping a clean
                # standalone route literal.
                normalized_body = body.replace('\\/', '/').replace('\\x2f', '/').replace('\\u002f', '/')
                if re.search(r'\b(?:fetch|axios|XMLHttpRequest)\s*\(', normalized_body, re.I) or 'application/json' in normalized_body.lower():
                    self._mark_api(f'API client code: {script_url}')
                # React/Webpack applications frequently place API actions in
                # lazy-loaded chunks. Follow only same-origin JavaScript
                # chunks, with a hard cap, so the request-file scan can map
                # the application without turning into an unbounded asset
                # crawler.
                chunk_pattern = re.compile(r"[\"'`]((?:https?://[^\"'`\s]+|/[^\"'`\s]+\.js(?:\?[^\"'`]*)?))[\"'`]")
                for chunk in chunk_pattern.findall(normalized_body):
                    if not re.search(r'(?:chunk|static/js)/[^/]+\.js(?:\?|$)', chunk, re.I):
                        continue
                    try:
                        chunk_url = normalize_url(urljoin(script_url, chunk))
                    except ValueError:
                        continue
                    if not self.scope.is_allowed(chunk_url) or chunk_url in self._analyzed_js:
                        continue
                    if len(self._analyzed_js) >= 40:
                        break
                    if chunk_url not in self.js_urls:
                        self.js_urls.append(chunk_url)
                    await self._analyze_javascript(session, chunk_url, ssl_context)
                route_pattern = re.compile(r"[\"'`]((?:https?://[^\"'`\s]+|/[^\"'`\s]+))[\"'`]")
                call_pattern = re.compile(r"\b(?:fetch|axios\.(?:get|post|put|patch|delete)|url)\s*\(?\s*[:=]?\s*[\"'`]((?:https?://[^\"'`\s]+|/[^\"'`\s]+))[\"'`]", re.I)
                matches = list(route_pattern.finditer(normalized_body)) + list(call_pattern.finditer(normalized_body))
                seen_routes = set()
                for match in matches:
                    route = match.group(1)
                    if route in seen_routes:
                        continue
                    seen_routes.add(route)
                    is_api_route = re.search(r'/(?:api|graphql|swagger|openapi|v[0-9]+)(?:[/?]|$)', route, re.I)
                    is_client_route = match.re is call_pattern and route.startswith(('/', 'http'))
                    if not is_api_route and not is_client_route:
                        continue
                    try:
                        endpoint_url = normalize_url(urljoin(script_url, route))
                    except ValueError:
                        continue
                    self._mark_api(f'API route in JavaScript: {endpoint_url}')
                    self._register_api_endpoint(endpoint_url, 'GET', 'javascript', list(parse_qs(urlparse(endpoint_url).query)))
        except Exception as exc:
            self.logger.debug(f'JavaScript analysis error for {script_url}: {exc}')

    async def _discover_api_documentation(self, target: str, crawl_data: Dict[str, Any]) -> None:
        """Probe documentation locations only after API behavior was identified."""
        candidates = (
            '/swagger.json', '/openapi.json', '/api/swagger.json', '/api/openapi.json',
            '/api-docs', '/swagger/v1/swagger.json', '/v1/openapi.json', '/v2/api-docs',
        )
        ssl_context = self._ssl_context()
        async with aiohttp.ClientSession(headers=self._session_headers()) as session:
            for path in candidates:
                url = urljoin(target, path)
                if not self.scope.is_allowed(url):
                    continue
                try:
                    async with self._request(session, 'GET', url, 'api-docs', ssl=ssl_context,
                                             timeout=aiohttp.ClientTimeout(total=min(self.timeout, 8)),
                                             headers=self._session_headers(), allow_redirects=False) as response:
                        if response is None or response.status != 200:
                            continue
                        body = await response.text()
                        try:
                            document = await response.json(content_type=None)
                        except Exception:
                            continue
                        if not isinstance(document, dict) or not isinstance(document.get('paths'), dict):
                            continue
                        self._mark_api(f'OpenAPI document: {url}')
                        self.api_docs.append(url)
                        for route, definition in document['paths'].items():
                            if not isinstance(definition, dict):
                                continue
                            common = definition.get('parameters', [])
                            for method, operation in definition.items():
                                if method.lower() not in {'get', 'post', 'put', 'patch', 'delete', 'options', 'head'} or not isinstance(operation, dict):
                                    continue
                                params = [p.get('name') for p in common if isinstance(p, dict) and p.get('name')]
                                params.extend(p.get('name') for p in operation.get('parameters', []) if isinstance(p, dict) and p.get('name'))
                                endpoint_url = urljoin(target, str(route).lstrip('/'))
                                self._register_api_endpoint(endpoint_url, method, 'openapi', params)
                                if method.lower() != 'get' and params:
                                    forms = crawl_data.setdefault('forms', [])
                                    forms.append({'url': endpoint_url, 'method': method.lower(), 'inputs': [
                                        {'name': p, 'type': 'json', 'value': ''} for p in dict.fromkeys(params)
                                    ], 'page': url, 'content_type': 'application/json'})
                except Exception as exc:
                    self.logger.debug(f'API documentation check error for {url}: {exc}')
        crawl_data['api_detected'] = self.api_detected
        crawl_data['api_signals'] = list(dict.fromkeys(self.api_signals))
        crawl_data['api_endpoints'] = self.api_endpoints
        crawl_data['api_docs'] = list(dict.fromkeys(self.api_docs))

    async def _test_api_surface(self, target: str, crawl_data: Dict[str, Any]) -> None:
        """Perform bounded, read-only verification of discovered API routes."""
        self.logger.info('[*] Verifying discovered API endpoints (read-only)')
        ssl_context = self._ssl_context()
        endpoints = [item for item in crawl_data.get('api_endpoints', []) if item.get('method', 'GET') in {'GET', 'HEAD', 'OPTIONS'}]
        async with aiohttp.ClientSession(headers=self._session_headers()) as session:
            for item in endpoints[:30]:
                url = item.get('url')
                if not url:
                    continue
                async with self._request(session, 'GET', url, 'api-verification', ssl=ssl_context,
                                         timeout=aiohttp.ClientTimeout(total=min(self.timeout, 8)),
                                         headers=self._session_headers(), allow_redirects=False) as response:
                    if response is None:
                        continue
                    content_type = response.headers.get('Content-Type', '')
                    if response.status < 500 and 'json' in content_type.lower():
                        self._mark_api(f'Verified JSON API response: {url}')
            graphql_routes = [
                item for item in crawl_data.get('api_endpoints', [])
                if re.search(r'/graphql(?:/|$)', str(item.get('url', '')).lower())
            ]
            for item in graphql_routes[:5]:
                url = item.get('url')
                if not url:
                    continue
                # Read-only protocol check. This does not execute a business
                # mutation and is enough to distinguish GraphQL from a path
                # that merely contains the word "graphql".
                probe = {'query': '{__typename}'}
                async with self._request(session, 'POST', url, 'graphql-verification', ssl=ssl_context,
                                         timeout=aiohttp.ClientTimeout(total=min(self.timeout, 8)),
                                         headers={**self._session_headers(), 'Content-Type': 'application/json'},
                                         allow_redirects=False, json=probe) as response:
                    if response is None:
                        continue
                    body = await response.text()
                    if response.status < 500 and ('application/json' in response.headers.get('Content-Type', '').lower() or '"data"' in body or '"errors"' in body):
                        self._mark_api(f'Verified GraphQL response: {url}')

    @staticmethod
    def _is_login_endpoint(url: str) -> bool:
        path = urlparse(url).path.lower().rstrip('/')
        return path.endswith(('/login.php', '/login', '/signin', '/sign-in'))

    @staticmethod
    def _is_auth_gate_response(status: int, location: str = '') -> bool:
        """Identify redirects that prove the current session is unauthenticated."""
        if status not in {301, 302, 303, 307, 308}:
            return False
        destination = str(location or '').lower()
        return any(marker in destination for marker in (
            'login.php', '/login', 'signin', 'sign-in', 'authenticate'
        ))

    @staticmethod
    def _looks_like_login_page(html: str) -> bool:
        lowered = html.lower()
        login_title = 'login ::' in lowered or 'login -' in lowered or 'sign in' in lowered
        has_user = bool(re.search(r'name=["\'](?:username|user|login)["\']', lowered))
        has_password = bool(re.search(r'type=["\']password["\']|name=["\']password["\']', lowered))
        return (login_title and has_password) or (has_user and has_password and 'login.php' in lowered)
    
    def _extract_form_data(self, form, page_url: str) -> Dict[str, Any]:
        """Extract form details for testing"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        try:
            action_url = normalize_url(urljoin(page_url, action))
        except ValueError:
            return None
        if not self.scope.is_allowed(action_url):
            return None
        
        inputs = []
        for input_field in form.find_all(['input', 'textarea', 'select']):
            input_name = input_field.get('name')
            input_type = input_field.get('type', 'text')
            if input_name:
                if input_field.name == 'textarea':
                    value = input_field.text or ''
                elif input_field.name == 'select':
                    selected = input_field.find('option', selected=True) or input_field.find('option')
                    value = selected.get('value', selected.text) if selected else ''
                else:
                    value = input_field.get('value', '')
                inputs.append({
                    'name': input_name,
                    'type': input_type,
                    'value': value,
                    'checked': input_field.has_attr('checked'),
                })
        
        if not inputs:
            return None
        
        return {
            'url': action_url,
            'method': method,
            'inputs': inputs,
            'page': page_url,
            'content_type': form.get('enctype', ''),
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
            ssl_context = self._ssl_context()
            
            async with aiohttp.ClientSession(headers=self._session_headers()) as session:
                async with self._request(
                    session, 'GET', target, 'security-headers',
                    ssl=ssl_context,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response is None:
                        return
                    headers = response.headers
                    
                    for header, description in security_headers.items():
                        if header not in headers:
                            self.findings.append({
                                'type': 'Missing Security Header',
                                'severity': 'low',
                                'title': f'Missing {header} header',
                                'description': f'The {header} header is not set ({description})',
                                'location': target,
                                'status_code': response.status,
                                'remediation': f'Add the {header} header to improve security'
                            })
        
        except Exception as e:
            self.logger.debug(f"Security headers check error: {e}")
    
    async def _check_ssl_configuration(self, target: str):
        """Report clear-text HTTP only after proving the endpoint is reachable."""
        if target.lower().startswith('https'):
            return
        try:
            ssl_context = self._ssl_context()
            async with aiohttp.ClientSession(headers=self._session_headers()) as session:
                async with self._request(
                    session, 'GET', target, 'protocol-check',
                    ssl=ssl_context,
                    timeout=aiohttp.ClientTimeout(total=min(self.timeout, 5)),
                    headers=self._session_headers(),
                    allow_redirects=False,
                ) as response:
                    if response is None:
                        return
                    location = str(response.headers.get('Location', ''))
                    if location.lower().startswith('https://'):
                        return
                    self.findings.append({
                        'type': 'Insecure Protocol',
                        'severity': 'medium',
                        'title': 'Website accessible over HTTP',
                        'description': f'The endpoint returned HTTP {response.status} without redirecting to HTTPS.',
                        'location': target,
                        'status_code': response.status,
                        'confidence': 'high',
                        'state': 'confirmed',
                        'evidence': f'HTTP {response.status} response received and no HTTPS redirect was observed.',
                        'remediation': 'Serve the application over HTTPS and redirect clear-text HTTP requests to HTTPS.',
                    })
        except Exception as exc:
            # Network failure is coverage information, not proof of an
            # insecure protocol. The request log retains the error.
            self.logger.debug(f"Protocol check error: {exc}")
    
    async def _test_sql_injection(self, target: str, crawl_data: Dict[str, Any]):
        """Test for SQL injection vulnerabilities"""
        self.logger.info("[*] Testing for SQL injection...")
        
        forms = crawl_data.get('forms', [])
        
        ssl_context = self._ssl_context()
        
        async with aiohttp.ClientSession(headers=self._session_headers()) as session:
            # Test forms
            for form in forms:
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'textarea', 'hidden', 'json']:
                        await self._test_sqli_on_input(
                            session, ssl_context, form, input_field['name']
                        )

            for page in crawl_data.get('pages', []):
                parsed = urlparse(page)
                for parameter in parse_qs(parsed.query, keep_blank_values=True):
                    await self._test_sqli_on_query(session, ssl_context, page, parameter)
    
    async def _test_sqli_on_input(self, session, ssl_context, form: Dict, param_name: str):
        """Test one form field with error and true/false differential probes."""
        if param_name.lower() in self.REDIRECT_PARAMETER_NAMES:
            return

        original = next(
            (field.get('value', '') for field in form.get('inputs', []) if field.get('name') == param_name),
            '',
        )

        async def probe(value: str, phase: str):
            data = self._form_data(form, param_name, value)
            method = form.get('method', 'get').lower()
            try:
                if method == 'get':
                    url = f"{form['url']}?{urlencode(data, doseq=True)}"
                    request_kwargs = {}
                    request_method = 'GET'
                else:
                    url = form['url']
                    request_kwargs = self._form_request_kwargs(form, data)
                    request_method = method.upper()
                async with self._request(
                    session, request_method, url, phase,
                    ssl=ssl_context,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers=self._session_headers(), allow_redirects=False,
                    **request_kwargs,
                ) as response:
                    if response is None:
                        return None
                    return {'status': response.status, 'text': await response.text(), 'url': url}
            except Exception as exc:
                self.logger.debug(f"Form SQLi probe error: {exc}")
                return None

        baseline = await probe(str(original), 'sqli-baseline')
        baseline_has_sql_error = bool(
            baseline and self.verifier.verify_sql_error(baseline['text'], self.SQL_ERRORS)['error_signature_found']
        )
        baseline_is_clean = baseline is not None and not baseline_has_sql_error
        # Error-based probes are useful for DVWA and similar lab targets, but
        # every probe below is comment-terminated; a lone quote is never
        # reported as SQL injection by itself.
        comment_payloads = self._sqli_comment_payloads()
        error_candidates = []
        for payload in comment_payloads[:3]:
            error_response = await probe(payload, 'sqli-error')
            if not error_response:
                continue
            verification = self.verifier.verify_sql_error(error_response['text'], self.SQL_ERRORS)
            if verification['error_signature_found'] and baseline_is_clean:
                error_candidates.append((payload, error_response, verification))
        positive = await probe(self.SQLI_BOOLEAN_TRUE, 'sqli-positive')
        negative = await probe(self.SQLI_BOOLEAN_FALSE, 'sqli-negative')
        if not positive or not negative:
            return

        positive_error = self.verifier.verify_sql_error(positive['text'], self.SQL_ERRORS)
        negative_error = self.verifier.verify_sql_error(negative['text'], self.SQL_ERRORS)
        if error_candidates and (positive_error['error_signature_found'] or negative_error['error_signature_found']) and baseline_is_clean and param_name.lower() not in self.FILE_PARAMETER_NAMES:
            payload, error_response, verification = error_candidates[0]
            self.findings.append({
                'type': 'SQL Injection', 'severity': 'critical',
                'title': f'SQL injection verified in {param_name}',
                'description': f'Form parameter "{param_name}" returned a recognizable database error across comment-terminated SQL probes.',
                'location': form['url'], 'parameter': param_name, 'method': form.get('method', 'get').upper(),
                'status_code': error_response['status'], 'confidence': verification['confidence'],
                'state': verification['state'],
                'evidence': f"Database error signature: {verification['matched_signature']}",
                'verification': verification,
                'remediation': 'Use parameterized queries and input validation',
                'payload': payload,
                'cwe': 'CWE-89', 'owasp': 'A03:2021-Injection',
            })
            return

        if baseline:
            differential = self.verifier.compare_sql_responses(
                baseline['text'], positive['text'], negative['text'],
                baseline['status'], positive['status'], negative['status'],
            )
            if differential['different_response']:
                self.findings.append({
                    'type': 'SQL Injection', 'severity': 'high',
                    'title': f'Boolean response difference in {param_name}',
                    'description': f'The true and false SQL conditions produced materially different responses for form parameter "{param_name}".',
                    'location': form['url'], 'parameter': param_name, 'method': form.get('method', 'get').upper(),
                    'status_code': positive['status'], 'confidence': differential['confidence'],
                    'state': 'suspected',
                    'evidence': f"Positive delta {differential['positive_delta']}; negative delta {differential['negative_delta']}; true/false similarity {differential['positive_negative_similarity']}.",
                    'verification': differential,
                    'remediation': 'Use parameterized queries and input validation',
                    'payload': self.SQLI_BOOLEAN_TRUE,
                    'cwe': 'CWE-89', 'owasp': 'A03:2021-Injection',
                })

    async def _test_sqli_on_query(self, session, ssl_context, page: str, param_name: str):
        parsed = urlparse(normalize_url(page))
        original_params = parse_qs(parsed.query, keep_blank_values=True)

        async def probe(value: str, phase: str):
            params = {key: list(values) for key, values in original_params.items()}
            params[param_name] = [value]
            test_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params, doseq=True), ''))
            try:
                async with self._request(session, 'GET', test_url, phase, ssl=ssl_context,
                                         timeout=aiohttp.ClientTimeout(total=self.timeout),
                                         headers=self._session_headers(), allow_redirects=False) as response:
                    if response is None:
                        return None
                    return {'status': response.status, 'text': await response.text(), 'url': test_url}
            except Exception as e:
                self.logger.debug(f"Query SQLi test error: {e}")
                return None

        if param_name.lower() in self.REDIRECT_PARAMETER_NAMES:
            return

        baseline = await probe(str(original_params.get(param_name, [''])[0]), 'sqli-baseline')
        baseline_has_sql_error = bool(
            baseline and self.verifier.verify_sql_error(baseline['text'], self.SQL_ERRORS)['error_signature_found']
        )
        baseline_is_clean = baseline is not None and not baseline_has_sql_error
        comment_payloads = self._sqli_comment_payloads()
        error_candidates = []
        for payload in comment_payloads[:3]:
            error_response = await probe(payload, 'sqli-error')
            if not error_response:
                continue
            verification = self.verifier.verify_sql_error(error_response['text'], self.SQL_ERRORS)
            if verification['error_signature_found'] and baseline_is_clean:
                error_candidates.append((payload, error_response, verification))
        positive = await probe(self.SQLI_BOOLEAN_TRUE, 'sqli-positive')
        negative = await probe(self.SQLI_BOOLEAN_FALSE, 'sqli-negative')
        if not positive or not negative:
            return

        positive_error = self.verifier.verify_sql_error(positive['text'], self.SQL_ERRORS)
        negative_error = self.verifier.verify_sql_error(negative['text'], self.SQL_ERRORS)
        if error_candidates and (positive_error['error_signature_found'] or negative_error['error_signature_found']) and baseline_is_clean and param_name.lower() not in self.FILE_PARAMETER_NAMES:
            payload, error_response, verification = error_candidates[0]
            self.findings.append({
                'type': 'SQL Injection', 'severity': 'critical',
                'title': f'SQL injection verified in {param_name}',
                'description': f'Parameter "{param_name}" returned a recognizable database error across comment-terminated SQL probes.',
                'location': page, 'parameter': param_name, 'method': 'GET',
                'status_code': error_response['status'],
                'confidence': verification['confidence'], 'state': verification['state'],
                'evidence': f"Database error signature: {verification['matched_signature']}",
                'verification': verification,
                'remediation': 'Use parameterized queries and input validation', 'payload': payload,
                'cwe': 'CWE-89', 'owasp': 'A03:2021-Injection',
            })
            return

        if baseline:
            differential = self.verifier.compare_sql_responses(
                baseline['text'], positive['text'], negative['text'],
                baseline['status'], positive['status'], negative['status'],
            )
            if differential['different_response']:
                self.findings.append({
                    'type': 'SQL Injection', 'severity': 'high',
                    'title': f'Boolean response difference in {param_name}',
                    'description': f'The true and false SQL conditions produced materially different responses for "{param_name}".',
                    'location': page, 'parameter': param_name, 'method': 'GET',
                    'status_code': positive['status'],
                    'confidence': differential['confidence'], 'state': 'suspected',
                    'evidence': f"Positive delta {differential['positive_delta']}; negative delta {differential['negative_delta']}; true/false similarity {differential['positive_negative_similarity']}.",
                    'verification': differential,
                    'remediation': 'Use parameterized queries and input validation', 'payload': self.SQLI_BOOLEAN_TRUE,
                    'cwe': 'CWE-89', 'owasp': 'A03:2021-Injection',
                })
    
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
        
        ssl_context = self._ssl_context()
        
        async with aiohttp.ClientSession(headers=self._session_headers()) as session:
            # Test query-string parameters discovered in crawled URLs.
            for page in crawl_data.get('pages', []):
                parsed = urlparse(page)
                query_parameters = parse_qs(parsed.query, keep_blank_values=True)
                for parameter in query_parameters:
                    await self._test_xss_on_query(session, ssl_context, page, parameter)

            # Test forms
            for form in forms:
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'textarea', 'json']:
                        await self._test_xss_on_input(
                            session, ssl_context, form, input_field['name']
                        )

    async def _test_xss_on_query(self, session, ssl_context, page: str, param_name: str):
        """Check a discovered GET parameter for exact reflection.

        This is a reflection signal, not automatic proof of executable XSS; the
        report labels it as a suspected finding for manual context validation.
        """
        test_payload = "<script>alert('XSS')</script>"
        try:
            page = normalize_url(page)
        except ValueError:
            return
        parsed = urlparse(page)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [test_payload]
        test_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params, doseq=True), ""))
        if not self.scope.is_allowed(test_url):
            return
        try:
            async with self._request(
                session, 'GET', test_url, 'xss',
                ssl=ssl_context,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers=self._session_headers(), allow_redirects=False
            ) as response:
                if response is None:
                    return
                text = await response.text()
                verification = self.verifier.verify_reflection(test_payload, text)
                if verification['payload_reflected']:
                    self.findings.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'medium',
                        'title': f'Potential reflected XSS in {param_name}',
                        'description': f'Parameter "{param_name}" reflects a test marker without contextual encoding',
                        'location': page,
                        'parameter': param_name,
                        'status_code': response.status,
                        'confidence': 'medium',
                        'state': 'suspected',
                        'evidence': f"Exact test marker was reflected in HTTP {response.status} response ({verification['context']})",
                        'verification': verification,
                        'cwe': 'CWE-79', 'owasp': 'A03:2021-Injection',
                        'remediation': 'Contextually encode untrusted output and manually verify the rendering context',
                        'payload': test_payload
                    })
        except Exception as e:
            self.logger.debug(f"Query XSS test error: {e}")
    
    async def _test_xss_on_input(self, session, ssl_context, form: Dict, param_name: str):
        """Test XSS on a specific input"""
        test_payload = "<script>alert('XSS')</script>"
        
        try:
            data = self._form_data(form, param_name, test_payload)
            
            if form['method'] == 'get':
                url = f"{form['url']}?{urlencode(data)}"
                async with self._request(
                    session, 'GET', url, 'xss',
                    ssl=ssl_context,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers=self._session_headers(), allow_redirects=False
                ) as response:
                    if response is None:
                        return
                    text = await response.text()
                    verification = self.verifier.verify_reflection(test_payload, text)
                    if verification['payload_reflected']:
                        self.findings.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'medium',
                            'title': f'Potential reflected XSS in {param_name}',
                            'description': f'Parameter "{param_name}" reflects unfiltered user input',
                            'location': form['url'],
                            'parameter': param_name,
                            'status_code': response.status,
                            'confidence': 'medium',
                            'state': 'suspected',
                            'evidence': f"Exact test marker was reflected in HTTP {response.status} response ({verification['context']})",
                            'verification': verification,
                            'remediation': 'Implement proper input validation and output encoding',
                            'payload': test_payload
                        })
            else:
                request_method = form.get('method', 'post').upper()
                async with self._request(
                    session, request_method, form['url'], 'xss',
                    **self._form_request_kwargs(form, data),
                    ssl=ssl_context,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers=self._session_headers(), allow_redirects=False
                ) as response:
                    if response is None:
                        return
                    text = await response.text()
                    verification = self.verifier.verify_reflection(test_payload, text)
                    if verification['payload_reflected']:
                        self.findings.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'medium',
                            'title': f'Potential reflected XSS in {param_name}',
                            'description': f'Parameter "{param_name}" reflects unfiltered user input',
                            'location': form['url'],
                            'parameter': param_name,
                            'status_code': response.status,
                            'confidence': 'medium',
                            'state': 'suspected',
                            'evidence': f"Exact test marker was reflected in HTTP {response.status} response ({verification['context']})",
                            'verification': verification,
                            'remediation': 'Implement proper input validation and output encoding',
                            'payload': test_payload
                        })
        
        except Exception as e:
            self.logger.debug(f"XSS test error: {e}")

    async def _test_ssti(self, target: str, crawl_data: Dict[str, Any]):
        """Run baseline-aware arithmetic probes against template-like inputs."""
        self.logger.info("[*] Testing for server-side template injection...")
        ssl_context = self._ssl_context()
        candidates = []
        for page in crawl_data.get('pages', []):
            parsed = urlparse(page)
            for parameter in parse_qs(parsed.query, keep_blank_values=True):
                candidates.append(('query', page, parameter))
        for form in crawl_data.get('forms', []):
            for input_field in form.get('inputs', []):
                if input_field.get('type', 'text') in {'text', 'search', 'textarea', 'json'}:
                    candidates.append(('form', form, input_field['name']))

        async with aiohttp.ClientSession(headers=self._session_headers()) as session:
            for source, candidate, parameter in candidates:
                try:
                    def build_probe(value: str):
                        if source == 'query':
                            parsed = urlparse(normalize_url(candidate))
                            params = parse_qs(parsed.query, keep_blank_values=True)
                            params[parameter] = [value]
                            endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params, doseq=True), ''))
                            return 'GET', endpoint, {}, candidate
                        form = candidate
                        data = self._form_data(form, parameter, value)
                        method = form.get('method', 'get').upper()
                        if method == 'GET':
                            endpoint = f"{form['url']}?{urlencode(data, doseq=True)}"
                            return method, endpoint, {}, form['url']
                        return method, form['url'], self._form_request_kwargs(form, data), form['url']

                    baseline_method, baseline_endpoint, baseline_kwargs, location = build_probe(
                        str(parse_qs(urlparse(candidate).query, keep_blank_values=True).get(parameter, [''])[0])
                        if source == 'query' else str(next((field.get('value', '') for field in candidate.get('inputs', []) if field.get('name') == parameter), ''))
                    )
                    if not self.scope.is_allowed(baseline_endpoint):
                        continue
                    async with self._request(
                        session, baseline_method, baseline_endpoint, 'ssti-baseline', ssl=ssl_context,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        headers=self._session_headers(), allow_redirects=False, **baseline_kwargs
                    ) as baseline_response:
                        if baseline_response is None:
                            continue
                        baseline_text = await baseline_response.text()

                    for payload, expected in self.SSTI_PROBES:
                        method, endpoint, kwargs, location = build_probe(payload)
                        if not self.scope.is_allowed(endpoint):
                            continue
                        async with self._request(
                            session, method, endpoint, 'ssti', ssl=ssl_context,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            headers=self._session_headers(), allow_redirects=False, **kwargs
                        ) as response:
                            if response is None:
                                continue
                            response_text = await response.text()
                            evaluated = (
                                expected not in baseline_text
                                and expected in response_text
                                and payload not in response_text
                            )
                            if evaluated:
                                verification = {
                                    'payload': payload,
                                    'expected_result': expected,
                                    'baseline_result_present': expected in baseline_text,
                                    'result_found': True,
                                    'payload_reflected': payload in response_text,
                                    'state': 'suspected',
                                    'confidence': 'medium',
                                }
                                self.findings.append({
                                    'type': 'Server-Side Template Injection (SSTI)',
                                    'severity': 'medium',
                                    'title': f'Possible SSTI in {parameter}',
                                    'description': f'The template expression in "{parameter}" appears to have been evaluated by the server.',
                                    'location': location,
                                    'parameter': parameter,
                                    'status_code': response.status,
                                    'confidence': 'medium',
                                    'state': 'suspected',
                                    'evidence': f'Expression {payload} produced the value {expected} in HTTP {response.status} response, absent from the baseline.',
                                    'verification': verification,
                                    'remediation': 'Treat user input as data, not a template; use a safe rendering API and strict allow-lists.',
                                    'payload': payload,
                                    'cwe': 'CWE-1336', 'owasp': 'A03:2021-Injection',
                                })
                                break
                except Exception as e:
                    self.logger.debug(f"SSTI test error: {e}")
    
    def _iter_named_candidates(self, crawl_data: Dict[str, Any], names: Set[str]):
        """Yield query/form inputs whose names fit the selected attack class."""
        def matches(parameter: str) -> bool:
            normalized = parameter.strip().lower()
            parts = set(part for part in re.split(r'[^a-z0-9]+', normalized) if part)
            return normalized in names or bool(parts.intersection(names))

        for page in crawl_data.get('pages', []):
            parsed = urlparse(page)
            params = parse_qs(parsed.query, keep_blank_values=True)
            for parameter, values in params.items():
                if matches(parameter):
                    yield 'query', page, parameter, str(values[0] if values else '')
        for form in crawl_data.get('forms', []):
            for field in form.get('inputs', []):
                parameter = field.get('name', '')
                if matches(parameter):
                    yield 'form', form, parameter, str(field.get('value', ''))

    def _build_candidate_probe(self, source: str, candidate: Any, parameter: str, value: str):
        if source == 'query':
            parsed = urlparse(normalize_url(candidate))
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[parameter] = [value]
            endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params, doseq=True), ''))
            return 'GET', endpoint, {}, candidate
        form = candidate
        data = self._form_data(form, parameter, value)
        method = form.get('method', 'get').upper()
        if method == 'GET':
            return method, f"{form['url']}?{urlencode(data, doseq=True)}", {}, form['url']
        return method, form['url'], self._form_request_kwargs(form, data), form['url']

    async def _send_candidate_probe(self, session, ssl_context, method: str, endpoint: str, phase: str, kwargs: Dict[str, Any]):
        try:
            async with self._request(
                session, method, endpoint, phase, ssl=ssl_context,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers=self._session_headers(), allow_redirects=False, **kwargs,
            ) as response:
                if response is None:
                    return None
                return {
                    'status': response.status,
                    'text': await response.text(),
                    'url': endpoint,
                    'content_type': response.headers.get('Content-Type', ''),
                }
        except Exception as exc:
            self.logger.debug(f"{phase} probe error: {exc}")
            return None

    async def _test_command_injection(self, target: str, crawl_data: Dict[str, Any]):
        """Look for command execution using marker-only, non-destructive probes."""
        self.logger.info("[*] Testing for command injection...")
        payloads = self._load_payload_file('command_injection_payloads.txt', self.COMMAND_PAYLOADS)
        candidates = list(self._iter_named_candidates(crawl_data, self.COMMAND_PARAMETER_NAMES))
        if not candidates:
            return
        ssl_context = self._ssl_context()
        marker = f"websentinel_cmd_{time.time_ns()}"
        async with aiohttp.ClientSession(headers=self._session_headers()) as session:
            for source, candidate, parameter, original in candidates:
                method, endpoint, kwargs, location = self._build_candidate_probe(source, candidate, parameter, original)
                baseline = await self._send_candidate_probe(session, ssl_context, method, endpoint, 'cmd-baseline', kwargs)
                if not baseline or marker in baseline['text']:
                    continue
                for payload in payloads:
                    rendered = payload.replace('{marker}', marker)
                    if '{marker}' not in payload:
                        rendered = f"{payload};printf '{marker}'"
                    method, endpoint, kwargs, location = self._build_candidate_probe(source, candidate, parameter, rendered)
                    response = await self._send_candidate_probe(session, ssl_context, method, endpoint, 'command-injection', kwargs)
                    if not response or marker not in response['text'] or rendered in response['text']:
                        continue
                    self.findings.append({
                        'type': 'OS Command Injection',
                        'severity': 'high',
                        'title': f'Command injection verified in {parameter}',
                        'description': f'An operating-system command marker was observed in the response for parameter "{parameter}".',
                        'location': location,
                        'parameter': parameter,
                        'method': method,
                        'status_code': response['status'],
                        'content_length': len(response['text']),
                        'content_type': response['content_type'],
                        'confidence': 'high',
                        'state': 'confirmed',
                        'evidence': f'Unique marker {marker} appeared after a non-destructive command probe and was absent from the baseline.',
                        'verification': {'marker': marker, 'baseline_marker_present': False, 'payload_reflected': False},
                        'remediation': 'Avoid shell execution where possible; otherwise use strict allow-lists and safe process APIs.',
                        'payload': rendered,
                        'cwe': 'CWE-78', 'owasp': 'A03:2021-Injection',
                    })
                    break

    async def _test_file_inclusion(self, target: str, crawl_data: Dict[str, Any]):
        """Test file-like inputs with local marker checks, without remote callbacks."""
        self.logger.info("[*] Testing for file inclusion / LFI...")
        payloads = self._load_payload_file('file_inclusion_payloads.txt', self.FILE_PAYLOADS)
        candidates = list(self._iter_named_candidates(crawl_data, self.FILE_PARAMETER_NAMES))
        if not candidates:
            return
        ssl_context = self._ssl_context()
        markers = ('root:x:0:0:', '127.0.0.1', '[extensions]')
        async with aiohttp.ClientSession(headers=self._session_headers()) as session:
            for source, candidate, parameter, original in candidates:
                method, endpoint, kwargs, location = self._build_candidate_probe(source, candidate, parameter, original)
                baseline = await self._send_candidate_probe(session, ssl_context, method, endpoint, 'file-inclusion-baseline', kwargs)
                if not baseline:
                    continue
                for payload in payloads:
                    method, endpoint, kwargs, location = self._build_candidate_probe(source, candidate, parameter, payload)
                    response = await self._send_candidate_probe(session, ssl_context, method, endpoint, 'file-inclusion', kwargs)
                    if not response:
                        continue
                    verification = self.verifier.verify_file_disclosure(response['text'], markers)
                    if not verification['marker_found'] or verification['matched_marker'].lower() in baseline['text'].lower():
                        continue
                    self.findings.append({
                        'type': 'File Inclusion / LFI',
                        'severity': 'high',
                        'title': f'File inclusion verified in {parameter}',
                        'description': f'Parameter "{parameter}" returned a known local-file marker during a bounded inclusion probe.',
                        'location': location,
                        'parameter': parameter,
                        'method': method,
                        'status_code': response['status'],
                        'content_length': len(response['text']),
                        'content_type': response['content_type'],
                        'confidence': 'high',
                        'state': 'confirmed',
                        'evidence': f"Matched local-file marker: {verification['matched_marker']}",
                        'verification': verification,
                        'remediation': 'Use server-side allow-lists for file identifiers and never concatenate user input into filesystem paths.',
                        'payload': payload,
                        'cwe': 'CWE-98', 'owasp': 'A01:2021-Broken Access Control',
                    })
                    break

    async def _test_directory_traversal(self, target: str, crawl_data: Dict[str, Any]):
        """Test GET and POST file-like inputs for directory traversal."""
        self.logger.info("[*] Testing for directory traversal...")
        candidates = list(self._iter_named_candidates(crawl_data, self.FILE_PARAMETER_NAMES))
        if not candidates:
            return
        ssl_context = self._ssl_context()
        async with aiohttp.ClientSession(headers=self._session_headers()) as session:
            for source, candidate, parameter, original in candidates:
                method, endpoint, kwargs, location = self._build_candidate_probe(source, candidate, parameter, original)
                baseline = await self._send_candidate_probe(session, ssl_context, method, endpoint, 'path-traversal-baseline', kwargs)
                if not baseline:
                    continue
                for payload in self.TRAVERSAL_PAYLOADS[:4]:
                    method, endpoint, kwargs, location = self._build_candidate_probe(source, candidate, parameter, payload)
                    response = await self._send_candidate_probe(session, ssl_context, method, endpoint, 'path-traversal', kwargs)
                    if not response:
                        continue
                    verification = self.verifier.verify_file_disclosure(response['text'], ('root:x:0:0:', '127.0.0.1', '[extensions]'))
                    if not verification['marker_found'] or verification['matched_marker'].lower() in baseline['text'].lower():
                        continue
                    self.findings.append({
                        'type': 'Directory Traversal',
                        'severity': 'high',
                        'title': f'File disclosure verified through {parameter}',
                        'description': f'Parameter "{parameter}" returned a known operating-system file marker during GET/POST traversal verification.',
                        'location': location,
                        'parameter': parameter,
                        'method': method,
                        'status_code': response['status'],
                        'content_length': len(response['text']),
                        'content_type': response['content_type'],
                        'confidence': verification['confidence'],
                        'state': 'confirmed',
                        'evidence': f"Matched file-content marker: {verification['matched_marker']}",
                        'verification': verification,
                        'remediation': 'Implement proper path validation and restrict file access',
                        'payload': payload,
                        'cwe': 'CWE-98', 'owasp': 'A01:2021-Broken Access Control',
                    })
                    break

    async def _test_open_redirect(self, target: str, crawl_data: Dict[str, Any]):
        """Check redirect-like parameters without following the destination."""
        self.logger.info("[*] Testing redirect parameters...")
        redirect_names = {'url', 'uri', 'next', 'redirect', 'redirect_url', 'return', 'return_url', 'callback'}
        canary = 'https://redirect-check.invalid/'
        ssl_context = self._ssl_context()
        candidates = []
        for page in crawl_data.get('pages', []):
            parsed = urlparse(page)
            params = parse_qs(parsed.query, keep_blank_values=True)
            for name in params:
                if name.lower() in redirect_names:
                    candidates.append((page, name, 'query'))
        for form in crawl_data.get('forms', []):
            for field in form.get('inputs', []):
                if field.get('name', '').lower() in redirect_names:
                    candidates.append((form, field['name'], 'form'))

        async with aiohttp.ClientSession(headers=self._session_headers()) as session:
            tested_candidates = set()
            for candidate, name, source in candidates:
                try:
                    if source == 'query':
                        parsed = urlparse(normalize_url(candidate))
                        params = parse_qs(parsed.query, keep_blank_values=True)
                        params[name] = [canary]
                        test_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params, doseq=True), ''))
                        method, endpoint, kwargs = 'GET', test_url, {}
                    else:
                        form = candidate
                        data = {field['name']: 'test' for field in form.get('inputs', [])}
                        data[name] = canary
                        method = form.get('method', 'get').upper()
                        if method == 'GET':
                            endpoint = f"{form['url']}?{urlencode(data)}"
                            kwargs = {}
                        else:
                            endpoint, kwargs = form['url'], self._form_request_kwargs(form, data)
                    candidate_key = (method, normalize_url(endpoint), name)
                    if candidate_key in tested_candidates:
                        continue
                    tested_candidates.add(candidate_key)
                    async with self._request(session, method, endpoint, 'open-redirect', ssl=ssl_context,
                                             timeout=aiohttp.ClientTimeout(total=self.timeout),
                                             headers=self._session_headers(), allow_redirects=False, **kwargs) as response:
                        if response is None:
                            return
                        location = response.headers.get('Location', '')
                        if location.startswith(canary):
                            self.findings.append({
                                'type': 'Open Redirect', 'severity': 'medium',
                                'title': f'Open redirect in {name}',
                                'description': f'Parameter "{name}" redirects to an attacker-controlled destination',
                                'location': endpoint, 'parameter': name,
                                'status_code': response.status,
                                'confidence': 'high', 'state': 'suspected',
                                'evidence': f'Location header returned the controlled canary: {location}',
                                'remediation': 'Allow-list trusted destinations and reject external redirect targets',
                                'payload': canary,
                            })
                except Exception as e:
                    self.logger.debug(f"Open redirect test error: {e}")
    
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
        signatures = {
            'config.php': ('<?php', 'DB_', 'database'),
            'wp-config.php': ('DB_NAME', 'DB_PASSWORD', '<?php'),
            'web.config': ('<configuration',),
            '.htaccess': ('RewriteRule', 'Deny from', 'AuthType', 'Options'),
            'phpinfo.php': ('php version', 'phpinfo'),
            'info.php': ('php version', 'phpinfo'),
        }
        
        ssl_context = self._ssl_context()
        
        async with aiohttp.ClientSession(headers=self._session_headers()) as session:
            for file in sensitive_files:
                try:
                    url = urljoin(target, file)
                    async with self._request(
                        session, 'GET', url, 'sensitive-file',
                        ssl=ssl_context,
                        timeout=aiohttp.ClientTimeout(total=5),
                        headers=self._session_headers()
                    ) as response:
                        if response is None:
                            return
                        if response.status == 200:
                            text = await response.text()
                            if len(text) > 0:
                                content_type = response.headers.get('Content-Type', '')
                                lowered = text.lower()
                                expected = signatures.get(file)
                                signature_match = bool(expected and any(marker.lower() in lowered for marker in expected))
                                if file == '.git/config':
                                    signature_match = bool(re.search(r'^\s*\[(?:core|remote(?:\s+|$))', text, re.I | re.M))
                                elif file == '.env':
                                    # A SPA fallback often contains '=' in
                                    # HTML attributes. Require multiple real
                                    # dotenv assignments and reject HTML.
                                    assignments = re.findall(r'^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S+', text, re.M)
                                    signature_match = len(assignments) >= 2 and 'text/html' not in content_type.lower()
                                elif file == 'config.yml':
                                    yaml_lines = re.findall(r'^\s*[A-Za-z_][\w.-]{1,}\s*:\s+\S+', text, re.M)
                                    signature_match = len(yaml_lines) >= 2 and 'text/html' not in content_type.lower()
                                elif file == 'settings.py':
                                    python_config = re.findall(r'^\s*(?:SECRET|DATABASE|DEBUG|ALLOWED_HOSTS)\w*\s*=|^\s*(?:from|import)\s+', text, re.I | re.M)
                                    signature_match = len(python_config) >= 2 and 'text/html' not in content_type.lower()
                                if file in {'.git/config', '.env', 'config.php', 'wp-config.php', 'config.yml', 'settings.py', 'web.config', '.htaccess', 'phpinfo.php', 'info.php'} and not signature_match:
                                    continue
                                if file in {'robots.txt', 'sitemap.xml'}:
                                    severity = 'info'
                                    title = f'Publicly accessible {file}'
                                    description = f'The file {file} is publicly accessible and may disclose application paths.'
                                    remediation = 'Review whether the file should be public and avoid listing sensitive paths.'
                                else:
                                    severity = 'high' if file in ['.git/config', '.env', 'config.php', 'wp-config.php'] else 'medium'
                                    title = f'Sensitive file exposed: {file}'
                                    description = f'The file {file} is publicly accessible and matched an expected content signature.'
                                    remediation = 'Restrict access to sensitive configuration or diagnostic files.'
                                self.findings.append({
                                    'type': 'Information Disclosure',
                                    'severity': severity,
                                    'title': title,
                                    'description': description,
                                    'location': url,
                                    'status_code': response.status,
                                    'content_length': len(text),
                                    'content_type': content_type,
                                    'remediation': remediation,
                                })
                
                except Exception as e:
                    self.logger.debug(f"File check error for {file}: {e}")
    
    async def _test_csrf(self, target: str, crawl_data: Dict[str, Any]):
        """Check for CSRF protection"""
        self.logger.info("[*] Checking CSRF protection...")
        
        forms = crawl_data.get('forms', [])
        tested_forms = set()
        
        for form in forms:
            if form['method'] == 'post':
                form_key = (
                    form.get('method', 'post').lower(),
                    form.get('url', ''),
                    tuple(sorted(str(inp.get('name', '')) for inp in form.get('inputs', []))),
                )
                if form_key in tested_forms:
                    continue
                tested_forms.add(form_key)
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
