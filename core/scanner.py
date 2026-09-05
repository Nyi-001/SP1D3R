"""Main scanner orchestrator"""
import asyncio
import ipaddress
from typing import Dict, List, Any
from datetime import datetime
from urllib.parse import urlsplit

from .port_scanner import PortScanner
from .subdomain_enum import SubdomainEnumerator
from .vuln_scanner import VulnerabilityScanner
from .cve_matcher import CVESuggestionMatcher
from .web_scanner import WebScanner
from modules.dns_analyzer import DNSAnalyzer
from modules.ssl_tester import SSLTester
from modules.waf_detector import WAFDetector
from modules.fingerprint import TechFingerprint
from .scope import ScopePolicy
from .finding_model import normalize_finding
from .request_file import parse_request_file
from colorama import Fore, Style


class PentestScanner:
    """Main penetration testing scanner orchestrator"""
    
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        scope_config = config.get('scope', {})
        self.scope = ScopePolicy(scope_config.get('allowed_hosts', []), scope_config.get('excluded_paths', []))
        
        # Initialize modules
        self.port_scanner = PortScanner(config, logger)
        self.subdomain_enum = SubdomainEnumerator(config, logger)
        self.vuln_scanner = VulnerabilityScanner(config, logger)
        self.cve_matcher = CVESuggestionMatcher(
            config.get('cve_catalog'),
            config.get('cve_cache_dir'),
        )
        self.web_scanner = WebScanner(config, logger)
        self.dns_analyzer = DNSAnalyzer(config, logger)
        self.ssl_tester = SSLTester(config, logger)
        self.waf_detector = WAFDetector(config, logger)
        self.tech_fingerprint = TechFingerprint(config, logger)
        
        self.results = {
            'scan_info': {},
            'target': {},
            'findings': [],
            'stats': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        self._finding_ids = set()
    
    async def scan(self, params: Dict[str, Any]) -> Dict:
        """Execute comprehensive scan based on parameters"""
        # A scanner instance may process multiple targets; do not leak results.
        self.results = {
            'scan_info': {},
            'target': {},
            'findings': [],
            'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }
        self._finding_ids = set()

        target = params['target']
        target = self.scope.assert_allowed(target if '://' in target else f"https://{target}")
        host_target = urlsplit(target).hostname or target
        try:
            is_ip_target = ipaddress.ip_address(host_target) is not None
        except ValueError:
            is_ip_target = False
        is_local_target = host_target.lower() in {'localhost', 'localhost.localdomain'}
        skip_name_recon = is_ip_target or is_local_target
        scan_type = params.get('scan_type', 'standard')
        module = params.get('module', 'all')
        active_checks = bool(self.config.get('scope', {}).get('active_checks', False))
        request_spec = None
        if params.get('request_file'):
            try:
                request_spec = parse_request_file(
                    params['request_file'],
                    target,
                    params.get('request_scheme'),
                )
                if not self.scope.is_allowed(request_spec['url']):
                    raise ValueError(f"request URL is outside the configured scope: {request_spec['url']}")
                request_cookie = next(
                    (str(value) for name, value in request_spec.get('headers', {}).items()
                     if str(name).lower() == 'cookie' and value),
                    '',
                )
                request_headers = {
                    str(name): str(value)
                    for name, value in request_spec.get('headers', {}).items()
                    if str(name).lower() not in {'host', 'content-length', 'connection', 'transfer-encoding'}
                }
                if request_headers:
                    # Keep the captured authentication context consistent
                    # for native checks and external tools such as WhatWeb,
                    # dirsearch, and Nuclei.
                    self.config.setdefault('scanning', {}).setdefault('headers', {}).update(request_headers)
                if request_cookie and not self.config.get('scanning', {}).get('cookie'):
                    # External fingerprint/content tools run before WebScanner
                    # is initialized; give them the same session context as
                    # the parsed request without requiring --cookie twice.
                    self.config.setdefault('scanning', {})['cookie'] = request_cookie
                self.logger.info(f"[*] Loaded Burp request seed: {request_spec['method']} {request_spec['url']}")
            except (OSError, ValueError) as exc:
                self.logger.error(f"[!] Request file error: {exc}")
                raise ValueError(f"unable to load request file '{params['request_file']}': {exc}") from exc
        
        # Record scan info
        self.results['scan_info'] = {
            'start_time': datetime.now().isoformat(),
            'target': target,
            'scan_type': scan_type,
            'module': module
        }
        if request_spec:
            self.results['scan_info']['request_file'] = request_spec['source']
        
        self.logger.info(f"Initializing {scan_type} scan on {target}")
        
        # Determine which modules to run based on scan type
        modules_to_run = self._get_modules_for_scan_type(scan_type, module)
        # Endpoint attack flags are meaningful only through the web scanner.
        # Make the CLI composable: requesting an active test must not silently
        # omit the web phase just because the user selected --module vuln.
        modules_to_run = self._include_required_active_modules(modules_to_run, params, active_checks)
        
        # Reconnaissance is staged deliberately: DNS and subdomain discovery
        # finish before content fuzzing begins. This makes the report's asset
        # chain trustworthy and prevents directory fuzzing from racing the
        # name-enumeration phase.
        scan_params = dict(params)
        scan_params['request_spec'] = request_spec
        preseeded_tools = set()
        # Phase 1: naming and DNS reconnaissance.
        recon_tasks = []
        if 'dns' in modules_to_run and not skip_name_recon:
            recon_tasks.append(self._run_dns_analysis(host_target))
        elif 'dns' in modules_to_run:
            self.results['target']['dns'] = {
                'records': {},
                'findings': [],
                'skipped': 'DNS enumeration is not applicable to a local-only target',
            }
            self.logger.info("[+] DNS enumeration skipped for local-only target")
        
        if 'subdomain' in modules_to_run and not skip_name_recon:
            recon_tasks.append(self._run_subdomain_enum(host_target, params))
        elif 'subdomain' in modules_to_run:
            self.results['target']['subdomains'] = []
            self.results['target']['subdomain_sources'] = {
                'skipped': 'Subdomain enumeration is not applicable to a local-only target'
            }
            self.logger.info("[+] Subdomain enumeration skipped for local-only target")
        
        if recon_tasks:
            await asyncio.gather(*recon_tasks, return_exceptions=True)

        # Phase 2: service and application fingerprinting.
        service_tasks = []
        if 'fingerprint' in modules_to_run:
            preseeded_tools.add('whatweb')
            service_tasks.append(self._run_fingerprinting(target))
        if 'waf' in modules_to_run:
            service_tasks.append(self._run_waf_detection(target))
        if 'port' in modules_to_run:
            service_tasks.append(self._run_port_scan(host_target, params))
        if 'ssl' in modules_to_run:
            service_tasks.append(self._run_ssl_test(target))
        if service_tasks:
            await asyncio.gather(*service_tasks, return_exceptions=True)

        # Phase 3: content discovery, after reconnaissance has completed.
        if active_checks and 'web' in modules_to_run:
            integration = await self._run_external_tools(target, {'external_tools': ['dirsearch']})
            preseeded_tools.add('dirsearch')
            discovered_assets = integration.get('assets', {}) if integration else {}
            scan_params['discovery_assets'] = discovered_assets
            scan_params['seed_urls'] = self._content_seed_urls(discovered_assets)

        # Phase 4: crawl and active verification.
        application_tasks = []
        if 'web' in modules_to_run:
            application_tasks.append(self._run_web_scan(target, scan_params))
        if 'vuln' in modules_to_run:
            application_tasks.append(self._run_vuln_scan(target, params))
        if application_tasks:
            await asyncio.gather(*application_tasks, return_exceptions=True)

        if params.get('external_tools') or (active_checks and 'web' in modules_to_run):
            tool_params = dict(params)
            requested_tools = list(params.get('external_tools') or [])
            if active_checks and 'web' in modules_to_run and 'dirsearch' not in requested_tools and 'dirsearch' not in preseeded_tools:
                requested_tools.append('dirsearch')
            requested_tools = [name for name in requested_tools if name not in preseeded_tools]
            tool_params['external_tools'] = requested_tools
            if requested_tools:
                await self._run_external_tools(target, tool_params)

        # Correlate the verified technology and service observations after
        # discovery has completed. These are suggestions, not confirmed
        # vulnerabilities, because banners can be spoofed or vendor-patched.
        self._run_cve_suggestions(bool(params.get('cve_check', False)))
        
        # Finalize results
        self.results['scan_info']['end_time'] = datetime.now().isoformat()
        self.results['scan_info']['duration'] = self._calculate_duration()
        
        # Calculate statistics
        self._calculate_statistics()
        self._print_terminal_results()
        
        return self.results

    async def _run_external_tools(self, target: str, params: Dict[str, Any]):
        """Run fixed-profile tools and commit their results before continuing."""
        try:
            from integrations.tool_manager import ToolManager

            manager = ToolManager(self.config, self.logger)
            # ToolManager owns subprocess timeouts and streams concise
            # progress. Keep this call in the scan coroutine so the result is
            # committed deterministically before dependent fingerprint data
            # is assembled.
            integration = manager.run_requested(target, params['external_tools'])
            for finding in integration.get('findings', []):
                self._add_finding(finding)
            self.results['target'].setdefault('external_assets', {}).update(integration.get('assets', {}))
            self.results.setdefault('tool_runs', []).extend(integration.get('tool_runs', []))
            self.results.setdefault('errors', []).extend(integration.get('errors', []))
            return integration
        except Exception as exc:
            self.logger.error(f"[!] External tool integration error: {exc}")
            self.results.setdefault('errors', []).append(str(exc))
            return {'findings': [], 'assets': {}, 'tool_runs': [], 'errors': [str(exc)]}

    @staticmethod
    def _content_seed_urls(assets: Dict[str, Any]) -> List[str]:
        """Select application pages from content discovery without crawling dotfiles."""
        seeds = []
        for item in assets.get('directories', []) if isinstance(assets, dict) else []:
            url = str(item.get('url', ''))
            path = urlsplit(url).path.lower()
            try:
                status_code = int(item.get('status'))
            except (TypeError, ValueError):
                status_code = 0
            content_type = str(item.get('content_type', '')).lower()
            if not url or status_code not in {200, 301, 302, 307, 308, 401, 403}:
                continue
            if any(part.startswith('.') for part in path.split('/') if part):
                continue
            if content_type.startswith('text/html') or path.endswith('/') or path.endswith(('.php', '.asp', '.aspx', '.jsp', '.html', '.htm')):
                seeds.append(url)
        return list(dict.fromkeys(seeds))[:150]
    
    def _get_modules_for_scan_type(self, scan_type: str, module: str) -> List[str]:
        """Determine which modules to run based on scan type"""
        if module != 'all':
            # Run specific module
            module_map = {
                'port': ['fingerprint', 'port'],
                'subdomain': ['dns', 'subdomain'],
                'vuln': ['fingerprint', 'waf', 'port', 'vuln'],
                'web': ['fingerprint', 'waf', 'web'],
                'ssl': ['ssl'],
                'dns': ['dns']
            }
            return module_map.get(module, [module])
        
        # Scan type profiles
        if scan_type == 'quick':
            return ['fingerprint', 'waf', 'port', 'subdomain']
        elif scan_type == 'standard':
            return ['fingerprint', 'waf', 'dns', 'subdomain', 'port', 'ssl', 'web']
        elif scan_type == 'deep':
            return ['fingerprint', 'waf', 'dns', 'subdomain', 'port', 'ssl', 'web', 'vuln']
        else:
            return ['fingerprint', 'waf', 'dns', 'subdomain', 'port', 'ssl', 'web', 'vuln']

    @staticmethod
    def _include_required_active_modules(
        modules: List[str], params: Dict[str, Any], active_checks: bool
    ) -> List[str]:
        """Ensure endpoint test flags cannot silently skip web scanning."""
        selected = list(modules)
        if active_checks and (
            params.get('test_sqli') or params.get('test_xss') or params.get('all_tests')
        ) and 'web' not in selected:
            selected.append('web')
        return selected
    
    async def _run_fingerprinting(self, target: str):
        """Run technology fingerprinting"""
        try:
            self.logger.info("[*] Running technology fingerprinting...")
            results = await self.tech_fingerprint.scan(target)
            fingerprint = dict(getattr(self.tech_fingerprint, 'last_observation', {}) or {})

            # WhatWeb supplies useful server/framework/plugin evidence even
            # when the application's Server header is hidden. It is a
            # passive fingerprinting profile, so it runs by default here.
            whatweb = await self._run_external_tools(target, {'external_tools': ['whatweb']})
            self.logger.info("[+] WhatWeb fingerprinting complete")
            whatweb_services = whatweb.get('assets', {}).get('services', []) if whatweb else []
            whatweb_technologies = self._whatweb_technologies(whatweb_services)
            results = self._merge_technologies(results, whatweb_technologies)
            fingerprint['whatweb'] = {
                'status': next((run.get('status') for run in whatweb.get('tool_runs', []) if run.get('tool') == 'whatweb'), 'not-run'),
                'services': whatweb_services,
            }

            self.results['target']['technologies'] = results
            self.results['target']['fingerprint'] = fingerprint
            self.logger.info(f"[+] Detected {len(results)} technologies (including WhatWeb)")
        except Exception as e:
            self.results['target']['fingerprint'] = {
                'target': target,
                'status_code': None,
                'final_url': target,
                'server': '',
                'powered_by': '',
                'content_type': '',
                'error': str(e),
            }
            self.results['target'].setdefault('technologies', [])
            self.logger.error(f"[!] Fingerprinting error: {e}")

    @staticmethod
    def _merge_technologies(primary: List[Dict[str, Any]], secondary: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged = []
        seen = set()
        for item in [*(primary or []), *(secondary or [])]:
            name = item.get('name') if isinstance(item, dict) else str(item)
            key = str(name).strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            merged.append(item)
        return merged

    @staticmethod
    def _whatweb_technologies(services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        metadata_plugins = {
            'ip', 'title', 'uncommonheaders', 'x-frame-options',
            'x-xss-protection', 'httpstatus', 'redirectlocation',
            'cookies', 'country', 'string', 'html5',
        }
        categories = {
            'httpserver': 'Web Server', 'apache': 'Web Server', 'nginx': 'Web Server',
            'iis': 'Web Server', 'cloudflare': 'Infrastructure', 'wordpress': 'CMS',
            'php': 'Programming Language', 'jquery': 'JavaScript Library',
            'bootstrap': 'JavaScript/CSS Library',
        }
        technologies = []
        for service in services or []:
            plugins = service.get('technologies', {}) if isinstance(service, dict) else {}
            if not isinstance(plugins, dict):
                continue
            for name, details in plugins.items():
                version = ''
                normalized = str(name).strip().lower()
                if normalized in metadata_plugins:
                    continue
                values = details if isinstance(details, list) else [details]
                for value in values:
                    if isinstance(value, dict):
                        candidate = value.get('version') or value.get('string') or ''
                    else:
                        candidate = str(value) if value else ''
                    if candidate:
                        version = candidate if not version else f'{version}, {candidate}'
                technologies.append({
                    'name': str(name),
                    'category': categories.get(normalized, 'Web Technology'),
                    'version': version,
                    'confidence': 'high',
                    'source': 'WhatWeb',
                })
        return technologies
    
    async def _run_waf_detection(self, target: str):
        """Run WAF detection"""
        try:
            self.logger.info("[*] Detecting Web Application Firewall...")
            waf_info = await self.waf_detector.detect(target)
            self.results['target']['waf'] = waf_info
            if waf_info.get('detected'):
                self.logger.warning(f"[!] WAF detected: {waf_info.get('name', 'Unknown')}")
        except Exception as e:
            self.logger.error(f"[!] WAF detection error: {e}")
    
    async def _run_dns_analysis(self, target: str):
        """Run DNS analysis"""
        try:
            self.logger.info("[*] Analyzing DNS configuration...")
            dns_results = await self.dns_analyzer.analyze(target)
            self.results['target']['dns'] = dns_results
            
            # Add findings
            for finding in dns_results.get('findings', []):
                self._add_finding(finding)
            
            self.logger.info(f"[+] DNS analysis complete: {len(dns_results.get('records', []))} records found")
        except Exception as e:
            self.logger.error(f"[!] DNS analysis error: {e}")
    
    async def _run_subdomain_enum(self, target: str, params: Dict):
        """Run subdomain enumeration"""
        try:
            self.logger.info("[*] Enumerating subdomains...")
            wordlist = params.get('wordlist')
            subdomains = await self.subdomain_enum.enumerate(target, wordlist)
            self.results['target']['subdomains'] = subdomains
            self.results['target']['subdomain_sources'] = self.subdomain_enum.source_details()
            self.logger.info(f"[+] Found {len(subdomains)} subdomains")
        except Exception as e:
            self.logger.error(f"[!] Subdomain enumeration error: {e}")
    
    async def _run_port_scan(self, target: str, params: Dict):
        """Run port scanning"""
        try:
            self.logger.info("[*] Scanning ports...")
            ports = params.get('ports', '1-1000')
            port_results = await self.port_scanner.scan(target, ports)
            self.results['target']['ports'] = port_results
            
            open_ports = [p for p in port_results if p.get('state') == 'open']
            self.logger.info(f"[+] Found {len(open_ports)} open ports")
            
            # An open TCP socket is an asset observation, not a vulnerability.
            # The old implementation promoted default port numbers directly
            # to HIGH findings, even when no protocol banner was received.
            # Keep the service and confidence in the port inventory; require
            # separate protocol evidence or a version/CVE correlation before
            # creating a security finding.
            for port in open_ports:
                if port.get('service_confidence') == 'high':
                    self.logger.info(
                        f"[+] Service banner observed on {port.get('port')}: {port.get('service')}"
                    )
        except Exception as e:
            self.logger.error(f"[!] Port scanning error: {e}")
    
    async def _run_ssl_test(self, target: str):
        """Run SSL/TLS testing"""
        try:
            self.logger.info("[*] Testing SSL/TLS configuration...")
            ssl_results = await self.ssl_tester.test(target)
            self.results['target']['ssl'] = ssl_results
            
            # Add findings
            for finding in ssl_results.get('findings', []):
                self._add_finding(finding)
            
            self.logger.info("[+] SSL/TLS testing complete")
        except Exception as e:
            self.logger.error(f"[!] SSL testing error: {e}")
    
    async def _run_web_scan(self, target: str, params: Dict):
        """Run web application scanning"""
        try:
            self.logger.info("[*] Scanning web application...")
            test_sqli = params.get('test_sqli', False)
            test_xss = params.get('test_xss', False)
            
            web_results = await self.web_scanner.scan(
                target, test_sqli, test_xss, params.get('seed_urls', []), params.get('request_spec'),
                params.get('discovery_assets', {})
            )
            
            # Add findings
            for finding in web_results.get('findings', []):
                self._add_finding(finding)
            self.results['target']['attack_surface'] = web_results.get('attack_surface', {})
            self.results['coverage'] = web_results.get('coverage', {})
            self.results['target']['crawl'] = web_results.get('crawl', {})
            self.results['target']['site_profile'] = web_results.get('site_profile', {})
            self._print_site_profile(web_results.get('site_profile', {}))
            
            self.logger.info(f"[+] Web scan complete: {len(web_results.get('findings', []))} findings")
        except Exception as e:
            self.logger.error(f"[!] Web scanning error: {e}")

    @staticmethod
    def _print_site_profile(profile: Dict[str, Any]) -> None:
        """Print a compact, colorized classification table for operators."""
        if not profile:
            return
        kind = str(profile.get('kind', 'unknown'))
        color = Fore.MAGENTA if 'GraphQL' in kind else (Fore.CYAN if 'API' in kind else Fore.GREEN)
        print(f"\n{color}{Style.BRIGHT}SITE PROFILE{Style.RESET_ALL}")
        rows = [
            ('Type', kind),
            ('Confidence', profile.get('confidence', 'unknown')),
            ('API detected', 'yes' if profile.get('api_detected') else 'no'),
            ('GraphQL detected', 'yes' if profile.get('graphql_detected') else 'no'),
            ('Pages / forms', f"{profile.get('pages', 0)} / {profile.get('forms', 0)}"),
            ('API routes', profile.get('api_endpoint_count', 0)),
            ('Next reviews', '; '.join(map(str, profile.get('recommended_reviews', [])))),
        ]
        width = max(len(str(label)) for label, _ in rows)
        for label, value in rows:
            value_color = Fore.YELLOW if label == 'Next reviews' else Fore.WHITE
            print(f"{color}  {str(label).ljust(width)}{Style.RESET_ALL} : {value_color}{value}{Style.RESET_ALL}")
        print()

    @staticmethod
    def _print_terminal_table(title: str, headers: List[str], rows: List[List[Any]], color=Fore.CYAN, limit: int = 40) -> None:
        """Render report-style tables for the interactive terminal."""
        print(f"{color}{Style.BRIGHT}{title}{Style.RESET_ALL}")
        if not rows:
            print(f"  {Fore.WHITE}No results recorded{Style.RESET_ALL}\n")
            return
        visible = [[str(value if value not in (None, '') else '—') for value in row] for row in rows[:limit]]
        widths = [len(str(header)) for header in headers]
        for row in visible:
            for index, value in enumerate(row):
                if index < len(widths):
                    widths[index] = min(max(widths[index], len(value)), 70)
        def format_row(row):
            values = []
            for index, value in enumerate(row):
                value = value[:widths[index] - 1] + '…' if len(value) > widths[index] else value
                values.append(value.ljust(widths[index]))
            return '  ' + ' | '.join(values)
        print(f"{Fore.WHITE}{format_row(headers)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'  ' + '-+-'.join('-' * width for width in widths)}{Style.RESET_ALL}")
        for row in visible:
            print(f"{Fore.WHITE}{format_row(row)}{Style.RESET_ALL}")
        if len(rows) > limit:
            print(f"{Fore.WHITE}  … {len(rows) - limit} additional rows are available in the report{Style.RESET_ALL}")
        print()

    def _print_terminal_results(self) -> None:
        """Print the report's key result tables after every completed scan."""
        target = self.results.get('target', {})
        coverage = self.results.get('coverage', {})
        profile = target.get('site_profile', {})
        print(f"\n{Fore.RED}{Style.BRIGHT}=== SP1D3R ASSESSMENT RESULTS ==={Style.RESET_ALL}")
        print(f"{Fore.WHITE}Target: {self.results.get('scan_info', {}).get('target', 'Unknown')}{Style.RESET_ALL}")
        if profile:
            print(f"{Fore.MAGENTA}Classification: {profile.get('kind', 'unknown')} ({profile.get('confidence', 'unknown')} confidence){Style.RESET_ALL}")
        self._print_terminal_table('Coverage', ['Metric', 'Result'], [
            ['Pages crawled', coverage.get('discovered_pages', 0)],
            ['Forms discovered', coverage.get('discovered_forms', 0)],
            ['Endpoints mapped', coverage.get('discovered_endpoints', 0)],
            ['Requests issued', coverage.get('tested_requests', 0)],
            ['API detected', 'Yes' if coverage.get('api_detected') else 'No'],
        ], Fore.CYAN)

        finding_rows = []
        for index, finding in enumerate(self.results.get('findings', []), 1):
            finding_rows.append([
                index, str(finding.get('severity', 'info')).upper(), finding.get('type', 'Finding'),
                finding.get('title', 'Unnamed finding'), finding.get('location', finding.get('url', '')),
            ])
        self._print_terminal_table('Findings', ['#', 'Severity', 'Type', 'Title', 'Location'], finding_rows, Fore.RED)

        check_rows = [[item.get('method', ''), item.get('status', ''), item.get('findings', 0), item.get('requests', 0)] for item in coverage.get('attack_checks', [])]
        self._print_terminal_table('Verification coverage', ['Method', 'Status', 'Findings', 'Requests'], check_rows, Fore.YELLOW)

        api_rows = [[item.get('method', 'GET'), item.get('url', ''), ', '.join(map(str, item.get('parameters', []))) or '—', item.get('source', 'discovery')] for item in coverage.get('api_endpoints', [])]
        if api_rows:
            self._print_terminal_table('Discovered API routes', ['Method', 'Route', 'Parameters', 'Source'], api_rows, Fore.MAGENTA)

        port_rows = [[item.get('port', ''), item.get('state', ''), item.get('service', ''), item.get('service_confidence', '—'), item.get('banner', '—')] for item in target.get('ports', [])]
        if port_rows:
            self._print_terminal_table('Open ports and services', ['Port', 'State', 'Service', 'Confidence', 'Banner'], port_rows, Fore.BLUE)

        tool_rows = [[item.get('tool', ''), item.get('status', ''), item.get('finding_count', 0), item.get('asset_count', 0), item.get('duration_seconds', '—')] for item in self.results.get('tool_runs', [])]
        if tool_rows:
            self._print_terminal_table('External tools', ['Tool', 'Status', 'Findings', 'Assets', 'Seconds'], tool_rows, Fore.GREEN)
    
    async def _run_vuln_scan(self, target: str, params: Dict):
        """Run vulnerability scanning"""
        try:
            self.logger.info("[*] Scanning for vulnerabilities...")
            cve_check = params.get('cve_check', False)
            
            vuln_results = await self.vuln_scanner.scan(target, cve_check)
            
            # Add findings
            for finding in vuln_results.get('findings', []):
                self._add_finding(finding)
            
            self.logger.info(f"[+] Vulnerability scan complete: {len(vuln_results.get('findings', []))} vulnerabilities found")
        except Exception as e:
            self.logger.error(f"[!] Vulnerability scanning error: {e}")

    def _run_cve_suggestions(self, online: bool = False) -> None:
        """Match discovered versions locally and optionally enrich from NVD."""
        target = self.results.get('target', {})
        technologies = target.get('technologies', [])
        ports = list(target.get('ports', []) or [])
        # Nmap stores richer product/version observations in external assets;
        # fold them into the same matcher used for native port banners.
        external_assets = target.get('external_assets', {})
        for service in external_assets.get('services', []) if isinstance(external_assets, dict) else []:
            if not isinstance(service, dict) or service.get('source') != 'nmap':
                continue
            product = service.get('product') or service.get('service') or ''
            version = service.get('version') or ''
            if product and version:
                ports.append({
                    'port': service.get('port'),
                    'protocol': service.get('protocol', 'tcp'),
                    'service': product,
                    'banner': f"{product} {version}",
                })
        if online:
            self.logger.info("[*] Querying NVD for version-based CVE suggestions...")
            suggestions = self.cve_matcher.enrich(technologies, ports, sources=('local', 'nvd'))
            for error in self.cve_matcher.lookup_errors:
                self.logger.warning(f"[!] CVE lookup skipped: {error}")
        else:
            suggestions = self.cve_matcher.match(technologies, ports)
        target['cve_suggestions'] = suggestions
        if suggestions:
            self.logger.info(f"[+] Matched {len(suggestions)} possible CVE(s) from discovered versions")
        else:
            self.logger.info("[+] No local CVE suggestions matched the discovered versions")
    
    def _add_finding(self, finding: Dict):
        """Add a finding to results"""
        normalized = normalize_finding(finding)
        if normalized['finding_id'] not in self._finding_ids:
            self._finding_ids.add(normalized['finding_id'])
            self.results['findings'].append(normalized)
    
    def _calculate_statistics(self):
        """Calculate finding statistics"""
        for finding in self.results['findings']:
            severity = finding.get('severity', 'info').lower()
            if severity in self.results['stats']:
                self.results['stats'][severity] += 1
    
    def _calculate_duration(self) -> str:
        """Calculate scan duration"""
        try:
            start = datetime.fromisoformat(self.results['scan_info']['start_time'])
            end = datetime.fromisoformat(self.results['scan_info']['end_time'])
            duration = end - start
            return str(duration)
        except:
            return "N/A"
