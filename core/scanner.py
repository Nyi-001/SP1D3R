"""Main scanner orchestrator"""
import asyncio
from typing import Dict, List, Any
from datetime import datetime

from .port_scanner import PortScanner
from .subdomain_enum import SubdomainEnumerator
from .vuln_scanner import VulnerabilityScanner
from .web_scanner import WebScanner
from modules.dns_analyzer import DNSAnalyzer
from modules.ssl_tester import SSLTester
from modules.waf_detector import WAFDetector
from modules.fingerprint import TechFingerprint


class PentestScanner:
    """Main penetration testing scanner orchestrator"""
    
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        
        # Initialize modules
        self.port_scanner = PortScanner(config, logger)
        self.subdomain_enum = SubdomainEnumerator(config, logger)
        self.vuln_scanner = VulnerabilityScanner(config, logger)
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
    
    async def scan(self, params: Dict[str, Any]) -> Dict:
        """Execute comprehensive scan based on parameters"""
        target = params['target']
        scan_type = params.get('scan_type', 'standard')
        module = params.get('module', 'all')
        
        # Record scan info
        self.results['scan_info'] = {
            'start_time': datetime.now().isoformat(),
            'target': target,
            'scan_type': scan_type,
            'module': module
        }
        
        self.logger.info(f"Initializing {scan_type} scan on {target}")
        
        # Determine which modules to run based on scan type
        modules_to_run = self._get_modules_for_scan_type(scan_type, module)
        
        # Run selected modules
        tasks = []
        
        if 'fingerprint' in modules_to_run:
            tasks.append(self._run_fingerprinting(target))
        
        if 'waf' in modules_to_run:
            tasks.append(self._run_waf_detection(target))
        
        if 'dns' in modules_to_run:
            tasks.append(self._run_dns_analysis(target))
        
        if 'subdomain' in modules_to_run:
            tasks.append(self._run_subdomain_enum(target, params))
        
        if 'port' in modules_to_run:
            tasks.append(self._run_port_scan(target, params))
        
        if 'ssl' in modules_to_run:
            tasks.append(self._run_ssl_test(target))
        
        if 'web' in modules_to_run:
            tasks.append(self._run_web_scan(target, params))
        
        if 'vuln' in modules_to_run:
            tasks.append(self._run_vuln_scan(target, params))
        
        # Execute all tasks concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Finalize results
        self.results['scan_info']['end_time'] = datetime.now().isoformat()
        self.results['scan_info']['duration'] = self._calculate_duration()
        
        # Calculate statistics
        self._calculate_statistics()
        
        return self.results
    
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
    
    async def _run_fingerprinting(self, target: str):
        """Run technology fingerprinting"""
        try:
            self.logger.info("[*] Running technology fingerprinting...")
            results = await self.tech_fingerprint.scan(target)
            self.results['target']['technologies'] = results
            self.logger.info(f"[+] Detected {len(results)} technologies")
        except Exception as e:
            self.logger.error(f"[!] Fingerprinting error: {e}")
    
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
            
            # Add findings for interesting ports
            for port in open_ports:
                if port.get('service') in ['ftp', 'telnet', 'mysql', 'mongodb', 'redis']:
                    self._add_finding({
                        'type': 'Exposed Service',
                        'severity': 'high',
                        'title': f"Potentially vulnerable {port.get('service')} service exposed",
                        'description': f"Port {port.get('port')} running {port.get('service')} is accessible",
                        'location': f"{target}:{port.get('port')}",
                        'remediation': 'Consider firewall restrictions or disabling the service if not needed'
                    })
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
            
            web_results = await self.web_scanner.scan(target, test_sqli, test_xss)
            
            # Add findings
            for finding in web_results.get('findings', []):
                self._add_finding(finding)
            
            self.logger.info(f"[+] Web scan complete: {len(web_results.get('findings', []))} findings")
        except Exception as e:
            self.logger.error(f"[!] Web scanning error: {e}")
    
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
    
    def _add_finding(self, finding: Dict):
        """Add a finding to results"""
        if finding not in self.results['findings']:
            self.results['findings'].append(finding)
    
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