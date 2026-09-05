"""Technology Fingerprinting Module"""
import asyncio
import aiohttp
import ssl
import certifi
import re
from typing import Dict, Any, List
from urllib.parse import urljoin
from bs4 import BeautifulSoup


class TechFingerprint:
    """Technology and framework fingerprinting"""
    
    # Technology signatures
    TECH_SIGNATURES = {
        # CMS
        'WordPress': [
            r'/wp-content/', r'/wp-includes/', r'wp-json',
            r'WordPress', r'/wp-admin/'
        ],
        'Joomla': [
            r'/administrator/', r'/components/com_', r'Joomla',
            r'/templates/system/'
        ],
        'Drupal': [
            r'Drupal', r'/sites/default/', r'/sites/all/',
            r'X-Drupal-', r'/misc/drupal.js'
        ],
        'Magento': [
            r'Magento', r'/skin/frontend/', r'/js/mage/',
            r'Mage.Cookies'
        ],
        'Shopify': [
            r'Shopify', r'cdn.shopify.com', r'/cart.js',
            r'shopify-checkout'
        ],
        
        # Frameworks
        'Django': [
            r'csrfmiddlewaretoken', r'__admin__', r'django',
            r'/static/admin/'
        ],
        'Ruby on Rails': [
            r'Rails', r'X-Runtime', r'_csrf_token',
            r'/assets/application-'
        ],
        'Laravel': [
            r'laravel', r'XSRF-TOKEN', r'laravel_session',
            r'/vendor/laravel/'
        ],
        'Express': [
            r'Express', r'X-Powered-By.*Express',
            r'connect.sid'
        ],
        'Flask': [
            r'Werkzeug', r'Flask', r'/static/.*\.py'
        ],
        'Spring': [
            r'Spring', r'JSESSIONID', r'Whitelabel Error Page',
            r'/spring/'
        ],
        'ASP.NET': [
            r'ASP.NET', r'__VIEWSTATE', r'__EVENTVALIDATION',
            r'X-AspNet-Version', r'\.aspx'
        ],
        
        # Web Servers
        'Apache': [r'Apache', r'Server.*Apache'],
        'Nginx': [r'nginx', r'Server.*nginx'],
        'IIS': [r'IIS', r'Server.*IIS', r'X-Powered-By.*ASP.NET'],
        'Cloudflare': [r'cloudflare', r'cf-ray', r'__cfduid'],
        
        # JavaScript Libraries
        'jQuery': [r'jquery', r'/jquery.*\.js'],
        'React': [r'React', r'react', r'_reactRoot'],
        'Angular': [r'Angular', r'ng-app', r'ng-controller'],
        'Vue.js': [r'Vue', r'v-app', r'data-v-'],
        'Bootstrap': [r'bootstrap', r'/bootstrap.*\.css'],
        
        # Databases (from error messages)
        'MySQL': [r'MySQL', r'mysqli', r'SQL syntax.*MySQL'],
        'PostgreSQL': [r'PostgreSQL', r'pg_', r'psql'],
        'MongoDB': [r'MongoDB', r'mongo'],
        'Redis': [r'Redis', r'WRONGTYPE'],
        
        # Other Technologies
        'PHP': [r'\.php', r'X-Powered-By.*PHP', r'PHPSESSID'],
        'Node.js': [r'Node.js', r'X-Powered-By.*Express'],
        'Python': [r'Python', r'\.py'],
        'Java': [r'\.jsp', r'\.java', r'JSESSIONID'],
    }
    
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        self.timeout = config.get('scanning', {}).get('timeout', 10)
        self.last_observation: Dict[str, Any] = {}
    
    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Fingerprint technologies used by target"""
        self.logger.info(f"Fingerprinting technologies for {target}")
        
        if not target.startswith('http'):
            target = f"http://{target}"
        
        technologies = []
        self.last_observation = {
            'target': target,
            'status_code': None,
            'final_url': target,
            'server': '',
            'powered_by': '',
            'content_type': '',
            'error': '',
        }
        
        try:
            ssl_context = (
                False
                if self.config.get('scanning', {}).get('insecure_tls', False)
                else ssl.create_default_context(cafile=certifi.where())
            )
            
            async with aiohttp.ClientSession() as session:
                # Fetch main page
                try:
                    async with session.get(
                        target,
                        ssl=ssl_context,
                        timeout=aiohttp.ClientTimeout(total=self.timeout)
                    ) as response:
                        headers = response.headers
                        html = await response.text()
                        self.last_observation.update({
                            'status_code': response.status,
                            'final_url': str(response.url),
                            'server': next((str(value) for name, value in headers.items() if name.lower() == 'server'), ''),
                            'powered_by': next((str(value) for name, value in headers.items() if name.lower() == 'x-powered-by'), ''),
                            'content_type': headers.get('Content-Type', ''),
                        })
                        
                        # Check headers for technology signatures
                        header_techs = self._check_headers(headers)
                        technologies.extend(header_techs)
                        
                        # Check HTML content
                        content_techs = self._check_content(html)
                        technologies.extend(content_techs)
                        
                        # Check meta tags and scripts
                        meta_techs = self._check_meta_and_scripts(html)
                        technologies.extend(meta_techs)
                
                except Exception as e:
                    self.last_observation['error'] = str(e)
                    self.logger.debug(f"Error fetching page: {e}")
                
                # Check for common paths
                path_techs = await self._check_common_paths(session, target, ssl_context)
                technologies.extend(path_techs)
        
        except Exception as e:
            self.last_observation['error'] = str(e)
            self.logger.error(f"Fingerprinting error: {e}")
        
        # Deduplicate technologies
        unique_techs = []
        seen = set()
        for tech in technologies:
            tech_name = tech.get('name')
            if tech_name not in seen:
                seen.add(tech_name)
                unique_techs.append(tech)
        
        self.logger.info(f"[+] Identified {len(unique_techs)} technologies")
        return unique_techs
    
    def _check_headers(self, headers: Dict) -> List[Dict[str, Any]]:
        """Check HTTP headers for technology signatures"""
        technologies = []
        
        headers_str = ' '.join([f"{k}:{v}" for k, v in headers.items()])
        
        # Check Server header
        server = next((value for name, value in headers.items() if str(name).lower() == 'server'), '')
        if server:
            server_detected = False
            for tech_name, patterns in self.TECH_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, f"Server:{server}", re.IGNORECASE):
                        server_detected = True
                        technologies.append({
                            'name': tech_name,
                            'category': self._get_category(tech_name),
                            'version': self._extract_version(server),
                            'confidence': 'high',
                            'source': 'Server header'
                        })
                        break
            if server and not server_detected:
                technologies.append({
                    'name': str(server),
                    'category': 'Web Server',
                    'version': self._extract_version(str(server)),
                    'confidence': 'high',
                    'source': 'Server header'
                })
        
        # Check X-Powered-By
        powered_by = next((value for name, value in headers.items() if str(name).lower() == 'x-powered-by'), '')
        if powered_by:
            for tech_name, patterns in self.TECH_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, f"X-Powered-By:{powered_by}", re.IGNORECASE):
                        technologies.append({
                            'name': tech_name,
                            'category': self._get_category(tech_name),
                            'version': self._extract_version(powered_by),
                            'confidence': 'high',
                            'source': 'X-Powered-By header'
                        })
                        break
        
        # Check cookies
        cookies = next((value for name, value in headers.items() if str(name).lower() == 'set-cookie'), '')
        if cookies:
            for tech_name, patterns in self.TECH_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, cookies, re.IGNORECASE):
                        technologies.append({
                            'name': tech_name,
                            'category': self._get_category(tech_name),
                            'version': None,
                            'confidence': 'medium',
                            'source': 'Cookie'
                        })
                        break
        
        return technologies
    
    def _check_content(self, html: str) -> List[Dict[str, Any]]:
        """Check HTML content for technology signatures"""
        technologies = []
        
        for tech_name, patterns in self.TECH_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    technologies.append({
                        'name': tech_name,
                        'category': self._get_category(tech_name),
                        'version': None,
                        'confidence': 'medium',
                        'source': 'HTML content'
                    })
                    break
        
        return technologies
    
    def _check_meta_and_scripts(self, html: str) -> List[Dict[str, Any]]:
        """Check meta tags and script sources"""
        technologies = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Check meta tags
            for meta in soup.find_all('meta'):
                content = str(meta.get('content', ''))
                name = str(meta.get('name', ''))
                for tech_name, patterns in self.TECH_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, content + name, re.IGNORECASE):
                            technologies.append({
                                'name': tech_name,
                                'category': self._get_category(tech_name),
                                'version': None,
                                'confidence': 'low',
                                'source': 'Meta tag'
                            })
                            break
            
            # Check script sources
            for script in soup.find_all('script', src=True):
                src = script.get('src', '')
                for tech_name, patterns in self.TECH_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, src, re.IGNORECASE):
                            version = self._extract_version(src)
                            technologies.append({
                                'name': tech_name,
                                'category': self._get_category(tech_name),
                                'version': version,
                                'confidence': 'high',
                                'source': 'Script source'
                            })
                            break
            
            # Check link tags (CSS)
            for link in soup.find_all('link', href=True):
                href = link.get('href', '')
                for tech_name, patterns in self.TECH_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, href, re.IGNORECASE):
                            technologies.append({
                                'name': tech_name,
                                'category': self._get_category(tech_name),
                                'version': self._extract_version(href),
                                'confidence': 'medium',
                                'source': 'Link tag'
                            })
                            break
        
        except Exception as e:
            self.logger.debug(f"Meta/script parsing error: {e}")
        
        return technologies
    
    async def _check_common_paths(self, session, target: str, ssl_context) -> List[Dict[str, Any]]:
        """Check for common technology-specific paths"""
        technologies = []
        common_paths = {
            'WordPress': (['/wp-admin/', '/wp-login.php'], ('wordpress', 'wp-login', 'wp-content')),
            'Joomla': (['/administrator/'], ('joomla', 'com_')),
            'Drupal': (['/user/login'], ('drupal', 'sites/default')),
            'phpMyAdmin': (['/phpmyadmin/', '/pma/'], ('phpmyadmin', 'pma')),
        }
        checks = [
            self._check_common_path(session, target, ssl_context, tech_name, path, markers)
            for tech_name, (paths, markers) in common_paths.items()
            for path in paths
        ]
        results = await asyncio.gather(*checks, return_exceptions=True)
        seen = set()
        for result in results:
            if not isinstance(result, dict):
                continue
            name = result.get('name')
            if name and name not in seen:
                seen.add(name)
                technologies.append(result)
        return technologies

    async def _check_common_path(self, session, target: str, ssl_context, tech_name: str, path: str, markers) -> Dict[str, Any]:
        """Probe one fingerprint path without serially delaying the scan."""
        try:
            # A target may contain a query string such as ``/?page_id=965``.
            # Append discovery paths to the origin path, never after the
            # query string.
            url = urljoin(target, path)
            async with session.get(
                url,
                ssl=ssl_context,
                timeout=aiohttp.ClientTimeout(total=5),
                allow_redirects=False
            ) as response:
                body = await response.text(errors='ignore') if response.status == 200 else ''
                location = response.headers.get('Location', '').lower()
                verified = any(marker in body.lower() for marker in markers) or any(marker in location for marker in markers)
                if verified:
                    return {
                        'name': tech_name,
                        'category': self._get_category(tech_name),
                        'version': None,
                        'confidence': 'high',
                        'source': f'Path {path} exists'
                    }
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.logger.debug(f"Path check error for {path}: {e}")
        except Exception as e:
            self.logger.debug(f"Unexpected error checking {path}: {e}")
        return {}
    
    def _get_category(self, tech_name: str) -> str:
        """Determine technology category"""
        cms = ['WordPress', 'Joomla', 'Drupal', 'Magento', 'Shopify']
        frameworks = ['Django', 'Ruby on Rails', 'Laravel', 'Express', 'Flask', 'Spring', 'ASP.NET']
        servers = ['Apache', 'Nginx', 'IIS', 'Cloudflare']
        js_libs = ['jQuery', 'React', 'Angular', 'Vue.js', 'Bootstrap']
        databases = ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']
        languages = ['PHP', 'Node.js', 'Python', 'Java']
        
        if tech_name in cms:
            return 'CMS'
        elif tech_name in frameworks:
            return 'Framework'
        elif tech_name in servers:
            return 'Web Server'
        elif tech_name in js_libs:
            return 'JavaScript Library'
        elif tech_name in databases:
            return 'Database'
        elif tech_name in languages:
            return 'Programming Language'
        else:
            return 'Other'
    
    def _extract_version(self, text: str) -> str:
        """Extract version number from text"""
        # Look for version patterns like 1.2.3, v1.2, etc.
        version_pattern = r'(?:v|version)?(\d+\.\d+(?:\.\d+)?)'
        match = re.search(version_pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
