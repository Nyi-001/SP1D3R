"""SSL/TLS Testing Module"""
import asyncio
import socket
import ssl
from typing import Dict, Any, List
from datetime import datetime


class SSLTester:
    """SSL/TLS certificate and configuration tester"""
    
    # Weak cipher suites
    WEAK_CIPHERS = [
        'RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon'
    ]
    
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        self.timeout = config.get('scanning', {}).get('timeout', 10)
    
    async def test(self, target: str) -> Dict[str, Any]:
        """Test SSL/TLS configuration"""
        self.logger.info(f"Testing SSL/TLS configuration for {target}")
        
        findings: List[Dict[str, Any]] = []
        info: Dict[str, Any] = {}
        
        # Parse target to get hostname and port
        if target.startswith('https://'):
            target = target.replace('https://', '')
        elif target.startswith('http://'):
            target = target.replace('http://', '')
        
        if ':' in target:
            hostname, port_str = target.split(':', 1)
            port = int(port_str)
        else:
            hostname = target.split('/')[0]
            port = 443
        
        try:
            # Test SSL/TLS connection
            cert_info, protocols = await self._test_ssl_connection(hostname, port)
            
            if cert_info:
                info['certificate'] = cert_info
                
                # Check certificate expiration
                if cert_info.get('expired'):
                    findings.append({
                        'type': 'SSL/TLS Issue',
                        'severity': 'critical',
                        'title': 'Expired SSL certificate',
                        'description': f"Certificate expired on {cert_info.get('notAfter')}",
                        'location': f"{hostname}:{port}",
                        'remediation': 'Renew the SSL certificate immediately'
                    })
                elif cert_info.get('expires_soon'):
                    findings.append({
                        'type': 'SSL/TLS Issue',
                        'severity': 'medium',
                        'title': 'SSL certificate expiring soon',
                        'description': f"Certificate expires on {cert_info.get('notAfter')}",
                        'location': f"{hostname}:{port}",
                        'remediation': 'Renew the SSL certificate before expiration'
                    })
                
                # Check for self-signed certificate
                if cert_info.get('self_signed'):
                    findings.append({
                        'type': 'SSL/TLS Issue',
                        'severity': 'medium',
                        'title': 'Self-signed SSL certificate',
                        'description': 'Certificate is self-signed and not trusted by browsers',
                        'location': f"{hostname}:{port}",
                        'remediation': 'Use a certificate from a trusted Certificate Authority'
                    })
            
            if protocols:
                info['protocols'] = protocols
                
                # Check for insecure protocols
                if 'SSLv2' in protocols or 'SSLv3' in protocols:
                    findings.append({
                        'type': 'SSL/TLS Issue',
                        'severity': 'high',
                        'title': 'Insecure SSL/TLS protocol enabled',
                        'description': 'SSLv2/SSLv3 are deprecated and vulnerable',
                        'location': f"{hostname}:{port}",
                        'remediation': 'Disable SSLv2 and SSLv3, use TLS 1.2 or higher'
                    })
                
                if 'TLSv1.0' in protocols or 'TLSv1.1' in protocols:
                    findings.append({
                        'type': 'SSL/TLS Issue',
                        'severity': 'medium',
                        'title': 'Outdated TLS protocol enabled',
                        'description': 'TLS 1.0 and 1.1 are deprecated',
                        'location': f"{hostname}:{port}",
                        'remediation': 'Disable TLS 1.0 and 1.1, use TLS 1.2 or higher'
                    })
        
        except Exception as e:
            self.logger.debug(f"SSL testing error: {e}")
        
        return {"info": info, "findings": findings}
    
    async def _test_ssl_connection(self, hostname: str, port: int) -> tuple:
        """Test SSL connection and retrieve certificate info"""
        cert_info = {}
        protocols = []
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            loop = asyncio.get_event_loop()
            
            def connect():
                sock = socket.create_connection((hostname, port), timeout=self.timeout)
                ssock = context.wrap_socket(sock, server_hostname=hostname)
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                ssock.close()
                return cert, cipher, version
            
            cert, cipher, version = await loop.run_in_executor(None, connect)
            
            if cert:
                # Parse certificate information
                cert_info = self._parse_certificate(cert)
            
            if cipher:
                cert_info['cipher'] = {
                    'name': cipher[0],
                    'version': cipher[1],
                    'bits': cipher[2]
                }
                
                # Check for weak ciphers
                cipher_name = cipher[0]
                if any(weak in cipher_name for weak in self.WEAK_CIPHERS):
                    cert_info['weak_cipher'] = True
            
            if version:
                protocols.append(version)
        
        except Exception as e:
            self.logger.debug(f"SSL connection test error: {e}")
        
        return cert_info, protocols
    
    def _parse_certificate(self, cert: Dict) -> Dict[str, Any]:
        """Parse SSL certificate details"""
        info = {}
        
        try:
            # Subject information
            subject = dict(x[0] for x in cert.get('subject', []))
            info['subject'] = subject
            info['commonName'] = subject.get('commonName', '')
            
            # Issuer information
            issuer = dict(x[0] for x in cert.get('issuer', []))
            info['issuer'] = issuer
            info['issuerName'] = issuer.get('commonName', '')
            
            # Check if self-signed
            info['self_signed'] = (subject.get('commonName') == issuer.get('commonName'))
            
            # Validity dates
            not_before = cert.get('notBefore', '')
            not_after = cert.get('notAfter', '')
            
            info['notBefore'] = not_before
            info['notAfter'] = not_after
            
            # Check expiration
            try:
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                now = datetime.now()
                days_until_expiry = (expiry_date - now).days
                
                info['days_until_expiry'] = days_until_expiry
                info['expired'] = days_until_expiry < 0
                info['expires_soon'] = 0 <= days_until_expiry <= 30
            except:
                pass
            
            # Subject Alternative Names
            san = cert.get('subjectAltName', [])
            if san:
                info['subjectAltName'] = [name[1] for name in san]
            
            # Serial number
            info['serialNumber'] = cert.get('serialNumber', '')
            
            # Version
            info['version'] = cert.get('version', '')
        
        except Exception as e:
            self.logger.debug(f"Certificate parsing error: {e}")
        
        return info
