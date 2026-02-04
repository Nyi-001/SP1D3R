# modules/ssl_tester.py
import ssl
import socket
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse


class SSLTester:
    def __init__(self, config: Dict, logger):
        self.config = config or {}
        self.logger = logger

        scanning_cfg = self.config.get("scanning", {})
        self.timeout = scanning_cfg.get("timeout", 10)

    async def test(self, target: str) -> Dict[str, Any]:
        host, port = self._normalize_target(target)
        info: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        cert, proto = self._get_certificate(host, port)
        if not cert:
            findings.append({
                "type": "SSL Connection Error",
                "severity": "high",
                "title": "Unable to retrieve certificate",
                "description": f"Failed to establish SSL/TLS connection to {host}:{port}.",
                "location": f"{host}:{port}",
                "remediation": "Verify that the service supports TLS and is reachable from the scanner."
            })
            return {"info": info, "findings": findings}

        info["protocol"] = proto
        info["subject"] = dict(cert.get("subject", []))
        info["issuer"] = dict(cert.get("issuer", []))
        info["not_before"] = cert.get("notBefore")
        info["not_after"] = cert.get("notAfter")
        info["serial_number"] = cert.get("serialNumber")

        self._check_expiry(cert, host, port, findings)
        self._check_self_signed(cert, host, port, findings)
        self._check_protocol(proto, host, port, findings)

        return {"info": info, "findings": findings}

    def _normalize_target(self, target: str) -> Tuple[str, int]:
        # Accept hostname, hostname:port, or URL
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or target
            port = parsed.port or 443
            return host, port

        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            try:
                return host, int(port_str)
            except ValueError:
                return host, 443

        return target, 443

    def _get_certificate(self, host: str, port: int) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # We do our own checks

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    return cert, proto
        except Exception as e:
            if self.logger:
                self.logger.error(f"[SSLTester] Error connecting to {host}:{port} - {e}")
            return None, None

    def _check_expiry(
        self,
        cert: Dict[str, Any],
        host: str,
        port: int,
        findings: List[Dict[str, Any]],
    ) -> None:
        not_after = cert.get("notAfter")
        if not not_after:
            return

        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now = datetime.utcnow()
            days_left = (exp - now).days

            if days_left < 0:
                findings.append({
                    "type": "Expired Certificate",
                    "severity": "high",
                    "title": "SSL/TLS certificate is expired",
                    "description": f"The certificate for {host} expired on {not_after}.",
                    "location": f"{host}:{port}",
                    "remediation": "Renew and replace the expired certificate."
                })
            elif days_left < 30:
                findings.append({
                    "type": "Expiring Certificate",
                    "severity": "medium",
                    "title": "SSL/TLS certificate is close to expiration",
                    "description": f"The certificate for {host} will expire on {not_after} (in {days_left} days).",
                    "location": f"{host}:{port}",
                    "remediation": "Plan to renew the certificate before it expires."
                })
        except Exception:
            # Ignore parsing errors silently or log at debug
            pass

    def _check_self_signed(
        self,
        cert: Dict[str, Any],
        host: str,
        port: int,
        findings: List[Dict[str, Any]],
    ) -> None:
        subject = cert.get("subject", [])
        issuer = cert.get("issuer", [])

        try:
            subject_dict = {k: v for tup in subject for (k, v) in tup}
            issuer_dict = {k: v for tup in issuer for (k, v) in tup}
        except Exception:
            return

        if subject_dict == issuer_dict:
            findings.append({
                "type": "Self-signed Certificate",
                "severity": "medium",
                "title": "Certificate appears to be self-signed",
                "description": f"The certificate for {host} appears to be self-signed.",
                "location": f"{host}:{port}",
                "remediation": "Use a certificate signed by a trusted public CA for internet-facing services."
            })

    def _check_protocol(
        self,
        proto: Optional[str],
        host: str,
        port: int,
        findings: List[Dict[str, Any]],
    ) -> None:
        if not proto:
            return

        weak = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
        if proto in weak:
            findings.append({
                "type": "Weak TLS Protocol",
                "severity": "high",
                "title": "Outdated/weak TLS protocol in use",
                "description": f"Service negotiated {proto} with the client.",
                "location": f"{host}:{port}",
                "remediation": "Disable legacy protocols and enforce TLS 1.2+ (ideally TLS 1.3)."
            })
