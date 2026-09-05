"""End-to-end checks against a deterministic in-memory vulnerable lab."""

import asyncio
import re
from urllib.parse import parse_qs, urlsplit

from core import web_scanner as web_scanner_module
from core.web_scanner import WebScanner
from core.scanner import PentestScanner


class LabLogger:
    def info(self, *_args, **_kwargs):
        pass

    def warning(self, *_args, **_kwargs):
        pass

    def debug(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass


def test_active_endpoint_flags_include_web_module() -> None:
    modules = PentestScanner._include_required_active_modules(
        ['fingerprint', 'waf', 'port', 'vuln'],
        {'all_tests': True},
        True,
    )
    assert modules[-1] == 'web'
    assert PentestScanner._include_required_active_modules(
        ['fingerprint', 'waf', 'port', 'vuln'], {'all_tests': False}, True
    ) == ['fingerprint', 'waf', 'port', 'vuln']


class FakeResponse:
    def __init__(self, status=200, text="", headers=None):
        self.status = status
        self._text = text
        self.headers = headers or {}

    async def text(self, *_, **__):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class FakeSession:
    """Small aiohttp-compatible transport for a safe local lab simulation."""

    def __init__(self, *_, **__):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def request(self, method, url, **kwargs):
        return FakeRequest(self._response(method, url, kwargs))

    @staticmethod
    def _response(method, url, kwargs):
        parsed = urlsplit(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        path = parsed.path

        if path == "/":
            return FakeResponse(text="""
                <html><body>
                  <a href="/xss?name=test">xss</a>
                  <a href="/sqli?id=1">sqli</a>
                  <a href="/always-error?id=1">always-error</a>
                  <a href="/template?template=hello">template</a>
                  <a href="/exec?cmd=echo">exec</a>
                  <a href="/include?file=index.php">include</a>
                  <a href="/redirect?next=/safe">redirect</a>
                  <form action="/form" method="post"><input name="name" value="test"></form>
                </body></html>
            """, headers={})
        if path == "/xss":
            return FakeResponse(text=f"<html>{query.get('name', [''])[0]}</html>", headers={})
        if path == "/sqli":
            value = query.get("id", [""])[0]
            if "'" in value:
                return FakeResponse(text="You have an error in your SQL syntax; check the manual")
            return FakeResponse(text="row found" if "1=1" in value else "no rows")
        if path == "/always-error":
            return FakeResponse(text="Fatal error: Uncaught mysqli diagnostic page")
        if path == "/template":
            value = query.get("template", [""])[0]
            return FakeResponse(text="49" if value == "{{7*7}}" else value)
        if path == "/exec":
            value = query.get("cmd", [""])[0]
            match = re.search(r"websentinel_cmd_[A-Za-z0-9_]+", value)
            return FakeResponse(text=match.group(0) if match else "command page")
        if path == "/include":
            value = query.get("file", [""])[0]
            return FakeResponse(text="root:x:0:0:root:/root:/bin/bash" if "etc/passwd" in value else "include page")
        if path == "/redirect":
            destination = query.get("next", [""])[0]
            if destination.startswith("https://redirect-check.invalid/"):
                return FakeResponse(status=302, headers={"Location": destination})
            return FakeResponse(text="redirect page")
        if path == "/form" and method.upper() == "POST":
            data = kwargs.get("data") or {}
            return FakeResponse(text=f"<html>{data.get('name', '')}</html>", headers={})
        if path == "/robots.txt":
            return FakeResponse(text="User-agent: *\nDisallow: /admin")
        return FakeResponse(status=404, text="not found")


class FakeRequest:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return await self.response.__aenter__()

    async def __aexit__(self, *args):
        return await self.response.__aexit__(*args)


def test_active_checks_match_expected_local_lab_findings(monkeypatch):
    monkeypatch.setattr(web_scanner_module.aiohttp, "ClientSession", FakeSession)

    async def run_scan():
        scanner = WebScanner(
            {
                "scope": {"allowed_hosts": ["127.0.0.1"], "active_checks": True},
                "modules": {"web_scanner": {"depth": 1}},
                "scanning": {
                    "timeout": 2,
                    "max_requests": 300,
                    "payload_limit": 3,
                    "all_active_tests": True,
                },
            },
            LabLogger(),
        )
        return await scanner.scan(
            "http://127.0.0.1:8080/",
            test_sqli=True,
            test_xss=True,
        )

    result = asyncio.run(run_scan())
    findings = result["findings"]
    types = {finding["type"] for finding in findings}
    assert "SQL Injection" in types
    assert "Cross-Site Scripting (XSS)" in types
    assert "Server-Side Template Injection (SSTI)" in types
    assert "OS Command Injection" in types
    assert "File Inclusion / LFI" in types
    assert "Directory Traversal" in types
    assert "Open Redirect" in types
    assert "CSRF" in types
    assert not any("/always-error" in finding["location"] for finding in findings)
    xss_findings = [finding for finding in findings if finding["type"] == "Cross-Site Scripting (XSS)"]
    assert xss_findings and all(
        finding["state"] == "suspected" and finding["confidence"] == "medium"
        for finding in xss_findings
    )

    checks = {item["method"]: item for item in result["coverage"]["attack_checks"]}
    assert all(item["status"] == "completed" for item in checks.values())
    assert result["coverage"]["discovered_pages"] >= 7
    assert result["coverage"]["tested_requests"] <= 300


def test_http_finding_requires_a_reachable_response(monkeypatch):
    monkeypatch.setattr(web_scanner_module.aiohttp, "ClientSession", FakeSession)

    async def run_check():
        scanner = WebScanner(
            {
                "scope": {"allowed_hosts": ["127.0.0.1"], "active_checks": True},
                "scanning": {"timeout": 2, "max_requests": 10},
            },
            LabLogger(),
        )
        await scanner._check_ssl_configuration("http://127.0.0.1:8080/")
        return scanner.findings

    findings = asyncio.run(run_check())
    assert len(findings) == 1
    assert findings[0]["type"] == "Insecure Protocol"
    assert findings[0]["state"] == "confirmed"


def test_open_port_is_not_promoted_to_high_service_finding():
    class PortStub:
        async def scan(self, *_args, **_kwargs):
            return [
                {"port": 21, "state": "open", "service": "ftp", "banner": "", "service_confidence": "low"},
                {"port": 23, "state": "open", "service": "telnet", "banner": "", "service_confidence": "low"},
            ]

    async def run_check():
        scanner = PentestScanner({"scope": {"allowed_hosts": ["example.test"]}, "scanning": {}}, LabLogger())
        scanner.port_scanner = PortStub()
        await scanner._run_port_scan("example.test", {"ports": "20-23"})
        return scanner

    scanner = asyncio.run(run_check())
    assert scanner.results["target"]["ports"][0]["service_confidence"] == "low"
    assert not scanner.results["findings"]
