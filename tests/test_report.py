from reports.generator import ReportGenerator


class DummyLogger:
    def info(self, *_args, **_kwargs):
        pass

    def warning(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass


def test_report_generator_receives_config_and_logger(tmp_path) -> None:
    generator = ReportGenerator({"reporting": {"output_dir": str(tmp_path)}}, DummyLogger())
    output = tmp_path / "report.json"
    assert generator.generate([], str(output), "json") == str(output)
    assert output.exists()


def test_html_report_contains_technical_finding_details(tmp_path) -> None:
    generator = ReportGenerator({"reporting": {"output_dir": str(tmp_path), "severity_threshold": "low"}}, DummyLogger())
    output = tmp_path / "report.html"
    results = [{
        "scan_info": {"target": "https://example.test", "scan_type": "standard", "duration": "1s"},
        "target": {"fingerprint": {"status_code": 200, "final_url": "https://example.test/", "server": "nginx/1.24", "powered_by": "PHP/8.2", "content_type": "text/html"}, "attack_surface": {"endpoint_count": 1, "parameters": [{"method": "GET", "endpoint": "https://example.test/search", "parameter": "q", "priority": "high", "checks": ["xss"], "sources": ["query-string"]}], "summary": {"xss": 1}}, "external_assets": {"directories": [{"url": "https://example.test/admin/", "status": 403, "length": 123, "source": "dirsearch"}]}},
        "findings": [{"title": "Reflected input", "type": "XSS", "severity": "medium", "location": "https://example.test/search?q=test", "parameter": "q", "status_code": 403, "content_length": 123, "content_type": "text/html", "confidence": "medium", "state": "suspected", "description": "Input was reflected", "impact": "A user-controlled value is returned in the response.", "evidence": "WSCANARY-123", "remediation": "Encode output"}],
        "stats": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
    }]
    generator.generate(results, str(output), "html")
    content = output.read_text(encoding="utf-8")
    assert "Open a finding to see what was observed" in content
    assert "WSCANARY-123" in content
    assert "Parameters to review" in content
    assert "Web server and technology fingerprint" in content
    assert content.index("Web server and technology fingerprint") < content.index("02 · EXECUTIVE SUMMARY")
    assert content.count("Web server and technology fingerprint") == 1
    assert "HTTP fingerprint" in content
    assert "nginx/1.24" in content
    assert "Open ports and services" in content
    assert "category-chip" in content
    assert "Executive summary" in content
    assert "Finding index" in content
    assert "finding-1" in content
    assert "HTTP status" in content
    assert "status-4xx" in content
    assert "Directory and path discovery" in content
    assert "Verification coverage" in content
    assert "What was observed" in content
    assert "Why it matters" in content
    assert "endpoint-value" in content
    assert "location-value" in content
    assert "HAPPY HACKING" not in content


def test_relative_report_paths_use_output_directory(tmp_path) -> None:
    generator = ReportGenerator({"reporting": {"output_dir": str(tmp_path)}}, DummyLogger())
    output = generator.generate([], "relative-report.json", "json")
    assert output == str(tmp_path / "relative-report.json")
    assert (tmp_path / "relative-report.json").exists()


def test_html_report_renders_cve_matches_as_suggestions(tmp_path) -> None:
    generator = ReportGenerator({"reporting": {"output_dir": str(tmp_path)}}, DummyLogger())
    output = tmp_path / "cve-report.html"
    generator.generate([{
        "scan_info": {"target": "https://example.test"},
        "target": {
            "fingerprint": {"server": "nginx/1.20.0"},
            "technologies": [{"name": "nginx", "version": "1.20.0", "source": "Server header"}],
            "cve_suggestions": [{
                "cve": "CVE-2021-23017", "product": "nginx", "detected_version": "1.20.0",
                "severity": "high", "confidence": "medium", "state": "suggested",
                "sources": ["Server header"], "ports": [],
                "summary": "Version match only", "affected_range": "0.6.18–1.20.0",
            }],
        },
        "findings": [],
    }], str(output), "html")
    content = output.read_text(encoding="utf-8")
    assert "Correlation suggestions" in content
    assert "CVE-2021-23017" in content
    assert "SUGGESTED" in content
    assert "not confirmed vulnerabilities" in content


def test_pdf_report_contains_security_assessment_sections(tmp_path) -> None:
    generator = ReportGenerator({"reporting": {"output_dir": str(tmp_path), "severity_threshold": "low"}}, DummyLogger())
    output = tmp_path / "assessment.pdf"
    results = [{
        "scan_info": {"target": "https://example.test", "scan_type": "standard"},
        "target": {
            "technologies": [{"name": "nginx", "category": "Web server", "version": "1.24", "confidence": "high", "source": "fingerprint"}],
            "external_assets": {"directories": [{"url": "https://example.test/admin/", "status": 403, "length": 120, "source": "dirsearch"}]},
        },
        "findings": [{
            "title": "Missing security header", "type": "Misconfiguration", "severity": "medium",
            "location": "https://example.test/", "status_code": 200, "state": "verified",
            "description": "The response did not include the expected header.",
            "impact": "Browser-side protections are reduced.", "evidence": "HTTP/1.1 200 OK",
            "remediation": "Set the header at the application or reverse proxy.",
        }],
        "coverage": {"discovered_pages": 3, "discovered_forms": 1, "discovered_endpoints": 4, "tested_requests": 8},
        "stats": {"medium": 1},
    }]
    assert generator.generate(results, str(output), "pdf") == str(output)
    assert output.read_bytes().startswith(b"%PDF")
    assert output.stat().st_size > 2000
