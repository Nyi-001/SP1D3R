from integrations.tool_manager import TOOL_PROFILES, ToolManager
from core.scanner import PentestScanner


class DummyLogger:
    def warning(self, *_args, **_kwargs):
        pass


def test_tool_profiles_are_explicit_and_wpscan_has_no_password_attack() -> None:
    assert {"assetfinder", "subfinder", "amass", "dnsenum", "whois", "httpx", "whatweb", "nmap", "nikto", "dirb", "dirsearch", "ffuf", "nuclei", "wpscan"}.issubset(TOOL_PROFILES)
    manager = ToolManager({"scope": {"allowed_hosts": ["example.test"], "active_checks": True}, "scanning": {}}, DummyLogger())
    command = manager._build_command("wpscan", "https://example.test")
    assert "--enumerate" in command
    assert "--passwords" not in command
    assert "--password-attack" not in command


def test_recon_profiles_use_scope_safe_commands() -> None:
    manager = ToolManager({"scope": {"allowed_hosts": ["example.test"], "active_checks": True}, "scanning": {}}, DummyLogger())
    assert manager._build_command("assetfinder", "https://example.test") == ["assetfinder", "--subs-only", "example.test"]
    assert manager._build_command("amass", "https://example.test") == ["amass", "enum", "-passive", "-d", "example.test"]
    assert manager._build_command("nmap", "https://example.test")[-1] == "example.test"
    assert "-oX" in manager._build_command("nmap", "https://example.test")


def test_nmap_xml_is_normalized_as_services() -> None:
    manager = ToolManager({"scope": {"allowed_hosts": ["example.test"], "active_checks": True}, "scanning": {}}, DummyLogger())
    xml = '<nmaprun><host><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24"/></port></ports></host></nmaprun>'
    assets = manager._extract_assets("nmap", xml)
    assert assets["services"][0]["service"] == "http"
    assert assets["services"][0]["product"] == "nginx"


def test_nuclei_output_is_normalized() -> None:
    manager = ToolManager({"scope": {"allowed_hosts": ["example.test"], "active_checks": True}, "scanning": {}}, DummyLogger())
    findings = manager._normalize_findings("nuclei", "https://example.test", '{"template-id":"demo","matched-at":"https://example.test/a","info":{"name":"Demo","severity":"medium"}}')
    assert findings[0]["title"] == "Demo"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["tool"] == "nuclei"


def test_whatweb_json_is_extracted_as_service_inventory() -> None:
    manager = ToolManager({"scope": {"allowed_hosts": ["example.test"], "active_checks": False}, "scanning": {}}, DummyLogger())
    output = '[{"target":"https://example.test/","http_status":200,"plugins":{"Apache":{"version":["2.4"]},"WordPress":{}}}]'
    assets = manager._extract_assets("whatweb", output)
    assert assets["services"][0]["status"] == 200
    assert "Apache" in assets["services"][0]["technologies"]


def test_whatweb_command_is_bounded_and_quiet() -> None:
    manager = ToolManager(
        {"scope": {"allowed_hosts": ["example.test"], "active_checks": False}, "scanning": {"whatweb_timeout": 8}},
        DummyLogger(),
    )
    command = manager._build_command("whatweb", "https://example.test")
    assert "--quiet" in command
    assert "--aggression=1" in command
    assert command[command.index("--open-timeout") + 1] == "8"
    assert command[command.index("--read-timeout") + 1] == "8"


def test_whatweb_reuses_authenticated_cookie_context() -> None:
    manager = ToolManager(
        {
            "scope": {"allowed_hosts": ["example.test"], "active_checks": False},
            "scanning": {"cookie": "PHPSESSID=lab-session; security=low"},
        },
        DummyLogger(),
    )
    command = manager._build_command("whatweb", "https://example.test")
    assert command[command.index("--cookie") + 1] == "PHPSESSID=lab-session; security=low"


def test_whatweb_valid_output_with_plugin_warning_is_not_marked_failed(monkeypatch) -> None:
    import subprocess

    manager = ToolManager(
        {"scope": {"allowed_hosts": ["example.test"], "active_checks": False}, "scanning": {}},
        DummyLogger(),
    )
    monkeypatch.setattr("integrations.tool_manager.shutil.which", lambda _name: "/usr/bin/whatweb")
    monkeypatch.setattr(
        "integrations.tool_manager.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["whatweb"], 1,
            stdout='[{"target":"https://example.test/","http_status":200,"plugins":{}}]',
            stderr="one plugin warning",
        ),
    )
    findings, assets, run = manager._run_one("whatweb", "https://example.test")
    assert findings == []
    assert assets["services"][0]["status"] == 200
    assert run["status"] == "completed-with-warnings"
    assert "one plugin warning" in run["stderr"]


def test_whatweb_metadata_is_not_reported_as_technology() -> None:
    services = [{
        "url": "https://example.test/",
        "status": 200,
        "technologies": {
            "IP": ["192.0.2.10"],
            "Title": [{"string": "Example"}],
            "Apache": [{"version": ["2.4."]}],
        },
    }]
    technologies = PentestScanner._whatweb_technologies(services)
    names = {item["name"] for item in technologies}
    assert names == {"Apache"}


def test_external_tool_timeout_is_reported_distinctly(monkeypatch) -> None:
    manager = ToolManager(
        {"scope": {"allowed_hosts": ["example.test"], "active_checks": True}, "scanning": {"tool_timeout": 2}},
        DummyLogger(),
    )

    def timed_out(*_args, **_kwargs):
        import subprocess
        raise subprocess.TimeoutExpired("nuclei", 2, output=b"", stderr=b"partial output")

    monkeypatch.setattr("integrations.tool_manager.shutil.which", lambda _name: "/usr/bin/nuclei")
    monkeypatch.setattr("integrations.tool_manager.subprocess.run", timed_out)
    findings, assets, run = manager._run_one("nuclei", "https://example.test")
    assert findings == []
    assert assets == {}
    assert run["status"] == "timeout"
    assert "partial output" in run["stderr"]


def test_dirsearch_json_is_normalized_with_status_code() -> None:
    manager = ToolManager({"scope": {"allowed_hosts": ["example.test"], "active_checks": True}, "scanning": {}}, DummyLogger())
    output = '{"results":[{"url":"https://example.test/admin/","status":403,"content-length":123,"content-type":"text/html","redirect":""}]}'
    findings = manager._normalize_findings("dirsearch", "https://example.test", output)
    assert findings[0]["status_code"] == 403
    assert findings[0]["tool"] == "dirsearch"


def test_dirsearch_filters_ordinary_404s_and_extracts_assets() -> None:
    manager = ToolManager({"scope": {"allowed_hosts": ["example.test"], "active_checks": True}, "scanning": {}}, DummyLogger())
    output = '{"results":[' \
        '{"url":"https://example.test/missing","status":404},' \
        '{"url":"https://example.test/admin/","status":403,"content-length":123}' \
        ']}'
    findings = manager._normalize_findings("dirsearch", "https://example.test", output)
    assets = manager._extract_assets("dirsearch", output)
    assert len(findings) == 1
    assert findings[0]["status_code"] == 403
    assert assets["directories"][0]["url"].endswith("/admin/")


def test_dirsearch_uses_bounded_default_scan_command() -> None:
    manager = ToolManager({"scope": {"allowed_hosts": ["example.test"], "active_checks": True}, "scanning": {"tool_timeout": 90, "dirsearch_timeout": 90, "timeout": 7}}, DummyLogger())
    command = manager._build_command("dirsearch", "https://example.test")
    assert command[:3] == ["dirsearch", "--url", "https://example.test/"]
    assert "--quiet-mode" in command
    assert "--no-color" in command
    assert command[command.index("--threads") + 1] == "5"
    assert command[command.index("--max-time") + 1] == "90"
    assert command[command.index("--timeout") + 1] == "7"
    assert "-w" not in command


def test_dirsearch_uses_parent_directory_for_file_target() -> None:
    manager = ToolManager({"scope": {"allowed_hosts": ["example.test"], "active_checks": True}, "scanning": {}}, DummyLogger())
    command = manager._build_command("dirsearch", "https://example.test/DVWA/security.php")
    assert command[command.index("--url") + 1] == "https://example.test/DVWA/"
