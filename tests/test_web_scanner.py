import asyncio

from core.web_scanner import WebScanner


class DummyLogger:
    def info(self, *_args, **_kwargs):
        pass

    def debug(self, *_args, **_kwargs):
        pass


def test_authenticated_session_headers_include_cookie() -> None:
    scanner = WebScanner(
        {
            "scope": {"allowed_hosts": ["example.test"]},
            "scanning": {"user_agent": "TestAgent", "cookie": "PHPSESSID=lab-session; security=low"},
        },
        DummyLogger(),
    )
    assert scanner._session_headers() == {
        "User-Agent": "TestAgent",
        "Cookie": "PHPSESSID=lab-session; security=low",
    }


def test_configured_authorization_header_is_replayed() -> None:
    scanner = WebScanner(
        {
            "scope": {"allowed_hosts": ["example.test"]},
            "scanning": {"headers": {"Authorization": "Bearer lab-token"}},
        },
        DummyLogger(),
    )
    assert scanner._session_headers()["Authorization"] == "Bearer lab-token"


def test_burp_headers_are_replayed_without_hop_by_hop_headers() -> None:
    scanner = WebScanner(
        {
            "scope": {"allowed_hosts": ["example.test"]},
            "scanning": {"user_agent": "TestAgent"},
        },
        DummyLogger(),
    )
    scanner.request_headers = {
        "Cookie": "PHPSESSID=burp-session",
        "Authorization": "Bearer lab-token",
        "Content-Type": "application/json",
    }
    headers = scanner._session_headers()
    assert headers["Cookie"] == "PHPSESSID=burp-session"
    assert headers["Authorization"] == "Bearer lab-token"
    assert headers["Content-Type"] == "application/json"


def test_form_request_kwargs_follow_captured_content_type() -> None:
    assert WebScanner._form_request_kwargs(
        {"content_type": "application/json"}, {"id": 7}
    ) == {"json": {"id": 7}}
    assert WebScanner._form_request_kwargs(
        {"content_type": "application/x-www-form-urlencoded"}, {"q": "test"}
    ) == {"data": {"q": "test"}}


def test_form_probe_preserves_hidden_and_checked_values() -> None:
    scanner = WebScanner({"scope": {"allowed_hosts": ["example.test"]}, "scanning": {}}, DummyLogger())
    form = {
        "inputs": [
            {"name": "token", "type": "hidden", "value": "abc"},
            {"name": "q", "type": "text", "value": "original"},
            {"name": "remember", "type": "checkbox", "value": "yes", "checked": True},
            {"name": "ignored", "type": "checkbox", "value": "no", "checked": False},
        ]
    }
    assert scanner._form_data(form, "q", "PAYLOAD") == {
        "token": "abc", "q": "PAYLOAD", "remember": "yes"
    }


def test_login_gate_detection_distinguishes_login_page_from_application_page() -> None:
    login_html = '<title>Login :: Damn Vulnerable Web Application (DVWA)</title><form action="login.php"><input name="username"><input type="password" name="password"></form>'
    app_html = '<title>XSS</title><form><input name="name"></form>'
    assert WebScanner._looks_like_login_page(login_html) is True
    assert WebScanner._looks_like_login_page(app_html) is False
    assert WebScanner._is_login_endpoint('http://localhost/DVWA/login.php') is True
    assert WebScanner._is_login_endpoint('http://localhost/DVWA/vulnerabilities/xss_r/') is False


def test_login_redirect_is_treated_as_an_authentication_gate() -> None:
    assert WebScanner._is_auth_gate_response(302, '../../login.php') is True
    assert WebScanner._is_auth_gate_response(303, '/signin') is True
    assert WebScanner._is_auth_gate_response(302, '/dashboard') is False
    assert WebScanner._is_auth_gate_response(200, '/login.php') is False


def test_active_attack_methods_run_independently() -> None:
    scanner = WebScanner({
        "scope": {"allowed_hosts": ["example.test"], "active_checks": True},
        "scanning": {"all_active_tests": True},
    }, DummyLogger())

    async def no_op(*_args, **_kwargs):
        return None

    async def fake_xss(*_args, **_kwargs):
        scanner.findings.append({"title": "XSS", "type": "XSS", "location": "https://example.test/"})

    async def fake_crawl(*_args, **_kwargs):
        return {"pages": [], "forms": []}

    scanner._check_security_headers = no_op
    scanner._check_ssl_configuration = no_op
    scanner._crawl_site = fake_crawl
    scanner._test_sql_injection = no_op
    scanner._test_xss = fake_xss
    scanner._test_ssti = no_op
    scanner._test_directory_traversal = no_op
    scanner._test_open_redirect = no_op
    scanner._check_common_files = no_op
    scanner._test_csrf = no_op

    result = asyncio.run(scanner.scan("https://example.test", test_xss=True))
    checks = {item["method"]: item for item in result["coverage"]["attack_checks"]}
    assert checks["Cross-site scripting"]["status"] == "completed"
    assert checks["SQL injection"]["status"] == "completed"
    assert checks["Server-side template injection"]["status"] == "completed"
    assert len(result["findings"]) == 1


def test_request_budget_warning_is_not_repeated() -> None:
    class WarningLogger(DummyLogger):
        def __init__(self):
            self.warnings = []

        def warning(self, message):
            self.warnings.append(message)

    logger = WarningLogger()
    scanner = WebScanner({
        "scope": {"allowed_hosts": ["example.test"]},
        "scanning": {"max_requests": 1},
    }, logger)
    scanner.request_count = 1

    import asyncio
    assert asyncio.run(scanner._reserve_request('x')) is False
    assert asyncio.run(scanner._reserve_request('x')) is False
    assert len(logger.warnings) == 1


def test_large_payload_collections_are_bounded() -> None:
    scanner = WebScanner(
        {
            "scope": {"allowed_hosts": ["example.test"]},
            "scanning": {"payload_limit": 3},
        },
        DummyLogger(),
    )
    payloads = scanner._load_payload_file(
        "command_injection_payloads.txt", scanner.COMMAND_PAYLOADS
    )
    assert len(payloads) == 3


def test_sqli_active_probes_use_comments_and_not_a_lone_quote() -> None:
    scanner = WebScanner(
        {
            "scope": {"allowed_hosts": ["example.test"]},
            "scanning": {"payload_limit": 8},
        },
        DummyLogger(),
    )
    probes = scanner._sqli_comment_payloads()
    assert probes
    assert all("'" not in probe or any(marker in probe for marker in ("--", "#", "/*")) for probe in probes)
    assert all(probe != "'" for probe in probes)
    assert any("-- -" in probe for probe in probes)


def test_named_candidate_probe_preserves_post_method_and_body() -> None:
    scanner = WebScanner({"scope": {"allowed_hosts": ["example.test"]}, "scanning": {}}, DummyLogger())
    form = {
        "url": "https://example.test/exec",
        "method": "post",
        "inputs": [{"name": "ip", "type": "text", "value": "127.0.0.1"}],
    }
    method, endpoint, kwargs, location = scanner._build_candidate_probe("form", form, "ip", ";printf marker")
    assert method == "POST"
    assert endpoint == "https://example.test/exec"
    assert kwargs["data"]["ip"] == ";printf marker"
    assert location == endpoint


def test_api_detection_registers_only_observed_api_signals() -> None:
    scanner = WebScanner({"scope": {"allowed_hosts": ["example.test"]}, "scanning": {}}, DummyLogger())
    scanner._inspect_api_response(
        "https://example.test/app",
        "text/html",
        '<script>fetch("/api/v1/users")</script>',
    )
    assert scanner.api_detected is True
    assert any("API client" in signal for signal in scanner.api_signals)
    # A client signal alone does not invent a route; routes are registered
    # when they are extracted from a JavaScript response or API document.
    assert scanner.api_endpoints == []


def test_api_route_pattern_is_added_to_attack_surface() -> None:
    scanner = WebScanner({"scope": {"allowed_hosts": ["example.test"]}, "scanning": {}}, DummyLogger())
    scanner._inspect_api_response(
        "https://example.test/api/v1/users?id=7",
        "application/json",
        '{"id": 7}',
    )
    result = __import__('core.attack_surface', fromlist=['build_attack_surface']).build_attack_surface({
        "pages": [], "forms": [], "api_endpoints": scanner.api_endpoints,
    })
    assert result["endpoint_count"] == 1
    assert result["parameters"][0]["parameter"] == "id"


def test_site_classifier_recommends_graphql_reviews() -> None:
    profile = WebScanner._classify_site(
        {
            "pages": [],
            "forms": [],
            "api_detected": True,
            "api_signals": ["GraphQL route"],
            "api_endpoints": [{"url": "http://example.test/graphql", "method": "POST"}],
        },
        {"directories": []},
    )
    assert profile["kind"] == "GraphQL API"
    assert profile["graphql_detected"] is True
    assert any("resolver" in item for item in profile["recommended_reviews"])
