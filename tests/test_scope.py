import pytest

from core.scope import ScopeError, ScopePolicy, normalize_url


def test_wildcard_scope_allows_apex_and_subdomains() -> None:
    policy = ScopePolicy(["*.example.test"], ["/logout*", "/delete*"])
    assert policy.is_allowed("https://example.test/")
    assert policy.is_allowed("https://api.example.test/v1")
    assert not policy.is_allowed("https://example.org/")
    assert not policy.is_allowed("https://example.test/logout")


def test_normalize_rejects_embedded_credentials() -> None:
    assert normalize_url("HTTPS://Example.TEST/a#fragment") == "https://example.test/a"
    with pytest.raises(ScopeError):
        normalize_url("https://user:password@example.test/")


def test_cidr_scope_accepts_ip_literals() -> None:
    policy = ScopePolicy(["192.0.2.0/24"])
    assert policy.is_allowed("https://192.0.2.10/")
    assert not policy.is_allowed("https://192.0.3.10/")


def test_path_scoped_allow_rule() -> None:
    policy = ScopePolicy(["localhost/DVWA"])
    assert policy.is_allowed("http://localhost/DVWA/vulnerabilities/xss_r/?name=test")
    assert not policy.is_allowed("http://localhost/other/")


def test_exclusion_matches_nested_application_paths() -> None:
    policy = ScopePolicy(["localhost/DVWA"], ["/logout*"])
    assert not policy.is_allowed("http://localhost/DVWA/logout.php")


def test_apex_scope_allows_subdomain_dns_verification_only() -> None:
    policy = ScopePolicy(["example.test"])
    assert policy.is_allowed_discovered_host("api.example.test", "example.test")
    assert not policy.is_allowed("https://api.example.test/")


def test_path_scoped_apex_does_not_expand_to_subdomains() -> None:
    policy = ScopePolicy(["example.test/app"])
    assert not policy.is_allowed_discovered_host("api.example.test", "example.test")


def test_loopback_aliases_share_scope() -> None:
    policy = ScopePolicy(["127.0.0.1"])
    assert policy.is_allowed("http://localhost/DVWA/vulnerabilities/exec")

    reverse_policy = ScopePolicy(["localhost"])
    assert reverse_policy.is_allowed("http://127.0.0.1/DVWA/")
