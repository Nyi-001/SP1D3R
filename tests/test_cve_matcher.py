from core.cve_matcher import CVESuggestionMatcher


def test_matches_versioned_web_technology() -> None:
    suggestions = CVESuggestionMatcher().match(
        [{"name": "nginx", "version": "1.20.0", "source": "Server header"}],
        [],
    )
    assert any(item["cve"] == "CVE-2021-23017" for item in suggestions)
    assert all(item["state"] == "suggested" for item in suggestions)


def test_matches_open_port_banner_without_treating_ssh_protocol_as_version() -> None:
    suggestions = CVESuggestionMatcher().match(
        [],
        [{"port": 22, "protocol": "tcp", "service": "ssh", "banner": "SSH-2.0-OpenSSH_8.9p1"}],
    )
    match = next(item for item in suggestions if item["cve"] == "CVE-2024-6387")
    assert match["detected_version"] == "8.9p1"
    assert match["ports"] == [22]


def test_unversioned_service_does_not_create_a_cve_suggestion() -> None:
    assert CVESuggestionMatcher().match([], [{"port": 80, "service": "http", "banner": ""}]) == []


def test_cpe_mapping_and_online_nvd_response_are_reported_as_suggestion(tmp_path) -> None:
    matcher = CVESuggestionMatcher(cache_dir=str(tmp_path))
    matcher._get_json = lambda *_args: {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-TEST-0001",
                "descriptions": [{"lang": "en", "value": "Test vulnerability."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.1}}]},
                "references": [{"url": "https://example.test/advisory"}],
            }
        }]
    }
    suggestions = matcher.enrich(
        [{"name": "nginx", "version": "1.20.0", "source": "WhatWeb"}],
        [],
        sources=("nvd",),
    )
    assert suggestions[0]["cve"] == "CVE-TEST-0001"
    assert suggestions[0]["state"] == "suggested"
    assert suggestions[0]["confidence"] == "medium"
