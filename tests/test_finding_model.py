from core.finding_model import normalize_finding


def test_findings_are_normalized_and_deduplicated_by_identity() -> None:
    first = normalize_finding({"type": "XSS", "severity": "HIGH", "location": "https://example.test/search", "parameter": "q"})
    second = normalize_finding({"title": "XSS", "severity": "high", "url": "https://example.test/search", "parameter": "q"})
    assert first["title"] == "XSS"
    assert first["severity"] == "high"
    assert first["finding_id"] == second["finding_id"]
    assert first["state"] == "suspected"
