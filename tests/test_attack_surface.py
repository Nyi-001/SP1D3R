from core.attack_surface import build_attack_surface, classify_endpoint, classify_parameter


def test_parameter_classifier_prioritizes_sensitive_input_families() -> None:
    result = classify_parameter("redirect")
    assert result["priority"] == "high"
    assert "open-redirect" in result["checks"]


def test_attack_surface_merges_query_and_form_parameters() -> None:
    surface = build_attack_surface({
        "pages": ["https://example.test/search?q=one&id=4"],
        "forms": [{"url": "https://example.test/search", "method": "post", "inputs": [{"name": "q"}, {"name": "comment"}]}],
    })
    names = {item["parameter"] for item in surface["parameters"]}
    assert names == {"q", "id", "comment"}
    assert surface["endpoint_count"] == 2
    assert surface["summary"]["reflection"] == 3


def test_endpoint_recommends_attack_paths_and_safe_verification() -> None:
    result = classify_endpoint("https://example.test/api/admin/upload")
    attacks = {item["attack"] for item in result["recommendations"]}
    assert result["priority"] == "high"
    assert "API authorization and method handling" in attacks
    assert "File upload validation" in attacks


def test_java_action_endpoint_does_not_receive_generic_input_validation() -> None:
    result = classify_endpoint("https://example.test/AdmissionFees.do")
    attacks = {item["attack"] for item in result["recommendations"]}
    assert "Java action endpoint review" in attacks
    assert "Input validation" not in attacks
    assert any("CSRF" in item["safe_verification"] for item in result["recommendations"])


def test_generic_endpoint_gets_route_review_not_parameter_review() -> None:
    result = classify_endpoint("https://example.test/")
    assert result["checks"] == ["endpoint-review"]
    assert result["recommendations"][0]["attack"] == "Route and method handling"


def test_parameter_contains_recommendation_guidance() -> None:
    result = classify_parameter("redirect")
    assert result["recommendations"]
    assert any("Location header" in item["safe_verification"] for item in result["recommendations"])
