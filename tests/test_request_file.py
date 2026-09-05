from core.request_file import parse_request_file
from core.web_scanner import WebScanner


def test_parse_burp_urlencoded_request(tmp_path):
    request_file = tmp_path / "burp-request.txt"
    request_file.write_text(
        "POST /DVWA/vulnerabilities/xss_r/ HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Cookie: PHPSESSID=lab; security=low\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "X-Test: retained\r\n"
        "\r\n"
        "name=test&token=abc",
        encoding="utf-8",
    )

    parsed = parse_request_file(str(request_file), "http://localhost/DVWA/security.php")

    assert parsed["method"] == "POST"
    assert parsed["url"] == "http://localhost/DVWA/vulnerabilities/xss_r/"
    assert parsed["headers"]["Cookie"] == "PHPSESSID=lab; security=low"
    assert {field["name"] for field in parsed["inputs"]} == {"name", "token"}


def test_parse_request_file_can_infer_target_from_host_header(tmp_path):
    request_file = tmp_path / "standalone-request.txt"
    request_file.write_text(
        "GET /DVWA/vulnerabilities/sqli/?id=1 HTTP/1.1\n"
        "Host: localhost\n\n",
        encoding="utf-8",
    )

    parsed = parse_request_file(str(request_file))

    assert parsed["url"] == "http://localhost/DVWA/vulnerabilities/sqli/?id=1"


def test_parse_request_file_extracts_multipart_fields_without_uploading_files(tmp_path):
    request_file = tmp_path / "upload-request.txt"
    request_file.write_text(
        "POST /upload HTTP/1.1\n"
        "hOsT: example.test\n"
        "Content-Type: multipart/form-data; boundary=BOUNDARY\n\n"
        "--BOUNDARY\r\n"
        "Content-Disposition: form-data; name=comment\r\n\r\n"
        "hello\r\n"
        "--BOUNDARY\r\n"
        "Content-Disposition: form-data; name=file; filename=test.txt\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "safe lab content\r\n"
        "--BOUNDARY--\r\n",
        encoding="utf-8",
    )

    parsed = parse_request_file(str(request_file), default_scheme="https")

    assert parsed["url"] == "https://example.test/upload"
    fields = {field["name"]: field for field in parsed["inputs"]}
    assert fields["comment"]["value"] == "hello"
    assert fields["file"]["type"] == "file"
    assert fields["file"]["filename"] == "test.txt"


def test_parse_burp_json_request_and_preserve_request_seed(tmp_path):
    request_file = tmp_path / "api-request.txt"
    request_file.write_text(
        "PUT /api/profile HTTP/1.1\n"
        "Host: example.test\n"
        "Content-Type: application/json\n\n"
        '{"user_id": 7, "display_name": "test"}',
        encoding="utf-8",
    )

    parsed = parse_request_file(str(request_file), "https://example.test/")
    crawl_data = WebScanner._request_spec_crawl_data(parsed)

    assert parsed["content_type"] == "application/json"
    assert {field["name"] for field in parsed["inputs"]} == {"user_id", "display_name"}
    assert crawl_data["forms"][0]["method"] == "put"
    assert crawl_data["forms"][0]["content_type"] == "application/json"


def test_api_request_uses_same_origin_referer_as_crawl_seed(tmp_path):
    request_file = tmp_path / "api-request.txt"
    request_file.write_text(
        "GET /identity/api/v2/user/dashboard HTTP/1.1\n"
        "Host: example.test\n"
        "Referer: https://example.test/dashboard\n\n",
        encoding="utf-8",
    )
    parsed = parse_request_file(str(request_file), "https://example.test/")
    crawl_data = WebScanner._request_spec_crawl_data(parsed)
    assert "https://example.test/dashboard" in crawl_data["pages"]
