"""Parse a raw HTTP request exported by Burp Suite or a similar proxy."""

from __future__ import annotations

import json
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit, urlunsplit

from .scope import normalize_url


def parse_request_file(
    filename: str,
    base_url: str | None = None,
    default_scheme: str | None = None,
) -> dict:
    path = Path(filename)
    raw = path.read_text(encoding="utf-8", errors="replace")
    head, separator, body = raw.replace("\r\n", "\n").partition("\n\n")
    lines = head.splitlines()
    if not lines:
        raise ValueError("request file is empty")
    first = lines[0].split()
    if len(first) < 2 or first[0].upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
        raise ValueError("request file must start with an HTTP request line")

    method, request_target = first[0].upper(), first[1]
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()

    if request_target.startswith(("http://", "https://")):
        url = request_target
    elif base_url:
        base = base_url
        if default_scheme:
            parsed_base = urlsplit(base_url)
            base = urlunsplit((default_scheme, parsed_base.netloc, parsed_base.path or "/", "", ""))
        url = urljoin(base, request_target)
    else:
        # A Burp request normally contains a Host header even when the
        # request target is relative. This makes -r self-contained while
        # retaining the explicit base_url compatibility used by callers.
        host = next((value.strip() for name, value in headers.items() if name.lower() == "host"), "")
        if not host or any(char in host for char in "\r\n /\\") or "@" in host:
            raise ValueError("relative request target requires a valid Host header")
        forwarded_scheme = next(
            (value for name, value in headers.items() if name.lower() == "x-forwarded-proto"),
            "",
        ).split(",", 1)[0].strip().lower()
        scheme = (default_scheme or forwarded_scheme or "http").lower()
        if scheme not in {"http", "https"}:
            raise ValueError("request scheme must be http or https")
        url = f"{scheme}://{host}{request_target}"
    url = normalize_url(url)
    content_type_header = next(
        (value for name, value in headers.items() if name.lower() == "content-type"),
        "",
    ).lower()
    content_type = content_type_header
    inputs = []
    if "application/json" in content_type and body.strip():
        try:
            values = json.loads(body)
        except json.JSONDecodeError:
            values = {}
        if isinstance(values, dict):
            inputs = [{"name": str(key), "type": "json", "value": value} for key, value in values.items()]
    elif "multipart/form-data" in content_type:
        # Parse multipart fields using the stdlib MIME parser. File content is
        # deliberately represented by metadata only; active checks should not
        # upload or mutate files unless a dedicated authorized module opts in.
        mime = BytesParser(policy=policy.default).parsebytes(
            f"Content-Type: {next((value for name, value in headers.items() if name.lower() == 'content-type'), content_type)}\r\nMIME-Version: 1.0\r\n\r\n{body.replace(chr(10), chr(13) + chr(10))}".encode(
                "utf-8", errors="replace"
            )
        )
        for part in mime.walk():
            if part.is_multipart():
                continue
            name = part.get_param("name", header="content-disposition")
            if not name:
                continue
            filename = part.get_filename()
            value = "" if filename else (part.get_content() or "")
            inputs.append({
                "name": str(name),
                "type": "file" if filename else "text",
                "value": str(value),
                "filename": str(filename) if filename else "",
                "content_type": part.get_content_type(),
            })
    elif "application/x-www-form-urlencoded" in content_type or not content_type:
        values = parse_qs(body, keep_blank_values=True)
        inputs = [{"name": key, "type": "text", "value": values[0] if values else ""} for key, values in values.items()]

    return {
        "source": str(path),
        "method": method,
        "url": url,
        "headers": headers,
        "body": body if separator else "",
        "content_type": content_type,
        "inputs": inputs,
    }
