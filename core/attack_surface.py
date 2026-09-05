"""Map discovered web inputs to relevant, prioritized security checks."""

from collections import defaultdict
from typing import Any, Dict, Iterable, List
from urllib.parse import parse_qsl, urlsplit


PARAMETER_CHECKS = {
    "id": ("authorization", "idor"),
    "uid": ("authorization", "idor"),
    "user_id": ("authorization", "idor"),
    "url": ("ssrf", "open-redirect"),
    "uri": ("ssrf", "open-redirect"),
    "next": ("open-redirect",),
    "redirect": ("open-redirect", "ssrf"),
    "redirect_url": ("open-redirect", "ssrf"),
    "callback": ("open-redirect", "ssrf"),
    "file": ("path-traversal", "lfi"),
    "path": ("path-traversal", "lfi"),
    "page": ("path-traversal", "lfi"),
    "template": ("ssti", "path-traversal"),
    "q": ("reflection", "xss"),
    "query": ("reflection", "xss", "sqli"),
    "search": ("reflection", "xss", "sqli"),
    "cmd": ("command-injection",),
    "command": ("command-injection",),
    "exec": ("command-injection",),
    "execute": ("command-injection",),
    "shell": ("command-injection",),
    "ping": ("command-injection",),
    "host": ("command-injection", "ssrf"),
    "hostname": ("command-injection", "ssrf"),
    "include": ("lfi",),
    "filename": ("path-traversal", "lfi"),
    "filepath": ("path-traversal", "lfi"),
    "name": ("reflection", "xss"),
    "comment": ("reflection", "xss"),
    "role": ("mass-assignment", "authorization"),
    "owner": ("mass-assignment", "authorization"),
    "permission": ("mass-assignment", "authorization"),
    "price": ("mass-assignment", "business-logic"),
}

ATTACK_GUIDANCE = {
    "authentication": ("Authentication and session controls", "The endpoint appears to handle login or identity state.", "Use supplied test credentials only; review rate limits, session rotation, generic errors, and cookie flags."),
    "authorization": ("Authorization / access control", "Check whether the same object is accessible under another authorized identity.", "Use two test accounts and compare access to harmless objects; do not alter data."),
    "idor": ("IDOR / BOLA", "Object identifiers may be directly user-controlled.", "Swap only a canary object ID between authorized accounts and compare status and ownership."),
    "ssrf": ("SSRF", "The parameter may cause the server to fetch a supplied URL.", "Use a controlled `.invalid` canary or an approved internal test endpoint; never target third-party systems."),
    "open-redirect": ("Open redirect", "The value resembles a navigation destination.", "Use a non-routable `.invalid` canary and inspect the Location header without following it."),
    "path-traversal": ("Path traversal", "The value may select a filesystem path.", "Use a harmless platform-specific canary and compare response signatures; do not read real secrets."),
    "lfi": ("Local file inclusion", "The parameter may include server-side files.", "Validate only against an explicitly created lab fixture file."),
    "ssti": ("Server-side template injection", "The value resembles a template or view selector.", "Use a non-executing marker first and manually validate the rendering context."),
    "reflection": ("Input reflection", "User input is returned by the endpoint.", "Send a unique inert marker and compare the encoded response context."),
    "xss": ("Cross-site scripting", "The parameter is commonly rendered in HTML or script context.", "Use a bounded marker payload and require context-aware evidence before confirmation."),
    "sqli": ("SQL injection", "The value is commonly used in a data lookup or search.", "Use error-based or differential checks only in an authorized lab; never perform destructive queries."),
    "command-injection": ("OS command injection", "The name suggests that the server may pass the value to an operating-system command.", "Use a unique marker-only probe and require execution evidence; never run destructive commands."),
    "mass-assignment": ("Mass assignment", "The field may change server-side object properties.", "Submit a harmless unauthorized field and verify that the server ignores it."),
    "business-logic": ("Business-logic validation", "The field may affect price, role, or workflow state.", "Use a zero-impact test transaction or dry-run fixture; do not place real orders."),
    "api": ("API authorization and method handling", "The route appears to expose an API surface with method and object-level risks.", "Review documented methods, object ownership, excessive data, and mass assignment with harmless requests."),
    "graphql": ("GraphQL schema and resolver authorization", "The route may expose schema and resolver behavior.", "Use read-only authorized queries and verify resolver authorization for each object."),
    "file-upload": ("File upload validation", "The route appears to accept uploaded content.", "Use a harmless non-executable fixture and verify type, size, storage, and retrieval controls."),
    "information-disclosure": ("Information disclosure", "Debug or diagnostic routes can expose implementation details.", "Check for stack traces and configuration leakage without triggering state changes."),
    "sensitive-files": ("Sensitive file exposure", "Backup or configuration routes may expose secrets.", "Check only approved filenames and redact any sensitive evidence before persistence."),
    "api-docs": ("API documentation exposure", "API schemas may reveal undocumented attack surface.", "Review schemas and authentication requirements without executing destructive operations."),
    "java-action": ("Java action endpoint review", "The `.do` route appears to dispatch a server-side application action rather than serve a static file.", "Review authentication, authorization, CSRF protection, allowed methods, and error handling with harmless requests."),
    "endpoint-review": ("Route and method handling", "The route was discovered as an application endpoint.", "Verify expected HTTP methods, authentication, authorization, and error handling with a harmless request."),
    "input-validation": ("Input validation", "The endpoint accepts user-controlled data.", "Check type, length, encoding, and rejection behavior with inert boundary values."),
}

ENDPOINT_RULES = {
    "login": ("authentication", "Authentication and session controls", "Check rate limiting, session rotation, cookie flags, and generic error messages without credential guessing."),
    "auth": ("authentication", "Authentication and session controls", "Review session handling and authorization using supplied test identities only."),
    "admin": ("authorization", "Administrative access control", "Verify the route is inaccessible to a least-privileged test account."),
    "api": ("api", "API authorization and method handling", "Review documented methods, object ownership, excessive data, and mass assignment with harmless requests."),
    "graphql": ("graphql", "GraphQL schema and resolver authorization", "Inspect schema exposure and resolver access using read-only authorized queries."),
    "upload": ("file-upload", "File upload validation", "Use a harmless non-executable fixture and verify type, size, storage, and retrieval controls."),
    "download": ("path-traversal", "Download path authorization", "Verify object ownership and filename normalization with a lab fixture."),
    "debug": ("information-disclosure", "Debug and diagnostic exposure", "Check for stack traces, configuration, and environment leakage without triggering state changes."),
    "backup": ("sensitive-files", "Backup and configuration exposure", "Check only approved filenames and confirm contents are non-sensitive before recording evidence."),
    "swagger": ("api-docs", "API documentation exposure", "Review whether documentation is intentionally public and whether listed endpoints enforce authorization."),
    "openapi": ("api-docs", "API documentation exposure", "Review schemas and authentication requirements without executing destructive operations."),
}


def _guidance(checks: Iterable[str]) -> List[Dict[str, str]]:
    guidance = []
    seen = set()
    for check in checks:
        item = ATTACK_GUIDANCE.get(check)
        if item and item[0] not in seen:
            guidance.append({"attack": item[0], "why": item[1], "safe_verification": item[2]})
            seen.add(item[0])
    return guidance


def classify_endpoint(endpoint: str) -> Dict[str, Any]:
    path = urlsplit(endpoint).path.lower()
    checks = []
    for keyword, (check, _attack, _verification) in ENDPOINT_RULES.items():
        if keyword in path and check not in checks:
            checks.append(check)
    if path.endswith('.do'):
        # Java action routes are dynamic server-side handlers. Their useful
        # review questions concern access control, CSRF, methods, and error
        # handling—not whether the URL itself accepts arbitrary input.
        checks = ['java-action'] + [check for check in checks if check != 'input-validation']
    if not checks:
        checks = ["endpoint-review"]
    return {
        "priority": "high" if any(check in checks for check in ("authorization", "authentication", "api", "file-upload")) else "normal",
        "checks": checks,
        "recommendations": _guidance(checks),
    }


def classify_parameter(name: str) -> Dict[str, Any]:
    normalized = name.strip().lower()
    checks = PARAMETER_CHECKS.get(normalized)
    if checks:
        return {"name": name, "priority": "high", "checks": list(checks), "recommendations": _guidance(checks)}
    return {"name": name, "priority": "normal", "checks": ["input-validation"], "recommendations": _guidance(["input-validation"])}


def build_attack_surface(crawl_data: Dict[str, Any]) -> Dict[str, Any]:
    records: Dict[tuple, Dict[str, Any]] = {}
    endpoints: Dict[tuple, Dict[str, Any]] = {}

    def add_endpoint(endpoint: str, method: str, source: str) -> None:
        key = (endpoint, method.upper())
        record = endpoints.setdefault(key, {"endpoint": endpoint, "method": method.upper(), "sources": [], **classify_endpoint(endpoint)})
        if source not in record["sources"]:
            record["sources"].append(source)

    def add_parameter(endpoint: str, method: str, name: str, source: str) -> None:
        key = (endpoint, method.upper(), name)
        record = records.setdefault(key, {"endpoint": endpoint, "method": method.upper(), "parameter": name, "sources": [], **classify_parameter(name)})
        if source not in record["sources"]:
            record["sources"].append(source)

    for page in crawl_data.get("pages", []):
        parsed = urlsplit(page)
        endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        add_endpoint(endpoint, "GET", "page")
        for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
            add_parameter(endpoint, "GET", name, "query-string")

    for form in crawl_data.get("forms", []):
        endpoint = str(form.get("url", ""))
        method = str(form.get("method", "GET")).upper()
        add_endpoint(endpoint, method, "form")
        for input_field in form.get("inputs", []):
            if isinstance(input_field, dict):
                name = input_field.get("name")
            else:
                name = input_field
            if name:
                add_parameter(endpoint, method, str(name), "form")

    # API routes are discovered separately from ordinary HTML pages (for
    # example from JavaScript bundles or an OpenAPI document). Keep them in
    # the same normalized inventory so reports and active checks agree on the
    # complete attack surface.
    for api in crawl_data.get("api_endpoints", []):
        endpoint = str(api.get("url", ""))
        method = str(api.get("method", "GET")).upper()
        if not endpoint:
            continue
        add_endpoint(endpoint, method, f"api:{api.get('source', 'discovery')}")
        for name in api.get("parameters", []):
            if name:
                add_parameter(endpoint, method, str(name), "api")

    parameters = sorted(records.values(), key=lambda item: (item["priority"] != "high", item["endpoint"], item["parameter"]))
    checks = defaultdict(int)
    for record in parameters:
        for check in record["checks"]:
            checks[check] += 1
    endpoint_list = sorted(endpoints.values(), key=lambda item: (item["priority"] != "high", item["endpoint"], item["method"]))
    return {
        "parameters": parameters,
        "endpoints": endpoint_list,
        "summary": dict(sorted(checks.items())),
        "endpoint_count": len(endpoint_list),
    }
