"""Scope enforcement for authorized web assessments."""

from __future__ import annotations

from fnmatch import fnmatch
from ipaddress import ip_address, ip_network
from urllib.parse import SplitResult, urlsplit, urlunsplit


class ScopeError(ValueError):
    """Raised when a target or discovered URL is outside the scan scope."""


def normalize_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ScopeError("only HTTP and HTTPS targets are supported")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ScopeError("target must have a hostname and no embedded credentials")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    netloc = host if parsed.port is None else f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


class ScopePolicy:
    def __init__(self, allowed_hosts: list[str], excluded_paths: list[str] | None = None):
        self.allowed_hosts = []
        self.allowed_paths = []
        for item in allowed_hosts:
            rule = item.strip()
            if not rule:
                continue
            host_rule, path_prefix = self._split_rule(rule)
            host_rule = host_rule.lower()
            self.allowed_hosts.append(host_rule)
            if path_prefix:
                self.allowed_paths.append((host_rule, path_prefix))
        self.excluded_paths = excluded_paths or []
        if not self.allowed_hosts:
            raise ScopeError("at least one --allow host or CIDR is required")

    @staticmethod
    def _split_rule(rule: str) -> tuple[str, str | None]:
        """Accept host rules and optional path-scoped rules such as localhost/DVWA."""
        try:
            ip_network(rule, strict=False)
            return rule, None
        except ValueError:
            pass
        if "://" in rule:
            parsed = urlsplit(rule)
            host = parsed.hostname or ""
            path = parsed.path
        else:
            host, separator, path = rule.partition("/")
            if not separator:
                return rule, None
            path = "/" + path
        path = path.rstrip("/") or "/"
        return host, None if path == "/" else path

    @staticmethod
    def _is_loopback_name(hostname: str) -> bool:
        return hostname.lower().rstrip('.') in {'localhost', '127.0.0.1', '::1'}

    @staticmethod
    def _is_loopback_rule(rule: str) -> bool:
        rule = rule.lower().rstrip('.')
        if rule in {'localhost', '127.0.0.1', '::1'}:
            return True
        try:
            network = ip_network(rule, strict=False)
            return ip_address('127.0.0.1') in network or ip_address('::1') in network
        except ValueError:
            return False

    def is_allowed_host(self, hostname: str) -> bool:
        hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
        try:
            address = ip_address(hostname)
        except ValueError:
            address = None
        for rule in self.allowed_hosts:
            if self._is_loopback_name(hostname) and self._is_loopback_rule(rule):
                return True
            if "/" in rule:
                try:
                    if address is not None and address in ip_network(rule, strict=False):
                        return True
                except ValueError:
                    continue
            elif rule.startswith("*."):
                base = rule[2:]
                if hostname == base or hostname.endswith("." + base):
                    return True
            elif hostname == rule:
                return True
        return False

    def is_allowed_discovered_host(self, hostname: str, parent: str) -> bool:
        """Allow DNS verification of children of an explicitly allowed apex.

        This is used only by subdomain enumeration. Crawling or active testing
        a discovered child still requires an explicit wildcard allow rule.
        Path-scoped rules such as ``localhost/DVWA`` never expand to children.
        """
        hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
        parent = parent.encode("idna").decode("ascii").lower().rstrip(".")
        if self.is_allowed_host(hostname):
            return True
        if not hostname.endswith("." + parent) or not self.is_allowed_host(parent):
            return False
        return not any(self._rule_matches_host(rule, parent) for rule, _prefix in self.allowed_paths)

    def is_allowed(self, value: str | SplitResult) -> bool:
        try:
            parsed = urlsplit(value) if isinstance(value, str) else value
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                return False
            if not self.is_allowed_host(parsed.hostname):
                return False
            path = parsed.path or "/"
            scoped_rules = [(rule, prefix) for rule, prefix in self.allowed_paths if self._rule_matches_host(rule, parsed.hostname)]
            if scoped_rules and not any(path == prefix or path.startswith(prefix + "/") for _rule, prefix in scoped_rules):
                return False
            return not any(self._path_excluded(path, pattern) for pattern in self.excluded_paths)
        except (UnicodeError, ValueError):
            return False

    def _rule_matches_host(self, rule: str, hostname: str) -> bool:
        hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if rule.startswith("*."):
            base = rule[2:]
            return hostname == base or hostname.endswith("." + base)
        if "/" in rule:
            try:
                return ip_address(hostname) in ip_network(rule, strict=False)
            except ValueError:
                return False
        return hostname == rule

    @staticmethod
    def _path_excluded(path: str, pattern: str) -> bool:
        """Match configured exclusions against nested application paths.

        A rule such as ``/logout*`` must exclude both ``/logout.php`` and
        ``/DVWA/logout.php``; otherwise an application mounted below a path
        prefix can still invalidate an authenticated session during crawling.
        """
        if fnmatch(path, pattern) or pattern in path:
            return True
        if pattern.startswith("/"):
            return fnmatch(path, f"*{pattern}")
        return False

    def assert_allowed(self, value: str) -> str:
        normalized = normalize_url(value)
        if not self.is_allowed(normalized):
            raise ScopeError(f"URL is outside the configured scope: {value}")
        return normalized
