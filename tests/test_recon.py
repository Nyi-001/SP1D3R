from core.subdomain_enum import SubdomainEnumerator
from modules.fingerprint import TechFingerprint


class DummyLogger:
    def info(self, *_args, **_kwargs):
        pass

    def warning(self, *_args, **_kwargs):
        pass

    def debug(self, *_args, **_kwargs):
        pass


def test_assetfinder_candidate_is_restricted_to_root_domain() -> None:
    assert SubdomainEnumerator._is_candidate("api.example.test", "example.test")
    assert not SubdomainEnumerator._is_candidate("example.test.evil.test", "example.test")
    assert not SubdomainEnumerator._is_candidate("example.test", "example.test")


def test_fingerprint_preserves_unknown_server_header() -> None:
    fingerprint = TechFingerprint({"scanning": {"timeout": 1}}, DummyLogger())
    results = fingerprint._check_headers({"Server": "LabServer/1.2"})
    assert results[0]["name"] == "LabServer/1.2"
    assert results[0]["category"] == "Web Server"
