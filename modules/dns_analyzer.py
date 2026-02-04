import aiodns
from typing import Dict, Any, List


class DNSAnalyzer:
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        self.resolver = aiodns.DNSResolver()

    async def analyze(self, domain: str) -> Dict[str, Any]:
        records = {}
        findings: List[Dict[str, Any]] = []

        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                result = await self.resolver.query(domain, rtype)
                records[rtype] = [str(r) for r in result]
            except Exception:
                records[rtype] = []

        # Simple SPF / DMARC check
        txt = " ".join(records.get("TXT", []))
        if "spf" not in txt.lower():
            findings.append({
                "type": "Missing SPF",
                "severity": "low",
                "title": "SPF record not found",
                "description": "Domain has no SPF policy in TXT records.",
                "location": domain,
                "remediation": "Add an SPF record to reduce spoofing risk."
            })

        return {"records": records, "findings": findings}
