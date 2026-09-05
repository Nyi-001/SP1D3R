"""Normalize findings from custom modules and external scanners."""

import hashlib
import json
from typing import Any, Dict


SEVERITIES = {"info", "low", "medium", "high", "critical"}


def normalize_finding(finding: Dict[str, Any], tool: str = "custom-scanner") -> Dict[str, Any]:
    """Return a stable, report-friendly finding without discarding source data."""
    result = dict(finding)
    title = str(result.get("title") or result.get("name") or result.get("type") or "Unnamed finding")
    location = str(result.get("location") or result.get("url") or result.get("matched-at") or "")
    severity = str(result.get("severity", "info")).lower()
    if severity not in SEVERITIES:
        severity = "info"
    evidence = result.get("evidence") or result.get("payload") or result.get("description") or ""
    result.update({
        "title": title,
        "location": location,
        "severity": severity,
        "confidence": str(result.get("confidence", "medium")).lower(),
        "state": str(result.get("state", "suspected")).lower(),
        "tool": str(result.get("tool", tool)),
        "evidence": str(evidence),
    })
    # Identity must describe the issue location, not the prose title. Tool
    # adapters often phrase the same issue differently (for example
    # "reflected XSS" versus "potential XSS"), which otherwise creates
    # duplicate report entries. Keep method and parameter so two distinct
    # inputs on one endpoint remain separate findings.
    fingerprint = json.dumps({
        "type": str(result.get("type") or title).strip().lower(),
        "location": location.rstrip('/'),
        "method": str(result.get("method", "")).upper(),
        "parameter": str(result.get("parameter", "")).strip().lower(),
    }, sort_keys=True)
    result["finding_id"] = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:20]
    return result
