"""Version-aware CVE suggestions from observed service fingerprints.

The matcher deliberately produces suggestions rather than vulnerability
findings. A banner or technology fingerprint can be spoofed, backported, or
incomplete; exact package verification is still required before reporting a
CVE as exploitable.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


VERSION_RE = re.compile(r"(?<!\d)(\d+\.\d+(?:\.\d+)?(?:p\d+)?)(?!\d)", re.IGNORECASE)


class CVESuggestionMatcher:
    """Match observed product versions against a small editable CVE catalog."""

    def __init__(self, catalog_path: Optional[str] = None, cache_dir: Optional[str] = None):
        default_path = Path(__file__).resolve().parent.parent / "data" / "cve_catalog.json"
        self.catalog_path = Path(catalog_path) if catalog_path else default_path
        self.cache_dir = Path(cache_dir or os.getenv("SP1D3R_CVE_CACHE", "reports/.cve-cache"))
        self.catalog = self._load_catalog()
        self.lookup_errors: List[str] = []

    def enrich(
        self,
        technologies: Iterable[Dict[str, Any]] = (),
        ports: Iterable[Dict[str, Any]] = (),
        sources: Iterable[str] = ("local", "nvd"),
    ) -> List[Dict[str, Any]]:
        """Return local and optional online CVE suggestions.

        Online matches are deliberately marked as suggestions. A remotely
        observed version is not proof of the installed package or of
        exploitability, especially behind a reverse proxy or vendor backport.
        """
        self.lookup_errors = []
        observations = self._technology_observations(technologies)
        observations.extend(self._port_observations(ports))
        source_set = {str(source).lower() for source in sources}
        results = self.match(technologies, ports) if "local" in source_set else []
        seen = {(item.get("cve"), item.get("detected_product"), item.get("detected_version")) for item in results}
        if "nvd" in source_set:
            for observation in observations:
                for item in self._query_nvd(observation):
                    key = (item.get("cve"), item.get("detected_product"), item.get("detected_version"))
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append(item)
        return sorted(results, key=lambda item: (self._severity_rank(item.get("severity")), item.get("cve", "")), reverse=True)

    def _query_nvd(self, observation: Dict[str, Any]) -> List[Dict[str, Any]]:
        cpe = self._cpe_for(observation["product"], observation["version"])
        if not cpe:
            return []
        try:
            payload = self._get_json("https://services.nvd.nist.gov/rest/json/cves/2.0", {"cpeName": cpe}, "nvd")
        except (OSError, ValueError) as exc:
            self.lookup_errors.append(f"{observation['product']} {observation['version']}: {exc}")
            return []
        suggestions = []
        for wrapper in payload.get("vulnerabilities", []) if isinstance(payload, dict) else []:
            cve_data = wrapper.get("cve", {}) if isinstance(wrapper, dict) else {}
            cve_id = cve_data.get("id")
            if not cve_id:
                continue
            description = next((str(item.get("value", "")) for item in cve_data.get("descriptions", []) if item.get("lang") == "en"), "NVD CVE record matched the observed CPE.")
            severity, cvss = self._cvss(cve_data)
            references = [str(item.get("url")) for item in cve_data.get("references", []) if item.get("url")][:5]
            suggestions.append({
                "cve": cve_id, "title": f"Possible {cve_id} exposure in {observation['product']}",
                "product": observation["product"], "detected_product": observation["product"],
                "detected_version": observation["version"], "severity": severity, "cvss": cvss,
                "state": "suggested", "confidence": "medium", "summary": description,
                "reference": references[0] if references else f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "references": references, "affected_range": f"CPE matched {cpe}",
                "sources": [observation["source"], "NVD"], "ports": [observation["port"]] if observation.get("port") else [],
                "evidence": [observation["evidence"], f"CPE query: {cpe}"],
                "recommendation": "Confirm the exact package build and vendor backports, then follow the vendor advisory before remediation decisions.",
            })
        return suggestions

    def _get_json(self, base_url: str, params: Dict[str, str], source: str) -> Dict[str, Any]:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        key = hashlib.sha256((base_url + "?" + urlencode(params)).encode()).hexdigest()
        cache_path = self.cache_dir / f"{source}_{key}.json"
        if cache_path.exists() and time.time() - cache_path.stat().st_mtime < 86400:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        headers = {"User-Agent": "SP1D3R-CVE-Enrichment/1.0", "Accept": "application/json"}
        if os.getenv("NVD_API_KEY") and source == "nvd":
            headers["apiKey"] = os.environ["NVD_API_KEY"]
        request = Request(base_url + "?" + urlencode(params), headers=headers)
        try:
            with urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            if exc.code == 429:
                raise OSError("NVD rate limit reached; set NVD_API_KEY or retry later") from exc
            raise OSError(f"NVD returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError) as exc:
            raise OSError(f"NVD request failed: {exc}") from exc
        cache_path.write_text(json.dumps(payload), encoding="utf-8")
        return payload

    @staticmethod
    def _cpe_for(product: str, version: str) -> str:
        mapping = {
            "apache": "apache:http_server", "nginx": "nginx:nginx", "openssh": "openbsd:openssh",
            "vsftpd": "vsftpd:vsftpd", "apache tomcat": "apache:tomcat", "wordpress": "wordpress:wordpress",
        }
        pair = mapping.get(product)
        if not pair or not version:
            return ""
        vendor, name = pair.split(":", 1)
        return f"cpe:2.3:a:{vendor}:{name}:{version}:*:*:*:*:*:*:*"

    @staticmethod
    def _cvss(cve_data: Dict[str, Any]) -> Tuple[str, str]:
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                metric = entries[0].get("cvssData", {})
                return str(metric.get("baseSeverity", "info")).lower(), str(metric.get("baseScore", ""))
        return "info", ""

    @staticmethod
    def _severity_rank(value: Any) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(str(value).lower(), 0)

    def _load_catalog(self) -> List[Dict[str, Any]]:
        try:
            return json.loads(self.catalog_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []

    def match(self, technologies: Iterable[Dict[str, Any]] = (), ports: Iterable[Dict[str, Any]] = ()) -> List[Dict[str, Any]]:
        observations = self._technology_observations(technologies)
        observations.extend(self._port_observations(ports))
        suggestions: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

        for observation in observations:
            for entry in self.catalog:
                if not self._product_matches(observation["product"], entry):
                    continue
                affected_range = self._matching_range(observation["version"], entry.get("affected", []))
                if not affected_range:
                    continue
                key = (str(entry.get("cve", "")), observation["product"], observation["version"])
                suggestion = suggestions.setdefault(key, {
                    "cve": entry.get("cve", ""),
                    "title": f"Possible {entry.get('cve', '')} exposure in {entry.get('product', observation['product'])}",
                    "product": entry.get("product", observation["product"]),
                    "detected_product": observation["product"],
                    "detected_version": observation["version"],
                    "severity": entry.get("severity", "info"),
                    "cvss": entry.get("cvss", ""),
                    "state": "suggested",
                    "confidence": "medium",
                    "summary": entry.get("summary", "Version matched a catalog entry."),
                    "reference": entry.get("reference", ""),
                    "affected_range": affected_range,
                    "sources": [],
                    "ports": [],
                    "evidence": [],
                    "recommendation": "Confirm the exact package build and vendor backports, then validate against the vendor advisory before remediation or exploitation decisions.",
                })
                source = observation["source"]
                if source not in suggestion["sources"]:
                    suggestion["sources"].append(source)
                port = observation.get("port")
                if port is not None and port not in suggestion["ports"]:
                    suggestion["ports"].append(port)
                evidence = observation["evidence"]
                if evidence not in suggestion["evidence"]:
                    suggestion["evidence"].append(evidence)

        return sorted(
            suggestions.values(),
            key=lambda item: ({"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(str(item["severity"]).lower(), 0), item["cve"]),
            reverse=True,
        )

    def _technology_observations(self, technologies: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        observations = []
        for technology in technologies or []:
            if not isinstance(technology, dict):
                continue
            name = str(technology.get("name", "")).strip()
            version = self._extract_version(str(technology.get("version", "")) or name)
            if not name or not version:
                continue
            product = self._canonical_product(f"{name} {technology.get('category', '')}")
            if not product:
                continue
            source = str(technology.get("source", "technology fingerprint"))
            observations.append({
                "product": product,
                "version": version,
                "source": source,
                "evidence": f"{name} {version} observed by {source}",
            })
        return observations

    def _port_observations(self, ports: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        observations = []
        for port in ports or []:
            if not isinstance(port, dict):
                continue
            banner = str(port.get("banner", "")).strip()
            service = str(port.get("service", "")).strip()
            combined = f"{service} {banner}"
            product = self._canonical_product(combined)
            version = self._extract_version(combined, product)
            if not product or not version:
                continue
            port_number = port.get("port")
            source = f"open port {port_number}/{port.get('protocol', 'tcp')} banner" if port_number else "open port banner"
            observations.append({
                "product": product,
                "version": version,
                "source": source,
                "port": port_number,
                "evidence": f"{service or product} {version} observed on {source}: {banner or service}",
            })
        return observations

    @staticmethod
    def _extract_version(value: str, product: str = "") -> str:
        product_patterns = {
            "openssh": r"openssh[_/ -]?(\d+\.\d+(?:p\d+)?)",
            "nginx": r"nginx[/ -]?(\d+\.\d+(?:\.\d+)?)",
            "apache": r"apache(?: httpd| http server)?[/ -]?(\d+\.\d+(?:\.\d+)?)",
            "vsftpd": r"vsftpd[_/ -]?(\d+\.\d+(?:\.\d+)?)",
            "apache tomcat": r"(?:apache )?tomcat[/ -]?(\d+\.\d+(?:\.\d+)?)",
            "wordpress": r"wordpress[/ -]?(\d+\.\d+(?:\.\d+)?)",
        }
        pattern = product_patterns.get(product)
        match = re.search(pattern, value or "", re.IGNORECASE) if pattern else VERSION_RE.search(value or "")
        return match.group(1) if match else ""

    @staticmethod
    def _version_tuple(value: str) -> Tuple[int, int, int]:
        numbers = [int(item) for item in re.findall(r"\d+", value or "")[:3]]
        return tuple((numbers + [0, 0, 0])[:3])  # type: ignore[return-value]

    @classmethod
    def _canonical_product(cls, value: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
        aliases = (
            ("apache tomcat", "apache tomcat"),
            ("tomcat", "apache tomcat"),
            ("apache http server", "apache"),
            ("apache httpd", "apache"),
            ("httpd", "apache"),
            ("apache", "apache"),
            ("openssh", "openssh"),
            ("ssh", "openssh"),
            ("vsftpd", "vsftpd"),
            ("nginx", "nginx"),
            ("wordpress", "wordpress"),
            ("wp", "wordpress"),
        )
        for alias, product in aliases:
            if alias in normalized:
                return product
        return ""

    @classmethod
    def _product_matches(cls, product: str, entry: Dict[str, Any]) -> bool:
        entry_values = [entry.get("product", ""), *(entry.get("aliases", []) or [])]
        return any(cls._canonical_product(str(value)) == product for value in entry_values)

    @classmethod
    def _matching_range(cls, version: str, ranges: Iterable[Dict[str, Any]]) -> str:
        observed = cls._version_tuple(version)
        for item in ranges or []:
            if not isinstance(item, dict):
                continue
            if item.get("exact") and observed == cls._version_tuple(str(item["exact"])):
                return f"exactly {item['exact']}"
            minimum = cls._version_tuple(str(item["min"])) if item.get("min") else None
            maximum = cls._version_tuple(str(item["max"])) if item.get("max") else None
            if minimum is not None and observed < minimum:
                continue
            if maximum is not None and observed > maximum:
                continue
            if minimum is not None or maximum is not None:
                return f"{item.get('min', 'any')}–{item.get('max', 'any')}"
        return ""
