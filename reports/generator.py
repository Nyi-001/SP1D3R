# reports/generator.py
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional


class ReportGenerator:
    def __init__(self, config: Dict, logger):
        self.config = config or {}
        self.logger = logger
        reporting_cfg = self.config.get("reporting", {})

        self.formats: List[str] = reporting_cfg.get("formats", ["html", "json"])
        self.severity_threshold = reporting_cfg.get("severity_threshold", "low")
        self.output_dir = Path(reporting_cfg.get("output_dir", "reports"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def generate(
        self,
        target: str,
        scan_type: str,
        results: Dict[str, Any],
        output_basename: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        results: {
          "modules": {
             "port": {"findings": [...]},
             "ssl": {"findings": [...]},
             ...
          },
          "meta": {...}
        }
        """
        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        base = output_basename or f"{target}_{scan_type}_{ts}"

        outputs: Dict[str, str] = {}

        if "json" in self.formats:
            path = self.output_dir / f"{base}.json"
            self._write_json(path, target, scan_type, results)
            outputs["json"] = str(path)

        if "html" in self.formats:
            path = self.output_dir / f"{base}.html"
            self._write_html(path, target, scan_type, results)
            outputs["html"] = str(path)

        # PDF could later be generated from HTML via wkhtmltopdf or similar
        if "pdf" in self.formats:
            if self.logger:
                self.logger.warning("PDF reporting not yet implemented. Skipping.")
            # placeholder for future implementation

        return outputs

    def _filter_by_severity(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        threshold_value = self._severity_order.get(self.severity_threshold, 1)
        filtered = []
        for f in findings:
            sev = f.get("severity", "low").lower()
            if self._severity_order.get(sev, 1) >= threshold_value:
                filtered.append(f)
        return filtered

    def _collect_all_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        all_findings: List[Dict[str, Any]] = []
        modules = results.get("modules", {})
        for module_name, data in modules.items():
            for f in data.get("findings", []):
                f = dict(f)
                f.setdefault("module", module_name)
                all_findings.append(f)
        return all_findings

    def _write_json(
        self,
        path: Path,
        target: str,
        scan_type: str,
        results: Dict[str, Any],
    ) -> None:
        all_findings = self._filter_by_severity(self._collect_all_findings(results))
        report = {
            "target": target,
            "scan_type": scan_type,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "findings": all_findings,
            "meta": results.get("meta", {}),
        }
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    def _write_html(
        self,
        path: Path,
        target: str,
        scan_type: str,
        results: Dict[str, Any],
    ) -> None:
        all_findings = self._filter_by_severity(self._collect_all_findings(results))

        summary_counts = {}
        for f in all_findings:
            sev = f.get("severity", "low").lower()
            summary_counts[sev] = summary_counts.get(sev, 0) + 1

        html = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='utf-8'>",
            f"<title>Pentest Report - {target}</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; }",
            ".severity-high { color: red; }",
            ".severity-medium { color: orange; }",
            ".severity-low { color: #999; }",
            "table { border-collapse: collapse; width: 100%; }",
            "th, td { border: 1px solid #ddd; padding: 8px; }",
            "th { background: #f2f2f2; }",
            "</style>",
            "</head>",
            "<body>",
            f"<h1>Pentest Report for {target}</h1>",
            f"<p><strong>Scan type:</strong> {scan_type}</p>",
            f"<p><strong>Generated at:</strong> {datetime.utcnow().isoformat()}Z</p>",
            "<h2>Severity Summary</h2>",
            "<ul>",
        ]
        for sev, count in summary_counts.items():
            html.append(f"<li><strong>{sev.title()}:</strong> {count}</li>")
        html.append("</ul>")

        html.append("<h2>Findings</h2>")
        html.append("<table>")
        html.append("<tr><th>Severity</th><th>Module</th><th>Type</th><th>Title</th><th>Location</th><th>Description</th><th>Remediation</th></tr>")
        for f in all_findings:
            sev = f.get("severity", "low").lower()
            css_class = f"severity-{sev}"
            html.append(
                "<tr>"
                f"<td class='{css_class}'>{sev.title()}</td>"
                f"<td>{f.get('module', '')}</td>"
                f"<td>{f.get('type', '')}</td>"
                f"<td>{f.get('title', '')}</td>"
                f"<td>{f.get('location', '')}</td>"
                f"<td>{f.get('description', '')}</td>"
                f"<td>{f.get('remediation', '')}</td>"
                "</tr>"
            )
        html.append("</table>")
        html.append("</body></html>")

        path.write_text("\n".join(html), encoding="utf-8")
