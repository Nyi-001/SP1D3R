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
        results: List[Dict[str, Any]],
        output_file: str,
        format: str = 'html'
    ) -> str:
        """
        Generate report from scan results
        
        results: List of scan results, each containing:
          {
            "scan_info": {...},
            "target": {...},
            "findings": [...],
            "stats": {...}
          }
        """
        self.logger.info(f"Generating {format} report...")
        
        output_path = Path(output_file)
        
        if format == 'json':
            self._write_json_report(output_path, results)
        elif format == 'html':
            self._write_html_report(output_path, results)
        elif format == 'pdf':
            self.logger.warning("PDF reporting not yet implemented. Skipping.")
        else:
            self.logger.error(f"Unsupported format: {format}")
            return None
        
        return str(output_path)

    def _write_json_report(self, path: Path, results: List[Dict[str, Any]]) -> None:
        """Write JSON report"""
        report = {
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'scans': results
        }
        path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    
    def _write_html_report(self, path: Path, results: List[Dict[str, Any]]) -> None:
        """Write HTML report"""
        all_findings = []
        total_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        # Aggregate findings and stats
        for result in results:
            all_findings.extend(result.get('findings', []))
            stats = result.get('stats', {})
            for severity in total_stats:
                total_stats[severity] += stats.get(severity, 0)
        
        # Filter by severity threshold
        threshold_value = self._severity_order.get(self.severity_threshold, 1)
        filtered_findings = [
            f for f in all_findings
            if self._severity_order.get(f.get('severity', 'low').lower(), 1) >= threshold_value
        ]
        
        html = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='utf-8'>",
            "<title>Automated Pentest Report</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }",
            ".container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }",
            "h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }",
            "h2 { color: #555; margin-top: 30px; border-bottom: 2px solid #ddd; padding-bottom: 5px; }",
            ".stats { display: flex; gap: 20px; margin: 20px 0; }",
            ".stat-box { flex: 1; padding: 15px; border-radius: 5px; text-align: center; }",
            ".stat-critical { background: #ffebee; color: #c62828; }",
            ".stat-high { background: #fff3e0; color: #ef6c00; }",
            ".stat-medium { background: #fff9c4; color: #f57f17; }",
            ".stat-low { background: #e8f5e9; color: #2e7d32; }",
            ".stat-box h3 { margin: 0; font-size: 32px; }",
            ".stat-box p { margin: 5px 0 0 0; font-size: 14px; }",
            "table { border-collapse: collapse; width: 100%; margin-top: 20px; }",
            "th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }",
            "th { background: #f2f2f2; font-weight: bold; }",
            "tr:hover { background: #f9f9f9; }",
            ".severity-critical { color: #c62828; font-weight: bold; }",
            ".severity-high { color: #ef6c00; font-weight: bold; }",
            ".severity-medium { color: #f57f17; }",
            ".severity-low { color: #666; }",
            ".footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #999; font-size: 12px; }",
            "</style>",
            "</head>",
            "<body>",
            "<div class='container'>",
            "<h1>🔒 Automated Penetration Testing Report</h1>",
            f"<p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>",
            f"<p><strong>Total Scans:</strong> {len(results)}</p>",
            
            "<h2>Executive Summary</h2>",
            "<div class='stats'>",
            f"<div class='stat-box stat-critical'><h3>{total_stats['critical']}</h3><p>Critical</p></div>",
            f"<div class='stat-box stat-high'><h3>{total_stats['high']}</h3><p>High</p></div>",
            f"<div class='stat-box stat-medium'><h3>{total_stats['medium']}</h3><p>Medium</p></div>",
            f"<div class='stat-box stat-low'><h3>{total_stats['low']}</h3><p>Low</p></div>",
            "</div>",
            
            f"<p><strong>Total Findings:</strong> {len(filtered_findings)}</p>",
        ]
        
        # Add scan details
        html.append("<h2>Scan Details</h2>")
        for i, result in enumerate(results, 1):
            scan_info = result.get('scan_info', {})
            target_info = result.get('target', {})
            html.append(f"<h3>Scan #{i}: {scan_info.get('target', 'Unknown')}</h3>")
            html.append(f"<p><strong>Type:</strong> {scan_info.get('scan_type', 'N/A')}</p>")
            html.append(f"<p><strong>Duration:</strong> {scan_info.get('duration', 'N/A')}</p>")
            
            # Technologies detected
            techs = target_info.get('technologies', [])
            if techs:
                html.append("<p><strong>Technologies Detected:</strong></p>")
                html.append("<ul>")
                for tech in techs[:10]:  # Show first 10
                    html.append(f"<li>{tech.get('name', 'Unknown')} ({tech.get('category', 'N/A')})</li>")
                html.append("</ul>")
        
        # Findings table
        if filtered_findings:
            html.append("<h2>Detailed Findings</h2>")
            html.append("<table>")
            html.append("<tr><th>Severity</th><th>Type</th><th>Title</th><th>Location</th><th>Description</th><th>Remediation</th></tr>")
            
            # Sort by severity
            severity_order_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
            sorted_findings = sorted(
                filtered_findings,
                key=lambda f: severity_order_map.get(f.get('severity', 'low').lower(), 0),
                reverse=True
            )
            
            for finding in sorted_findings:
                sev = finding.get('severity', 'low').lower()
                css_class = f"severity-{sev}"
                html.append(
                    "<tr>"
                    f"<td class='{css_class}'>{sev.upper()}</td>"
                    f"<td>{finding.get('type', 'N/A')}</td>"
                    f"<td>{finding.get('title', 'N/A')}</td>"
                    f"<td>{finding.get('location', 'N/A')}</td>"
                    f"<td>{finding.get('description', 'N/A')}</td>"
                    f"<td>{finding.get('remediation', 'N/A')}</td>"
                    "</tr>"
                )
            html.append("</table>")
        else:
            html.append("<p><em>No findings at or above the configured severity threshold.</em></p>")
        
        html.append("<div class='footer'>")
        html.append("<p>Generated by Automated Penetration Testing Tool</p>")
        html.append("<p>Author: Pangerkumzuk Longkumer | NEXUSCIPHERGUARD INDIA</p>")
        html.append("</div>")
        html.append("</div>")
        html.append("</body></html>")
        
        path.write_text("\n".join(html), encoding='utf-8')
