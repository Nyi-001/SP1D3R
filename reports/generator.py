# reports/generator.py
import json
from html import escape
from datetime import datetime, timezone
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

    @staticmethod
    def _status_class(value: Any) -> str:
        try:
            status = int(str(value).strip())
        except (TypeError, ValueError):
            return "status-other"
        if 200 <= status < 300:
            return "status-2xx"
        if 300 <= status < 400:
            return "status-3xx"
        if 400 <= status < 500:
            return "status-4xx"
        if 500 <= status < 600:
            return "status-5xx"
        return "status-other"

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
        if not output_path.is_absolute() and output_path.parent == Path('.'):
            output_path = self.output_dir / output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == 'json':
            self._write_json_report(output_path, results)
        elif format == 'html':
            self._write_html_report(output_path, results)
        elif format == 'pdf':
            self._write_pdf_report(output_path, results)
        else:
            self.logger.error(f"Unsupported format: {format}")
            return None
        
        return str(output_path)

    def _write_json_report(self, path: Path, results: List[Dict[str, Any]]) -> None:
        """Write JSON report"""
        report = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'scans': results
        }
        path.write_text(json.dumps(report, indent=2), encoding='utf-8')

    def _write_pdf_report(self, path: Path, results: List[Dict[str, Any]]) -> None:
        """Write a reader-friendly security assessment PDF."""
        try:
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import (
                KeepTogether,
                PageBreak,
                Paragraph,
                Preformatted,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
        except ImportError as exc:
            raise RuntimeError("PDF reports require the 'reportlab' package; install requirements.txt") from exc

        # Bug-report theme: a quiet paper background, dark ink, and one blue
        # editorial accent. Red/orange/yellow are reserved for severity.
        navy = colors.HexColor('#102A43')
        ink = colors.HexColor('#243B53')
        muted = colors.HexColor('#627D98')
        line = colors.HexColor('#D9E2EC')
        panel = colors.HexColor('#F0F4F8')
        red = colors.HexColor('#B42318')
        orange = colors.HexColor('#B54708')
        yellow = colors.HexColor('#A15C00')
        green = colors.HexColor('#147A52')
        blue = colors.HexColor('#007C91')

        all_findings = [finding for result in results for finding in result.get('findings', [])]
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        threshold = self._severity_order.get(self.severity_threshold, 1)
        findings = [
            finding for finding in all_findings
            if severity_order.get(str(finding.get('severity', 'info')).lower(), 0) >= threshold
        ]
        findings.sort(key=lambda item: severity_order.get(str(item.get('severity', 'info')).lower(), 0), reverse=True)
        stats = {
            severity: sum(1 for finding in all_findings if str(finding.get('severity', 'info')).lower() == severity)
            for severity in ('critical', 'high', 'medium', 'low', 'info')
        }
        coverage = [result.get('coverage', {}) for result in results]
        coverage_totals = {
            'pages': sum(int(item.get('discovered_pages', 0)) for item in coverage),
            'forms': sum(int(item.get('discovered_forms', 0)) for item in coverage),
            'endpoints': sum(int(item.get('discovered_endpoints', 0)) for item in coverage),
            'requests': sum(int(item.get('tested_requests', 0)) for item in coverage),
        }
        targets = [str(result.get('scan_info', {}).get('target', 'Unknown')) for result in results]
        target_label = targets[0] if len(targets) == 1 else f'{len(targets)} targets'
        scope_rules = self.config.get('scope', {}).get('allowed_hosts', [])
        excluded_paths = self.config.get('scope', {}).get('excluded_paths', [])
        highest = findings[0] if findings else None
        highest_severity = str(highest.get('severity', 'info')).lower() if highest else 'info'
        severity_colors = {
            'critical': (colors.HexColor('#FEE4E2'), red),
            'high': (colors.HexColor('#FFEAD5'), orange),
            'medium': (colors.HexColor('#FFF4CC'), yellow),
            'low': (colors.HexColor('#DCFAE6'), green),
            'info': (colors.HexColor('#E0EFFF'), blue),
        }

        stylesheet = getSampleStyleSheet()
        styles = {
            'cover_title': ParagraphStyle('PdfCoverTitle', parent=stylesheet['Title'], fontName='Helvetica-Bold', fontSize=26, leading=31, textColor=colors.white, alignment=TA_LEFT, spaceAfter=8),
            'cover_subtitle': ParagraphStyle('PdfCoverSubtitle', parent=stylesheet['Normal'], fontName='Helvetica', fontSize=11, leading=15, textColor=colors.HexColor('#D9E2EC'), spaceAfter=5),
            'h1': ParagraphStyle('PdfH1', parent=stylesheet['Heading1'], fontName='Helvetica-Bold', fontSize=17, leading=21, textColor=navy, spaceBefore=8, spaceAfter=9),
            'h2': ParagraphStyle('PdfH2', parent=stylesheet['Heading2'], fontName='Helvetica-Bold', fontSize=12.5, leading=16, textColor=navy, spaceBefore=11, spaceAfter=6),
            'body': ParagraphStyle('PdfBody', parent=stylesheet['BodyText'], fontName='Helvetica', fontSize=9, leading=12.5, textColor=ink, spaceAfter=6),
            'small': ParagraphStyle('PdfSmall', parent=stylesheet['BodyText'], fontName='Helvetica', fontSize=8, leading=10.5, textColor=muted, spaceAfter=3),
            'label': ParagraphStyle('PdfLabel', parent=stylesheet['BodyText'], fontName='Helvetica-Bold', fontSize=7.8, leading=9.5, textColor=muted, spaceAfter=2),
            'table_header': ParagraphStyle('PdfTableHeader', parent=stylesheet['BodyText'], fontName='Helvetica-Bold', fontSize=7.8, leading=9.5, textColor=navy),
            'table_cell': ParagraphStyle('PdfTableCell', parent=stylesheet['BodyText'], fontName='Helvetica', fontSize=8, leading=10.5, textColor=ink),
            'table_mono': ParagraphStyle('PdfTableMono', parent=stylesheet['BodyText'], fontName='Courier', fontSize=7.2, leading=8.5, textColor=ink, wordWrap='CJK'),
            'finding_title': ParagraphStyle('PdfFindingTitle', parent=stylesheet['Heading2'], fontName='Helvetica-Bold', fontSize=12, leading=15, textColor=navy, spaceBefore=8, spaceAfter=5),
            'evidence': ParagraphStyle('PdfEvidence', parent=stylesheet['Code'], fontName='Courier', fontSize=7.2, leading=9, textColor=ink, backColor=colors.HexColor('#F1F5F9'), borderPadding=5, leftIndent=0, rightIndent=0, spaceAfter=0),
            'center': ParagraphStyle('PdfCenter', parent=stylesheet['BodyText'], fontName='Helvetica-Bold', fontSize=11, leading=13, alignment=TA_CENTER, textColor=ink),
            'closing': ParagraphStyle('PdfClosing', parent=stylesheet['BodyText'], fontName='Helvetica-Bold', fontSize=12, leading=15, alignment=TA_CENTER, textColor=red, spaceBefore=9, spaceAfter=9),
        }

        def text(value: Any, style: str = 'body') -> Paragraph:
            value = '—' if value in (None, '') else str(value)
            return Paragraph(escape(value).replace('\n', '<br/>'), styles[style])

        def rich(value: Any, style: str = 'body') -> Paragraph:
            rendered = json.dumps(value, indent=2, default=str) if isinstance(value, (dict, list)) else str(value)
            return text(rendered, style)

        def table(rows: List[List[Any]], widths: Optional[List[float]] = None, header: bool = True) -> Table:
            converted = []
            for row_index, row in enumerate(rows):
                converted.append([
                    cell if hasattr(cell, 'wrap') else text(cell, 'table_header' if header and row_index == 0 else 'table_cell')
                    for cell in row
                ])
            table_obj = Table(converted, colWidths=widths, repeatRows=1 if header else 0, hAlign='LEFT')
            commands = [
                ('GRID', (0, 0), (-1, -1), 0.35, line),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]
            if header:
                commands.extend([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#EAF0F7')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), navy),
                ])
                if len(converted) > 1:
                    commands.append(('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, panel]))
            table_obj.setStyle(TableStyle(commands))
            return table_obj

        def status_cell(value: Any) -> Paragraph:
            status = '—' if value in (None, '') else str(value)
            status_class = self._status_class(value)
            palette = {
                'status-2xx': (colors.HexColor('#DCFAE6'), green),
                'status-3xx': (colors.HexColor('#E0EFFF'), blue),
                'status-4xx': (colors.HexColor('#FFF4CC'), yellow),
                'status-5xx': (colors.HexColor('#FEE4E2'), red),
                'status-other': (colors.HexColor('#EEF2F6'), muted),
            }
            background, foreground = palette[status_class]
            return Paragraph(escape(status), ParagraphStyle(f'Http{status_class}', parent=styles['table_cell'], fontName='Helvetica-Bold', textColor=foreground, backColor=background, alignment=TA_CENTER, borderPadding=3))

        def severity_cell(value: Any) -> Paragraph:
            severity = str(value or 'info').lower()
            background, foreground = severity_colors.get(severity, severity_colors['info'])
            return Paragraph(escape(severity.upper()), ParagraphStyle(f'Severity{severity}', parent=styles['table_cell'], fontName='Helvetica-Bold', textColor=foreground, backColor=background, alignment=TA_CENTER, borderPadding=3))

        def evidence_block(value: Any) -> Table:
            rendered = json.dumps(value, indent=2, default=str) if isinstance(value, (dict, list)) else str(value)
            evidence = Preformatted(rendered[:12000], styles['evidence'])
            box = Table([[evidence]], colWidths=[155 * mm], hAlign='LEFT')
            box.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F2F4F7')),
                ('BOX', (0, 0), (-1, -1), 0.5, line),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 7),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ]))
            return box

        def section(title: str, subtitle: str = '') -> List[Any]:
            items: List[Any] = [Paragraph(escape(title), styles['h1'])]
            if subtitle:
                items.append(text(subtitle, 'small'))
            return items

        story: List[Any] = []
        generated = datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')
        scan_type = str(results[0].get('scan_info', {}).get('scan_type', 'assessment')) if results else 'assessment'
        cover_banner = Table([[[
            Paragraph('SP1D3R // BUG REPORT', ParagraphStyle('CoverEyebrow', parent=styles['cover_subtitle'], fontName='Helvetica-Bold', fontSize=10, textColor=blue, spaceAfter=10)),
            Paragraph('Web Vulnerability Report', styles['cover_title']),
            Paragraph('A clear technical record of the affected endpoint, reproduction evidence, impact, and recommended fix.', styles['cover_subtitle']),
        ]]], colWidths=[155 * mm], hAlign='LEFT')
        cover_banner.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), navy),
            ('BOX', (0, 0), (-1, -1), 0.8, line),
            ('LINEABOVE', (0, 0), (-1, 0), 5, colors.HexColor('#2CB1BC')),
            ('LEFTPADDING', (0, 0), (-1, -1), 16),
            ('RIGHTPADDING', (0, 0), (-1, -1), 16),
            ('TOPPADDING', (0, 0), (-1, -1), 16),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 16),
        ]))

        # Cover page: concise enough for management, but still useful to a tester.
        story.extend([
            Spacer(1, 28 * mm),
            cover_banner,
            Spacer(1, 18 * mm),
            table([
                ['Assessment target', target_label],
                ['Assessment profile', scan_type.title()],
                ['Report date', generated],
                ['Classification', 'CONFIDENTIAL — AUTHORIZED TESTING ONLY'],
            ], widths=[45 * mm, 110 * mm], header=False),
            Spacer(1, 16 * mm),
            Paragraph('Document purpose', styles['h2']),
            text('This report records the assets, coverage, observations, verification results, and remediation priorities produced by the authorized assessment. It is intended for technical review, risk triage, and remediation tracking.'),
            Spacer(1, 8 * mm),
            Paragraph('Reading the report', styles['h2']),
            text('This document is evidence-led. A discovery or recommendation is not treated as a confirmed vulnerability unless the scanner recorded supporting verification evidence.'),
            PageBreak(),
        ])

        # Put the web identity first. Reviewers can now see the actual HTTP
        # server response before they reach risk summaries or attack results.
        story.extend(section('1. Web server and technology profile', 'Verified HTTP identity, platform indicators, and WhatWeb observations'))
        for result_index, result in enumerate(results, 1):
            target_info = result.get('target', {})
            fingerprint = target_info.get('fingerprint', {})
            technologies = target_info.get('technologies', [])
            story.append(Paragraph(f"Scan {result_index}: {escape(str(result.get('scan_info', {}).get('target', 'Unknown')))}", styles['h2']))
            story.append(table([
                ['HTTP status', 'Final URL', 'Server header', 'X-Powered-By', 'Content type'],
                [fingerprint.get('status_code', '—'), fingerprint.get('final_url', result.get('scan_info', {}).get('target', '—')), fingerprint.get('server') or 'Not disclosed', fingerprint.get('powered_by') or 'Not disclosed', fingerprint.get('content_type') or '—'],
            ], widths=[20 * mm, 52 * mm, 28 * mm, 27 * mm, 28 * mm]))
            if fingerprint.get('error'):
                story.append(text(f"Fingerprinting note: {fingerprint['error']}", 'small'))
            if technologies:
                tech_rows = [['Technology / server', 'Category', 'Version', 'Confidence', 'Source']]
                for technology in technologies[:80]:
                    if isinstance(technology, dict):
                        tech_rows.append([technology.get('name', ''), technology.get('category', ''), technology.get('version', ''), technology.get('confidence', ''), technology.get('source', '')])
                    else:
                        tech_rows.append([technology, 'Detected signature', '', '', 'Fingerprint module'])
                story.append(Paragraph('Technology indicators', styles['h2']))
                story.append(table(tech_rows, widths=[40 * mm, 30 * mm, 25 * mm, 28 * mm, 32 * mm]))
            else:
                story.append(text('No named technology was verified. The HTTP fingerprint above records whether the server disclosed an identifying banner.', 'small'))
            external_assets = target_info.get('external_assets', {})
            whatweb_services = [item for item in external_assets.get('services', []) if isinstance(item, dict) and item.get('source') == 'whatweb'] if isinstance(external_assets, dict) else []
            if whatweb_services:
                whatweb_rows = [['Target', 'HTTP status', 'WhatWeb observations']]
                for service in whatweb_services[:20]:
                    plugins = service.get('technologies', {})
                    whatweb_rows.append([service.get('url', ''), status_cell(service.get('status')), ', '.join(map(str, plugins.keys())) if isinstance(plugins, dict) else str(plugins)])
                story.append(Paragraph('WhatWeb observations', styles['h2']))
                story.append(table(whatweb_rows, widths=[70 * mm, 25 * mm, 60 * mm]))

        cve_suggestions = [
            suggestion
            for result in results
            for suggestion in result.get('target', {}).get('cve_suggestions', [])
        ]
        story.append(Paragraph('CVE correlation suggestions', styles['h2']))
        story.append(text('Version matches are shown as suggestions only. Confirm the exact package build, vendor backports, configuration, and advisory status before treating a CVE as applicable.', 'small'))
        if cve_suggestions:
            cve_rows = [['CVE', 'Product / version', 'Severity', 'Confidence', 'Observed source', 'Why it was suggested']]
            for suggestion in cve_suggestions[:80]:
                product_version = f"{suggestion.get('product', 'Unknown')} {suggestion.get('detected_version', '')}".strip()
                source = ', '.join(map(str, suggestion.get('sources', [])))
                ports = ', '.join(str(port) for port in suggestion.get('ports', []))
                if ports:
                    source = f"{source} (port {ports})"
                cve_rows.append([
                    suggestion.get('cve', '—'),
                    product_version,
                    severity_cell(suggestion.get('severity', 'info')),
                    suggestion.get('confidence', 'medium').upper(),
                    source or 'Version fingerprint',
                    f"{suggestion.get('summary', '')} Match: {suggestion.get('affected_range', 'catalog range')}.",
                ])
            story.append(table(cve_rows, widths=[24 * mm, 35 * mm, 18 * mm, 21 * mm, 35 * mm, 42 * mm]))
        else:
            story.append(text('No local catalog match was found for a versioned technology or service banner. Unversioned services cannot be correlated reliably.', 'small'))

        summary_text = (
            f'The assessment covered {target_label} and recorded {len(all_findings)} finding(s). '
            f'The highest recorded severity is {highest_severity.upper()}. '
            'Priorities should be confirmed by the application owner and retested after remediation.'
            if all_findings else
            f'The assessment covered {target_label}. No findings were recorded by the checks that completed. '
            'This is not a guarantee that the application is free of vulnerabilities; review coverage and skipped checks before closure.'
        )
        story.extend(section('2. Executive summary', 'Management view of the assessment result'))
        story.append(text(summary_text))
        risk_label = 'No recorded finding' if not all_findings else f'{highest_severity.upper()} priority requires review'
        risk_color = {'critical': red, 'high': orange, 'medium': yellow, 'low': green, 'info': blue}.get(highest_severity, muted)
        risk_table = Table([[Paragraph(escape(risk_label), ParagraphStyle('RiskLabel', parent=styles['center'], textColor=risk_color)), text('Review the highest-priority evidence first, assign an owner, and track remediation through retesting.', 'small')]], colWidths=[55 * mm, 100 * mm])
        risk_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), panel), ('BOX', (0, 0), (-1, -1), 0.8, line), ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), ('LEFTPADDING', (0, 0), (-1, -1), 10), ('RIGHTPADDING', (0, 0), (-1, -1), 10), ('TOPPADDING', (0, 0), (-1, -1), 10), ('BOTTOMPADDING', (0, 0), (-1, -1), 10)]))
        story.append(risk_table)
        story.append(Spacer(1, 8 * mm))
        story.append(Paragraph('Severity distribution', styles['h2']))
        story.append(table([
            ['Critical', 'High', 'Medium', 'Low', 'Informational', 'Total'],
            [str(stats['critical']), str(stats['high']), str(stats['medium']), str(stats['low']), str(stats['info']), str(len(all_findings))],
        ], widths=[25 * mm] * 6))

        story.extend(section('3. Scope and methodology', 'Authorization, boundaries, and assessment controls'))
        scope_rows = [
            ['Target(s)', ', '.join(targets) or 'Unknown'],
            ['Allowed scope', ', '.join(map(str, scope_rules)) if scope_rules else 'Explicit target host'],
            ['Excluded paths', ', '.join(map(str, excluded_paths)) if excluded_paths else 'None recorded'],
            ['Active verification', 'Enabled' if self.config.get('scope', {}).get('active_checks') else 'Disabled'],
            ['Request limit', self.config.get('scanning', {}).get('max_requests', 'Configured limit')],
            ['Tool timeout', self.config.get('scanning', {}).get('tool_timeout', 'Configured limit')],
            ['TLS certificate verification', 'Disabled by explicit --insecure override' if self.config.get('scanning', {}).get('insecure_tls') else 'Enabled'],
            ['Severity threshold', self.severity_threshold],
        ]
        request_files = [
            str(result.get('scan_info', {}).get('request_file', ''))
            for result in results
            if result.get('scan_info', {}).get('request_file')
        ]
        if request_files:
            scope_rows.insert(4, ['Burp request seed', ', '.join(request_files)])
        story.append(table([['Control', 'Recorded value'], *scope_rows], widths=[45 * mm, 110 * mm]))
        story.append(text('Methods included the project’s scoped reconnaissance, crawl and attack-surface mapping, safe active checks where enabled, external tool normalization, and evidence-backed report generation. Active testing must only be performed with explicit authorization.', 'small'))

        story.extend(section('4. Coverage and attack surface', 'What the scanner reached and what requires technical review'))
        story.append(table([
            ['Pages', 'Forms', 'Endpoints', 'Requests tested'],
            [str(coverage_totals['pages']), str(coverage_totals['forms']), str(coverage_totals['endpoints']), str(coverage_totals['requests'])],
        ], widths=[38.75 * mm] * 4))
        for result_index, result in enumerate(results, 1):
            result_coverage = result.get('coverage', {})
            request_seed = result_coverage.get('request_seed', {})
            if result_coverage.get('auth_state') == 'authentication_required':
                if request_seed:
                    story.append(text('Authentication note: the general crawl encountered a login gate, but active checks continued using the explicitly supplied Burp request seed.', 'small'))
                else:
                    story.append(text('Authentication status: the supplied session was not accepted. Active vulnerability checks were skipped on login-gated routes; provide a fresh authorized session and retest.', 'small'))
            if request_seed:
                story.append(text(
                    f"Burp request seed replayed: {request_seed.get('method', 'GET')} {request_seed.get('url', '')} "
                    f"from {request_seed.get('source', 'request file')}",
                    'small',
                ))
            if int(result_coverage.get('discovered_pages', 0) or 0) == 0:
                story.append(text(
                    'Coverage warning: no application page was retrieved successfully. Active input results are not meaningful until the HTTP/TLS access problem is resolved; for an authorized target with an invalid certificate, rerun with --insecure.',
                    'small',
                ))
            profile = result_coverage.get('site_profile', {})
            if profile:
                story.append(Paragraph('Site classification', styles['h2']))
                story.append(table([
                    ['Type', 'Confidence', 'API', 'GraphQL', 'API routes', 'Recommended reviews'],
                    [profile.get('kind', 'unknown'), profile.get('confidence', 'unknown'),
                     'Yes' if profile.get('api_detected') else 'No',
                     'Yes' if profile.get('graphql_detected') else 'No',
                     profile.get('api_endpoint_count', 0),
                     '; '.join(map(str, profile.get('recommended_reviews', [])))],
                ], widths=[30 * mm, 22 * mm, 15 * mm, 20 * mm, 20 * mm, 48 * mm]))
            if result_coverage.get('api_detected'):
                story.append(Paragraph('API surface identified', styles['h2']))
                story.append(text('API-specific discovery and read-only verification were enabled because API behavior was observed during the assessment. This is an attack-surface classification, not a vulnerability claim.', 'small'))
                api_rows = [['Method', 'API route', 'Parameters', 'Source']]
                for api in result_coverage.get('api_endpoints', [])[:80]:
                    api_rows.append([api.get('method', 'GET'), api.get('url', ''), ', '.join(map(str, api.get('parameters', []))) or '—', api.get('source', 'discovery')])
                if len(api_rows) > 1:
                    story.append(table(api_rows, widths=[20 * mm, 72 * mm, 40 * mm, 23 * mm]))
            target_info = result.get('target', {})
            attack_surface = target_info.get('attack_surface', {})
            if attack_surface.get('endpoints'):
                story.append(Paragraph(f'Scan {result_index}: endpoints requiring review', styles['h2']))
                endpoint_rows = [['Method', 'Endpoint', 'Priority', 'Recommended review']]
                for endpoint in attack_surface.get('endpoints', [])[:80]:
                    recommendations = endpoint.get('recommendations', [])
                    review = ', '.join(str(item.get('attack', '')) for item in recommendations) or 'Manual endpoint review'
                    endpoint_rows.append([endpoint.get('method', ''), endpoint.get('endpoint', ''), endpoint.get('priority', ''), review])
                story.append(table(endpoint_rows, widths=[18 * mm, 65 * mm, 22 * mm, 50 * mm]))
            if attack_surface.get('parameters'):
                story.append(Paragraph(f'Scan {result_index}: parameter review queue', styles['h2']))
                parameter_rows = [['Method', 'Endpoint', 'Parameter', 'Checks']]
                for parameter in attack_surface.get('parameters', [])[:100]:
                    parameter_rows.append([parameter.get('method', ''), parameter.get('endpoint', ''), parameter.get('parameter', ''), ', '.join(map(str, parameter.get('checks', [])))])
                story.append(table(parameter_rows, widths=[18 * mm, 62 * mm, 30 * mm, 45 * mm]))

            attack_checks = result.get('coverage', {}).get('attack_checks', [])
            if attack_checks:
                story.append(Paragraph(f'Scan {result_index}: active verification coverage', styles['h2']))
                check_rows = [['Attack method', 'Status', 'Findings', 'Requests', 'Result']]
                for check in attack_checks:
                    findings_count = int(check.get('findings', 0) or 0)
                    result_note = check.get('reason') or ('No finding recorded' if findings_count == 0 else 'Evidence recorded in findings section')
                    check_rows.append([
                        check.get('method', ''), check.get('status', ''), findings_count,
                        check.get('requests', 0), result_note,
                    ])
                story.append(table(check_rows, widths=[42 * mm, 25 * mm, 20 * mm, 22 * mm, 46 * mm]))

        story.extend([PageBreak(), *section('5. Findings and remediation', 'Detailed observations, supporting evidence, and recommended actions')])
        if not findings:
            story.append(text('No findings met the configured severity threshold. Review the coverage section, skipped tools, and informational asset inventory before treating the assessment as clean.'))
        for number, finding in enumerate(findings, 1):
            severity = str(finding.get('severity', 'info')).lower()
            metadata = [
                ['Severity', severity_cell(severity), 'State', text(finding.get('state', 'suspected'), 'table_cell')],
                ['Type', text(finding.get('type', 'Finding'), 'table_cell'), 'Confidence', text(finding.get('confidence', 'medium'), 'table_cell')],
                ['Location', text(finding.get('location', finding.get('url', '')), 'table_mono'), 'Parameter', text(finding.get('parameter', '—'), 'table_mono')],
                ['Method', text(finding.get('method', '—'), 'table_cell'), 'HTTP status', status_cell(finding.get('status_code'))],
                ['Tool', text(finding.get('tool', 'custom-scanner'), 'table_cell'), 'Finding ID', text(finding.get('finding_id', '—'), 'table_cell')],
            ]
            metadata_table = Table([[cell if hasattr(cell, 'wrap') else text(cell, 'label') for cell in row] for row in metadata], colWidths=[25 * mm, 52.5 * mm, 25 * mm, 52.5 * mm])
            metadata_table.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.35, line), ('BACKGROUND', (0, 0), (0, -1), panel), ('BACKGROUND', (2, 0), (2, -1), panel), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 6), ('RIGHTPADDING', (0, 0), (-1, -1), 6), ('TOPPADDING', (0, 0), (-1, -1), 5), ('BOTTOMPADDING', (0, 0), (-1, -1), 5)]))
            finding_flow = [Paragraph(f'{number}. {escape(str(finding.get("title", "Unnamed finding")))}', styles['finding_title']), metadata_table]
            for label, key in [('What was observed', 'description'), ('Why it matters', 'impact'), ('Verification details', 'verification'), ('Recommended fix', 'remediation')]:
                value = finding.get(key)
                if value not in (None, '', [], {}):
                    finding_flow.extend([Paragraph(label, styles['h2']), rich(value)])
            for label, key in [('Evidence', 'evidence'), ('Request', 'request'), ('Response', 'response'), ('Payload', 'payload')]:
                value = finding.get(key)
                if value not in (None, '', [], {}):
                    finding_flow.extend([Paragraph(label, styles['h2']), evidence_block(value)])
            story.append(KeepTogether(finding_flow))

        story.extend([PageBreak(), *section('6. Verified assets and tool activity', 'Services, paths, network records, and external-tool execution')])
        for result_index, result in enumerate(results, 1):
            target_info = result.get('target', {})
            story.append(Paragraph(f'Scan {result_index}: {escape(str(result.get("scan_info", {}).get("target", "Unknown")))}', styles['h2']))
            technologies = target_info.get('technologies', [])
            ports = target_info.get('ports', [])
            if ports:
                port_rows = [['Port', 'Protocol', 'State', 'Service', 'Confidence', 'Evidence', 'Banner']]
                for port in ports[:100]:
                    port_rows.append([port.get('port', ''), port.get('protocol', ''), port.get('state', ''), port.get('service', ''), port.get('service_confidence', '—'), port.get('service_source', '—'), port.get('banner', '')])
                story.append(Paragraph('Open ports and services', styles['h2']))
                story.append(table(port_rows, widths=[13 * mm, 18 * mm, 18 * mm, 26 * mm, 23 * mm, 27 * mm, 30 * mm]))
            subdomains = target_info.get('subdomains', [])
            subdomain_sources = target_info.get('subdomain_sources', {})
            if subdomains:
                story.append(Paragraph('Verified subdomains', styles['h2']))
                story.append(table([['Hostname'], *[[subdomain] for subdomain in subdomains[:150]]], widths=[155 * mm]))
            elif isinstance(subdomain_sources, dict) and subdomain_sources.get('skipped'):
                story.append(Paragraph('Subdomain enumeration', styles['h2']))
                story.append(text(f"Not applicable: {subdomain_sources['skipped']}"))
            dns = target_info.get('dns', {})
            story.append(Paragraph('DNS assessment', styles['h2']))
            if isinstance(dns, dict) and dns.get('skipped'):
                story.append(text(f"Not applicable: {dns['skipped']}"))
            elif isinstance(dns, dict) and dns.get('records'):
                dns_rows = [['Record type', 'Values']]
                for record_type, values in dns.get('records', {}).items():
                    dns_rows.append([record_type, ', '.join(map(str, values or [])) or '—'])
                story.append(table(dns_rows, widths=[35 * mm, 120 * mm]))
            else:
                story.append(text('No DNS records were returned.'))
            external_assets = target_info.get('external_assets', {})
            directories = external_assets.get('directories', []) if isinstance(external_assets, dict) else []
            if directories:
                directory_rows = [['Path', 'HTTP status', 'Response length', 'Source']]
                for directory in directories[:150]:
                    directory_rows.append([directory.get('url', ''), status_cell(directory.get('status')), directory.get('length', '—'), directory.get('source', 'dirsearch')])
                story.append(Paragraph('Directory and path discovery', styles['h2']))
                story.append(table(directory_rows, widths=[82 * mm, 24 * mm, 28 * mm, 21 * mm]))
            whatweb_services = [
                item for item in external_assets.get('services', [])
                if isinstance(item, dict) and item.get('source') == 'whatweb'
            ] if isinstance(external_assets, dict) else []
            if whatweb_services:
                whatweb_rows = [['Target', 'HTTP status', 'WhatWeb observations']]
                for service in whatweb_services[:20]:
                    plugins = service.get('technologies', {})
                    whatweb_rows.append([
                        service.get('url', ''),
                        status_cell(service.get('status')),
                        ', '.join(map(str, plugins.keys())) if isinstance(plugins, dict) else str(plugins),
                    ])
                story.append(Paragraph('WhatWeb observations', styles['h2']))
                story.append(table(whatweb_rows, widths=[70 * mm, 25 * mm, 60 * mm]))
            tool_runs = result.get('tool_runs', [])
            if tool_runs:
                run_rows = [['Tool', 'Status', 'Duration', 'Findings', 'Assets']]
                for run in tool_runs:
                    run_rows.append([run.get('tool', ''), run.get('status', ''), run.get('duration_seconds', '—'), run.get('finding_count', 0), run.get('asset_count', 0)])
                story.append(Paragraph('External tool execution', styles['h2']))
                story.append(table(run_rows, widths=[42 * mm, 32 * mm, 28 * mm, 26 * mm, 27 * mm]))
                for run in tool_runs:
                    diagnostic = str(run.get('stderr', '') or '').strip()
                    if run.get('status') not in {'completed'} or diagnostic:
                        if diagnostic:
                            story.append(text(f"{run.get('tool', 'tool')} diagnostic: {diagnostic}", 'small'))

        appendix_has_content = any(
            result.get('errors') or result.get('coverage', {}).get('request_log')
            for result in results
        )
        if appendix_has_content:
            story.append(PageBreak())
        story.extend(section('7. Assessment notes and appendix', 'Operational notes for technical review and retesting'))
        if not appendix_has_content:
            story.append(text('No additional scan notes or request-coverage records were supplied for this assessment.'))
        for result_index, result in enumerate(results, 1):
            errors = result.get('errors', [])
            coverage_log = result.get('coverage', {}).get('request_log', [])
            if errors:
                story.append(Paragraph(f'Scan {result_index} notes', styles['h2']))
                for error in errors[:50]:
                    story.append(text(f'• {error}'))
            if coverage_log:
                story.append(Paragraph(f'Scan {result_index} request coverage sample', styles['h2']))
                request_rows = [['Method', 'URL', 'Status', 'Phase']]
                for request in coverage_log[:100]:
                    request_rows.append([request.get('method', ''), request.get('url', ''), status_cell(request.get('status')), request.get('phase', '')])
                story.append(table(request_rows, widths=[18 * mm, 88 * mm, 24 * mm, 25 * mm]))
        story.append(Spacer(1, 8 * mm))
        story.append(text('End of report. Findings should be validated against the application’s current deployment and retested after remediation.', 'small'))

        def draw_page(canvas, document) -> None:
            canvas.saveState()
            width, height = A4
            canvas.setFillColor(colors.white)
            canvas.rect(0, height - 13 * mm, width, 13 * mm, stroke=0, fill=1)
            canvas.setStrokeColor(blue)
            canvas.setLineWidth(2.5)
            canvas.line(18 * mm, height - 14 * mm, width - 18 * mm, height - 14 * mm)
            canvas.setFillColor(navy)
            canvas.setFont('Helvetica-Bold', 8)
            canvas.drawString(18 * mm, height - 8 * mm, 'SP1D3R // BUG REPORT')
            canvas.setFillColor(muted)
            canvas.setFont('Helvetica', 7.5)
            canvas.drawString(18 * mm, 10 * mm, 'Confidential — authorized testing documentation')
            canvas.drawRightString(width - 18 * mm, 10 * mm, f'Page {document.page}')
            canvas.restoreState()

        document = SimpleDocTemplate(
            str(path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
            topMargin=22 * mm, bottomMargin=17 * mm, title='Web Vulnerability Bug Report',
            author='SP1D3R — Web Security Testing Assistant',
        )
        document.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    
    def _write_html_report(self, path: Path, results: List[Dict[str, Any]]) -> None:
        """Write a self-contained, filterable HTML assessment report."""
        all_findings = [finding for result in results for finding in result.get('findings', [])]
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        threshold = self._severity_order.get(self.severity_threshold, 1)
        findings = [f for f in all_findings if severity_order.get(str(f.get('severity', 'info')).lower(), 0) >= threshold]
        findings.sort(key=lambda f: severity_order.get(str(f.get('severity', 'info')).lower(), 0), reverse=True)
        stats = {severity: sum(1 for f in all_findings if str(f.get('severity', 'info')).lower() == severity) for severity in ('critical', 'high', 'medium', 'low', 'info')}
        coverage = [result.get('coverage', {}) for result in results]
        coverage_totals = {
            'pages': sum(int(item.get('discovered_pages', 0)) for item in coverage),
            'forms': sum(int(item.get('discovered_forms', 0)) for item in coverage),
            'endpoints': sum(int(item.get('discovered_endpoints', 0)) for item in coverage),
            'requests': sum(int(item.get('tested_requests', 0)) for item in coverage),
        }
        target_names = [str(result.get('scan_info', {}).get('target', 'Unknown')) for result in results]
        target_label = target_names[0] if len(target_names) == 1 else f"{len(target_names)} targets"
        scope_rules = self.config.get('scope', {}).get('allowed_hosts', [])
        scope_label = ', '.join(map(str, scope_rules)) if scope_rules else 'Recorded in scan configuration'
        ordered_all_findings = sorted(all_findings, key=lambda item: severity_order.get(str(item.get('severity', 'info')).lower(), 0), reverse=True)
        highest_finding = ordered_all_findings[0] if ordered_all_findings else None
        highest_severity = str(highest_finding.get('severity', 'info')).lower() if highest_finding else 'info'
        if all_findings:
            severity_text = ', '.join(
                f"{stats[level]} {level}" for level in ('critical', 'high', 'medium', 'low', 'info') if stats[level]
            )
            highest_title = str(highest_finding.get('title', 'the highest-priority finding'))
            summary_text = (
                f"The assessment covered {target_label} and recorded {len(all_findings)} finding(s): {severity_text}. "
                f"The highest-priority item is {highest_title} ({highest_severity}). "
                "The technical evidence and recommended fixes are set out below."
            )
            risk_text = f"Start with {highest_title}. Confirm the evidence, assign an owner, and track the fix through retesting."
        else:
            summary_text = (
                f"The assessment covered {target_label}. No findings were recorded by the checks that completed. "
                "This reflects the available coverage and verification results; it is not a guarantee that the application is free of vulnerabilities."
            )
            risk_text = "No finding was recorded. Review the coverage and scan notes before treating the result as a clean assessment."

        html = [
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1'>",
            "<title>Web Vulnerability Bug Report</title><style>.closing-message{margin:38px auto 14px;text-align:center;color:#d92d20;font:800 18px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em}</style><style>",
            ":root{--bg:#f4f7fb;--panel:#fff;--ink:#172033;--muted:#667085;--line:#e4e8ef;--navy:#12233f;--blue:#3478f6;--red:#d92d20;--orange:#f79009;--yellow:#eaaa08;--green:#039855;--shadow:0 8px 24px rgba(16,35,65,.07)}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}.shell{display:grid;grid-template-columns:245px 1fr;min-height:100vh}.sidebar{background:var(--navy);color:#dbe6f7;padding:28px 18px;position:sticky;top:0;height:100vh}.brand{font-weight:800;font-size:18px;color:#fff;margin-bottom:28px}.brand small{display:block;color:#91a4c4;font-size:11px;font-weight:500;margin-top:5px}.sidebar a{display:block;color:#b8c7df;text-decoration:none;padding:10px 12px;border-radius:8px;margin:3px 0}.sidebar a:hover{background:#20395f;color:#fff}.main{max-width:1500px;width:100%;padding:34px 42px}.hero{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;margin-bottom:24px}.eyebrow{color:var(--blue);font-weight:700;text-transform:uppercase;letter-spacing:.08em;font-size:11px}.hero h1{font-size:32px;margin:7px 0}.muted{color:var(--muted)}.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);padding:22px;margin:18px 0}.cards{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:12px}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;box-shadow:var(--shadow)}.card strong{font-size:28px;display:block}.card span{color:var(--muted);font-size:12px}.card.critical strong{color:var(--red)}.card.high strong{color:var(--orange)}.card.medium strong{color:var(--yellow)}.card.low strong{color:var(--green)}.card.info strong{color:var(--blue)}.coverage{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.coverage strong{font-size:22px;display:block}.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.toolbar input,.toolbar select{border:1px solid var(--line);border-radius:8px;padding:10px 12px;background:#fff;color:var(--ink);min-width:180px}.toolbar input{flex:1}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:760px}th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);background:#f8fafc}tr:hover{background:#f8fbff}.badge{display:inline-block;border-radius:999px;padding:4px 9px;font-size:11px;font-weight:800;text-transform:uppercase}.badge-critical{background:#fee4e2;color:#b42318}.badge-high{background:#ffead5;color:#b54708}.badge-medium{background:#fff4cc;color:#8a5b00}.badge-low{background:#dcfae6;color:#027a48}.badge-info{background:#e0efff;color:#175cd3}.badge-state{background:#edf2f7;color:#475467}.finding{border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:12px;padding:18px;margin:12px 0;background:#fff}.finding.sev-critical{border-left-color:var(--red)}.finding.sev-high{border-left-color:var(--orange)}.finding.sev-medium{border-left-color:var(--yellow)}.finding.sev-low{border-left-color:var(--green)}.finding summary{cursor:pointer;list-style:none}.finding summary::-webkit-details-marker{display:none}.finding-title{display:flex;justify-content:space-between;gap:12px;align-items:center}.finding-title h3{margin:0;font-size:16px}.detail-grid{display:grid;grid-template-columns:145px 1fr;gap:9px 16px;margin:18px 0}.detail-label{font-weight:700;color:var(--muted)}pre{background:#101828;color:#d1e0f5;border-radius:8px;padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:12px}code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all}.pill{color:var(--muted);font-size:12px}.empty{padding:26px;text-align:center;color:var(--muted)}.footer{color:var(--muted);font-size:12px;padding:28px 0 10px}@media(max-width:900px){.shell{display:block}.sidebar{height:auto;position:static}.main{padding:22px}.cards{grid-template-columns:repeat(2,1fr)}.coverage{grid-template-columns:repeat(2,1fr)}.hero{display:block}}</style>",
            "<style>.panel{transition:transform .18s ease,box-shadow .18s ease}.panel:hover{transform:translateY(-1px);box-shadow:0 12px 30px rgba(16,35,65,.1)}.section-recon{border-top:4px solid #3478f6}.section-findings{border-top:4px solid #d92d20}.section-attack{border-top:4px solid #ec4899}.section-tools{border-top:4px solid #667085}.category-chip{display:inline-block;border-radius:999px;padding:4px 8px;margin-right:8px;font-size:10px;letter-spacing:.08em;font-weight:800;vertical-align:2px}.chip-recon{background:#e0efff;color:#175cd3}.chip-web{background:#ede9fe;color:#6d28d9}.chip-network{background:#dcfae6;color:#027a48}.chip-dns{background:#fff4cc;color:#8a5b00}.chip-security{background:#fee4e2;color:#b42318}.chip-tools{background:#edf2f7;color:#475467}.asset-heading{border-bottom:1px solid var(--line);padding:16px 0 10px;margin:24px 0 0}.section-tools .asset-heading:first-of-type{margin-top:8px}</style>",
            "<style>:root{--bg:#080b10;--panel:#111720;--panel-2:#151d28;--ink:#e8edf4;--muted:#9aa8ba;--line:#273342;--navy:#07090d;--blue:#58a6ff;--red:#ff4d5a;--orange:#ff9d45;--yellow:#ffd166;--green:#4ade80;--shadow:0 14px 35px rgba(0,0,0,.28)}html{scroll-behavior:smooth}body{background:radial-gradient(circle at 78% -10%,#1d1117 0,#080b10 38%),var(--bg);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;line-height:1.55}.sidebar{background:linear-gradient(180deg,#130d12 0%,#080b10 64%);border-right:1px solid #3b2029;box-shadow:10px 0 30px rgba(0,0,0,.2)}.brand{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.03em;color:#fff;text-transform:uppercase}.brand:before{content:'● ';color:#ff4d5a}.brand small{color:#e06a78;text-transform:none}.sidebar a{color:#aebaca;border-left:2px solid transparent}.sidebar a:hover{background:#24151c;color:#fff;border-left-color:#ff4d5a}.main{max-width:1540px;padding:38px 46px}.eyebrow{color:#ff6673;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.14em}.hero h1{color:#fff;font-size:clamp(28px,4vw,42px);letter-spacing:-.03em}.hero .muted,.muted{color:#9aa8ba}.pill{background:#171d27;border:1px solid #364354;border-radius:999px;padding:7px 12px;color:#c8d2df;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.panel,.card{background:linear-gradient(145deg,rgba(20,28,39,.98),rgba(13,18,26,.98));border-color:#2b3746;box-shadow:var(--shadow)}.panel:hover{box-shadow:0 18px 42px rgba(0,0,0,.36);transform:translateY(-2px)}.cards .card{position:relative;overflow:hidden}.cards .card:after{content:'';position:absolute;right:-28px;top:-28px;width:90px;height:90px;border:1px solid currentColor;border-radius:50%;opacity:.12}.card strong{color:#fff}.card span{color:#aab6c5}.card.critical{border-top:3px solid var(--red)}.card.high{border-top:3px solid var(--orange)}.card.medium{border-top:3px solid var(--yellow)}.card.low{border-top:3px solid var(--green)}.card.info{border-top:3px solid var(--blue)}.coverage strong{color:#fff}.toolbar input,.toolbar select{background:#0b1017;color:#e8edf4;border-color:#354354}.toolbar input::placeholder{color:#738195}table{border:1px solid #2a3645;border-radius:10px;overflow:hidden}th{background:#1a222d;color:#aebdce;border-bottom:1px solid #3a4656}td{border-bottom-color:#283443;color:#d9e1eb}tr:hover{background:#1c2632}.finding{background:#101720;border-color:#2d3948}.finding summary{color:#f2f5f8}.finding.sev-critical{border-left-color:var(--red);box-shadow:inset 12px 0 24px rgba(255,77,90,.04)}.finding.sev-high{border-left-color:var(--orange)}.finding.sev-medium{border-left-color:var(--yellow)}.finding.sev-low{border-left-color:var(--green)}.finding-title h3{color:#fff}.detail-label{color:#9aa8ba}.badge-critical{background:#4a1820;color:#ff9da5}.badge-high{background:#4a2917;color:#ffc083}.badge-medium{background:#493a15;color:#ffe29a}.badge-low{background:#123b28;color:#91f4b0}.badge-info{background:#132f4e;color:#9dceff}.badge-state{background:#273241;color:#d1d9e3}.category-chip{border:1px solid currentColor}.chip-recon{background:#102d4a;color:#75b8ff}.chip-web{background:#2a1c4d;color:#c5a8ff}.chip-network{background:#113b2a;color:#87efac}.chip-dns{background:#433414;color:#ffe08a}.chip-security{background:#491923;color:#ff9da5}.chip-tools{background:#273241;color:#c5d0de}.section-recon{border-top-color:#58a6ff}.section-findings{border-top-color:#ff4d5a}.section-attack{border-top-color:#d98cff}.section-tools{border-top-color:#8593a6}.asset-heading{border-bottom-color:#334153;color:#f4f7fb}pre{background:#080c12;border:1px solid #263445;color:#d5e4f5;line-height:1.6}code,.mono{color:#b9dcff}.empty{background:#0d131b;border:1px dashed #344253;border-radius:10px;color:#92a1b4}.footer{color:#718096;border-top:1px solid #273342;margin-top:30px;padding-top:20px}@media(max-width:900px){.main{padding:24px 18px}.sidebar{border-right:0;border-bottom:1px solid #3b2029}.hero h1{font-size:30px}}</style>",
            "<style>.cover-panel{border-top:4px solid #ff4d5a}.section-kicker{color:#ff7380;font:700 11px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.14em}.summary-copy{max-width:980px;font-size:16px;color:#e3e9f1;line-height:1.75}.facts-grid{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:12px;margin-top:22px}.fact{background:#0c121a;border:1px solid #2c3949;border-radius:10px;padding:14px}.fact-label{display:block;color:#8492a5;font:700 10px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.1em;text-transform:uppercase;margin-bottom:5px}.fact-value{color:#f4f7fb;font-weight:650;word-break:break-word}.risk-callout{margin-top:18px;border-left:3px solid #ff4d5a;background:rgba(255,77,90,.07);border-radius:0 8px 8px 0;padding:13px 16px;color:#f0c5ca}.risk-callout strong{display:block;color:#ff8992;font:700 11px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px}.finding-blurb{color:#aebaca;font-size:13px;margin-top:8px}.finding h4{color:#ffb3ba;font-size:11px;letter-spacing:.08em;text-transform:uppercase;margin:20px 0 6px}.finding p{color:#d8e0ea;max-width:1000px}.method-note{color:#aebaca;font-size:13px;border-left:2px solid #566579;padding-left:12px}.section-attack>h3{color:#f1f5f9}.report-note{font-size:12px;color:#7e8da1}@media(max-width:900px){.facts-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:560px){.facts-grid{grid-template-columns:1fr}}</style>",
            "<style>:root{--bg:#f5f7fa;--panel:#fff;--ink:#182230;--muted:#667085;--line:#d9e0e8;--navy:#101828;--blue:#175cd3;--red:#b42318;--orange:#b54708;--yellow:#8a5b00;--green:#027a48;--shadow:0 8px 24px rgba(16,24,40,.08)}body{background:linear-gradient(180deg,#eef2f6 0,#f8fafc 420px);color:var(--ink)}.sidebar{background:#101828;border-right:1px solid #243247;box-shadow:none}.sidebar a{color:#b8c4d4}.sidebar a:hover{background:#1d2939;border-left-color:#f04438}.main{max-width:1320px;padding:28px 42px}.hero{background:linear-gradient(120deg,#101828 0%,#1d2939 100%);border-bottom:4px solid #d92d20;border-radius:14px;padding:28px 30px;margin-bottom:18px;box-shadow:0 12px 28px rgba(16,24,40,.14)}.hero h1{color:#fff;margin:8px 0;font-size:clamp(28px,4vw,40px)}.hero .muted{color:#b9c5d4}.eyebrow{color:#f97066}.pill{background:#243247;border-color:#475467;color:#e4e7ec}.panel,.card{background:#fff;border-color:#d9e0e8;box-shadow:var(--shadow)}.panel:hover{box-shadow:0 12px 28px rgba(16,24,40,.1);transform:none}.cover-panel{border-top-color:#d92d20}.section-kicker{color:#b42318}.summary-copy{color:#344054}.fact{background:#f8fafc;border-color:#d9e0e8}.fact-label{color:#667085}.fact-value{color:#182230}.risk-callout{background:#fff5f5;border-left-color:#d92d20;color:#475467}.risk-callout strong{color:#b42318}.cards .card:after{border-color:currentColor}.card strong{color:#182230}.card span{color:#667085}.toolbar input,.toolbar select{background:#fff;color:#182230;border-color:#cbd5e1}.toolbar input::placeholder{color:#98a2b3}table{border-color:#d9e0e8}th{background:#f2f4f7;color:#475467;border-bottom-color:#d9e0e8}td{color:#344054;border-bottom-color:#eaecf0}tr:hover{background:#f8fafc}.finding{background:#fff;border-color:#d9e0e8;box-shadow:0 4px 14px rgba(16,24,40,.05)}.finding summary{color:#182230}.finding-title h3{color:#182230}.finding-blurb{color:#667085}.finding h4{color:#b42318}.finding p{color:#344054}.detail-label{color:#667085}.badge-critical{background:#fee4e2;color:#b42318}.badge-high{background:#ffead5;color:#b54708}.badge-medium{background:#fff4cc;color:#8a5b00}.badge-low{background:#dcfae6;color:#027a48}.badge-info{background:#e0efff;color:#175cd3}.badge-state{background:#eef2f6;color:#475467}.category-chip{border:0}.chip-recon{background:#e0efff;color:#175cd3}.chip-web{background:#ede9fe;color:#6941c6}.chip-network{background:#dcfae6;color:#027a48}.chip-dns{background:#fff4cc;color:#8a5b00}.chip-security{background:#fee4e2;color:#b42318}.chip-tools{background:#eef2f6;color:#475467}.asset-heading{border-bottom-color:#d9e0e8;color:#182230}.method-note{color:#667085;border-left-color:#98a2b3}.section-attack>h3{color:#182230}pre{background:#101828;border-color:#243247;color:#d0d5dd}.empty{background:#f8fafc;border-color:#cbd5e1;color:#667085}.finding-index{margin:18px 0 24px}.finding-index table{min-width:0}.finding-index td:first-child{width:55px;font-weight:700}.finding-index a{color:#175cd3;font-weight:650;text-decoration:none}.finding-index a:hover{text-decoration:underline}.finding-index .mono{color:#475467}.footer{color:#667085;border-top-color:#d9e0e8}@media(max-width:900px){.main{padding:20px}.facts-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:560px){.facts-grid{grid-template-columns:1fr}.hero{padding:22px}.finding-title{display:block}.finding-title>span{display:block;margin-top:8px}}</style>",
            "<style>.mono{color:#334155!important;background:#f8fafc;border:1px solid #dbe4ee;border-radius:5px;padding:2px 5px;font-weight:600}.endpoint-value{color:#334155!important;background:#f8fafc;border-left:3px solid #94a3b8}.hostname-value{color:#1e3a8a!important;background:#eff6ff;border-left:3px solid #60a5fa}.location-value{color:#334155!important;background:#f8fafc}.pill{background:#f8fafc;border-color:#cbd5e1;color:#475569}.finding-index .mono{background:transparent;border:0;padding:0}.table-wrap .mono{white-space:nowrap}.http-status{display:inline-block;min-width:44px;text-align:center;padding:3px 7px;border-radius:5px;font:700 11px ui-monospace,SFMono-Regular,Menlo,monospace}.status-2xx{background:#ecfdf3;color:#047857;border:1px solid #a7f3d0}.status-3xx{background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe}.status-4xx{background:#fffbeb;color:#a16207;border:1px solid #fde68a}.status-5xx{background:#fef2f2;color:#b91c1c;border:1px solid #fecaca}.status-other{background:#f1f5f9;color:#475569;border:1px solid #cbd5e1}.asset-status-table .http-status{margin-top:1px}.profile-grid{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:10px;margin:16px 0 20px}.profile-item{background:#f8fafc;border:1px solid #dbe4ee;border-radius:8px;padding:13px;min-height:74px}.profile-item span{display:block;color:#64748b;font:700 10px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase;margin-bottom:7px}.profile-item strong{display:block;color:#172033;word-break:break-word}.section-web{border-top:4px solid #2563eb}.section-web h2{color:#172033}.section-kicker{color:#2563eb}.hero{background:#fff;border:1px solid #dbe4ee;border-top:5px solid #2563eb;border-radius:12px;box-shadow:0 10px 28px rgba(30,41,59,.07)}.hero h1{color:#172033}.hero .muted{color:#64748b}.sidebar{background:#172033}.sidebar a{color:#cbd5e1}.sidebar a:hover{background:#263650;color:#fff;border-left-color:#60a5fa}.brand{color:#fff}.brand small{color:#94a3b8}.panel,.card{box-shadow:0 5px 18px rgba(30,41,59,.06);border-radius:10px}.panel:hover{box-shadow:0 8px 22px rgba(30,41,59,.09)}.summary-copy{font-size:15px;line-height:1.75;color:#334155}.facts-grid{margin-top:18px}.fact{background:#f8fafc}.risk-callout{background:#f8fafc;border-left-color:#2563eb;color:#475569}.risk-callout strong{color:#1d4ed8}.section-findings{border-top-color:#c62828}.section-attack{border-top-color:#6d28d9}.section-tools{border-top-color:#64748b}.finding{box-shadow:0 3px 12px rgba(30,41,59,.045)}pre{background:#172033;color:#e2e8f0;border:0}.footer{border-top:1px solid #dbe4ee}@media(max-width:900px){.profile-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:560px){.profile-grid{grid-template-columns:1fr}}</style>",
            "<style>/* Bug Report presentation system */:root{--paper:#f7f8fa;--surface:#fff;--ink:#202733;--muted:#687385;--line:#d5dce5;--blue:#0b5fff;--red:#b42318;--amber:#a15c00;--green:#147a52;--violet:#6841c6}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.65 Arial,Helvetica,sans-serif}.shell{display:block;min-height:100vh}.sidebar{position:sticky;top:0;z-index:5;height:auto;padding:15px 5vw;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:24px}.brand{color:var(--ink);font-size:18px;font-weight:800;white-space:nowrap}.brand small{display:inline;color:var(--muted);font-size:12px;font-weight:400;margin-left:8px}.sidebar a{color:#405066;text-decoration:none;font-size:12px;font-weight:700;padding:7px 0;border-bottom:2px solid transparent}.sidebar a:hover{color:var(--blue);border-bottom-color:var(--blue)}.main{width:min(1160px,100%);margin:0 auto;padding:38px 5vw 70px}.hero{display:flex;justify-content:space-between;align-items:flex-start;gap:28px;background:#fff;border:1px solid var(--line);border-top:6px solid var(--blue);border-radius:4px;padding:30px 34px;margin-bottom:24px;box-shadow:0 8px 24px rgba(32,39,51,.06)}.eyebrow,.section-kicker{color:var(--blue);font-size:11px;font-weight:800;letter-spacing:.13em}.hero h1{margin:8px 0;font-size:38px;line-height:1.1;color:var(--ink);letter-spacing:-.035em}.muted{color:var(--muted)}.pill{background:#eef4ff;border:1px solid #bfd3ff;border-radius:3px;color:#1246a5;padding:8px 11px;font-size:11px;font-weight:800;white-space:nowrap}.panel{background:var(--surface);border:1px solid var(--line);border-radius:4px;box-shadow:0 5px 16px rgba(32,39,51,.045);padding:28px 32px;margin:20px 0}.panel:hover{box-shadow:0 8px 22px rgba(32,39,51,.07);transform:none}.panel h2{font-size:24px;line-height:1.2;margin:8px 0 12px}.panel h3{font-size:17px}.section-web{border-top:4px solid var(--blue)}.section-findings{border-top:4px solid var(--red)}.section-attack{border-top:4px solid var(--violet)}.section-tools{border-top:4px solid #64748b}.section-kicker{font-size:11px}.summary-copy{max-width:900px;font-size:17px;line-height:1.75}.facts-grid{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:12px;margin-top:22px}.fact{background:#f8fafc;border:1px solid var(--line);border-radius:3px;padding:15px}.fact-label,.profile-item span{display:block;color:var(--muted);font-size:10px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;margin-bottom:6px}.fact-value,.profile-item strong{display:block;color:var(--ink);font-weight:700;word-break:break-word}.risk-callout{margin-top:18px;padding:14px 17px;background:#f6f9ff;border-left:4px solid var(--blue);color:#405066}.risk-callout strong{display:block;color:#1246a5;font-size:11px;letter-spacing:.08em;text-transform:uppercase;margin-bottom:4px}.cards{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:12px}.card{background:#fff;border:1px solid var(--line);border-top:4px solid #94a3b8;border-radius:3px;padding:18px;box-shadow:none}.card strong{display:block;font-size:32px;line-height:1;color:var(--ink)}.card span{display:block;color:var(--muted);font-size:12px;margin-top:7px}.card.critical{border-top-color:var(--red)}.card.critical strong{color:var(--red)}.card.high{border-top-color:#d97706}.card.high strong{color:#b54708}.card.medium{border-top-color:#d4a72c}.card.medium strong{color:#8a5b00}.card.low{border-top-color:var(--green)}.card.low strong{color:var(--green)}.card.info{border-top-color:var(--blue)}.card.info strong{color:var(--blue)}.coverage{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.coverage>div{border-left:3px solid #cbd5e1;padding:10px 14px}.coverage strong{display:block;font-size:28px;line-height:1.1}.coverage span{font-size:12px}.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}.toolbar input,.toolbar select{border:1px solid #bfc9d6;border-radius:3px;padding:11px 12px;background:#fff;color:var(--ink);font:inherit;font-size:13px}.toolbar input{flex:1;min-width:250px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:720px}th,td{text-align:left;padding:13px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:#536174;background:#f1f5f9}td{font-size:13px}tr:hover{background:#fafcff}.badge{display:inline-block;border-radius:3px;padding:4px 8px;font-size:10px;font-weight:800;letter-spacing:.05em;text-transform:uppercase}.badge-critical{background:#fef2f2;color:var(--red)}.badge-high{background:#fff7ed;color:#b54708}.badge-medium{background:#fffbeb;color:#8a5b00}.badge-low{background:#ecfdf3;color:var(--green)}.badge-info{background:#eff6ff;color:#1d4ed8}.badge-state{background:#f1f5f9;color:#475569}.finding{border:1px solid var(--line);border-left:5px solid var(--blue);border-radius:3px;padding:22px;margin:16px 0;background:#fff;box-shadow:0 4px 12px rgba(32,39,51,.04)}.finding.sev-critical{border-left-color:var(--red)}.finding.sev-high{border-left-color:#d97706}.finding.sev-medium{border-left-color:#d4a72c}.finding.sev-low{border-left-color:var(--green)}.finding summary{cursor:pointer;list-style:none}.finding summary::-webkit-details-marker{display:none}.finding-title{display:flex;justify-content:space-between;gap:16px;align-items:center}.finding-title h3{margin:0;font-size:18px}.finding-blurb{color:#536174;margin-top:10px}.finding h4{color:#536174;font-size:11px;letter-spacing:.08em;text-transform:uppercase;margin:22px 0 7px}.finding p{max-width:950px}.detail-grid{display:grid;grid-template-columns:150px 1fr;gap:10px 18px;margin:20px 0;padding:16px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}.detail-label{font-weight:800;color:var(--muted)}pre{background:#202733;color:#e8edf4;border-radius:3px;padding:16px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12px/1.55 'Courier New',monospace}code,.mono{font-family:'Courier New',monospace;font-size:12px;word-break:break-all}.mono{color:#334155!important;background:#f8fafc;border:1px solid #dbe4ee;border-radius:3px;padding:2px 5px}.endpoint-value{border-left:3px solid #94a3b8}.hostname-value{color:#1e3a8a!important;background:#eff6ff;border-left:3px solid #60a5fa}.location-value{background:#fafafa}.profile-grid{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:10px;margin:18px 0 22px}.profile-item{background:#f8fafc;border:1px solid var(--line);border-radius:3px;padding:14px;min-height:78px}.profile-item strong{font-size:14px}.asset-heading{border-bottom:1px solid var(--line);padding:16px 0 9px;margin:24px 0 0}.method-note{color:var(--muted);border-left:3px solid #cbd5e1;padding-left:13px}.empty{padding:28px;text-align:center;background:#f8fafc;border:1px dashed #b9c5d3;color:var(--muted)}.footer{color:var(--muted);font-size:12px;border-top:1px solid var(--line);margin-top:35px;padding-top:20px}@media(max-width:900px){.sidebar{position:static;overflow:auto;flex-wrap:wrap}.main{padding:24px 18px 50px}.hero{display:block;padding:24px}.hero h1{font-size:31px}.cards{grid-template-columns:repeat(2,1fr)}.facts-grid,.profile-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:560px){.cards,.facts-grid,.profile-grid,.coverage{grid-template-columns:1fr}.panel{padding:22px 18px}.finding-title{display:block}.finding-title>span{display:block;margin-top:10px}.detail-grid{grid-template-columns:1fr;gap:4px}}</style>",
            "<style>/* Reader-scale typography */body{font-size:13px;line-height:1.55}.main{padding:28px 4vw 56px}.hero{padding:22px 26px;margin-bottom:18px}.hero h1{font-size:30px;line-height:1.15}.panel{padding:22px 26px;margin:16px 0}.panel h2{font-size:20px;margin:6px 0 10px}.panel h3{font-size:15px}.summary-copy{font-size:14px;line-height:1.6}.facts-grid{margin-top:16px}.fact{padding:12px}.cards{gap:10px}.card{padding:14px}.card strong{font-size:26px}.coverage strong{font-size:24px}.toolbar input,.toolbar select{padding:8px 10px;font-size:12px}.table-wrap th,.table-wrap td{padding:9px 10px}.table-wrap th{font-size:9px}.table-wrap td{font-size:12px}.finding{padding:18px;margin:12px 0}.finding-title h3{font-size:16px}.finding-blurb{font-size:12px}.finding h4{font-size:10px;margin:16px 0 5px}.detail-grid{font-size:12px;grid-template-columns:130px 1fr;gap:7px 14px;margin:15px 0;padding:12px 0}.detail-label{font-size:12px}pre{font-size:10px;line-height:1.45;padding:12px}code,.mono{font-size:11px}.profile-item{padding:11px}.profile-item strong{font-size:13px}.asset-heading{padding:12px 0 7px;margin:18px 0 0}.method-note{font-size:12px}.footer{font-size:11px}</style>",
            "<style>/* Reader-first presentation */body{background:#f3f5f7;color:#1f2933;font:13px/1.55 Arial,Helvetica,sans-serif}.shell{display:block}.sidebar{position:static;height:auto;padding:13px 5vw;background:#17324d;border:0;display:flex;align-items:center}.brand{font-size:17px;letter-spacing:.08em}.brand small{display:inline;margin-left:8px;color:#b9c7d6;font-size:11px}.sidebar a{display:none}.main{width:min(1040px,100%);padding:24px 5vw 48px}.hero{display:block;background:#fff;border:1px solid #d7dee7;border-top:5px solid #00a6a6;border-radius:6px;padding:22px 24px;box-shadow:none}.hero h1{font-size:29px;color:#17324d}.hero .muted{color:#66788a}.pill{display:inline-block;margin-top:12px;background:#e6f7f7;border-color:#9bd8d8;color:#176b70}.panel{background:#fff;border:1px solid #d7dee7;border-radius:6px;box-shadow:none;padding:20px 24px;margin:15px 0}.panel:hover{transform:none;box-shadow:none}.panel h2{font-size:19px;color:#17324d}.section-web{border-top:4px solid #00a6a6}.section-findings{border-top:4px solid #c0392b}.section-attack{border-top:4px solid #7562a8}.section-tools{border-top:4px solid #829ab1}.section-kicker,.eyebrow{color:#007c91}.cards{gap:8px}.card{border-radius:5px;padding:12px;box-shadow:none}.card strong{font-size:23px}.card span{font-size:11px}.coverage{gap:8px}.coverage>div{padding:8px 10px}.coverage strong{font-size:20px}.table-wrap{border:1px solid #d7dee7;border-radius:4px}.table-wrap table{min-width:0}.table-wrap th{padding:8px 9px;background:#edf2f7;color:#52606d}.table-wrap td{padding:8px 9px;color:#1f2933}.finding{border-radius:5px;padding:15px;border-left-width:4px;box-shadow:none}.finding-title h3{font-size:15px;color:#17324d}.finding-blurb{color:#52606d}.detail-grid{grid-template-columns:125px 1fr;gap:6px 12px}.mono,.endpoint-value,.location-value{background:#f7f9fb;color:#243b53!important}.hostname-value{background:#e6f6f7;color:#0b4f6c!important}.footer{border-top:1px solid #d7dee7}@media(max-width:700px){.cards,.coverage{grid-template-columns:repeat(2,1fr)}.main{padding:18px 14px 38px}.panel{padding:17px 15px}.detail-grid{grid-template-columns:1fr}}</style>",
            "<style>/* Modern assessment layout */:root{--bg:#eef3f7;--panel:#ffffff;--ink:#102a43;--muted:#627d98;--line:#d9e2ec;--navy:#102a43;--blue:#007c91;--red:#c0392b;--orange:#c56a12;--yellow:#a66b00;--green:#147d64;--shadow:0 10px 28px rgba(16,42,67,.08)}body{background:var(--bg);color:var(--ink);font-family:Inter,Segoe UI,Arial,sans-serif}.sidebar{background:var(--navy);padding:24px 18px;border-right:4px solid #2cb1bc}.brand{font-family:Inter,Segoe UI,sans-serif;font-size:20px;letter-spacing:.12em}.brand:before{content:'◈ ';color:#2cb1bc}.brand small{color:#9fb3c8}.sidebar a{color:#d9e2ec;border-radius:4px;padding:9px 11px}.sidebar a:hover{background:#243b53;color:#fff;border-left-color:#2cb1bc}.main{max-width:1380px;padding:32px 44px}.hero{background:linear-gradient(120deg,#102a43,#243b53);border:0;border-radius:8px;padding:28px 32px;box-shadow:0 12px 30px rgba(16,42,67,.18)}.hero h1{color:#fff;letter-spacing:-.04em}.hero .muted{color:#d9e2ec}.eyebrow,.section-kicker{color:#7fe3e8}.pill{background:#243b53;border-color:#486581;color:#fff}.panel,.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow)}.panel{padding:24px 28px}.panel h2{color:var(--navy)}.section-web{border-top:4px solid #2cb1bc}.section-findings{border-top:4px solid var(--red)}.section-attack{border-top:4px solid #7b61a8}.section-tools{border-top:4px solid #829ab1}.category-chip{border-radius:4px}.chip-web{background:#e6fffa;color:#147d64}.chip-recon{background:#e6f6f7;color:#007c91}.chip-network{background:#edf2f7;color:#486581}.chip-security{background:#fdecea;color:#c0392b}.chip-tools{background:#edf2f7;color:#486581}.facts-grid,.profile-grid{gap:10px}.fact,.profile-item{background:#f7f9fb;border-color:var(--line);border-radius:5px}.card{border-top-width:4px}.table-wrap{border:1px solid var(--line);border-radius:6px}.table-wrap table{min-width:0}.table-wrap th{background:#f0f4f8;color:#486581}.table-wrap td{color:#243b53}.finding{border-radius:6px;border-left-width:5px}.finding-title h3{color:#102a43}.detail-label{color:#627d98}.method-note{color:#486581;border-left-color:#9fb3c8}.mono{color:#243b53!important;background:#f7f9fb}.endpoint-value{border-left-color:#829ab1}.hostname-value{color:#0b4f6c!important;background:#e6f6f7;border-left-color:#2cb1bc}pre{background:#102a43;border:0}.footer{border-top-color:var(--line)}</style>",
            "</head><body><div class='shell'><aside class='sidebar'><div class='brand'>SP1D3R<small>Bug report</small></div>",
            "<a href='#web-profile'>01 · Web profile</a><a href='#executive-summary'>02 · Executive summary</a><a href='#coverage'>03 · Coverage</a><a href='#verification-coverage'>04 · Active verification</a><a href='#findings'>05 · Findings</a><a href='#attack-surface'>06 · Attack surface</a><a href='#tools'>07 · Assets & evidence</a></aside><main class='main'>",
            "<header class='hero' id='summary'><div><div class='eyebrow'>SP1D3R · BUG REPORT</div><h1>Web Vulnerability Report</h1>",
            f"<div class='muted'>Generated {escape(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))} · {len(results)} scan(s) · evidence-backed assessment</div></div><div class='pill'>AUTHORIZED · THRESHOLD: {escape(str(self.severity_threshold).upper())}</div></header>",
            "<section class='panel section-web' id='web-profile'><div class='section-kicker'>01 · WEB PROFILE</div><h2>Web server and technology fingerprint</h2><p class='method-note'>Verified HTTP identity appears first so the reader can establish what service responded before reviewing risk or coverage.</p>",
        ]

        for index, result in enumerate(results, 1):
            scan_info = result.get('scan_info', {})
            target_info = result.get('target', {})
            fingerprint = target_info.get('fingerprint', {})
            technologies = target_info.get('technologies', [])
            html.append(f"<h3 class='asset-heading'>Scan {index}: {escape(str(scan_info.get('target', 'Unknown')))}</h3>")
            html.append("<div class='profile-grid'>")
            for label, value in [('HTTP status', fingerprint.get('status_code') or '—'), ('Final URL', fingerprint.get('final_url') or scan_info.get('target', '—')), ('Server header', fingerprint.get('server') or 'Not disclosed'), ('X-Powered-By', fingerprint.get('powered_by') or 'Not disclosed'), ('Content type', fingerprint.get('content_type') or '—')]:
                html.append(f"<div class='profile-item'><span>{escape(label)}</span><strong>{escape(str(value))}</strong></div>")
            html.append("</div>")
            if fingerprint.get('error'):
                html.append(f"<div class='risk-callout'><strong>Fingerprinting note</strong>{escape(str(fingerprint['error']))}</div>")
            if technologies:
                html.append("<h3 class='asset-heading'>Technology indicators</h3><div class='table-wrap'><table><thead><tr><th>Technology / server</th><th>Category</th><th>Version</th><th>Confidence</th><th>Evidence source</th></tr></thead><tbody>")
                for technology in technologies:
                    if isinstance(technology, dict):
                        html.append("<tr>" + ''.join(f"<td>{escape(str(technology.get(key, '')))}</td>" for key in ('name', 'category', 'version', 'confidence', 'source')) + "</tr>")
                    else:
                        html.append(f"<tr><td>{escape(str(technology))}</td><td colspan='4'>Detected by fingerprint module</td></tr>")
                html.append("</tbody></table></div>")
            else:
                html.append("<div class='empty'>No named technology was verified. The HTTP fingerprint above records whether the server disclosed an identifying banner.</div>")
            external_assets = target_info.get('external_assets', {})
            whatweb_services = [item for item in external_assets.get('services', []) if isinstance(item, dict) and item.get('source') == 'whatweb'] if isinstance(external_assets, dict) else []
            if whatweb_services:
                html.append("<h3 class='asset-heading'>WhatWeb observations</h3><div class='table-wrap'><table><thead><tr><th>Target</th><th>HTTP status</th><th>Observations</th></tr></thead><tbody>")
                for service in whatweb_services:
                    plugins = service.get('technologies', {})
                    observations = ', '.join(map(str, plugins.keys())) if isinstance(plugins, dict) else str(plugins)
                    status = service.get('status')
                    status_html = f"<span class='http-status {self._status_class(status)}'>{escape(str(status if status not in (None, '') else '—'))}</span>"
                    html.append(f"<tr><td class='mono'>{escape(str(service.get('url', '')))}</td><td>{status_html}</td><td>{escape(observations)}</td></tr>")
                html.append("</tbody></table></div>")
        cve_suggestions = [
            suggestion
            for result in results
            for suggestion in result.get('target', {}).get('cve_suggestions', [])
        ]
        html.append("<h3 class='asset-heading'><span class='category-chip chip-security'>CVE</span>Correlation suggestions</h3><p class='method-note'>These are version matches from the local catalog, not confirmed vulnerabilities. Confirm the exact package build, vendor backports, configuration, and current advisory before treating a match as applicable.</p>")
        if cve_suggestions:
            html.append("<div class='table-wrap'><table><thead><tr><th>CVE</th><th>Product / version</th><th>Severity</th><th>Confidence</th><th>Observed source</th><th>Reason</th></tr></thead><tbody>")
            for suggestion in cve_suggestions[:80]:
                source = ', '.join(map(str, suggestion.get('sources', [])))
                ports = ', '.join(str(port) for port in suggestion.get('ports', []))
                if ports:
                    source = f"{source} (port {ports})"
                severity = str(suggestion.get('severity', 'info')).lower()
                html.append(
                    f"<tr><td class='mono'>{escape(str(suggestion.get('cve', '—')))}</td>"
                    f"<td>{escape(str(suggestion.get('product', 'Unknown')))} {escape(str(suggestion.get('detected_version', '')))}</td>"
                    f"<td><span class='badge badge-{escape(severity)}'>{escape(severity)}</span></td>"
                    f"<td><span class='badge badge-state'>SUGGESTED · {escape(str(suggestion.get('confidence', 'medium')).upper())}</span></td>"
                    f"<td>{escape(source or 'Version fingerprint')}</td>"
                    f"<td>{escape(str(suggestion.get('summary', 'Version matched a catalog entry.')))} Match: {escape(str(suggestion.get('affected_range', 'catalog range')))}.</td></tr>"
                )
            html.append("</tbody></table></div>")
        else:
            html.append("<div class='empty'>No local catalog match was found for a versioned technology or service banner. Unversioned services cannot be correlated reliably.</div>")

        html.extend([
            "</section>",
            "<section class='panel cover-panel' id='executive-summary'><div class='section-kicker'>02 · EXECUTIVE SUMMARY</div><h2>Assessment summary</h2>",
            f"<p class='summary-copy'>{escape(summary_text)}</p><div class='facts-grid'><div class='fact'><span class='fact-label'>Target</span><span class='fact-value'>{escape(target_label)}</span></div><div class='fact'><span class='fact-label'>Scope</span><span class='fact-value'>{escape(scope_label)}</span></div><div class='fact'><span class='fact-label'>Coverage</span><span class='fact-value'>{coverage_totals['pages']} pages · {coverage_totals['endpoints']} endpoints</span></div><div class='fact'><span class='fact-label'>Requests</span><span class='fact-value'>{coverage_totals['requests']}</span></div></div><div class='risk-callout'><strong>Priority note</strong>{escape(risk_text)}</div></section>",
            "<section class='cards'>",
            *[f"<div class='card {severity}'><strong>{stats[severity]}</strong><span>{severity.title()} findings</span></div>" for severity in ('critical', 'high', 'medium', 'low', 'info')],
            "</section>",
            "<section class='panel section-recon' id='coverage'><h2><span class='category-chip chip-recon'>RECON</span>Assessment coverage</h2><div class='coverage'>",
            f"<div><strong>{coverage_totals['pages']}</strong><span class='muted'>Pages crawled</span></div><div><strong>{coverage_totals['forms']}</strong><span class='muted'>Forms discovered</span></div><div><strong>{coverage_totals['endpoints']}</strong><span class='muted'>Endpoints mapped</span></div><div><strong>{coverage_totals['requests']}</strong><span class='muted'>Requests issued</span></div>",
            "</div></section>",
            "<section class='panel section-attack' id='verification-coverage'><h2><span class='category-chip chip-web'>ACTIVE</span>Verification coverage</h2><p class='method-note'>Each method is recorded independently. A finding from one check does not stop the remaining checks for the same scan.</p>",
        ])

        for index, result in enumerate(results, 1):
            checks = result.get('coverage', {}).get('attack_checks', [])
            coverage = result.get('coverage', {})
            request_seed = coverage.get('request_seed', {})
            if coverage.get('auth_state') == 'authentication_required' and request_seed:
                html.append("<div class='risk-callout'><strong>Authentication note</strong>The general crawl encountered a login gate, but active checks continued using the explicitly supplied Burp request seed.</div>")
            elif coverage.get('auth_state') == 'authentication_required':
                html.append("<div class='risk-callout'><strong>Authentication status</strong>The supplied session was not accepted. Active vulnerability checks were skipped on login-gated routes; provide a fresh authorized session and retest.</div>")
            if int(coverage.get('discovered_pages', 0) or 0) == 0:
                html.append("<div class='risk-callout'><strong>Coverage warning</strong>No application page was retrieved successfully. Active input results are not meaningful until the HTTP/TLS access problem is resolved; for an authorized target with an invalid certificate, rerun with <span class='mono'>--insecure</span>.</div>")
            profile = coverage.get('site_profile', {})
            if profile:
                html.append("<h3>Site classification</h3><div class='table-wrap'><table><thead><tr><th>Type</th><th>Confidence</th><th>API</th><th>GraphQL</th><th>Routes</th><th>Recommended reviews</th></tr></thead><tbody>")
                html.append(f"<tr><td>{escape(str(profile.get('kind', 'unknown')))}</td><td>{escape(str(profile.get('confidence', 'unknown')))}</td><td>{'Yes' if profile.get('api_detected') else 'No'}</td><td>{'Yes' if profile.get('graphql_detected') else 'No'}</td><td>{escape(str(profile.get('api_endpoint_count', 0)))}</td><td>{escape('; '.join(map(str, profile.get('recommended_reviews', []))))}</td></tr></tbody></table></div>")
            if coverage.get('api_detected'):
                signals = coverage.get('api_signals', [])
                api_endpoints = coverage.get('api_endpoints', [])
                docs = coverage.get('api_docs', [])
                html.append("<div class='risk-callout'><strong>API surface identified</strong>Read-only API discovery and API-specific verification were enabled because the application exposed API behavior. This is based on observed signals, not a vulnerability claim.</div>")
                html.append(f"<h3>API discovery ({escape(str(len(api_endpoints)))} routes)</h3><p class='muted'>Signals: {escape('; '.join(map(str, signals[:8])) or 'API response or route pattern')}" + (f" · Documentation: {escape(', '.join(map(str, docs)))}" if docs else '') + "</p>")
                if api_endpoints:
                    html.append("<div class='table-wrap'><table><thead><tr><th>Method</th><th>API route</th><th>Parameters</th><th>Source</th></tr></thead><tbody>")
                    for api in api_endpoints[:80]:
                        html.append(f"<tr><td>{escape(str(api.get('method', 'GET')))}</td><td class='mono endpoint-value'>{escape(str(api.get('url', '')))}</td><td>{escape(', '.join(map(str, api.get('parameters', []))) or '—')}</td><td>{escape(str(api.get('source', 'discovery')))}</td></tr>")
                    html.append("</tbody></table></div>")
            if checks:
                html.append(f"<h3>Scan {index}</h3><div class='table-wrap'><table><thead><tr><th>Attack method</th><th>Status</th><th>Findings</th><th>Requests</th><th>Notes</th></tr></thead><tbody>")
                for check in checks:
                    html.append(f"<tr><td>{escape(str(check.get('method', '')))}</td><td><span class='badge badge-state'>{escape(str(check.get('status', '')))}</span></td><td>{escape(str(check.get('findings', 0)))}</td><td>{escape(str(check.get('requests', 0)))}</td><td>{escape(str(check.get('reason', '')))}</td></tr>")
                html.append("</tbody></table></div>")
        html.append("</section>")

        html.extend([
            "<section class='panel section-findings' id='findings'><div class='hero'><div><h2><span class='category-chip chip-security'>SECURITY</span>Findings</h2><div class='method-note'>Open a finding to see what was observed, why it matters, the supporting evidence, and the recommended fix.</div></div></div>",
            "<div class='toolbar'><input id='finding-search' placeholder='Search title, URL, parameter, tool…'><select id='severity-filter'><option value=''>All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select><select id='state-filter'><option value=''>All states</option><option>confirmed</option><option>verified</option><option>suspected</option><option>possible</option></select></div>",
        ])

        if findings:
            html.append("<div class='finding-index'><h3>Finding index</h3><div class='table-wrap'><table><thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>State</th><th>HTTP</th><th>Location</th></tr></thead><tbody>")
            for number, finding in enumerate(findings, 1):
                severity = str(finding.get('severity', 'info')).lower()
                state = str(finding.get('state', 'suspected')).lower()
                status = finding.get('status_code')
                status_text = str(status) if status not in (None, '') else '—'
                status_html = f"<span class='http-status {self._status_class(status)}'>{escape(status_text)}</span>"
                html.append(f"<tr><td><a href='#finding-{number}'>#{number}</a></td><td>{escape(str(finding.get('title', 'Unnamed finding')))}</td><td><span class='badge badge-{escape(severity)}'>{escape(severity)}</span></td><td><span class='badge badge-state'>{escape(state)}</span></td><td>{status_html}</td><td class='mono location-value'>{escape(str(finding.get('location', finding.get('url', ''))))}</td></tr>")
            html.append("</tbody></table></div></div><div id='finding-list'>")
            for number, finding in enumerate(findings, 1):
                severity = str(finding.get('severity', 'info')).lower()
                state = str(finding.get('state', 'suspected')).lower()
                searchable = escape(' '.join(str(finding.get(key, '')) for key in ('title', 'type', 'location', 'parameter', 'tool', 'description'))).lower()
                open_attr = " open" if severity in {'critical', 'high', 'medium'} else ""
                blurb = str(finding.get('description', '')).strip() or 'Review the evidence and affected input below.'
                html.append(f"<details id='finding-{number}' class='finding sev-{escape(severity)}' data-severity='{escape(severity)}' data-state='{escape(state)}' data-search='{searchable}'{open_attr}><summary><div class='finding-title'><h3>#{number} · {escape(str(finding.get('title', 'Unnamed finding')))}</h3><span><span class='badge badge-{escape(severity)}'>{escape(severity)}</span> <span class='badge badge-state'>{escape(state)}</span></span></div><div class='finding-blurb'>{escape(blurb)}</div><div class='pill'>{escape(str(finding.get('location', finding.get('url', ''))))}</div></summary>")
                html.append("<div class='detail-grid'>")
                for label, key in [('Severity', 'severity'), ('Type', 'type'), ('Method', 'method'), ('Location', 'location'), ('Parameter', 'parameter'), ('HTTP status', 'status_code'), ('Response length', 'content_length'), ('Content type', 'content_type'), ('Confidence', 'confidence'), ('Validation state', 'state'), ('Tool', 'tool'), ('Finding ID', 'finding_id'), ('CWE', 'cwe'), ('OWASP', 'owasp')]:
                    raw_value = finding.get(key, 'N/A')
                    if key == 'status_code' and raw_value not in (None, '', 'N/A'):
                        value = f"<span class='http-status {self._status_class(raw_value)}'>{escape(str(raw_value))}</span>"
                    else:
                        value = escape(str(raw_value))
                    html.append(f"<div class='detail-label'>{escape(label)}</div><div>{value}</div>")
                html.append("</div>")
                for label, key in [('What was observed', 'description'), ('Why it matters', 'impact'), ('Evidence', 'evidence'), ('Verification details', 'verification'), ('Request', 'request'), ('Response', 'response'), ('Payload', 'payload'), ('Recommended fix', 'remediation')]:
                    value = finding.get(key)
                    if value not in (None, '', [], {}):
                        rendered = json.dumps(value, indent=2, default=str) if isinstance(value, (dict, list)) else str(value)
                        tag = 'pre' if label in {'Evidence', 'Request', 'Response', 'Payload'} else 'p'
                        html.append(f"<h4>{escape(label)}</h4><{tag}>{escape(rendered)}</{tag}>")
                html.append("</details>")
            html.append("</div>")
        else:
            html.append("<div class='empty'>No findings at or above the configured threshold.</div>")
        html.append("</section>")

        html.append("<section class='panel section-attack' id='attack-surface'><h2><span class='category-chip chip-web'>ANALYSIS</span>Attack surface review</h2><p class='method-note'>This is the tester's review queue: endpoints and parameters that deserve attention based on their role. A recommendation here is not a confirmed vulnerability.</p><h3>Endpoints to review</h3>")
        for result in results:
            attack_surface = result.get('target', {}).get('attack_surface', {})
            endpoints = attack_surface.get('endpoints', [])
            if endpoints:
                html.append("<div class='table-wrap'><table><thead><tr><th>Method</th><th>Endpoint</th><th>Priority</th><th>Possible attack review</th><th>Safe verification</th><th>Source</th></tr></thead><tbody>")
                for endpoint in endpoints:
                    recommendations = endpoint.get('recommendations', [])
                    attacks = '<br>'.join(escape(str(item.get('attack', ''))) for item in recommendations)
                    verification = '<br>'.join(escape(str(item.get('safe_verification', ''))) for item in recommendations)
                    html.append(f"<tr><td>{escape(str(endpoint.get('method', '')))}</td><td class='mono endpoint-value'>{escape(str(endpoint.get('endpoint', '')))}</td><td>{escape(str(endpoint.get('priority', '')))}</td><td>{attacks or 'Manual endpoint review'}</td><td>{verification or 'Review input validation and authorization safely.'}</td><td>{escape(', '.join(map(str, endpoint.get('sources', []))))}</td></tr>")
                html.append("</tbody></table></div>")
            html.append("<h3>Parameters to review</h3>")
            parameters = attack_surface.get('parameters', [])
            if parameters:
                html.append("<div class='table-wrap'><table><thead><tr><th>Method</th><th>Endpoint</th><th>Parameter</th><th>Priority</th><th>Recommended attack review</th><th>Safe verification</th><th>Source</th></tr></thead><tbody>")
                for parameter in parameters:
                    recommendations = parameter.get('recommendations', [])
                    attacks = '<br>'.join(escape(str(item.get('attack', ''))) for item in recommendations)
                    verification = '<br>'.join(escape(str(item.get('safe_verification', ''))) for item in recommendations)
                    values = (parameter.get('method', ''), parameter.get('endpoint', ''), parameter.get('parameter', ''), parameter.get('priority', ''), ', '.join(map(str, parameter.get('checks', []))), ', '.join(map(str, parameter.get('sources', []))))
                    html.append("<tr>" + ''.join(f"<td>{escape(str(value))}</td>" for value in values[:4]) + f"<td>{attacks or escape(values[4])}</td><td>{verification or 'Review input validation safely.'}</td><td>{escape(values[5])}</td></tr>")
                html.append("</tbody></table></div>")
        html.append("</section>")

        html.append("<section class='panel section-tools' id='tools'><h2><span class='category-chip chip-tools'>DETAILS</span>Evidence and asset inventory</h2>")
        for index, result in enumerate(results, 1):
            scan_info = result.get('scan_info', {})
            target_info = result.get('target', {})
            html.append(f"<h3>Scan {index}: {escape(str(scan_info.get('target', 'Unknown')))}</h3><p class='muted'>Profile: {escape(str(scan_info.get('scan_type', 'N/A')))} · Duration: {escape(str(scan_info.get('duration', 'N/A')))}</p>")
            request_seed = result.get('coverage', {}).get('request_seed', {})
            auth_state = result.get('coverage', {}).get('auth_state')
            if auth_state == 'authentication_required' and not request_seed:
                html.append("<div class='risk-callout'><strong>Authentication status</strong>The supplied session was not accepted. Active vulnerability checks were skipped on login-gated routes; provide a fresh authorized session and retest.</div>")
            elif auth_state == 'authentication_required' and request_seed:
                html.append("<div class='risk-callout'><strong>Authentication note</strong>The general crawl encountered a login gate, but active checks continued using the explicitly supplied Burp request seed.</div>")
            if request_seed:
                html.append(
                    "<div class='risk-callout'><strong>Burp request seed</strong>"
                    f"{escape(str(request_seed.get('method', 'GET')))} "
                    f"<span class='mono endpoint-value'>{escape(str(request_seed.get('url', '')))}</span> "
                    f"replayed from {escape(str(request_seed.get('source', 'request file')))}."
                    " The captured method, body fields, cookies, and safe headers were retained for active checks.</div>"
                )
            subdomains = target_info.get('subdomains', [])
            source_map = target_info.get('subdomain_sources', {})
            html.append(f"<h3 class='asset-heading'><span class='category-chip chip-recon'>RECON</span>Verified subdomains ({escape(str(len(subdomains)))})</h3>")
            if subdomains:
                html.append("<div class='table-wrap'><table><thead><tr><th>Hostname</th><th>Discovery source</th></tr></thead><tbody>")
                for subdomain in subdomains:
                    sources = source_map.get(subdomain, ['verified DNS source'])
                    html.append(f"<tr><td class='mono hostname-value'>{escape(str(subdomain))}</td><td>{escape(', '.join(map(str, sources)))}</td></tr>")
                html.append("</tbody></table></div>")
            else:
                if isinstance(source_map, dict) and source_map.get('skipped'):
                    html.append(f"<div class='empty'>Not applicable: {escape(str(source_map['skipped']))}</div>")
                else:
                    html.append("<div class='empty'>No subdomains were verified in the configured scope. Passive candidates are not reported until DNS verification succeeds.</div>")

            ports = target_info.get('ports', [])
            html.append(f"<h3 class='asset-heading'><span class='category-chip chip-network'>NETWORK</span>Open ports and services ({escape(str(len(ports)))})</h3>")
            if ports:
                html.append("<div class='table-wrap'><table><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Confidence</th><th>Evidence</th><th>Banner</th></tr></thead><tbody>")
                for port in ports:
                    html.append("<tr>" + ''.join(f"<td>{escape(str(port.get(key, '')))}</td>" for key in ('port', 'protocol', 'state', 'service', 'service_confidence', 'service_source', 'banner')) + "</tr>")
                html.append("</tbody></table></div>")
            else:
                html.append("<div class='empty'>No open ports were verified in the selected port range.</div>")

            external_assets = target_info.get('external_assets', {})
            directories = external_assets.get('directories', []) if isinstance(external_assets, dict) else []
            html.append(f"<h3 class='asset-heading'><span class='category-chip chip-web'>WEB</span>Directory and path discovery ({escape(str(len(directories)))})</h3>")
            if directories:
                html.append("<div class='table-wrap'><table class='asset-status-table'><thead><tr><th>Path</th><th>HTTP status</th><th>Response length</th><th>Source</th></tr></thead><tbody>")
                for directory in directories:
                    status = directory.get('status')
                    status_text = str(status) if status not in (None, '') else '—'
                    status_html = f"<span class='http-status {self._status_class(status)}'>{escape(status_text)}</span>"
                    html.append(f"<tr><td class='mono endpoint-value'>{escape(str(directory.get('url', '')))}</td><td>{status_html}</td><td>{escape(str(directory.get('length', '—')))}</td><td>{escape(str(directory.get('source', 'dirsearch')))}</td></tr>")
                html.append("</tbody></table></div>")
            else:
                html.append("<div class='empty'>No directory or path results were returned by the content-discovery tools.</div>")

            whatweb_services = [
                item for item in external_assets.get('services', [])
                if isinstance(item, dict) and item.get('source') == 'whatweb'
            ] if isinstance(external_assets, dict) else []
            html.append(f"<h3 class='asset-heading'><span class='category-chip chip-web'>WEB</span>WhatWeb observations ({escape(str(len(whatweb_services)))})</h3>")
            if whatweb_services:
                html.append("<div class='table-wrap'><table><thead><tr><th>Target</th><th>HTTP status</th><th>Observations</th></tr></thead><tbody>")
                for service in whatweb_services:
                    plugins = service.get('technologies', {})
                    observations = ', '.join(map(str, plugins.keys())) if isinstance(plugins, dict) else str(plugins)
                    status = service.get('status')
                    status_html = f"<span class='http-status {self._status_class(status)}'>{escape(str(status if status not in (None, '') else '—'))}</span>"
                    html.append(f"<tr><td class='mono endpoint-value'>{escape(str(service.get('url', '')))}</td><td>{status_html}</td><td>{escape(observations)}</td></tr>")
                html.append("</tbody></table></div>")
            else:
                html.append("<div class='empty'>WhatWeb returned no structured service observations.</div>")

            dns = target_info.get('dns', {})
            html.append("<h3 class='asset-heading'><span class='category-chip chip-dns'>DNS</span>DNS records</h3>")
            if dns.get('records'):
                html.append("<div class='table-wrap'><table><thead><tr><th>Record type</th><th>Values</th></tr></thead><tbody>")
                for record_type, values in dns.get('records', {}).items():
                    html.append(f"<tr><td>{escape(str(record_type))}</td><td class='mono'>{escape(', '.join(map(str, values or [])) or '—')}</td></tr>")
                html.append("</tbody></table></div>")
            else:
                if isinstance(dns, dict) and dns.get('skipped'):
                    html.append(f"<div class='empty'>Not applicable: {escape(str(dns['skipped']))}</div>")
                else:
                    html.append("<div class='empty'>No DNS records were returned.</div>")

            waf = target_info.get('waf', {})
            html.append("<h3 class='asset-heading'><span class='category-chip chip-security'>SECURITY</span>WAF detection</h3><pre>" + escape(json.dumps(waf or {'detected': False}, indent=2, default=str)) + "</pre>")
            ssl_info = target_info.get('ssl', {})
            html.append("<h3 class='asset-heading'><span class='category-chip chip-network'>TLS</span>TLS assessment</h3><pre>" + escape(json.dumps(ssl_info or {'info': {}, 'findings': []}, indent=2, default=str)) + "</pre>")
            tool_runs = result.get('tool_runs', [])
            if tool_runs:
                html.append("<div class='table-wrap'><table><thead><tr><th>Tool</th><th>Status</th><th>Duration</th><th>Findings</th><th>Assets</th></tr></thead><tbody>")
                for run in tool_runs:
                    html.append("<tr>" + ''.join(f"<td>{escape(str(run.get(key, '')))}</td>" for key in ('tool', 'status', 'duration_seconds', 'finding_count', 'asset_count')) + "</tr>")
                html.append("</tbody></table></div>")
                for run in tool_runs:
                    diagnostic = str(run.get('stderr', '') or '').strip()
                    if run.get('status') not in {'completed'} or diagnostic:
                        if diagnostic:
                            html.append(f"<div class='risk-callout'><strong>{escape(str(run.get('tool', 'tool')))} diagnostic</strong>{escape(diagnostic)}</div>")
            cov = result.get('coverage', {})
            if cov.get('request_log'):
                html.append(f"<details><summary>Request coverage log ({escape(str(len(cov['request_log'])))} requests)</summary><pre>{escape(json.dumps(cov['request_log'][:250], indent=2, default=str))}</pre></details>")
            if external_assets:
                html.append(f"<details><summary>External tool assets ({escape(str(sum(len(v) for v in external_assets.values())))} assets)</summary><pre>{escape(json.dumps(external_assets, indent=2, default=str))}</pre></details>")
            if result.get('errors'):
                html.append("<h4>Scan notes</h4><ul>" + ''.join(f"<li>{escape(str(error))}</li>" for error in result['errors']) + "</ul>")
        html.extend(["</section><div class='footer'>Prepared by SP1D3R · Scope, authorization controls, and scan notes are retained with the assessment data.</div>",
                     "</main></div><script>",
                     "const search=document.getElementById('finding-search'), sev=document.getElementById('severity-filter'), state=document.getElementById('state-filter');function apply(){const q=(search.value||'').toLowerCase(),s=sev.value,t=state.value;document.querySelectorAll('#finding-list .finding').forEach(x=>{x.style.display=(!q||x.dataset.search.includes(q))&&(!s||x.dataset.severity===s)&&(!t||x.dataset.state===t)?'block':'none'})}search.addEventListener('input',apply);sev.addEventListener('change',apply);state.addEventListener('change',apply);</script></body></html>"])
        path.write_text("\n".join(html), encoding='utf-8')
