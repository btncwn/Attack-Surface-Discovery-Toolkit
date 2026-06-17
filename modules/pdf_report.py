# modules/pdf_report.py - v2.10 Professional Multi-Page Executive PDF Report
# Fixed: Historical Trend score extraction with flexible index support

import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, PageBreak
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.lineplots import LinePlot

from modules.executive_summary import generate_executive_summary, prioritize_remediation


# ============================================================
# BRANDING CONFIG
# ============================================================

BRANDING = {
    "company_name": "Attack Surface Discovery Toolkit",
    "primary_color": "#1a1a2e",
    "secondary_color": "#0f3460",
    "accent_color": "#e94560",
    "logo_path": None,
    "report_title": "Attack Surface Assessment Report",
    "footer_text": "Confidential - For Internal Use Only"
}


class TOCDocTemplate(SimpleDocTemplate):
    """Custom document template with TOC tracking."""

    def afterFlowable(self, flowable):
        """Track TOC entries after each flowable."""
        if isinstance(flowable, Paragraph):
            text = flowable.getPlainText()
            style_name = flowable.style.name

            if style_name == "PageTitle" and text != "Table of Contents":
                self.notify("TOCEntry", (0, text, self.page))


def generate_pdf_report(domain: str, report_data: dict) -> str:
    """Generate professional multi-page executive PDF report with TRUE dynamic TOC."""

    os.makedirs("reports", exist_ok=True)
    filename = f"reports/{domain}_report.pdf"

    exec_summary = generate_executive_summary(report_data)
    prioritized = prioritize_remediation(report_data.get("findings", []))
    styles = build_styles()

    doc = TOCDocTemplate(
        filename,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )

    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(
            name="TOCLevel1",
            fontSize=10,
            leftIndent=20,
            firstLineIndent=-20,
            spaceBefore=5,
            leading=14,
            textColor=colors.HexColor("#333333"),
        )
    ]

    story = []

    # TOC Page
    story.append(Paragraph("Table of Contents", styles["PageTitle"]))
    story.append(Spacer(1, 20))
    story.append(toc)
    story.append(PageBreak())

    # Cover Page
    story.extend(build_cover_page(domain, report_data, styles))
    story.append(PageBreak())

    # Executive Summary
    story.extend(build_executive_summary_page(domain, exec_summary, styles))
    story.append(PageBreak())

    # Key Metrics
    story.extend(build_key_metrics_page(exec_summary, report_data, styles))
    story.append(PageBreak())

    # Remediation Roadmap
    story.extend(build_remediation_page(prioritized, styles))
    story.append(PageBreak())

    # Technical Findings
    story.extend(build_findings_page(report_data.get("findings", []), styles))
    story.append(PageBreak())

    # CVE Intelligence
    story.extend(build_cve_page(report_data, styles))
    story.append(PageBreak())

    # Asset Discovery
    story.extend(build_asset_discovery_page(report_data, styles))
    story.append(PageBreak())

    # Historical Trend
    story.extend(build_historical_trend_page(report_data, styles))

    doc.multiBuild(
        story,
        onFirstPage=_add_page_number,
        onLaterPages=_add_page_number
    )

    return filename


def build_styles():
    styles = getSampleStyleSheet()

    custom_styles = [
        ParagraphStyle(
            name='ReportTitle',
            parent=styles['Heading1'],
            fontSize=24,
            alignment=TA_CENTER,
            spaceAfter=30,
            textColor=colors.HexColor('#1a1a2e')
        ),
        ParagraphStyle(
            name='PageTitle',
            parent=styles['Heading1'],
            fontSize=20,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=colors.HexColor('#0f3460')
        ),
        ParagraphStyle(
            name='SectionTitle',
            parent=styles['Heading2'],
            fontSize=14,
            spaceBefore=12,
            spaceAfter=8,
            textColor=colors.HexColor('#0f3460')
        ),
        ParagraphStyle(
            name='FindingHeader',
            parent=styles['Normal'],
            fontSize=11,
            leftIndent=10,
            spaceAfter=4,
            textColor=colors.HexColor('#333')
        ),
        ParagraphStyle(
            name='FindingDetail',
            parent=styles['Normal'],
            fontSize=9,
            leftIndent=20,
            spaceAfter=8,
            textColor=colors.HexColor('#444')
        ),
        ParagraphStyle(
            name='Recommendation',
            parent=styles['Normal'],
            fontSize=9,
            leftIndent=20,
            spaceAfter=10,
            textColor=colors.HexColor('#0066cc')
        ),
        ParagraphStyle(
            name='ManagementSummary',
            parent=styles['Normal'],
            fontSize=11,
            leftIndent=10,
            spaceAfter=8,
            textColor=colors.HexColor('#333')
        ),
        ParagraphStyle(
            name='Footer',
            parent=styles['Normal'],
            fontSize=8,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#666')
        ),
        ParagraphStyle(
            name='EmptyState',
            parent=styles['Normal'],
            fontSize=11,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#666'),
            spaceAfter=10
        ),
    ]

    for style in custom_styles:
        if style.name not in styles:
            styles.add(style)

    return styles


def _add_page_number(canvas, doc):
    """Add page numbers to each page."""
    page_num = canvas.getPageNumber()
    text = f"Page {page_num}"
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(colors.HexColor('#666'))
    canvas.drawCentredString(15*cm, 1.5*cm, text)


def add_footer(elements, styles):
    """Add footer to page."""
    elements.append(Spacer(1, 20))
    elements.append(Paragraph(BRANDING['footer_text'], styles['Footer']))


# ============================================================
# HELPER: Flexible Score Extraction
# ============================================================

def extract_score(row):
    """
    Supports multiple database formats:
    - (scan_date, score, rating)
    - (id, domain, score, rating, scan_date)
    - (id, domain, score, rating, scan_date, findings_json)
    """
    try:
        if not row:
            return 0

        # Try to find score based on common patterns
        # Pattern 1: (scan_date, score, rating) -> score at index 1
        # Pattern 2: (id, domain, score, rating, scan_date) -> score at index 2
        # Pattern 3: (id, domain, score, rating, scan_date, findings_json) -> score at index 2

        if len(row) == 3:
            # (scan_date, score, rating)
            return safe_score(row[1])
        elif len(row) >= 5:
            # (id, domain, score, rating, scan_date, ...)
            return safe_score(row[2])
        else:
            # Last resort: check each element for numeric value
            for value in row:
                if isinstance(value, (int, float)):
                    return safe_score(value)
                elif isinstance(value, str) and value.replace('.', '').isdigit():
                    return safe_score(value)

        return 0
    except Exception:
        return 0


def build_cover_page(domain, report_data, styles):
    """Cover Page"""
    elements = []

    # Bookmark for TOC
    elements.append(Paragraph('<a name="cover"/>', styles["Normal"]))
    elements.append(Spacer(1, 10))

    score_data = report_data.get('attack_surface_score', {})
    score = score_data.get('score', 0)
    rating = score_data.get('rating', 'Unknown')

    elements.append(Spacer(1, 50))
    elements.append(
        Paragraph("ATTACK SURFACE DISCOVERY", styles['ReportTitle']))
    elements.append(Paragraph("ASSESSMENT REPORT", styles['ReportTitle']))
    elements.append(Spacer(1, 40))

    elements.append(Paragraph(f"<b>Target:</b> {domain}", styles['Normal']))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(
        f"<b>Assessment Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
    elements.append(Spacer(1, 10))
    elements.append(
        Paragraph(f"<b>Prepared By:</b> {BRANDING['company_name']}", styles['Normal']))
    elements.append(Spacer(1, 10))
    elements.append(
        Paragraph("<b>Classification:</b> Internal - Confidential", styles['Normal']))
    elements.append(Spacer(1, 40))

    elements.append(
        Paragraph(f"<b>Risk Rating:</b> {rating}", styles['Normal']))
    elements.append(
        Paragraph(f"<b>Attack Surface Score:</b> {score}/100", styles['Normal']))

    add_footer(elements, styles)
    return elements


def build_executive_summary_page(domain, exec_summary, styles):
    """Executive Summary"""
    elements = []

    elements.append(Paragraph("Executive Summary", styles['PageTitle']))
    elements.append(Spacer(1, 15))

    # Risk Matrix
    elements.append(Paragraph("Executive Risk Matrix", styles['SectionTitle']))

    risk_data = [
        ["Severity", "Count", "Impact"],
        ["Critical", str(exec_summary.get('critical_count', 0)),
         "Immediate Action"],
        ["High", str(exec_summary.get('high_count', 0)), "High Priority"],
        ["Medium", str(exec_summary.get('medium_count', 0)),
         "Standard Priority"],
        ["Low", str(exec_summary.get('low_count', 0)), "Routine Priority"],
        ["Info", str(exec_summary.get('informational_count', 0)),
         "Informational"],
    ]

    risk_table = Table(risk_data, colWidths=[3*cm, 3*cm, 6*cm])
    risk_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e8f0fe')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 20))

    # Score
    score = exec_summary.get('score', 0)
    rating = exec_summary.get('rating', 'Unknown')

    elements.append(
        Paragraph(f"<b>Overall Score:</b> {score}/100", styles['Normal']))
    elements.append(
        Paragraph(f"<b>Risk Rating:</b> {rating}", styles['Normal']))
    elements.append(Spacer(1, 15))

    # Management Summary
    elements.append(Paragraph("Management Summary", styles['SectionTitle']))

    total = exec_summary.get('total_findings', 0)
    critical = exec_summary.get('critical_count', 0)
    high = exec_summary.get('high_count', 0)

    if critical > 0:
        summary_text = f"The assessment identified {critical} critical and {high} high-severity weaknesses requiring immediate remediation."
    elif high > 0:
        summary_text = f"The assessment identified {high} high-severity weaknesses. No critical vulnerabilities were found."
    else:
        summary_text = f"The assessment identified {total} findings with no critical or high severity issues."

    elements.append(Paragraph(summary_text, styles['ManagementSummary']))

    add_footer(elements, styles)
    return elements


def build_key_metrics_page(exec_summary, report_data, styles):
    """Key Metrics"""
    elements = []

    elements.append(Paragraph("Key Metrics", styles['PageTitle']))
    elements.append(Spacer(1, 15))

    metrics = [
        ["Subdomains", str(exec_summary.get('subdomain_count', 0))],
        ["Hidden Assets", str(exec_summary.get('asset_count', 0))],
        ["Open Ports", str(exec_summary.get('open_ports_count', 0))],
        ["SSL Status", "Valid" if report_data.get(
            'ssl_information') else "Unknown"],
        ["CVE Findings", str(exec_summary.get('cve_count', 0))],
        ["Critical Findings", str(exec_summary.get('critical_count', 0))],
        ["High Findings", str(exec_summary.get('high_count', 0))],
        ["Medium Findings", str(exec_summary.get('medium_count', 0))],
        ["Low Findings", str(exec_summary.get('low_count', 0))],
    ]

    metric_data = []
    for i in range(0, len(metrics), 3):
        row = []
        for j in range(3):
            if i + j < len(metrics):
                label, value = metrics[i + j]
                row.append(
                    Paragraph(f"<b>{label}</b><br/>{value}", styles['Normal']))
            else:
                row.append("")
        metric_data.append(row)

    metric_table = Table(metric_data, colWidths=[5*cm, 5*cm, 5*cm])
    metric_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
    ]))
    elements.append(metric_table)

    add_footer(elements, styles)
    return elements


def build_remediation_page(prioritized, styles):
    """Remediation Roadmap"""
    elements = []

    elements.append(Paragraph("Remediation Roadmap", styles['PageTitle']))
    elements.append(Spacer(1, 15))
    elements.append(
        Paragraph("Prioritized remediation plan based on severity:", styles['Normal']))
    elements.append(Spacer(1, 10))

    for item in prioritized[:5]:
        priority = item.get('priority_label', 'P5')
        severity = item.get('severity', '')
        finding_text = item.get('finding', '')
        rec = item.get('recommendation', '')
        score_impact = item.get('score_impact', 0)

        elements.append(Paragraph(
            f"<b>{priority}</b> - {severity}: {finding_text} <font color='#666'>(+{score_impact} pts)</font>",
            styles['FindingHeader']
        ))
        elements.append(
            Paragraph(f"<i>Recommendation:</i> {rec[:120]}...", styles['FindingDetail']))
        elements.append(Spacer(1, 5))

    add_footer(elements, styles)
    return elements


def build_findings_page(findings, styles):
    """Technical Findings"""
    elements = []

    elements.append(Paragraph("Technical Findings", styles['PageTitle']))
    elements.append(Spacer(1, 15))

    for finding in findings:
        severity = finding.get('severity', '')
        finding_text = finding.get('finding', '')
        rec = finding.get('recommendation', '')

        elements.append(
            Paragraph(f"<b>{severity}</b>: {finding_text}", styles['FindingHeader']))
        elements.append(
            Paragraph(f"<i>Recommendation:</i> {rec}", styles['Recommendation']))
        elements.append(Spacer(1, 5))

    add_footer(elements, styles)
    return elements


def build_cve_page(report_data, styles):
    """CVE Intelligence with empty state"""
    elements = []

    elements.append(
        Paragraph("Vulnerability Intelligence", styles['PageTitle']))
    elements.append(Spacer(1, 15))

    cve_results = report_data.get('cve_correlation', {})

    # Show detected technologies
    tech_info = report_data.get('technology_fingerprint', {})
    server = tech_info.get('server', 'Unknown')

    elements.append(
        Paragraph(f"<b>Detected Technologies:</b> {server}", styles['Normal']))
    elements.append(Spacer(1, 10))

    if cve_results:
        total_cves = sum(len(cves) for cves in cve_results.values())
        elements.append(Paragraph(
            f"Found {total_cves} CVEs across {len(cve_results)} technologies", styles['Normal']))
        elements.append(Spacer(1, 10))

        cve_data = [
            ["Tech", "CVE ID", "CVSS", "Severity", "Exploit", "Description"]
        ]

        for tech, cves in cve_results.items():
            for cve in cves[:3]:
                desc = cve.get('description', '')[:40] + "..."
                cve_data.append([
                    tech.upper()[:6],
                    cve.get('cve_id', ''),
                    str(cve.get('cvss_score', 'N/A')),
                    cve.get('severity', 'Unknown'),
                    "YES" if cve.get('has_exploit', False) else "NO",
                    desc
                ])
            if len(cves) > 3:
                cve_data.append(
                    [tech.upper()[:6], f"... and {len(cves) - 3} more", "", "", "", ""])

        cve_table = Table(cve_data, colWidths=[
                          1.8*cm, 2.5*cm, 1.5*cm, 2*cm, 1.5*cm, 5.2*cm])
        cve_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e8f0fe')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(cve_table)
    else:
        elements.append(Paragraph(
            "No mapped CVEs found for detected technologies.",
            styles['EmptyState']
        ))
        elements.append(Spacer(1, 5))
        elements.append(Paragraph(
            "This may indicate that the technologies in use are not associated with known vulnerabilities, "
            "or that the assessment did not detect version-specific details.",
            styles['Normal']
        ))

    add_footer(elements, styles)
    return elements


def build_asset_discovery_page(report_data, styles):
    """Asset Discovery"""
    elements = []

    elements.append(Paragraph("Asset Discovery", styles['PageTitle']))
    elements.append(Spacer(1, 15))

    subdomains = report_data.get('subdomains', [])
    if subdomains:
        unique_subdomains = sorted(set(
            item["subdomain"] if isinstance(item, dict) else str(item)
            for item in subdomains
        ))

        elements.append(Paragraph(
            f"Discovered Unique Assets ({len(unique_subdomains)})", styles['SectionTitle']))
        elements.append(
            Paragraph(", ".join(unique_subdomains[:15]), styles['Normal']))
        if len(unique_subdomains) > 15:
            elements.append(
                Paragraph(f"... and {len(unique_subdomains) - 15} more", styles['Normal']))
        elements.append(Spacer(1, 10))

    hidden = report_data.get('hidden_assets_preview', [])
    hidden_count = report_data.get('hidden_assets_count', 0)

    if hidden:
        risk_level = "HIGH" if hidden_count > 10 else "MEDIUM" if hidden_count > 3 else "LOW"
        elements.append(Paragraph(
            f"Hidden Assets Found via CT Logs ({hidden_count} total) - Risk Level: {risk_level}",
            styles['SectionTitle']
        ))
        elements.append(Paragraph(", ".join(hidden[:10]), styles['Normal']))
        if hidden_count > 10:
            elements.append(
                Paragraph(f"... and {hidden_count - 10} more", styles['Normal']))

    add_footer(elements, styles)
    return elements


def build_historical_trend_page(report_data, styles):
    """Historical Trend with graph"""
    elements = []

    elements.append(Paragraph("Historical Trend", styles['PageTitle']))
    elements.append(Spacer(1, 15))

    history = report_data.get('history', [])

    if history and len(history) >= 2:
        current = history[0]
        previous = history[1]

        # 🆕 Use flexible score extraction
        current_score = extract_score(current)
        previous_score = extract_score(previous)
        change = current_score - previous_score if current_score and previous_score else 0

        comparison_data = [
            ["", "Previous", "Current", "Change"],
            ["Score", str(previous_score), str(current_score),
             f"{'+' if change >= 0 else ''}{change}"]
        ]

        table = Table(comparison_data, colWidths=[4*cm, 3*cm, 3*cm, 3*cm])
        table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, 1), 16),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e8f0fe')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))

        if len(history) >= 3:
            elements.append(Paragraph("Score Trend", styles['SectionTitle']))

            scores = []
            for row in history[:10]:
                score = extract_score(row)
                if score > 0:
                    scores.append(score)

            if len(scores) >= 3:
                drawing = Drawing(400, 150)
                line = LinePlot()
                line.x = 50
                line.y = 20
                line.width = 300
                line.height = 100

                data_points = list(enumerate(scores))
                line.data = [data_points]

                try:
                    line.lines[0].strokeColor = colors.HexColor('#0f3460')
                    line.lines[0].strokeWidth = 2
                except:
                    pass

                line.xValueAxis.valueMin = -0.5
                line.xValueAxis.valueMax = len(scores) - 0.5
                line.xValueAxis.valueStep = 1

                min_score = max(0, min(scores) - 5)
                max_score = min(100, max(scores) + 5)
                if min_score == max_score:
                    min_score = max(0, min_score - 5)
                    max_score = min(100, max_score + 5)

                line.yValueAxis.valueMin = min_score
                line.yValueAxis.valueMax = max_score

                drawing.add(line)
                elements.append(drawing)
                elements.append(Spacer(1, 10))

        exposure_changes = report_data.get('exposure_changes', {})
        resolved = exposure_changes.get('resolved_findings', [])
        new_findings = exposure_changes.get('new_findings', [])

        if resolved or new_findings:
            elements.append(
                Paragraph("Exposure Changes", styles['SectionTitle']))
            if resolved:
                elements.append(
                    Paragraph(f"Resolved: {len(resolved)} findings", styles['Normal']))
            if new_findings:
                elements.append(
                    Paragraph(f"New: {len(new_findings)} findings", styles['Normal']))
    else:
        elements.append(
            Paragraph("No historical scan data available.", styles['Normal']))

    elements.append(Spacer(1, 15))

    # Disclaimer
    elements.append(Paragraph("Disclaimer", styles['SectionTitle']))
    elements.append(Paragraph(
        "This report reflects the attack surface at the time of assessment. "
        "Results are based on publicly accessible information and automated analysis.",
        styles['Normal']
    ))

    add_footer(elements, styles)
    return elements


def safe_score(value):
    """Safely convert score value to int or float."""
    try:
        score = float(value)
        if score.is_integer():
            return int(score)
        return score
    except (ValueError, TypeError):
        return 0
