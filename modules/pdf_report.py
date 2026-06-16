# modules/pdf_report.py - v4.4 Professional Multi-Page Executive PDF Report
# Fixed: safe trend graph styling, numeric score handling, emoji-free PDF output

import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.lineplots import LinePlot

from modules.executive_summary import (
    generate_executive_summary,
    prioritize_remediation,
)


FOOTER_TEXT = "Attack Surface Assessment Report"


def generate_pdf_report(domain: str, report_data: dict) -> str:
    """Generate professional multi-page executive PDF report."""

    os.makedirs("reports", exist_ok=True)
    filename = f"reports/{domain}_report.pdf"

    exec_summary = generate_executive_summary(report_data)
    prioritized = prioritize_remediation(report_data.get("findings", []))

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72,
    )

    styles = build_styles()
    story = []

    story.extend(build_cover_page(domain, report_data, styles))
    story.append(PageBreak())

    story.extend(build_executive_summary_page(exec_summary, styles))
    story.append(PageBreak())

    story.extend(build_key_metrics_page(exec_summary, report_data, styles))
    story.append(PageBreak())

    story.extend(build_remediation_page(prioritized, styles))
    story.append(PageBreak())

    story.extend(build_findings_page(report_data.get("findings", []), styles))
    story.append(PageBreak())

    story.extend(build_cve_page(report_data, styles))
    story.append(PageBreak())

    story.extend(build_asset_discovery_page(report_data, styles))
    story.append(PageBreak())

    story.extend(build_historical_trend_page(report_data, styles))

    doc.build(story)
    return filename


def build_styles():
    styles = getSampleStyleSheet()

    custom_styles = [
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Heading1"],
            fontSize=24,
            alignment=TA_CENTER,
            spaceAfter=30,
            textColor=colors.HexColor("#1a1a2e"),
        ),
        ParagraphStyle(
            name="PageTitle",
            parent=styles["Heading1"],
            fontSize=20,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=colors.HexColor("#16213e"),
        ),
        ParagraphStyle(
            name="SectionTitle",
            parent=styles["Heading2"],
            fontSize=14,
            spaceBefore=12,
            spaceAfter=8,
            textColor=colors.HexColor("#0f3460"),
        ),
        ParagraphStyle(
            name="FindingHeader",
            parent=styles["Normal"],
            fontSize=11,
            leftIndent=10,
            spaceAfter=4,
            textColor=colors.HexColor("#333333"),
        ),
        ParagraphStyle(
            name="FindingDetail",
            parent=styles["Normal"],
            fontSize=9,
            leftIndent=20,
            spaceAfter=6,
            textColor=colors.HexColor("#555555"),
        ),
        ParagraphStyle(
            name="Recommendation",
            parent=styles["Normal"],
            fontSize=9,
            leftIndent=20,
            spaceAfter=10,
            textColor=colors.HexColor("#0066cc"),
        ),
        ParagraphStyle(
            name="ManagementSummary",
            parent=styles["Normal"],
            fontSize=11,
            leftIndent=10,
            spaceAfter=8,
            textColor=colors.HexColor("#333333"),
        ),
        ParagraphStyle(
            name="Footer",
            parent=styles["Normal"],
            fontSize=8,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#666666"),
        ),
    ]

    for style in custom_styles:
        if style.name not in styles:
            styles.add(style)

    return styles


def add_footer(elements, styles):
    elements.append(Spacer(1, 20))
    elements.append(Paragraph(FOOTER_TEXT, styles["Footer"]))


def build_cover_page(domain, report_data, styles):
    elements = []

    score_data = report_data.get("attack_surface_score", {})
    score = score_data.get("score", 0)
    rating = score_data.get("rating", "Unknown")

    elements.append(Spacer(1, 80))
    elements.append(
        Paragraph("ATTACK SURFACE DISCOVERY", styles["ReportTitle"]))
    elements.append(Paragraph("ASSESSMENT REPORT", styles["ReportTitle"]))
    elements.append(Spacer(1, 40))

    elements.append(Paragraph(f"<b>Target:</b> {domain}", styles["Normal"]))
    elements.append(Spacer(1, 10))
    elements.append(
        Paragraph(
            f"<b>Assessment Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 10))
    elements.append(
        Paragraph(
            "<b>Prepared By:</b> Attack Surface Discovery Toolkit",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 10))
    elements.append(
        Paragraph("<b>Classification:</b> Internal - Confidential",
                  styles["Normal"])
    )
    elements.append(Spacer(1, 40))

    elements.append(
        Paragraph(f"<b>Risk Rating:</b> {rating}", styles["Normal"]))
    elements.append(
        Paragraph(f"<b>Attack Surface Score:</b> {score}/100", styles["Normal"]))

    add_footer(elements, styles)
    return elements


def build_executive_summary_page(exec_summary, styles):
    elements = []

    elements.append(Paragraph("Executive Summary", styles["PageTitle"]))
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Risk Matrix", styles["SectionTitle"]))

    risk_data = [
        ["Severity", "Count"],
        ["Critical", str(exec_summary.get("critical_count", 0))],
        ["High", str(exec_summary.get("high_count", 0))],
        ["Medium", str(exec_summary.get("medium_count", 0))],
        ["Low", str(exec_summary.get("low_count", 0))],
        ["Informational", str(exec_summary.get("informational_count", 0))],
    ]

    risk_table = Table(risk_data, colWidths=[6 * cm, 6 * cm])
    risk_table.setStyle(
        TableStyle(
            [
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("FONTSIZE", (0, 1), (-1, -1), 14),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 1, colors.lightgrey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8f0fe")),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    elements.append(risk_table)
    elements.append(Spacer(1, 20))

    score = exec_summary.get("score", 0)
    rating = exec_summary.get("rating", "Unknown")

    elements.append(
        Paragraph(f"<b>Overall Score:</b> {score}/100", styles["Normal"]))
    elements.append(
        Paragraph(f"<b>Risk Rating:</b> {rating}", styles["Normal"]))
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Management Summary", styles["SectionTitle"]))

    total = exec_summary.get("total_findings", 0)
    critical = exec_summary.get("critical_count", 0)
    high = exec_summary.get("high_count", 0)
    medium = exec_summary.get("medium_count", 0)

    if critical > 0:
        summary_text = (
            f"The attack surface assessment identified {critical} critical and "
            f"{high} high-severity weaknesses requiring immediate remediation. "
            "Prioritize patching or mitigating these vulnerabilities to reduce "
            "the risk of potential exploitation."
        )
    elif high > 0:
        summary_text = (
            f"The attack surface assessment identified {high} high-severity weakness "
            "related to missing HTTP security controls. No critical vulnerabilities "
            "were identified during the assessment. Immediate remediation of browser "
            "security headers is recommended."
        )
    elif medium > 0:
        summary_text = (
            f"The attack surface assessment identified {total} findings, with "
            f"{medium} medium-severity issue(s). No critical or high vulnerabilities "
            "were detected. Routine security hygiene is recommended to maintain the "
            "current posture."
        )
    else:
        summary_text = (
            "The attack surface assessment identified no critical or high-severity "
            "findings. Regular monitoring is recommended to maintain security posture."
        )

    elements.append(Paragraph(summary_text, styles["ManagementSummary"]))

    add_footer(elements, styles)
    return elements


def build_key_metrics_page(exec_summary, report_data, styles):
    elements = []

    elements.append(Paragraph("Key Metrics", styles["PageTitle"]))
    elements.append(Spacer(1, 15))

    metrics = [
        ["Subdomains", str(exec_summary.get("subdomain_count", 0))],
        ["Hidden Assets", str(exec_summary.get("asset_count", 0))],
        ["Open Ports", str(exec_summary.get("open_ports_count", 0))],
        ["SSL Status", "Valid" if report_data.get(
            "ssl_information") else "Unknown"],
        ["CVE Findings", str(exec_summary.get("cve_count", 0))],
        ["Critical Findings", str(exec_summary.get("critical_count", 0))],
        ["High Findings", str(exec_summary.get("high_count", 0))],
        ["Medium Findings", str(exec_summary.get("medium_count", 0))],
        ["Low Findings", str(exec_summary.get("low_count", 0))],
    ]

    metric_data = []
    for i in range(0, len(metrics), 3):
        row = []
        for j in range(3):
            if i + j < len(metrics):
                label, value = metrics[i + j]
                row.append(
                    Paragraph(f"<b>{label}</b><br/>{value}", styles["Normal"]))
            else:
                row.append("")
        metric_data.append(row)

    metric_table = Table(metric_data, colWidths=[5 * cm, 5 * cm, 5 * cm])
    metric_table.setStyle(
        TableStyle(
            [
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 1, colors.lightgrey),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8f9fa")),
                ("TOPPADDING", (0, 0), (-1, -1), 15),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 15),
            ]
        )
    )
    elements.append(metric_table)

    add_footer(elements, styles)
    return elements


def build_remediation_page(prioritized, styles):
    elements = []

    elements.append(Paragraph("Remediation Roadmap", styles["PageTitle"]))
    elements.append(Spacer(1, 15))
    elements.append(
        Paragraph("Prioritized remediation plan based on severity.",
                  styles["Normal"])
    )
    elements.append(Spacer(1, 10))

    for item in prioritized[:5]:
        priority = item.get("priority_label", "P5")
        severity = item.get("severity", "")
        finding_text = item.get("finding", "")
        recommendation = item.get("recommendation", "")
        score_impact = item.get("score_impact", 0)

        elements.append(
            Paragraph(
                f"<b>{priority}</b> - {severity}: {finding_text} "
                f"<font color='#666666'>(+{score_impact} pts)</font>",
                styles["FindingHeader"],
            )
        )

        if recommendation:
            short_recommendation = (
                recommendation[:120] + "..."
                if len(recommendation) > 120
                else recommendation
            )
            elements.append(
                Paragraph(
                    f"<i>Recommendation:</i> {short_recommendation}",
                    styles["FindingDetail"],
                )
            )

        elements.append(Spacer(1, 5))

    add_footer(elements, styles)
    return elements


def build_findings_page(findings, styles):
    elements = []

    elements.append(Paragraph("Technical Findings", styles["PageTitle"]))
    elements.append(Spacer(1, 15))

    if not findings:
        elements.append(Paragraph("No findings detected.", styles["Normal"]))

    for finding in findings:
        severity = finding.get("severity", "")
        finding_text = finding.get("finding", "")
        recommendation = finding.get("recommendation", "")

        elements.append(
            Paragraph(f"<b>{severity}</b>: {finding_text}",
                      styles["FindingHeader"])
        )

        if recommendation:
            elements.append(
                Paragraph(
                    f"<i>Recommendation:</i> {recommendation}",
                    styles["Recommendation"],
                )
            )

        elements.append(Spacer(1, 5))

    add_footer(elements, styles)
    return elements


def build_cve_page(report_data, styles):
    elements = []

    elements.append(
        Paragraph("Vulnerability Intelligence", styles["PageTitle"]))
    elements.append(Spacer(1, 15))

    cve_results = report_data.get("cve_correlation", {})

    if cve_results:
        total_cves = sum(len(cves) for cves in cve_results.values())
        elements.append(
            Paragraph(
                f"Detected {total_cves} CVEs across {len(cve_results)} technologies.",
                styles["Normal"],
            )
        )
        elements.append(Spacer(1, 10))

        cve_data = [["Tech", "CVE ID", "CVSS",
                     "Severity", "Exploit", "Description"]]

        for tech, cves in cve_results.items():
            for cve in cves[:3]:
                description = cve.get("description", "")
                short_description = (
                    description[:80] + "..."
                    if len(description) > 80
                    else description
                )

                cve_data.append(
                    [
                        tech.upper()[:6],
                        cve.get("cve_id", ""),
                        str(cve.get("cvss_score", "N/A")),
                        cve.get("severity", "Unknown"),
                        "YES" if cve.get("has_exploit", False) else "NO",
                        short_description,
                    ]
                )

            if len(cves) > 3:
                cve_data.append(
                    [
                        tech.upper()[:6],
                        f"... and {len(cves) - 3} more",
                        "",
                        "",
                        "",
                        "",
                    ]
                )

        cve_table = Table(
            cve_data,
            colWidths=[1.8 * cm, 2.5 * cm, 1.5 *
                       cm, 2 * cm, 1.5 * cm, 5.2 * cm],
        )
        cve_table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 8),
                    ("FONTSIZE", (0, 1), (-1, -1), 7),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("GRID", (0, 0), (-1, -1), 1, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8f0fe")),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        elements.append(cve_table)
    else:
        elements.append(
            Paragraph(
                "No CVEs detected for the identified technologies.",
                styles["Normal"],
            )
        )

    add_footer(elements, styles)
    return elements


def build_asset_discovery_page(report_data, styles):
    elements = []

    elements.append(Paragraph("Asset Discovery", styles["PageTitle"]))
    elements.append(Spacer(1, 15))

    subdomains = report_data.get("subdomains", [])
    if subdomains:
        unique_subdomains = sorted(
            set(
                item["subdomain"] if isinstance(item, dict) else str(item)
                for item in subdomains
            )
        )

        elements.append(
            Paragraph(
                f"Discovered Subdomains ({len(unique_subdomains)})",
                styles["SectionTitle"],
            )
        )
        elements.append(
            Paragraph(", ".join(unique_subdomains[:15]), styles["Normal"])
        )

        if len(unique_subdomains) > 15:
            elements.append(
                Paragraph(
                    f"... and {len(unique_subdomains) - 15} more",
                    styles["Normal"],
                )
            )

        elements.append(Spacer(1, 10))

    hidden = report_data.get("hidden_assets_preview", [])
    hidden_count = report_data.get("hidden_assets_count", 0)

    if hidden:
        if hidden_count > 10:
            risk_level = "HIGH"
        elif hidden_count > 3:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        elements.append(
            Paragraph(
                f"Hidden Assets Found via CT Logs ({hidden_count} total) "
                f"- Risk Level: {risk_level}",
                styles["SectionTitle"],
            )
        )
        elements.append(
            Paragraph(
                f"{hidden_count} assets discovered in CT logs that were not identified "
                "during standard enumeration and should be reviewed.",
                styles["Normal"],
            )
        )
        elements.append(Spacer(1, 5))
        elements.append(Paragraph(", ".join(hidden[:10]), styles["Normal"]))

        if hidden_count > 10:
            elements.append(
                Paragraph(
                    f"... and {hidden_count - 10} more",
                    styles["Normal"],
                )
            )

    add_footer(elements, styles)
    return elements


def build_historical_trend_page(report_data, styles):
    elements = []

    elements.append(Paragraph("Risk Score Trend", styles["PageTitle"]))
    elements.append(Spacer(1, 15))

    history = report_data.get("history", [])

    if history and len(history) >= 2:
        current = history[0]
        previous = history[1]

        current_score = safe_score(current[1]) if len(current) > 1 else 0
        previous_score = safe_score(previous[1]) if len(previous) > 1 else 0
        change = current_score - previous_score

        comparison_data = [
            ["", "Previous", "Current", "Change"],
            [
                "Score",
                str(previous_score),
                str(current_score),
                f"{'+' if change >= 0 else ''}{change}",
            ],
        ]

        table = Table(comparison_data, colWidths=[
                      4 * cm, 3 * cm, 3 * cm, 3 * cm])
        table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("FONTSIZE", (0, 1), (-1, 1), 16),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("GRID", (0, 0), (-1, -1), 1, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8f0fe")),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        elements.append(table)
        elements.append(Spacer(1, 20))

        scores = []
        for row in history[:10]:
            if len(row) > 1:
                score = safe_score(row[1])
                scores.append(score)

        if len(scores) >= 3:
            elements.append(
                Paragraph("Score Trend (Last 10 Scans)", styles["SectionTitle"]))
            elements.append(build_score_trend_graph(scores))
            elements.append(Spacer(1, 10))

        exposure_changes = report_data.get("exposure_changes", {})
        resolved = exposure_changes.get("resolved_findings", [])
        new_findings = exposure_changes.get("new_findings", [])

        if resolved or new_findings:
            elements.append(
                Paragraph("Exposure Changes", styles["SectionTitle"]))

            if resolved:
                elements.append(
                    Paragraph(
                        f"Resolved: {len(resolved)} findings", styles["Normal"])
                )
                for item in resolved[:3]:
                    elements.append(Paragraph(f"- {item}", styles["Normal"]))

            if new_findings:
                elements.append(
                    Paragraph(
                        f"New: {len(new_findings)} findings detected",
                        styles["Normal"],
                    )
                )
                for item in new_findings[:3]:
                    elements.append(Paragraph(f"- {item}", styles["Normal"]))
    else:
        elements.append(
            Paragraph(
                "No historical scan data available for comparison.",
                styles["Normal"],
            )
        )

    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Disclaimer", styles["SectionTitle"]))
    elements.append(
        Paragraph(
            "This report reflects the attack surface observed at the time of assessment. "
            "Absence of findings does not guarantee absence of vulnerabilities. "
            "Results are based on publicly accessible information and automated analysis.",
            styles["Normal"],
        )
    )

    add_footer(elements, styles)
    return elements


def build_score_trend_graph(scores):
    drawing = Drawing(400, 150)

    line = LinePlot()
    line.x = 50
    line.y = 20
    line.width = 300
    line.height = 100

    data_points = list(enumerate(scores))
    line.data = [data_points]

    try:
        line.lines[0].strokeColor = colors.HexColor("#0f3460")
        line.lines[0].strokeWidth = 2
    except Exception:
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
    return drawing


def safe_score(value):
    try:
        score = float(value)
        if score.is_integer():
            return int(score)
        return score
    except (ValueError, TypeError):
        return 0
