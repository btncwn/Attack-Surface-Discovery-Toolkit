from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def generate_pdf_report(domain: str, report_data: dict) -> str:
    filename = f"reports/{domain}_report.pdf"

    pdf = canvas.Canvas(filename, pagesize=A4)
    width, height = A4

    y = height - 50

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(50, y, "Attack Surface Discovery Report")

    y -= 40
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Target:")
    pdf.setFont("Helvetica", 12)
    pdf.drawString(120, y, domain)

    score = report_data.get("attack_surface_score", {})

    y -= 40
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Overall Risk Score")

    y -= 25
    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, y, f"Score: {score.get('score', 'N/A')} / 100")

    y -= 20
    pdf.drawString(50, y, f"Rating: {score.get('rating', 'Unknown')}")

    y -= 40
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Findings")

    findings = report_data.get("findings", [])

    pdf.setFont("Helvetica", 11)

    if findings:
        for finding in findings:
            y -= 25
            pdf.drawString(
                50,
                y,
                f"{finding['severity']} - {finding['finding']}"
            )

            y -= 18
            pdf.drawString(
                70,
                y,
                f"Recommendation: {finding['recommendation']}"
            )

            if y < 80:
                pdf.showPage()
                y = height - 50
                pdf.setFont("Helvetica", 11)
    else:
        y -= 25
        pdf.drawString(50, y, "No findings detected.")

    pdf.save()

    return filename
