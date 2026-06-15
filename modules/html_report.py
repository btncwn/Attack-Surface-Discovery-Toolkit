import os


def generate_html_report(domain: str, report_data: dict):

    os.makedirs("reports", exist_ok=True)

    filename = f"reports/{domain}_report.html"

    findings = report_data.get("findings", [])

    html = f"""
    <html>
    <head>
        <title>Attack Surface Report - {domain}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
            }}

            h1 {{
                color: #2c3e50;
            }}

            h2 {{
                color: #34495e;
            }}

            .finding {{
                border: 1px solid #ddd;
                padding: 10px;
                margin: 10px 0;
            }}
        </style>
    </head>

    <body>

        <h1>Attack Surface Discovery Report</h1>

        <h2>Target</h2>

        <p>{domain}</p>

        <h2>Findings</h2>
    """

    for finding in findings:

        html += f"""
        <div class="finding">

            <b>Severity:</b> {finding['severity']}<br>

            <b>Finding:</b> {finding['finding']}<br>

            <b>Recommendation:</b> {finding['recommendation']}

        </div>
        """

    html += """
    </body>
    </html>
    """

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as report_file:

        report_file.write(html)

    return filename
