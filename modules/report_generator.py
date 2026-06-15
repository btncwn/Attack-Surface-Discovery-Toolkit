import json
import os


def save_report(domain: str, report_data: dict):

    os.makedirs("reports", exist_ok=True)

    filename = f"reports/{domain}_report.json"

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as report_file:

        json.dump(
            report_data,
            report_file,
            indent=4
        )

    return filename
