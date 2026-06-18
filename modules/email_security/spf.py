from dataclasses import dataclass


@dataclass
class SPFResult:
    status: str
    record: str
    score: int
    issue: str


def analyze_spf(dns_records: dict) -> SPFResult:
    txt_records = dns_records.get("TXT", [])

    spf_record = None

    for record in txt_records:
        if "v=spf1" in record.lower():
            spf_record = record
            break

    if not spf_record:
        return SPFResult(
            status="MISSING",
            record="",
            score=0,
            issue="No SPF record found"
        )

    if "-all" in spf_record:
        return SPFResult(
            status="PASS",
            record=spf_record,
            score=20,
            issue=""
        )

    if "~all" in spf_record:
        return SPFResult(
            status="SOFTFAIL",
            record=spf_record,
            score=15,
            issue="SPF uses softfail (~all)"
        )

    if "+all" in spf_record:
        return SPFResult(
            status="FAIL",
            record=spf_record,
            score=0,
            issue="SPF allows all senders (+all)"
        )

    return SPFResult(
        status="PARTIAL",
        record=spf_record,
        score=10,
        issue="SPF policy not fully restrictive"
    )
