from dataclasses import dataclass
from typing import Dict, List, Any
from datetime import datetime


@dataclass
class TimelineEvent:
    event_type: str
    severity: str
    title: str
    description: str
    timestamp: str


def generate_exposure_timeline(
    current_report: Dict[str, Any],
    previous_report: Dict[str, Any] | None = None
) -> List[Dict[str, Any]]:
    events: List[TimelineEvent] = []

    now = datetime.now().isoformat()

    if not previous_report:
        events.append(TimelineEvent(
            event_type="baseline",
            severity="INFO",
            title="Baseline scan created",
            description="This is the first recorded scan for this domain.",
            timestamp=now
        ))
        return [event.__dict__ for event in events]

    current_score = _extract_score(current_report)
    previous_score = _extract_score(previous_report)

    if current_score != previous_score:
        direction = "improved" if current_score > previous_score else "declined"
        severity = "INFO" if current_score > previous_score else "HIGH"

        events.append(TimelineEvent(
            event_type="score_change",
            severity=severity,
            title=f"Cyber score {direction}",
            description=f"Score changed from {previous_score} to {current_score}.",
            timestamp=now
        ))

    current_assets = _extract_assets(current_report)
    previous_assets = _extract_assets(previous_report)

    new_assets = sorted(current_assets - previous_assets)
    removed_assets = sorted(previous_assets - current_assets)

    for asset in new_assets[:20]:
        events.append(TimelineEvent(
            event_type="new_asset",
            severity="MEDIUM",
            title="New internet-facing asset discovered",
            description=f"New asset detected: {asset}",
            timestamp=now
        ))

    for asset in removed_assets[:20]:
        events.append(TimelineEvent(
            event_type="removed_asset",
            severity="INFO",
            title="Asset removed from exposure",
            description=f"Previously observed asset no longer appears: {asset}",
            timestamp=now
        ))

    current_findings = _extract_findings(current_report)
    previous_findings = _extract_findings(previous_report)

    new_findings = sorted(current_findings - previous_findings)
    resolved_findings = sorted(previous_findings - current_findings)

    for finding in new_findings[:20]:
        events.append(TimelineEvent(
            event_type="new_finding",
            severity="HIGH",
            title="New security finding detected",
            description=finding,
            timestamp=now
        ))

    for finding in resolved_findings[:20]:
        events.append(TimelineEvent(
            event_type="resolved_finding",
            severity="INFO",
            title="Security finding resolved",
            description=finding,
            timestamp=now
        ))

    return [event.__dict__ for event in events]


def _extract_score(report: Dict[str, Any]) -> int:
    score = report.get("attack_surface_score", {})
    if isinstance(score, dict):
        return int(score.get("score", 0))
    try:
        return int(score)
    except Exception:
        return 0


def _extract_assets(report: Dict[str, Any]) -> set:
    assets = set()

    for item in report.get("subdomains", []):
        if isinstance(item, dict):
            value = item.get("subdomain")
            if value:
                assets.add(value)
        elif isinstance(item, str):
            assets.add(item)

    for item in report.get("certificate_transparency_subdomains", []):
        if isinstance(item, str):
            assets.add(item)

    asset_analysis = report.get("asset_analysis", {})
    for item in asset_analysis.get("hidden_assets", []):
        if isinstance(item, str):
            assets.add(item)

    return assets


def _extract_findings(report: Dict[str, Any]) -> set:
    findings = set()

    for finding in report.get("findings", []):
        if isinstance(finding, dict):
            text = finding.get("finding") or finding.get("title")
            if text:
                findings.add(text)

    return findings
