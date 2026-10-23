from collections import Counter
from datetime import datetime
import logging

import models


logger = logging.getLogger(__name__)


# ==============================
# Helpers
# ==============================

SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1
}


PRIORITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1
}


def now_iso():

    return datetime.utcnow().isoformat()


def clean_text(value, default=""):

    if value is None:
        return default

    text = str(value).strip()

    return text if text else default


def normalize_level(value):

    level = clean_text(
        value,
        "Low"
    ).title()

    if level not in [
        "Critical",
        "High",
        "Medium",
        "Low"
    ]:
        return "Low"

    return level


def normalize_type(value):

    return clean_text(
        value,
        "unknown"
    ).lower()


def normalize_confidence(value):

    try:

        confidence = float(value)

    except Exception:

        return 0.0


    if confidence > 1 and confidence <= 100:
        confidence = confidence / 100


    if confidence < 0:
        return 0.0

    if confidence > 1:
        return 1.0

    return confidence


def empty_level_counts():

    return {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }


def get_level_counts(threats, field_name):

    counts = empty_level_counts()

    for threat in threats:

        level = normalize_level(
            getattr(
                threat,
                field_name,
                "Low"
            )
        )

        counts[level] += 1


    return counts


def get_type_counts(threats):

    counter = Counter()

    for threat in threats:

        threat_type = normalize_type(
            threat.type
        )

        counter[threat_type] += 1


    return dict(
        sorted(
            counter.items(),
            key=lambda item: (
                item[1],
                item[0]
            ),
            reverse=True
        )
    )


def sort_threats(threats):

    return sorted(
        threats,
        key=lambda threat: (
            SEVERITY_ORDER.get(
                normalize_level(
                    threat.severity
                ),
                0
            ),
            PRIORITY_ORDER.get(
                normalize_level(
                    getattr(
                        threat,
                        "priority",
                        "Low"
                    )
                ),
                0
            ),
            normalize_confidence(
                threat.confidence_score
            ),
            clean_text(
                threat.detected_at
            )
        ),
        reverse=True
    )


def build_recommendations(type_counts):

    recommendations = []

    threat_types = set(
        type_counts.keys()
    )


    if "phishing" in threat_types:

        recommendations.append(
            "Review suspicious emails and login pages, strengthen email filtering, and enforce multi-factor authentication."
        )


    if "malware" in threat_types:

        recommendations.append(
            "Review malware indicators, update endpoint protection, patch affected systems, and monitor suspicious processes and network activity."
        )


    if "data_leak" in threat_types:

        recommendations.append(
            "Investigate exposed information, review affected accounts and credentials, and determine whether containment or notification actions are required."
        )


    if "fake_domain" in threat_types:

        recommendations.append(
            "Monitor suspicious or lookalike domains, review brand impersonation activity, and consider domain takedown procedures where appropriate."
        )


    if "cyber_incident" in threat_types:

        recommendations.append(
            "Review security logs, investigate indicators of compromise, preserve relevant evidence, and contain affected systems when necessary."
        )


    recommendations.append(
        "Validate collected intelligence before taking operational security actions."
    )

    recommendations.append(
        "Prioritize threats based on severity, relevance to the monitored organization, and confidence score."
    )


    return recommendations


def build_report_content(
    organization,
    threats,
    severity_counts,
    priority_counts,
    type_counts,
    top_threats,
    recommendations,
    generated_at
):

    lines = []

    lines.append(
        "CYBER THREAT INTELLIGENCE REPORT"
    )

    lines.append(
        "=" * 50
    )

    lines.append(
        f"Organization: {organization.name}"
    )

    lines.append(
        f"Domain: {clean_text(organization.domain, 'N/A')}"
    )

    lines.append(
        f"Sector: {clean_text(organization.sector, 'N/A')}"
    )

    lines.append(
        f"Generated At: {generated_at}"
    )

    lines.append(
        f"Total Detected Threats: {len(threats)}"
    )


    lines.append("")
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 50)

    lines.append(
        (
            f"The OSINT Collector identified {len(threats)} confirmed threat item(s) "
            f"related to {organization.name}. "
            f"The highest observed severity count is Critical={severity_counts['Critical']}, "
            f"High={severity_counts['High']}, Medium={severity_counts['Medium']}, "
            f"Low={severity_counts['Low']}."
        )
    )


    lines.append("")
    lines.append("SEVERITY SUMMARY")
    lines.append("-" * 50)

    for level in [
        "Critical",
        "High",
        "Medium",
        "Low"
    ]:

        lines.append(
            f"{level}: {severity_counts[level]}"
        )


    lines.append("")
    lines.append("PRIORITY SUMMARY")
    lines.append("-" * 50)

    for level in [
        "Critical",
        "High",
        "Medium",
        "Low"
    ]:

        lines.append(
            f"{level}: {priority_counts[level]}"
        )


    lines.append("")
    lines.append("THREAT TYPES")
    lines.append("-" * 50)

    for threat_type, count in type_counts.items():

        lines.append(
            f"{threat_type}: {count}"
        )


    lines.append("")
    lines.append("TOP DETECTED THREATS")
    lines.append("-" * 50)

    for index, threat in enumerate(
        top_threats,
        start=1
    ):

        confidence = (
            normalize_confidence(
                threat.confidence_score
            )
            * 100
        )

        lines.append(
            f"{index}. {clean_text(threat.title, 'Untitled Threat')}"
        )

        lines.append(
            f"   Type: {normalize_type(threat.type)}"
        )

        lines.append(
            f"   Severity: {normalize_level(threat.severity)}"
        )

        lines.append(
            f"   Priority: {normalize_level(getattr(threat, 'priority', 'Low'))}"
        )

        lines.append(
            f"   Relevance: {clean_text(getattr(threat, 'relevance', 'Low'), 'Low')}"
        )

        lines.append(
            f"   Confidence: {confidence:.1f}%"
        )

        lines.append(
            f"   Status: {clean_text(getattr(threat, 'status', 'Open'), 'Open')}"
        )

        lines.append(
            f"   Detected At: {clean_text(getattr(threat, 'detected_at', ''), 'N/A')}"
        )

        description = clean_text(
            threat.description,
            "No description available."
        )

        lines.append(
            f"   Description: {description}"
        )

        lines.append("")


    lines.append("RECOMMENDATIONS")
    lines.append("-" * 50)

    for index, recommendation in enumerate(
        recommendations,
        start=1
    ):

        lines.append(
            f"{index}. {recommendation}"
        )


    lines.append("")
    lines.append("REPORT NOTE")
    lines.append("-" * 50)
    lines.append(
        "This report is generated from collected OSINT data and AI-assisted analysis results stored inside the OSINT Collector system."
    )


    return "\n".join(
        lines
    )


# ==============================
# Main Report Engine
# ==============================

def generate_cti_report(organization_id, db):

    try:

        organization = db.query(
            models.Organization
        ).filter(
            models.Organization.id == organization_id
        ).first()


        if not organization:

            return {
                "status": "Failed",
                "report_created": False,
                "message": "Organization not found"
            }


        threats = db.query(
            models.Threat
        ).filter(
            models.Threat.organization_id == organization_id
        ).order_by(
            models.Threat.id.desc()
        ).all()


        if not threats:

            return {
                "status": "Completed",
                "report_created": False,
                "message": "No threats found for this organization",
                "total_threats": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }


        severity_counts = get_level_counts(
            threats,
            "severity"
        )

        priority_counts = get_level_counts(
            threats,
            "priority"
        )

        type_counts = get_type_counts(
            threats
        )


        sorted_threats = sort_threats(
            threats
        )

        top_threats = sorted_threats[:10]


        recommendations = build_recommendations(
            type_counts
        )


        generated_at = now_iso()


        report_content = build_report_content(
            organization=organization,
            threats=threats,
            severity_counts=severity_counts,
            priority_counts=priority_counts,
            type_counts=type_counts,
            top_threats=top_threats,
            recommendations=recommendations,
            generated_at=generated_at
        )


        report = models.Report(
            title=(
                f"Threat Intelligence Report - "
                f"{organization.name}"
            ),
            type="CTI",
            content=report_content,
            generated_at=generated_at,
            user_id=organization.user_id,
            organization_id=organization.id
        )


        db.add(
            report
        )

        db.commit()

        db.refresh(
            report
        )


        return {
            "status": "Completed",
            "report_created": True,
            "report_id": report.id,
            "total_threats": len(threats),
            "critical": severity_counts["Critical"],
            "high": severity_counts["High"],
            "medium": severity_counts["Medium"],
            "low": severity_counts["Low"],
            "message": "CTI report generated successfully"
        }


    except Exception as error:

        db.rollback()

        logger.exception(
            "CTI report generation failed for organization_id=%s",
            organization_id
        )

        return {
            "status": "Failed",
            "report_created": False,
            "message": str(error)
        }
