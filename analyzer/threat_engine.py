from datetime import datetime
import logging

import models


logger = logging.getLogger(__name__)


# =========================
# Threat Types
# =========================

VALID_THREAT_TYPES = [
    "phishing",
    "malware",
    "data_leak",
    "fake_domain",
    "cyber_incident"
]


# =========================
# Helpers
# =========================

def now_iso():

    return datetime.utcnow().isoformat()


def clean_text(value, default=""):

    if value is None:
        return default

    return str(value).strip()


def normalize_relevance(value):

    relevance = clean_text(
        value,
        "Low"
    ).title()

    if relevance not in [
        "Low",
        "Medium",
        "High",
        "Critical"
    ]:
        return "Low"

    return relevance


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


# =========================
# Severity
# =========================

def calculate_severity(
    threat_type,
    relevance,
    confidence_score
):

    relevance = normalize_relevance(
        relevance
    )

    confidence_score = normalize_confidence(
        confidence_score
    )


    if threat_type == "data_leak":

        if (
            relevance in ["High", "Critical"]
            and confidence_score >= 0.90
        ):
            return "Critical"

        return "High"


    if threat_type == "malware":

        if (
            relevance in ["High", "Critical"]
            and confidence_score >= 0.90
        ):
            return "Critical"

        return "High"


    if threat_type == "phishing":

        if relevance in ["High", "Critical"]:
            return "High"

        return "Medium"


    if threat_type == "fake_domain":

        if relevance in ["High", "Critical"]:
            return "High"

        return "Medium"


    if threat_type == "cyber_incident":

        if (
            relevance in ["High", "Critical"]
            and confidence_score >= 0.85
        ):
            return "High"

        return "Medium"


    return "Low"


# =========================
# Priority
# =========================

def calculate_priority(
    severity,
    relevance
):

    relevance = normalize_relevance(
        relevance
    )

    severity = clean_text(
        severity,
        "Low"
    ).title()


    if severity == "Critical":
        return "Critical"


    if severity == "High":

        if relevance in ["High", "Critical"]:
            return "High"

        return "Medium"


    if severity == "Medium":

        if relevance in ["High", "Critical"]:
            return "High"

        if relevance == "Medium":
            return "Medium"

        return "Low"


    return "Low"


def get_collected_data_for_analysis(
    analysis,
    db
):

    if getattr(
        analysis,
        "collected_data",
        None
    ):

        return analysis.collected_data


    return db.query(
        models.CollectedData
    ).filter(
        models.CollectedData.id == analysis.collected_data_id
    ).first()


def threat_exists(
    analysis_id,
    db
):

    existing_threat = db.query(
        models.Threat
    ).filter(
        models.Threat.analysis_result_id == analysis_id
    ).first()

    return existing_threat is not None


def create_threat_from_analysis(
    analysis,
    collected_data,
    organization,
    db
):

    classification = clean_text(
        analysis.classification
    ).lower()

    relevance = normalize_relevance(
        analysis.relevance
    )

    confidence_score = normalize_confidence(
        analysis.confidence_score
    )

    severity = calculate_severity(
        classification,
        relevance,
        confidence_score
    )

    priority = calculate_priority(
        severity,
        relevance
    )


    title = clean_text(
        collected_data.title,
        f"Threat from collected data #{collected_data.id}"
    )

    description = clean_text(
        analysis.summary,
        clean_text(collected_data.content)[:500]
    )


    new_threat = models.Threat(
        title=title,
        type=classification,
        severity=severity,
        priority=priority,
        relevance=relevance,
        confidence_score=confidence_score,
        description=description,
        status="Open",
        detected_at=now_iso(),
        analysis_result_id=analysis.id,
        user_id=organization.user_id,
        organization_id=organization.id
    )


    db.add(
        new_threat
    )

    return new_threat


# =========================
# Main Threat Engine
# =========================

def run_threat_detection(
    organization_id,
    db
):

    organization = db.query(
        models.Organization
    ).filter(
        models.Organization.id == organization_id
    ).first()


    if not organization:

        return {
            "status": "Failed",
            "message": "Organization not found",
            "threats_created": 0
        }


    analysis_results = db.query(
        models.AnalysisResult
    ).join(
        models.CollectedData,
        models.AnalysisResult.collected_data_id
        == models.CollectedData.id
    ).filter(
        models.CollectedData.organization_id == organization_id
    ).order_by(
        models.AnalysisResult.id.asc()
    ).all()


    if not analysis_results:

        return {
            "status": "Completed",
            "threats_created": 0,
            "skipped_results": 0,
            "failed_results": 0,
            "message": "No analysis results found"
        }


    threats_created = 0
    skipped_results = 0
    failed_results = []


    for analysis in analysis_results:

        classification = clean_text(
            analysis.classification
        ).lower()


        if classification not in VALID_THREAT_TYPES:

            skipped_results += 1
            continue


        if threat_exists(
            analysis.id,
            db
        ):

            skipped_results += 1
            continue


        try:

            collected_data = get_collected_data_for_analysis(
                analysis,
                db
            )


            if not collected_data:

                skipped_results += 1
                continue


            create_threat_from_analysis(
                analysis,
                collected_data,
                organization,
                db
            )


            db.commit()

            threats_created += 1


        except Exception as error:

            db.rollback()

            failed_results.append({
                "analysis_result_id": analysis.id,
                "error": str(error)
            })

            logger.exception(
                "Threat detection failed for analysis_result_id=%s",
                analysis.id
            )


    return {
        "status": "Completed",
        "threats_created": threats_created,
        "skipped_results": skipped_results,
        "failed_results": len(failed_results),
        "errors": failed_results,
        "message": (
            "Threat detection completed successfully"
            if not failed_results
            else "Threat detection completed with warnings"
        )
    }
