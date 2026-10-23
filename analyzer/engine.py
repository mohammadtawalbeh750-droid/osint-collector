from datetime import datetime
import logging

import models

from .ai_analyzer import analyze_content


logger = logging.getLogger(__name__)


def now_iso():

    return datetime.utcnow().isoformat()


def clean_text(value, default=""):

    if value is None:
        return default

    return str(value).strip()


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


def normalize_analysis_output(result):

    if not isinstance(result, dict):

        result = {}


    classification = clean_text(
        result.get("classification"),
        "uncertain"
    ).lower()


    relevance = clean_text(
        result.get("relevance"),
        "Low"
    )


    if relevance.lower() in [
        "low",
        "medium",
        "high",
        "critical"
    ]:

        relevance = relevance.title()


    model_name = clean_text(
        result.get("model_name"),
        "Hybrid Rules + TF-IDF + Logistic Regression v3"
    )


    summary = clean_text(
        result.get("summary"),
        "No summary generated."
    )


    confidence_score = normalize_confidence(
        result.get("confidence_score", 0)
    )


    return {
        "model_name": model_name,
        "classification": classification,
        "relevance": relevance,
        "confidence_score": confidence_score,
        "summary": summary
    }


def analysis_exists(
    collected_data_id,
    db
):

    existing_analysis = db.query(
        models.AnalysisResult
    ).filter(
        models.AnalysisResult.collected_data_id == collected_data_id
    ).first()

    return existing_analysis is not None


def create_analysis_result(
    collected_data_id,
    result,
    db
):

    normalized_result = normalize_analysis_output(
        result
    )


    analysis_result = models.AnalysisResult(
        collected_data_id=collected_data_id,
        model_name=normalized_result["model_name"],
        classification=normalized_result["classification"],
        relevance=normalized_result["relevance"],
        confidence_score=normalized_result["confidence_score"],
        summary=normalized_result["summary"],
        analyzed_at=now_iso()
    )


    db.add(
        analysis_result
    )

    return analysis_result


def run_analysis(
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
            "items_analyzed": 0
        }


    collected_items = db.query(
        models.CollectedData
    ).filter(
        models.CollectedData.organization_id == organization_id
    ).order_by(
        models.CollectedData.id.asc()
    ).all()


    if not collected_items:

        return {
            "status": "Completed",
            "items_analyzed": 0,
            "skipped_items": 0,
            "failed_items": 0,
            "message": "No collected data found"
        }


    analyzed_count = 0
    skipped_count = 0
    failed_items = []


    for item in collected_items:

        if analysis_exists(
            item.id,
            db
        ):

            skipped_count += 1
            continue


        try:

            content = clean_text(
                item.content
            )


            if not content:

                skipped_count += 1
                continue


            result = analyze_content(
                content,
                organization.keywords or ""
            )


            create_analysis_result(
                item.id,
                result,
                db
            )


            db.commit()

            analyzed_count += 1


        except Exception as error:

            db.rollback()

            failed_items.append({
                "collected_data_id": item.id,
                "error": str(error)
            })

            logger.exception(
                "Analysis failed for collected_data_id=%s",
                item.id
            )


    return {
        "status": "Completed",
        "items_analyzed": analyzed_count,
        "skipped_items": skipped_count,
        "failed_items": len(failed_items),
        "errors": failed_items,
        "message": (
            "Analysis completed successfully"
            if not failed_items
            else "Analysis completed with warnings"
        )
    }
