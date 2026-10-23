from datetime import datetime
import logging

from .web_collector import collect_website
from .telegram_collector import collect_telegram
from .darkweb_collector import collect_darkweb
from .processor import process_content

import models


logger = logging.getLogger(__name__)


def now_iso():

    return datetime.utcnow().isoformat()


def normalize_text(value):

    if value is None:
        return ""

    return str(value).strip()


def normalize_source_type(value):

    return normalize_text(value).lower()


def is_source_active(value):

    status = normalize_text(value).lower()

    return status in [
        "active",
        "enabled",
        "true",
        "1",
        "yes"
    ]


def parse_date(value):

    if not value:
        return now_iso()

    if isinstance(value, datetime):
        return value.replace(tzinfo=None).isoformat()

    text_value = normalize_text(value)

    try:

        parsed_date = datetime.fromisoformat(
            text_value.replace("Z", "+00:00")
        )

        if parsed_date.tzinfo:
            parsed_date = parsed_date.replace(
                tzinfo=None
            )

        return parsed_date.isoformat()

    except Exception:

        return now_iso()


def process_osint_content(raw_content, keywords):

    processed = process_content(
        raw_content or "",
        keywords or ""
    )

    if isinstance(processed, dict):

        return {
            "content": normalize_text(
                processed.get("content")
            ),
            "matched_keywords": processed.get(
                "matched_keywords",
                []
            )
        }

    return {
        "content": normalize_text(processed),
        "matched_keywords": []
    }


def website_content_exists(
    organization_id,
    source_id,
    url,
    content,
    db
):

    existing_item = db.query(
        models.CollectedData
    ).filter(
        models.CollectedData.organization_id == organization_id,
        models.CollectedData.source_id == source_id,
        models.CollectedData.url == url,
        models.CollectedData.content == content
    ).first()

    return existing_item is not None


def telegram_message_exists(
    organization_id,
    source_id,
    url,
    db
):

    existing_message = db.query(
        models.CollectedData
    ).filter(
        models.CollectedData.organization_id == organization_id,
        models.CollectedData.source_id == source_id,
        models.CollectedData.url == url
    ).first()

    return existing_message is not None


def save_collected_data(
    title,
    content,
    url,
    data_type,
    collected_at,
    organization_id,
    source_id,
    db
):

    collected_data = models.CollectedData(
        title=title,
        content=content,
        url=url,
        data_type=data_type,
        collected_at=collected_at,
        organization_id=organization_id,
        source_id=source_id
    )

    db.add(collected_data)

    return collected_data


def collect_from_website(
    source,
    organization,
    keywords,
    db
):

    result = collect_website(
        source.url
    )

    if result.get("data_type") == "error":

        raise Exception(
            result.get(
                "content",
                "Website collection failed"
            )
        )


    processed = process_osint_content(
        result.get("content", ""),
        keywords
    )

    processed_content = processed["content"]

    if not processed_content:

        return 0


    result_url = result.get(
        "url",
        source.url
    )

    if website_content_exists(
        organization.id,
        source.id,
        result_url,
        processed_content,
        db
    ):

        return 0


    save_collected_data(
        title=result.get("title", source.name),
        content=processed_content,
        url=result_url,
        data_type=result.get("data_type", "website"),
        collected_at=now_iso(),
        organization_id=organization.id,
        source_id=source.id,
        db=db
    )

    return 1


def collect_from_telegram(
    source,
    organization,
    keywords,
    db
):

    result = collect_telegram(
        source.url,
        limit=50
    )

    if result.get("data_type") == "error":

        raise Exception(
            result.get(
                "error",
                "Telegram collection failed"
            )
        )


    messages = result.get(
        "messages",
        []
    )

    if not isinstance(messages, list):
        return 0


    collected_count = 0

    for message in messages:

        message_url = message.get("url")

        if not message_url:
            continue


        if telegram_message_exists(
            organization.id,
            source.id,
            message_url,
            db
        ):
            continue


        processed = process_osint_content(
            message.get("text", ""),
            keywords
        )

        processed_content = processed["content"]

        if not processed_content:
            continue


        message_id = message.get(
            "message_id",
            "unknown"
        )

        message_date = parse_date(
            message.get("date")
        )


        save_collected_data(
            title=(
                f'{result.get("title", source.name)} '
                f'- Message {message_id}'
            ),
            content=processed_content,
            url=message_url,
            data_type="telegram",
            collected_at=message_date,
            organization_id=organization.id,
            source_id=source.id,
            db=db
        )

        collected_count += 1


    return collected_count



def collect_from_darkweb(
    source,
    organization,
    keywords,
    db
):

    result = collect_darkweb(
        source,
        organization,
        keywords
    )

    if result.get("data_type") == "error":

        raise Exception(
            result.get(
                "content",
                "Dark Web collection failed"
            )
        )

    items = result.get(
        "items",
        []
    )

    if not isinstance(items, list):
        return 0

    collected_count = 0

    for item in items:

        raw_content = normalize_text(
            item.get("content")
        )

        if not raw_content:
            continue

        processed = process_osint_content(
            raw_content,
            keywords
        )

        processed_content = processed["content"] or raw_content

        result_url = normalize_text(
            item.get("url")
        ) or source.url

        if website_content_exists(
            organization.id,
            source.id,
            result_url,
            processed_content,
            db
        ):
            continue

        save_collected_data(
            title=item.get("title", source.name),
            content=processed_content,
            url=result_url,
            data_type=item.get("data_type", "darkweb"),
            collected_at=parse_date(
                item.get("collected_at")
            ),
            organization_id=organization.id,
            source_id=source.id,
            db=db
        )

        collected_count += 1

    return collected_count


def run_collection(organization_id, db):

    job = models.CollectionJob(
        organization_id=organization_id,
        status="Running",
        started_at=now_iso(),
        finished_at=None,
        items_collected=0
    )

    db.add(job)
    db.commit()
    db.refresh(job)


    collected_count = 0
    source_errors = []
    checked_sources = 0


    try:

        organization = db.query(
            models.Organization
        ).filter(
            models.Organization.id == organization_id
        ).first()

        if not organization:

            raise Exception(
                "Organization not found"
            )


        if organization.monitoring_status == "Inactive":

            raise Exception(
                "Organization is inactive"
            )


        keywords = organization.keywords or ""


        sources = db.query(
            models.Source
        ).filter(
            models.Source.organization_id == organization_id
        ).all()


        active_sources = [
            source
            for source in sources
            if is_source_active(source.enabled)
        ]


        if not active_sources:

            job.status = "Completed"
            job.finished_at = now_iso()
            job.items_collected = 0

            db.commit()

            return {
                "status": "Completed",
                "items_collected": 0,
                "job_id": job.id,
                "sources_checked": 0,
                "message": "No active sources found"
            }


        for source in active_sources:

            checked_sources += 1

            source_type = normalize_source_type(
                source.type
            )

            try:

                if source_type == "website":

                    collected_count += collect_from_website(
                        source,
                        organization,
                        keywords,
                        db
                    )


                elif source_type == "telegram":

                    collected_count += collect_from_telegram(
                        source,
                        organization,
                        keywords,
                        db
                    )


                elif source_type in [
                    "dark web",
                    "darkweb",
                    "dark_web"
                ]:

                    collected_count += collect_from_darkweb(
                        source,
                        organization,
                        keywords,
                        db
                    )


                else:

                    source_errors.append({
                        "source_id": source.id,
                        "source_name": source.name,
                        "error": (
                            f"Unsupported source type: {source.type}"
                        )
                    })


            except Exception as source_error:

                source_errors.append({
                    "source_id": source.id,
                    "source_name": source.name,
                    "error": str(source_error)
                })


            finally:

                source.last_checked = now_iso()


        job.status = "Completed"
        job.finished_at = now_iso()
        job.items_collected = collected_count

        db.commit()


        return {
            "status": "Completed",
            "items_collected": collected_count,
            "job_id": job.id,
            "sources_checked": checked_sources,
            "source_errors": source_errors,
            "message": (
                "Collection completed successfully"
                if not source_errors
                else "Collection completed with warnings"
            )
        }


    except Exception as error:

        db.rollback()

        try:

            job.status = "Failed"
            job.finished_at = now_iso()
            job.items_collected = collected_count

            db.commit()

        except Exception:

            db.rollback()


        logger.exception(
            "Collection failed for organization_id=%s",
            organization_id
        )


        return {
            "status": "Failed",
            "items_collected": collected_count,
            "job_id": job.id,
            "error": str(error)
        }
