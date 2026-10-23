from datetime import datetime, timedelta
from urllib.parse import urlparse

import os
import random
import smtplib
import string
import re
from email.message import EmailMessage

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, or_, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import engine, SessionLocal, Base

import models
import schemas

# Collection Engine
from collector.engine import run_collection

# AI Analysis Engine
from analyzer.engine import run_analysis

# Threat Detection + Prioritization Engine
from analyzer.threat_engine import run_threat_detection

# CTI Report Generation Engine
from reporter.engine import generate_cti_report


# =========================
# Create Tables
# =========================

Base.metadata.create_all(bind=engine)


def ensure_account_columns():

    with engine.begin() as connection:

        columns = connection.execute(
            text("PRAGMA table_info(users)")
        ).fetchall()

        existing_columns = {
            column[1] for column in columns
        }

        if "last_login" not in existing_columns:

            connection.execute(
                text(
                    "ALTER TABLE users "
                    "ADD COLUMN last_login VARCHAR DEFAULT 'Never'"
                )
            )


ensure_account_columns()


# =========================
# App
# =========================

app = FastAPI(
    title="OSINT Collector API"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================
# Database
# =========================

def get_db():

    db = SessionLocal()

    try:

        yield db

    finally:

        db.close()


# =========================
# Helper Functions
# =========================

def clean_text(value, default=""):

    if value is None:
        return default

    return str(value).strip()


def normalize_email(value):

    return clean_text(value).lower()


def jordan_time_now():

    return (
        datetime.utcnow()
        + timedelta(hours=3)
    ).strftime("%Y-%m-%d %H:%M:%S")


def normalize_domain(value):

    domain = clean_text(value).lower()

    domain = domain.replace("https://", "")
    domain = domain.replace("http://", "")
    domain = domain.replace("www.", "")

    domain = domain.split("/")[0].strip()

    return domain


def normalize_url(value):

    return clean_text(value)


def validate_strong_password(password: str):
    clean_pw = clean_text(password)
    
    if len(clean_pw) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long."
        )
    
    if not re.search(r"[A-Z]", clean_pw):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one uppercase letter."
        )
        
    if not re.search(r"[a-z]", clean_pw):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one lowercase letter."
        )
        
    if not re.search(r"\d", clean_pw):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one digit."
        )
        
    if not re.search(r"[@$!%*?&._]", clean_pw):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one special character (e.g. @$!%*?&)."
        )
        
    return clean_pw


def require_user(user_id: int, db: Session):

    user = db.query(
        models.User
    ).filter(
        models.User.id == user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return user


def require_admin(admin_id: int, db: Session):

    admin = require_user(
        admin_id,
        db
    )

    if admin.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    return admin


def require_organization(organization_id: int, db: Session):

    organization = db.query(
        models.Organization
    ).filter(
        models.Organization.id == organization_id
    ).first()

    if not organization:
        raise HTTPException(
            status_code=404,
            detail="Organization not found"
        )

    return organization


def require_user_organization(
    organization_id: int,
    user_id: int,
    db: Session
):

    organization = db.query(
        models.Organization
    ).filter(
        models.Organization.id == organization_id,
        models.Organization.user_id == user_id
    ).first()

    if not organization:
        raise HTTPException(
            status_code=404,
            detail="Organization not found"
        )

    return organization


def validate_monitoring_status(value):

    status = clean_text(
        value,
        "Active"
    )

    if status not in ["Active", "Inactive"]:
        return "Active"

    return status


def validate_source_type(value):

    source_type = clean_text(value).lower()

    allowed_types = {
        "website": "Website",
        "telegram": "Telegram",
        "dark web": "Dark Web",
        "darkweb": "Dark Web",
        "dark_web": "Dark Web"
    }

    if source_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Invalid source type. Use Website, Telegram, or Dark Web"
        )

    return allowed_types[source_type]


def validate_source_url(source_type, url):

    clean_url = normalize_url(url)

    if not clean_url:
        raise HTTPException(
            status_code=400,
            detail="Source URL is required"
        )

    if source_type == "Dark Web":
        parsed_darkweb_url = urlparse(clean_url)

        if parsed_darkweb_url.scheme in ["http", "https", "intelx"]:
            return clean_url

        if parsed_darkweb_url.scheme == "darkweb":
            query_part = (parsed_darkweb_url.netloc + parsed_darkweb_url.path).strip("/")
            if not query_part:
                query_part = "target_search"
            return f"https://intelx.io/?s={query_part}"

        if not ("." in clean_url or "@" in clean_url or "http" in clean_url):
            return f"https://intelx.io/?s={clean_url.replace(' ', '%20')}"

        return clean_url

    parsed_url = urlparse(clean_url)

    if parsed_url.scheme not in ["http", "https"]:
        raise HTTPException(
            status_code=400,
            detail="Source URL must start with http:// or https://"
        )

    if not parsed_url.netloc:
        raise HTTPException(
            status_code=400,
            detail="Invalid source URL"
        )

    if source_type == "Telegram":

        allowed_hosts = [
            "t.me",
            "www.t.me",
            "telegram.me",
            "www.telegram.me"
        ]

        if parsed_url.netloc.lower() not in allowed_hosts:
            raise HTTPException(
                status_code=400,
                detail="Telegram source URL must use t.me"
            )

        if not parsed_url.path.strip("/"):
            raise HTTPException(
                status_code=400,
                detail="Telegram source URL must include a channel name"
            )

    return clean_url


def validate_role(role):

    clean_role = clean_text(role).lower()

    if clean_role not in ["admin", "analyst", "viewer"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid role"
        )

    return clean_role


def build_user_profile(user):

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at,
        "last_login": getattr(
            user,
            "last_login",
            None
        ) or "Never"
    }


def validate_threat_type(value):

    clean_type = clean_text(value).lower()

    allowed_types = [
        "phishing",
        "malware",
        "data_leak",
        "fake_domain",
        "cyber_incident"
    ]

    if clean_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="Invalid threat type"
        )

    return clean_type


def validate_severity(value):

    clean_severity = clean_text(
        value,
        "Low"
    ).title()

    allowed_severities = [
        "Low",
        "Medium",
        "High",
        "Critical"
    ]

    if clean_severity not in allowed_severities:
        raise HTTPException(
            status_code=400,
            detail="Invalid severity"
        )

    return clean_severity


def validate_status(value):

    clean_status = clean_text(
        value,
        "Open"
    )

    allowed_statuses = [
        "Open",
        "Investigating",
        "Resolved"
    ]

    if clean_status not in allowed_statuses:
        return "Open"

    return clean_status


def priority_from_severity(severity):

    if severity == "Critical":
        return "Critical"

    if severity == "High":
        return "High"

    if severity == "Medium":
        return "Medium"

    return "Low"


def safe_commit(db: Session):

    try:

        db.commit()

    except IntegrityError as error:

        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="Database integrity error"
        ) from error


def delete_source_data(source_id: int, db: Session):

    collected_items = db.query(
        models.CollectedData
    ).filter(
        models.CollectedData.source_id == source_id
    ).all()

    collected_ids = [
        item.id for item in collected_items
    ]

    if collected_ids:

        analysis_items = db.query(
            models.AnalysisResult
        ).filter(
            models.AnalysisResult.collected_data_id.in_(
                collected_ids
            )
        ).all()

        analysis_ids = [
            item.id for item in analysis_items
        ]

        if (
            analysis_ids and
            hasattr(models.Threat, "analysis_result_id")
        ):

            db.query(
                models.Threat
            ).filter(
                models.Threat.analysis_result_id.in_(
                    analysis_ids
                )
            ).delete(
                synchronize_session=False
            )

        db.query(
            models.AnalysisResult
        ).filter(
            models.AnalysisResult.collected_data_id.in_(
                collected_ids
            )
        ).delete(
            synchronize_session=False
        )

        db.query(
            models.CollectedData
        ).filter(
            models.CollectedData.id.in_(
                collected_ids
            )
        ).delete(
            synchronize_session=False
        )


def delete_organization_data(
    organization_id: int,
    db: Session
):

    reports = db.query(
        models.Report
    ).filter(
        models.Report.organization_id == organization_id
    ).all()

    report_ids = [
        report.id for report in reports
    ]

    if report_ids:

        db.query(
            models.Feedback
        ).filter(
            models.Feedback.report_id.in_(
                report_ids
            )
        ).delete(
            synchronize_session=False
        )

    db.query(
        models.Report
    ).filter(
        models.Report.organization_id == organization_id
    ).delete(
        synchronize_session=False
    )


    db.query(
        models.Threat
    ).filter(
        models.Threat.organization_id == organization_id
    ).delete(
        synchronize_session=False
    )


    collected_items = db.query(
        models.CollectedData
    ).filter(
        models.CollectedData.organization_id == organization_id
    ).all()

    collected_ids = [
        item.id for item in collected_items
    ]

    if collected_ids:

        db.query(
            models.AnalysisResult
        ).filter(
            models.AnalysisResult.collected_data_id.in_(
                collected_ids
            )
        ).delete(
            synchronize_session=False
        )

        db.query(
            models.CollectedData
        ).filter(
            models.CollectedData.id.in_(
                collected_ids
            )
        ).delete(
            synchronize_session=False
        )


    db.query(
        models.CollectionJob
    ).filter(
        models.CollectionJob.organization_id == organization_id
    ).delete(
        synchronize_session=False
    )


    db.query(
        models.Source
    ).filter(
        models.Source.organization_id == organization_id
    ).delete(
        synchronize_session=False
    )


def delete_user_data(
    user_id: int,
    db: Session
):

    organizations = db.query(
        models.Organization
    ).filter(
        models.Organization.user_id == user_id
    ).all()

    for organization in organizations:

        delete_organization_data(
            organization.id,
            db
        )

        db.delete(organization)


    db.query(
        models.Feedback
    ).filter(
        models.Feedback.user_id == user_id
    ).delete(
        synchronize_session=False
    )


    db.query(
        models.Report
    ).filter(
        models.Report.user_id == user_id
    ).delete(
        synchronize_session=False
    )


    db.query(
        models.Threat
    ).filter(
        models.Threat.user_id == user_id
    ).delete(
        synchronize_session=False
    )


    db.query(
        models.Source
    ).filter(
        models.Source.user_id == user_id
    ).delete(
        synchronize_session=False
    )



# =========================
# Environment + Email OTP
# =========================

PASSWORD_RESET_CODES = {}


def get_reset_code_expiry_minutes():

    try:

        minutes = int(
            os.getenv(
                "PASSWORD_RESET_CODE_EXPIRE_MINUTES",
                "10"
            )
        )

    except Exception:

        minutes = 10


    if minutes < 1:
        return 10

    if minutes > 60:
        return 60

    return minutes


def generate_reset_code():

    return "".join(
        random.choices(
            string.digits,
            k=6
        )
    )


def cleanup_expired_reset_codes():

    current_time = datetime.utcnow()

    expired_emails = [
        email
        for email, data in PASSWORD_RESET_CODES.items()
        if data["expires_at"] < current_time
    ]

    for email in expired_emails:

        PASSWORD_RESET_CODES.pop(
            email,
            None
        )


def send_password_reset_email(
    recipient_email,
    reset_code
):
    # استخدام المنفذ 465 مع SMTP_SSL لتجاوز قيود الشبكة وحظر الـ Timeout
    smtp_host = "smtp.gmail.com"
    smtp_port = 465
    smtp_email = "mohammadtawalbeh750@gmail.com"
    smtp_password = "ojhzzumhvukzauce"
    smtp_from_name = "OSINT Collector"

    message = EmailMessage()
    message["Subject"] = "OSINT Collector Password Reset Code"
    message["From"] = f"{smtp_from_name} <{smtp_email}>"
    message["To"] = recipient_email

    message.set_content(
        f"""
Hello,

Your OSINT Collector password reset code is:

{reset_code}

This code expires in {get_reset_code_expiry_minutes()} minutes.

If you did not request this password reset, ignore this email.

OSINT Collector
""".strip()
    )

    try:
        with smtplib.SMTP_SSL(
            smtp_host,
            smtp_port,
            timeout=20
        ) as smtp_server:

            smtp_server.login(
                smtp_email,
                smtp_password
            )
            smtp_server.send_message(
                message
            )
        return True

    except Exception as error:
        print(
            "SMTP SEND ERROR:",
            str(error)
        )
        return False


# =========================
# Home
# =========================

@app.get("/")
def home():

    return {
        "message": "OSINT Collector Backend is running"
    }


# =========================
# Organizations
# =========================

@app.get("/organizations/{user_id}")
def get_organizations(
    user_id: int,
    db: Session = Depends(get_db)
):

    require_user(
        user_id,
        db
    )

    return db.query(
        models.Organization
    ).filter(
        models.Organization.user_id == user_id
    ).all()


@app.post("/organizations/{user_id}")
def create_organization(
    user_id: int,
    organization: schemas.Organization,
    db: Session = Depends(get_db)
):

    require_user(
        user_id,
        db
    )

    name = clean_text(
        organization.name
    )

    domain = normalize_domain(
        organization.domain
    )

    if not name or not domain:

        raise HTTPException(
            status_code=400,
            detail="Organization name and domain are required"
        )


    existing_organization = db.query(
        models.Organization
    ).filter(
        models.Organization.user_id == user_id,
        or_(
            func.lower(models.Organization.name) == name.lower(),
            func.lower(models.Organization.domain) == domain.lower()
        )
    ).first()

    if existing_organization:

        raise HTTPException(
            status_code=409,
            detail="Organization already exists with the same name or domain"
        )


    new_org = models.Organization(
        name=name,
        domain=domain,
        sector=clean_text(organization.sector),
        keywords=clean_text(organization.keywords),
        monitoring_status=validate_monitoring_status(
            organization.monitoring_status
        ),
        user_id=user_id
    )

    db.add(new_org)

    safe_commit(db)

    db.refresh(new_org)

    return new_org


@app.delete("/organizations/{organization_id}")
def delete_organization(
    organization_id: int,
    db: Session = Depends(get_db)
):

    organization = require_organization(
        organization_id,
        db
    )

    delete_organization_data(
        organization_id,
        db
    )

    db.delete(organization)

    safe_commit(db)

    return {
        "message": "Organization deleted successfully"
    }


# =========================
# Sources
# =========================

@app.get("/sources/{user_id}")
def get_sources(
    user_id: int,
    db: Session = Depends(get_db)
):

    require_user(
        user_id,
        db
    )

    return db.query(
        models.Source
    ).filter(
        models.Source.user_id == user_id
    ).all()


@app.post("/sources/{user_id}")
def create_source(
    user_id: int,
    source: schemas.Source,
    db: Session = Depends(get_db)
):

    require_user_organization(
        source.organization_id,
        user_id,
        db
    )

    name = clean_text(
        source.name
    )

    source_type = validate_source_type(
        source.type
    )

    source_url = validate_source_url(
        source_type,
        source.url
    )

    if not name:

        raise HTTPException(
            status_code=400,
            detail="Source name is required"
        )


    existing_source = db.query(
        models.Source
    ).filter(
        models.Source.organization_id == source.organization_id,
        or_(
            func.lower(models.Source.name) == name.lower(),
            func.lower(models.Source.url) == source_url.lower()
        )
    ).first()

    if existing_source:

        raise HTTPException(
            status_code=409,
            detail="This source already exists for the selected organization"
        )


    new_source = models.Source(
        name=name,
        type=source_type,
        url=source_url,
        description=clean_text(source.description),
        enabled=validate_monitoring_status(source.enabled),
        last_checked=clean_text(source.last_checked, "Never"),
        user_id=user_id,
        organization_id=source.organization_id
    )

    db.add(new_source)

    safe_commit(db)

    db.refresh(new_source)

    return new_source


@app.delete("/sources/{source_id}")
def delete_source(
    source_id: int,
    db: Session = Depends(get_db)
):

    source = db.query(
        models.Source
    ).filter(
        models.Source.id == source_id
    ).first()

    if not source:

        raise HTTPException(
            status_code=404,
            detail="Source not found"
        )

    delete_source_data(
        source_id,
        db
    )

    db.delete(source)

    safe_commit(db)

    return {
        "message": "Source deleted successfully"
    }


# =========================
# Threats
# =========================

@app.get("/threats/{user_id}")
def get_threats(
    user_id: int,
    db: Session = Depends(get_db)
):

    require_user(
        user_id,
        db
    )

    return db.query(
        models.Threat
    ).filter(
        models.Threat.user_id == user_id
    ).all()


@app.post("/threats/{user_id}")
def create_threat(
    user_id: int,
    threat: schemas.Threat,
    db: Session = Depends(get_db)
):

    require_user_organization(
        threat.organization_id,
        user_id,
        db
    )

    title = clean_text(
        threat.title
    )

    threat_type = validate_threat_type(
        threat.type
    )

    severity = validate_severity(
        threat.severity
    )

    status = validate_status(
        threat.status
    )

    if not title:

        raise HTTPException(
            status_code=400,
            detail="Threat title is required"
        )


    duplicate_threat = db.query(
        models.Threat
    ).filter(
        models.Threat.user_id == user_id,
        models.Threat.organization_id == threat.organization_id,
        func.lower(models.Threat.title) == title.lower(),
        func.lower(models.Threat.type) == threat_type.lower()
    ).first()

    if duplicate_threat:

        raise HTTPException(
            status_code=409,
            detail="A similar threat already exists for this organization"
        )


    threat_data = {
        "title": title,
        "type": threat_type,
        "severity": severity,
        "description": clean_text(threat.description),
        "status": status,
        "user_id": user_id,
        "organization_id": threat.organization_id
    }

    if hasattr(models.Threat, "priority"):
        threat_data["priority"] = priority_from_severity(
            severity
        )

    if hasattr(models.Threat, "relevance"):
        threat_data["relevance"] = "Manual"

    if hasattr(models.Threat, "confidence_score"):
        threat_data["confidence_score"] = None


    new_threat = models.Threat(
        **threat_data
    )

    db.add(new_threat)

    safe_commit(db)

    db.refresh(new_threat)

    return new_threat


@app.delete("/threats/{threat_id}")
def delete_threat(
    threat_id: int,
    db: Session = Depends(get_db)
):

    threat = db.query(
        models.Threat
    ).filter(
        models.Threat.id == threat_id
    ).first()

    if not threat:

        raise HTTPException(
            status_code=404,
            detail="Threat not found"
        )

    db.delete(threat)

    safe_commit(db)

    return {
        "message": "Threat deleted successfully"
    }


# =========================
# Reports
# =========================

@app.get("/reports/{user_id}")
def get_reports(
    user_id: int,
    db: Session = Depends(get_db)
):

    require_user(
        user_id,
        db
    )

    return db.query(
        models.Report
    ).filter(
        models.Report.user_id == user_id
    ).all()


@app.post("/reports/{user_id}")
def create_report(
    user_id: int,
    report: schemas.Report,
    db: Session = Depends(get_db)
):

    require_user_organization(
        report.organization_id,
        user_id,
        db
    )

    title = clean_text(
        report.title
    )

    report_type = clean_text(
        report.type,
        "CTI"
    )

    report_content = clean_text(
        report.content
    )

    if not title or not report_content:

        raise HTTPException(
            status_code=400,
            detail="Report title and content are required"
        )


    new_report = models.Report(
        title=title,
        type=report_type,
        content=report_content,
        generated_at=getattr(
            report,
            "generated_at",
            None
        ) or datetime.utcnow().isoformat(),
        user_id=user_id,
        organization_id=report.organization_id
    )

    db.add(new_report)

    safe_commit(db)

    db.refresh(new_report)

    return new_report


@app.delete("/reports/{report_id}")
def delete_report(
    report_id: int,
    db: Session = Depends(get_db)
):

    report = db.query(
        models.Report
    ).filter(
        models.Report.id == report_id
    ).first()

    if not report:

        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )


    db.query(
        models.Feedback
    ).filter(
        models.Feedback.report_id == report_id
    ).delete(
        synchronize_session=False
    )

    db.delete(report)

    safe_commit(db)

    return {
        "message": "Report deleted successfully"
    }


# =========================
# Automatic CTI Report Generation
# =========================

@app.post("/generate-report/{organization_id}")
def generate_report(
    organization_id: int,
    db: Session = Depends(get_db)
):

    require_organization(
        organization_id,
        db
    )

    result = generate_cti_report(
        organization_id,
        db
    )

    return result


# =========================
# Feedback
# =========================

@app.get("/feedback")
def get_feedback(
    db: Session = Depends(get_db)
):

    return db.query(
        models.Feedback
    ).all()


@app.post("/feedback")
def create_feedback(
    feedback: schemas.Feedback,
    db: Session = Depends(get_db)
):

    require_user(
        feedback.user_id,
        db
    )

    report = db.query(
        models.Report
    ).filter(
        models.Report.id == feedback.report_id
    ).first()

    if not report:

        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )


    rating = int(feedback.rating)

    if rating < 1 or rating > 5:

        raise HTTPException(
            status_code=400,
            detail="Rating must be between 1 and 5"
        )


    comment = clean_text(
        feedback.comment
    )

    if not comment:

        raise HTTPException(
            status_code=400,
            detail="Feedback comment is required"
        )


    duplicate_feedback = db.query(
        models.Feedback
    ).filter(
        models.Feedback.user_id == feedback.user_id,
        models.Feedback.report_id == feedback.report_id
    ).first()

    if duplicate_feedback:

        raise HTTPException(
            status_code=409,
            detail="Feedback already submitted for this report"
        )


    new_feedback = models.Feedback(
        user_id=feedback.user_id,
        report_id=feedback.report_id,
        comment=comment,
        rating=rating,
        created_at=getattr(
            feedback,
            "created_at",
            None
        ) or datetime.utcnow().isoformat()
    )

    db.add(new_feedback)

    safe_commit(db)

    db.refresh(new_feedback)

    return new_feedback


# =========================
# Collection
# =========================

@app.post("/collect/{organization_id}")
def start_collection(
    organization_id: int,
    db: Session = Depends(get_db)
):

    organization = require_organization(
        organization_id,
        db
    )

    if organization.monitoring_status == "Inactive":

        raise HTTPException(
            status_code=400,
            detail="Organization is inactive"
        )


    result = run_collection(
        organization_id,
        db
    )

    return result


@app.get("/collection-jobs/{organization_id}")
def get_collection_jobs(
    organization_id: int,
    db: Session = Depends(get_db)
):

    require_organization(
        organization_id,
        db
    )

    jobs = db.query(
        models.CollectionJob
    ).filter(
        models.CollectionJob.organization_id == organization_id
    ).all()

    return jobs


@app.get("/collected-data/{organization_id}")
def get_collected_data(
    organization_id: int,
    db: Session = Depends(get_db)
):

    require_organization(
        organization_id,
        db
    )

    data = db.query(
        models.CollectedData
    ).filter(
        models.CollectedData.organization_id == organization_id
    ).all()

    return data


# =========================
# AI Analysis
# =========================

@app.post("/analyze/{organization_id}")
def start_analysis(
    organization_id: int,
    db: Session = Depends(get_db)
):

    require_organization(
        organization_id,
        db
    )

    result = run_analysis(
        organization_id,
        db
    )

    return result


@app.get("/analysis-results/{organization_id}")
def get_analysis_results(
    organization_id: int,
    db: Session = Depends(get_db)
):

    require_organization(
        organization_id,
        db
    )

    results = db.query(
        models.AnalysisResult
    ).join(
        models.CollectedData,
        models.AnalysisResult.collected_data_id
        == models.CollectedData.id
    ).filter(
        models.CollectedData.organization_id
        == organization_id
    ).all()

    return results


# =========================
# Threat Detection + Prioritization
# =========================

@app.post("/detect-threats/{organization_id}")
def detect_threats(
    organization_id: int,
    db: Session = Depends(get_db)
):

    require_organization(
        organization_id,
        db
    )

    result = run_threat_detection(
        organization_id,
        db
    )

    return result


# =========================
# Users
# =========================

@app.post("/users")
def create_user(
    user: schemas.User,
    db: Session = Depends(get_db)
):

    username = clean_text(
        user.username
    )

    email = normalize_email(
        user.email
    )

    password = validate_strong_password(
        user.password
    )

    role = validate_role(
        user.role
    )


    if not username or not email or not password:

        raise HTTPException(
            status_code=400,
            detail="Username, email, and password are required"
        )


    existing_user_by_email = db.query(
        models.User
    ).filter(
        func.lower(models.User.email) == email.lower()
    ).first()

    if existing_user_by_email:

        raise HTTPException(
            status_code=409,
            detail="This email is already registered to another account. Each email can only be used for one account."
        )


    existing_user_by_username = db.query(
        models.User
    ).filter(
        func.lower(models.User.username) == username.lower()
    ).first()

    if existing_user_by_username:

        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )


    new_user = models.User(
        username=username,
        email=email,
        password=password,
        role=role,
        created_at=getattr(
            user,
            "created_at",
            None
        ) or jordan_time_now()
    )

    db.add(new_user)

    safe_commit(db)

    db.refresh(new_user)

    return new_user


@app.get("/users/{admin_id}")
def get_users(
    admin_id: int,
    db: Session = Depends(get_db)
):

    require_admin(
        admin_id,
        db
    )

    return db.query(
        models.User
    ).all()


@app.put("/users/{user_id}/role")
def change_role(
    user_id: int,
    role: str,
    db: Session = Depends(get_db)
):

    user = db.query(
        models.User
    ).filter(
        models.User.id == user_id
    ).first()

    if not user:

        raise HTTPException(
            status_code=404,
            detail="User not found"
        )


    if user.role == "admin":

        raise HTTPException(
            status_code=400,
            detail="Admin role cannot be changed"
        )


    clean_role = validate_role(
        role
    )

    user.role = clean_role

    safe_commit(db)

    db.refresh(user)

    return {
        "message": "Role updated"
    }


@app.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db)
):

    user = db.query(
        models.User
    ).filter(
        models.User.id == user_id
    ).first()

    if not user:

        raise HTTPException(
            status_code=404,
            detail="User not found"
        )


    if user.role == "admin":

        raise HTTPException(
            status_code=400,
            detail="Admin account cannot be deleted"
        )


    delete_user_data(
        user_id,
        db
    )

    db.delete(user)

    safe_commit(db)

    return {
        "message": "User deleted"
    }



@app.get("/users/{user_id}/profile")
def get_user_profile(
    user_id: int,
    db: Session = Depends(get_db)
):

    user = require_user(
        user_id,
        db
    )

    return build_user_profile(
        user
    )


@app.put("/users/{user_id}/change-password")
def change_user_password(
    user_id: int,
    current_password: str,
    new_password: str,
    db: Session = Depends(get_db)
):

    user = require_user(
        user_id,
        db
    )

    clean_current_password = clean_text(
        current_password
    )

    clean_new_password = validate_strong_password(
        new_password
    )

    if not clean_current_password:

        raise HTTPException(
            status_code=400,
            detail="Current password is required"
        )

    if user.password != clean_current_password:

        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect"
        )

    if clean_current_password == clean_new_password:

        raise HTTPException(
            status_code=400,
            detail="New password must be different from current password"
        )

    user.password = clean_new_password

    safe_commit(db)

    db.refresh(user)

    return {
        "message": "Password changed successfully"
    }


# =========================
# Password Reset OTP
# =========================


@app.post("/request-password-reset")
def request_password_reset(
    email: str,
    db: Session = Depends(get_db)
):

    cleanup_expired_reset_codes()


    clean_email = normalize_email(
        email
    )


    if not clean_email:

        raise HTTPException(
            status_code=400,
            detail="Email is required"
        )


    user = db.query(
        models.User
    ).filter(
        func.lower(models.User.email) == clean_email.lower()
    ).first()


    if not user:

        raise HTTPException(
            status_code=404,
            detail="Email not found"
        )


    reset_code = generate_reset_code()

    expires_at = (
        datetime.utcnow()
        + timedelta(
            minutes=get_reset_code_expiry_minutes()
        )
    )


    PASSWORD_RESET_CODES[clean_email] = {
        "code": reset_code,
        "expires_at": expires_at,
        "attempts": 0
    }


    try:

        email_sent = send_password_reset_email(
            clean_email,
            reset_code
        )

    except Exception as error:

        PASSWORD_RESET_CODES.pop(
            clean_email,
            None
        )

        print(
            "PASSWORD RESET EMAIL ERROR:",
            str(error)
        )

        raise HTTPException(
            status_code=500,
            detail="Could not send security code by email. Please check Gmail SMTP settings."
        )


    if not email_sent:

        PASSWORD_RESET_CODES.pop(
            clean_email,
            None
        )

        raise HTTPException(
            status_code=500,
            detail="Gmail SMTP is not configured. Please check backend .env settings."
        )


    return {
        "message": "Security code sent to your email",
        "email_sent": True,
        "expires_in_minutes": get_reset_code_expiry_minutes()
    }


@app.post("/reset-password-with-code")
def reset_password_with_code(
    email: str,
    code: str,
    new_password: str,
    db: Session = Depends(get_db)
):

    cleanup_expired_reset_codes()


    clean_email = normalize_email(
        email
    )

    clean_code = clean_text(
        code
    )

    clean_password = validate_strong_password(
        new_password
    )


    if not clean_email or not clean_code:

        raise HTTPException(
            status_code=400,
            detail="Email and code are required"
        )


    reset_data = PASSWORD_RESET_CODES.get(
        clean_email
    )


    if not reset_data:

        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset code"
        )


    if reset_data["attempts"] >= 5:

        PASSWORD_RESET_CODES.pop(
            clean_email,
            None
        )

        raise HTTPException(
            status_code=400,
            detail="Too many incorrect attempts. Request a new code"
        )


    if reset_data["code"] != clean_code:

        reset_data["attempts"] += 1

        raise HTTPException(
            status_code=400,
            detail="Invalid reset code"
        )


    user = db.query(
        models.User
    ).filter(
        func.lower(models.User.email) == clean_email.lower()
    ).first()


    if not user:

        raise HTTPException(
            status_code=404,
            detail="Email not found"
        )


    user.password = clean_password

    safe_commit(db)

    db.refresh(user)


    PASSWORD_RESET_CODES.pop(
        clean_email,
        None
    )


    return {
        "message": "Password reset successfully"
    }

# =========================
# Login
# =========================

@app.post("/login")
def login(
    email: str,
    password: str,
    db: Session = Depends(get_db)
):

    clean_email = normalize_email(
        email
    )

    clean_password = clean_text(
        password
    )

    user = db.query(
        models.User
    ).filter(
        func.lower(models.User.email) == clean_email.lower(),
        models.User.password == clean_password
    ).first()

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )


    login_time = jordan_time_now()

    if hasattr(
        user,
        "last_login"
    ):

        user.last_login = login_time

        safe_commit(db)

        db.refresh(user)


    return {
        "message": "Login successful",
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "last_login": getattr(
            user,
            "last_login",
            login_time
        )
    }



# =========================
# Logout
# =========================

@app.post("/logout")
def logout():

    return {
        "message": "Logged out"
    }