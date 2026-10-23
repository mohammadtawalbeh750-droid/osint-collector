from datetime import datetime
import re

from pydantic import BaseModel, ConfigDict, field_validator


EMAIL_REGEX = re.compile(
    r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
)


def current_time():

    return datetime.utcnow().isoformat()


def clean_string(value, default=""):

    if value is None:
        return default

    return str(value).strip()


def normalize_domain(value):

    domain = clean_string(value).lower()

    domain = domain.replace("https://", "")
    domain = domain.replace("http://", "")
    domain = domain.replace("www.", "")

    return domain.split("/")[0].strip()


def normalize_role(value):

    role = clean_string(value).lower()

    if role not in [
        "admin",
        "analyst",
        "viewer"
    ]:
        return "viewer"

    return role


def normalize_status(value, default="Active"):

    status = clean_string(value, default)

    if status not in [
        "Active",
        "Inactive"
    ]:
        return default

    return status


def normalize_threat_status(value):

    status = clean_string(value, "Open")

    if status not in [
        "Open",
        "Investigating",
        "Resolved"
    ]:
        return "Open"

    return status


# =========================
# Organization Schema
# =========================

class Organization(BaseModel):

    name: str
    domain: str
    sector: str = ""
    keywords: str = ""
    monitoring_status: str = "Active"

    @field_validator("name")
    @classmethod
    def clean_name(cls, value):

        return clean_string(value)


    @field_validator("domain")
    @classmethod
    def clean_domain(cls, value):

        return normalize_domain(value)


    @field_validator("sector", "keywords", mode="before")
    @classmethod
    def clean_optional_text(cls, value):

        return clean_string(value)


    @field_validator("monitoring_status")
    @classmethod
    def clean_monitoring_status(cls, value):

        return normalize_status(value)


    model_config = ConfigDict(
        from_attributes=True
    )


# =========================
# Source Schema
# =========================

class Source(BaseModel):

    name: str
    type: str
    url: str
    description: str = ""
    enabled: str = "Active"
    last_checked: str = "Never"

    organization_id: int

    @field_validator("name", "type", "url")
    @classmethod
    def clean_required_text(cls, value):

        return clean_string(value)


    @field_validator("description", mode="before")
    @classmethod
    def clean_description(cls, value):

        return clean_string(value)


    @field_validator("enabled")
    @classmethod
    def clean_enabled(cls, value):

        return normalize_status(value)


    @field_validator("last_checked", mode="before")
    @classmethod
    def clean_last_checked(cls, value):

        return clean_string(value, "Never")


    model_config = ConfigDict(
        from_attributes=True
    )


# =========================
# Threat Schema
# =========================

class Threat(BaseModel):

    title: str
    type: str
    severity: str = "Low"
    description: str = ""
    status: str = "Open"

    organization_id: int

    @field_validator("title", "type")
    @classmethod
    def clean_required_text(cls, value):

        return clean_string(value)


    @field_validator("severity")
    @classmethod
    def clean_severity(cls, value):

        severity = clean_string(value, "Low").title()

        if severity not in [
            "Low",
            "Medium",
            "High",
            "Critical"
        ]:
            return "Low"

        return severity


    @field_validator("description", mode="before")
    @classmethod
    def clean_description(cls, value):

        return clean_string(value)


    @field_validator("status")
    @classmethod
    def clean_status(cls, value):

        return normalize_threat_status(value)


    model_config = ConfigDict(
        from_attributes=True
    )


# =========================
# Report Schema
# =========================

class Report(BaseModel):

    title: str
    type: str = "CTI"
    content: str
    generated_at: str = ""

    organization_id: int

    @field_validator("title", "content")
    @classmethod
    def clean_required_text(cls, value):

        return clean_string(value)


    @field_validator("type", mode="before")
    @classmethod
    def clean_type(cls, value):

        return clean_string(value, "CTI")


    @field_validator("generated_at", mode="before")
    @classmethod
    def clean_generated_at(cls, value):

        return clean_string(value, current_time())


    model_config = ConfigDict(
        from_attributes=True
    )


# =========================
# Collected Data Schema
# =========================

class CollectedData(BaseModel):

    title: str = ""
    content: str = ""
    url: str = ""
    data_type: str = "website"
    collected_at: str = ""

    organization_id: int
    source_id: int | None = None

    @field_validator(
        "title",
        "content",
        "url",
        "data_type",
        mode="before"
    )
    @classmethod
    def clean_text_fields(cls, value):

        return clean_string(value)


    @field_validator("collected_at", mode="before")
    @classmethod
    def clean_collected_at(cls, value):

        return clean_string(value, current_time())


    model_config = ConfigDict(
        from_attributes=True
    )


# =========================
# Analysis Result Schema
# =========================

class AnalysisResult(BaseModel):

    collected_data_id: int

    model_name: str = ""
    classification: str = "uncertain"
    relevance: str = "Low"
    confidence_score: float | None = None
    summary: str = ""
    analyzed_at: str = ""

    @field_validator(
        "model_name",
        "classification",
        "relevance",
        "summary",
        mode="before"
    )
    @classmethod
    def clean_text_fields(cls, value):

        return clean_string(value)


    @field_validator("analyzed_at", mode="before")
    @classmethod
    def clean_analyzed_at(cls, value):

        return clean_string(value, current_time())


    model_config = ConfigDict(
        from_attributes=True
    )


# =========================
# Collection Job Schema
# =========================

class CollectionJob(BaseModel):

    status: str = "Pending"
    started_at: str = ""
    finished_at: str | None = None
    items_collected: int = 0

    organization_id: int

    @field_validator("status", mode="before")
    @classmethod
    def clean_status(cls, value):

        return clean_string(value, "Pending")


    @field_validator("started_at", mode="before")
    @classmethod
    def clean_started_at(cls, value):

        return clean_string(value, current_time())


    @field_validator("finished_at", mode="before")
    @classmethod
    def clean_finished_at(cls, value):

        if value is None:
            return None

        return clean_string(value)


    model_config = ConfigDict(
        from_attributes=True
    )


# =========================
# Feedback Schema
# =========================

class Feedback(BaseModel):

    user_id: int
    report_id: int
    comment: str
    rating: int
    created_at: str = ""

    @field_validator("comment")
    @classmethod
    def clean_comment(cls, value):

        return clean_string(value)


    @field_validator("created_at", mode="before")
    @classmethod
    def clean_created_at(cls, value):

        return clean_string(value, current_time())


    model_config = ConfigDict(
        from_attributes=True
    )


# =========================
# User Schema
# =========================

class User(BaseModel):

    username: str
    email: str
    password: str
    role: str = "viewer"
    created_at: str = ""

    @field_validator("username", "password")
    @classmethod
    def clean_required_text(cls, value):

        return clean_string(value)


    @field_validator("email")
    @classmethod
    def clean_email(cls, value):

        email = clean_string(value).lower()

        return email


    @field_validator("role")
    @classmethod
    def clean_role(cls, value):

        return normalize_role(value)


    @field_validator("created_at", mode="before")
    @classmethod
    def clean_created_at(cls, value):

        return clean_string(value, current_time())


    model_config = ConfigDict(
        from_attributes=True
    )
