from datetime import datetime

from sqlalchemy import (
    Column,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint
)
from sqlalchemy.orm import relationship

from database import Base


def current_time():

    return datetime.utcnow().isoformat()


# =========================
# User
# =========================

class User(Base):

    __tablename__ = "users"

    __table_args__ = (
        UniqueConstraint(
            "email",
            name="uq_users_email"
        ),
        UniqueConstraint(
            "username",
            name="uq_users_username"
        ),
    )


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(
        String,
        nullable=False,
        index=True
    )

    email = Column(
        String,
        nullable=False,
        index=True
    )

    password = Column(
        String,
        nullable=False
    )

    role = Column(
        String,
        nullable=False,
        default="viewer",
        index=True
    )

    created_at = Column(
        String,
        default=current_time
    )

    last_login = Column(
        String,
        default="Never"
    )


    # Relations

    organizations = relationship(
        "Organization",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    sources = relationship(
        "Source",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    threats = relationship(
        "Threat",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    reports = relationship(
        "Report",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    feedback = relationship(
        "Feedback",
        back_populates="user",
        cascade="all, delete-orphan"
    )


# =========================
# Organization
# =========================

class Organization(Base):

    __tablename__ = "organizations"

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "name",
            name="uq_organizations_user_name"
        ),
        UniqueConstraint(
            "user_id",
            "domain",
            name="uq_organizations_user_domain"
        ),
    )


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    name = Column(
        String,
        nullable=False,
        index=True
    )

    domain = Column(
        String,
        nullable=False,
        index=True
    )

    sector = Column(
        String,
        default=""
    )

    keywords = Column(
        Text,
        default=""
    )

    monitoring_status = Column(
        String,
        nullable=False,
        default="Active",
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )


    # Relations

    user = relationship(
        "User",
        back_populates="organizations"
    )

    sources = relationship(
        "Source",
        back_populates="organization",
        cascade="all, delete-orphan"
    )

    threats = relationship(
        "Threat",
        back_populates="organization",
        cascade="all, delete-orphan"
    )

    reports = relationship(
        "Report",
        back_populates="organization",
        cascade="all, delete-orphan"
    )

    collected_data = relationship(
        "CollectedData",
        back_populates="organization",
        cascade="all, delete-orphan"
    )

    collection_jobs = relationship(
        "CollectionJob",
        back_populates="organization",
        cascade="all, delete-orphan"
    )


# =========================
# Source
# =========================

class Source(Base):

    __tablename__ = "sources"

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "name",
            name="uq_sources_organization_name"
        ),
        UniqueConstraint(
            "organization_id",
            "url",
            name="uq_sources_organization_url"
        ),
    )


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    name = Column(
        String,
        nullable=False,
        index=True
    )

    type = Column(
        String,
        nullable=False,
        index=True
    )

    url = Column(
        Text,
        nullable=False
    )

    description = Column(
        Text,
        default=""
    )

    enabled = Column(
        String,
        nullable=False,
        default="Active",
        index=True
    )

    last_checked = Column(
        String,
        default="Never"
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id"),
        nullable=False,
        index=True
    )


    # Relations

    user = relationship(
        "User",
        back_populates="sources"
    )

    organization = relationship(
        "Organization",
        back_populates="sources"
    )

    collected_data = relationship(
        "CollectedData",
        back_populates="source",
        cascade="all, delete-orphan"
    )


# =========================
# Threat
# =========================

class Threat(Base):

    __tablename__ = "threats"

    __table_args__ = (
        UniqueConstraint(
            "analysis_result_id",
            name="uq_threats_analysis_result_id"
        ),
    )


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    title = Column(
        String,
        nullable=False,
        index=True
    )

    type = Column(
        String,
        nullable=False,
        index=True
    )

    severity = Column(
        String,
        nullable=False,
        default="Low",
        index=True
    )

    priority = Column(
        String,
        default="Low",
        index=True
    )

    relevance = Column(
        String,
        default="Manual",
        index=True
    )

    confidence_score = Column(
        Float,
        nullable=True
    )

    description = Column(
        Text,
        default=""
    )

    status = Column(
        String,
        nullable=False,
        default="Open",
        index=True
    )

    detected_at = Column(
        String,
        default=current_time,
        index=True
    )

    analysis_result_id = Column(
        Integer,
        ForeignKey("analysis_results.id"),
        nullable=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id"),
        nullable=False,
        index=True
    )


    # Relations

    user = relationship(
        "User",
        back_populates="threats"
    )

    organization = relationship(
        "Organization",
        back_populates="threats"
    )

    analysis_result = relationship(
        "AnalysisResult",
        back_populates="threat"
    )


# =========================
# Report
# =========================

class Report(Base):

    __tablename__ = "reports"


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    title = Column(
        String,
        nullable=False,
        index=True
    )

    type = Column(
        String,
        nullable=False,
        default="CTI",
        index=True
    )

    content = Column(
        Text,
        nullable=False
    )

    generated_at = Column(
        String,
        default=current_time,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id"),
        nullable=False,
        index=True
    )


    # Relations

    user = relationship(
        "User",
        back_populates="reports"
    )

    organization = relationship(
        "Organization",
        back_populates="reports"
    )

    feedback = relationship(
        "Feedback",
        back_populates="report",
        cascade="all, delete-orphan"
    )


# =========================
# Collected Data
# =========================

class CollectedData(Base):

    __tablename__ = "collected_data"


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    title = Column(
        String,
        default="",
        index=True
    )

    content = Column(
        Text,
        default=""
    )

    url = Column(
        Text,
        default=""
    )

    data_type = Column(
        String,
        default="website",
        index=True
    )

    collected_at = Column(
        String,
        default=current_time,
        index=True
    )

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id"),
        nullable=False,
        index=True
    )

    source_id = Column(
        Integer,
        ForeignKey("sources.id"),
        nullable=True,
        index=True
    )


    # Relations

    organization = relationship(
        "Organization",
        back_populates="collected_data"
    )

    source = relationship(
        "Source",
        back_populates="collected_data"
    )

    analysis_result = relationship(
        "AnalysisResult",
        back_populates="collected_data",
        uselist=False,
        cascade="all, delete-orphan"
    )


# =========================
# Analysis Result
# =========================

class AnalysisResult(Base):

    __tablename__ = "analysis_results"

    __table_args__ = (
        UniqueConstraint(
            "collected_data_id",
            name="uq_analysis_results_collected_data_id"
        ),
    )


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    collected_data_id = Column(
        Integer,
        ForeignKey("collected_data.id"),
        nullable=False,
        index=True
    )

    model_name = Column(
        String,
        default=""
    )

    classification = Column(
        String,
        default="uncertain",
        index=True
    )

    relevance = Column(
        String,
        default="Low",
        index=True
    )

    confidence_score = Column(
        Float,
        nullable=True
    )

    summary = Column(
        Text,
        default=""
    )

    analyzed_at = Column(
        String,
        default=current_time,
        index=True
    )


    # Relations

    collected_data = relationship(
        "CollectedData",
        back_populates="analysis_result"
    )

    threat = relationship(
        "Threat",
        back_populates="analysis_result",
        uselist=False,
        cascade="all, delete-orphan"
    )


# =========================
# Collection Job
# =========================

class CollectionJob(Base):

    __tablename__ = "collection_jobs"


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    status = Column(
        String,
        nullable=False,
        default="Pending",
        index=True
    )

    started_at = Column(
        String,
        default=current_time,
        index=True
    )

    finished_at = Column(
        String,
        nullable=True
    )

    items_collected = Column(
        Integer,
        default=0
    )

    organization_id = Column(
        Integer,
        ForeignKey("organizations.id"),
        nullable=False,
        index=True
    )


    # Relation

    organization = relationship(
        "Organization",
        back_populates="collection_jobs"
    )


# =========================
# Feedback
# =========================

class Feedback(Base):

    __tablename__ = "feedback"

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "report_id",
            name="uq_feedback_user_report"
        ),
    )


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    report_id = Column(
        Integer,
        ForeignKey("reports.id"),
        nullable=False,
        index=True
    )

    comment = Column(
        Text,
        nullable=False
    )

    rating = Column(
        Integer,
        nullable=False,
        index=True
    )

    created_at = Column(
        String,
        default=current_time,
        index=True
    )


    # Relations

    user = relationship(
        "User",
        back_populates="feedback"
    )

    report = relationship(
        "Report",
        back_populates="feedback"
    )
