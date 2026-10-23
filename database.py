from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker


# =========================
# Database URL
# =========================

DATABASE_URL = "sqlite:///./osint.db"


# =========================
# Engine
# =========================

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False
    },
    echo=False
)


# =========================
# Enable SQLite Foreign Keys
# =========================

@event.listens_for(engine, "connect")
def enable_sqlite_foreign_keys(dbapi_connection, connection_record):

    cursor = dbapi_connection.cursor()

    cursor.execute(
        "PRAGMA foreign_keys=ON"
    )

    cursor.close()


# =========================
# Session
# =========================

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


# =========================
# Base Model
# =========================

Base = declarative_base()
