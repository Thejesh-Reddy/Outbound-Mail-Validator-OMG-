"""MySQL connection and persistence models for OMG."""

import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import Boolean, CHAR, Column, DateTime, DECIMAL, Enum, ForeignKey, Index, JSON, String, URL, create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker


load_dotenv(Path(__file__).resolve().parent / "n-omg.env")

MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "OMG_Database")

if MYSQL_PASSWORD is None:
    raise RuntimeError("MYSQL_PASSWORD is missing from n-omg.env")
if not re.fullmatch(r"[A-Za-z0-9_]+", MYSQL_DATABASE):
    raise RuntimeError("MYSQL_DATABASE may contain only letters, numbers and underscores")

Base = declarative_base()


def new_record_id():
    return secrets.token_hex(12)


def utc_now_naive():
    """Return UTC time in the naive format used by MySQL DATETIME."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id = Column(CHAR(24), primary_key=True, default=new_record_id)
    name = Column(String(100), nullable=False)
    email = Column(String(320), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False, server_default=text("1"))
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    id = Column(CHAR(24), primary_key=True, default=new_record_id)
    account_id = Column(CHAR(24), ForeignKey("users.id"), nullable=False, index=True)
    jti_hash = Column(CHAR(64), nullable=False, unique=True)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)


class AnalysisRecord(Base):
    __tablename__ = "email_analysis"
    id = Column(CHAR(24), primary_key=True, default=new_record_id)
    transaction_id = Column(CHAR(36), nullable=False, unique=True)
    status = Column(Enum("SAFE", "WARNING", "RESTRICTED", name="omg_status"), nullable=False)
    confidence_score = Column(DECIMAL(5, 2), nullable=False)
    message = Column(String(100), nullable=False)
    text_result = Column(JSON, nullable=True)
    url_result = Column(JSON, nullable=True)
    attachment_result = Column(JSON, nullable=True)
    error_details = Column(JSON, nullable=True)
    popup = Column(JSON, nullable=True)


_url = URL.create(
    "mysql+pymysql",
    username=MYSQL_USER,
    password=MYSQL_PASSWORD,
    host=MYSQL_HOST,
    port=MYSQL_PORT,
    database=MYSQL_DATABASE,
    query={"charset": "utf8mb4"},
)
engine = create_engine(_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def connect_to_mysql():
    """Create the configured database/tables and verify connectivity."""
    server_url = URL.create(
        _url.drivername,
        username=MYSQL_USER,
        password=MYSQL_PASSWORD,
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        query={"charset": "utf8mb4"},
    )
    server_engine = create_engine(server_url, pool_pre_ping=True)
    try:
        with server_engine.begin() as connection:
            connection.execute(
                text(
                    f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DATABASE}` "
                    "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                )
            )
    finally:
        server_engine.dispose()

    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    Base.metadata.create_all(engine)
    print("MySQL connected successfully")


def close_database():
    engine.dispose()