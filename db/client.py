"""
Database connection and pool management for PostgreSQL / Supabase.
Supports pg8000 (standard Python dialect compatible with Google Cloud Run & Supabase)
and SQLite for local testing/ephemeral environments.
"""
import os
import logging
from typing import Optional
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

logger = logging.getLogger("satark.db")

_ENGINE: Optional[Engine] = None


def get_db_url() -> str:
    """
    Constructs or retrieves the database URL.
    Prefers SUPABASE_DB_URL or DATABASE_URL; falls back to local SQLite when unset.
    """
    url = os.getenv("SUPABASE_DB_URL") or os.getenv("DATABASE_URL")
    if url:
        if url.startswith("postgresql://") and "+pg8000" not in url:
            url = url.replace("postgresql://", "postgresql+pg8000://", 1)
        return url

    # Default to persistent local SQLite for testing if no Postgres credentials supplied
    # On serverless (Vercel/AWS Lambda), only /tmp is writable
    if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
        sqlite_path = os.getenv("SQLITE_PATH", "/tmp/satark_forensic.db")
    else:
        sqlite_path = os.getenv("SQLITE_PATH", "data/satark_forensic.db")
    os.makedirs(os.path.dirname(sqlite_path), exist_ok=True)
    return f"sqlite:///{sqlite_path}"


def get_engine() -> Engine:
    """Returns a singleton SQLAlchemy engine with pooling configured."""
    global _ENGINE
    if _ENGINE is None:
        db_url = get_db_url()
        connect_args = {}
        if db_url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}

        _ENGINE = create_engine(
            db_url,
            connect_args=connect_args,
            pool_pre_ping=True
        )
        # Ensure schema tables exist if using SQLite
        if db_url.startswith("sqlite"):
            _init_sqlite_schema(_ENGINE)
        logger.info(f"Database engine initialized with {db_url.split('@')[-1] if '@' in db_url else db_url}")
    return _ENGINE


def _init_sqlite_schema(engine: Engine):
    """Initializes local SQLite tables matching the PostgreSQL schema."""
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                user_id TEXT,
                title TEXT,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                exposure_stage TEXT NOT NULL DEFAULT 'UNASSESSED',
                financial_loss_status TEXT NOT NULL DEFAULT 'UNKNOWN',
                risk_level TEXT NOT NULL DEFAULT 'UNKNOWN',
                summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                mime_type TEXT NOT NULL DEFAULT 'text/plain',
                byte_size INTEGER NOT NULL DEFAULT 0,
                original_filename TEXT NOT NULL,
                extracted_text TEXT,
                language TEXT NOT NULL DEFAULT 'en',
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS entities (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_value TEXT NOT NULL,
                normalized_value TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 1.0,
                first_seen_evidence_id TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS case_events (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_timestamp TIMESTAMP,
                timestamp_precision TEXT NOT NULL DEFAULT 'UNKNOWN',
                actor TEXT,
                object TEXT,
                status TEXT NOT NULL DEFAULT 'OBSERVED',
                confidence REAL NOT NULL DEFAULT 1.0,
                evidence_refs TEXT DEFAULT '[]',
                reasoning_trace TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS entity_relationships (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                source_entity_id TEXT NOT NULL,
                target_entity_id TEXT NOT NULL,
                relation_type TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 1.0,
                supporting_evidence_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))


def check_db_health() -> bool:
    try:
        engine = get_engine()
        with engine.connect() as conn:
            return conn.execute(text("SELECT 1")).scalar() == 1
    except Exception as e:
        logger.warning(f"Database health check failed: {e}")
        return False


def get_db():
    """Legacy compatibility stub for operations.py."""
    try:
        from google.cloud import firestore
        from config import PROJECT_ID
        return firestore.Client(project=PROJECT_ID)
    except Exception:
        return None
