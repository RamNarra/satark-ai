"""
Database connection and pool management for PostgreSQL / Supabase.
Supports pg8000 (standard Python dialect compatible with Google Cloud Run & Supabase).
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
    Prefers SUPABASE_DB_URL or DATABASE_URL; falls back to AlloyDB / Cloud SQL parameters.
    """
    url = os.getenv("SUPABASE_DB_URL") or os.getenv("DATABASE_URL")
    if url:
        # Normalize driver for pg8000 if generic postgresql:// is provided
        if url.startswith("postgresql://") and "+pg8000" not in url:
            url = url.replace("postgresql://", "postgresql+pg8000://", 1)
        return url

    # Local fallback / dev database
    user = os.getenv("DB_USER", "postgres")
    password = os.getenv("DB_PASS", "postgres")
    host = os.getenv("DB_HOST", "127.0.0.1")
    port = os.getenv("DB_PORT", "5432")
    dbname = os.getenv("DB_NAME", "satark")
    return f"postgresql+pg8000://{user}:{password}@{host}:{port}/{dbname}"


def get_engine() -> Engine:
    """
    Returns a singleton SQLAlchemy engine with pooling configured.
    """
    global _ENGINE
    if _ENGINE is None:
        db_url = get_db_url()
        _ENGINE = create_engine(
            db_url,
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "5")),
            pool_timeout=30,
            pool_recycle=1800,
            pool_pre_ping=True
        )
        logger.info("Database engine initialized")
    return _ENGINE


def check_db_health() -> bool:
    """
    Runs a simple SELECT 1 to verify database connectivity.
    """
    try:
        engine = get_engine()
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1")).scalar()
            return result == 1
    except Exception as e:
        logger.warning(f"Database health check failed: {e}")
        return False
