from google.cloud import firestore
from config import PROJECT_ID
import logging

logger = logging.getLogger(__name__)

_db = None


def get_db() -> firestore.Client:
    global _db
    if _db is None:
        try:
            _db = firestore.Client(project=PROJECT_ID)
            logger.info("Firestore client initialized successfully")
        except Exception as e:
            logger.error(f"Firestore init failed: {e}")
            _db = None
    return _db
