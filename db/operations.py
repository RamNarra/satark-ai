from db.client import get_db
from datetime import datetime, timezone
import hashlib
import logging
from functools import lru_cache
import os
import time

from google.cloud.firestore_v1.base_vector_query import DistanceMeasure
from google.cloud.firestore_v1.base_query import FieldFilter
from google.cloud.firestore_v1.vector import Vector

from config import LOCATION, MODEL_EMBEDDING, PROJECT_ID

try:
    from google import genai
except Exception:
    genai = None  # type: ignore

logger = logging.getLogger(__name__)

# Collection names (mirrors your original 4 AlloyDB tables)
FRAUD_PATTERNS = "fraud_patterns"
THREAT_INTEL = "threat_intelligence"
CASES = "cases"
OSINT_CACHE = "osint_cache"


_embed_client = (
    genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)
    if genai is not None
    else None
)
EMBEDDING_DIMENSION = int(os.getenv("EMBEDDING_DIMENSION", "768"))


def upsert_fraud_pattern_record(pattern: dict) -> bool:
    """Upsert a curated fraud pattern document used for intelligence matching."""
    db = get_db()
    if not db:
        return False

    try:
        source_key = (
            f"{pattern.get('scam_type', 'unknown')}|"
            f"{pattern.get('sub_type', 'unknown')}|"
            f"{pattern.get('year', 'na')}"
        )
        doc_id = pattern.get("id") or hashlib.sha256(source_key.encode()).hexdigest()[:24]
        payload = {
            **pattern,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "active": bool(pattern.get("active", True)),
        }
        embedding_source = pattern.get("embedding_source_text") or _build_pattern_embedding_text(payload)
        embedding = _get_embedding_vector(embedding_source)
        if embedding:
            payload["embedding"] = Vector(embedding)
            payload["embedding_source_text"] = embedding_source
            payload["embedding_model"] = MODEL_EMBEDDING
            payload["embedding_updated_at"] = datetime.now(timezone.utc).isoformat()
        db.collection(FRAUD_PATTERNS).document(doc_id).set(payload, merge=True)
        return True
    except Exception as e:
        logger.error(f"upsert_fraud_pattern_record failed: {e}")
        return False


def save_case(acknowledgment_id: str, case_data: dict) -> bool:
    """Save a full analysis case — mirrors AlloyDB 'cases' table."""
    db = get_db()
    if not db:
        return False
    try:
        # Keep a stable summary for listing, but also store the full case payload
        # so historical runs can be reloaded (Tasks/Docs links, OSINT, matches).
        doc = {
            "acknowledgment_id": acknowledgment_id,
            "case_id": case_data.get("case_id") or acknowledgment_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scam_type": case_data.get("scam_type", "UNKNOWN"),
            "risk_level": case_data.get("risk_level", "UNKNOWN"),
            "confidence": case_data.get("confidence", 0),
            "golden_hour_active": case_data.get("golden_hour_active", False),
            "input_type": case_data.get("input_type", "text"),
            "summary": case_data.get("summary", ""),
        }
        if isinstance(case_data, dict):
            doc.update(case_data)
        db.collection(CASES).document(acknowledgment_id).set(doc)
        return True
    except Exception as e:
        logger.error(f"save_case failed: {e}")
        return False


def save_fraud_pattern(text: str, scam_type: str, confidence: float) -> bool:
    """Store scam message pattern — mirrors AlloyDB 'fraud_patterns' table."""
    db = get_db()
    if not db:
        return False
    try:
        pattern_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        doc = {
            "hash": pattern_hash,
            "scam_type": scam_type,
            "sub_type": scam_type,
            "confidence": confidence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "preview": text[:200],
            "trigger_phrases": _extract_phrases(text),
            "example_messages": [text[:500]],
            "severity": _severity_from_confidence(confidence),
            "active": True,
            "source": "runtime_observation",
        }
        embedding = _get_embedding_vector(text)
        if embedding:
            doc["embedding"] = Vector(embedding)
            doc["embedding_source_text"] = text
            doc["embedding_model"] = MODEL_EMBEDDING
            doc["embedding_updated_at"] = datetime.now(timezone.utc).isoformat()
        db.collection(FRAUD_PATTERNS).document(pattern_hash).set(doc, merge=True)
        return True
    except Exception as e:
        logger.error(f"save_fraud_pattern failed: {e}")
        return False


def find_similar_patterns(
    query_text: str,
    scam_type: str | None = None,
    limit: int = 5,
    min_score: int = 25,
) -> list:
    """Find semantically similar fraud patterns using Firestore native vector search."""
    db = get_db()
    if not db:
        return []

    if not query_text and not scam_type:
        return []

    try:
        if scam_type and not query_text.strip():
            docs = (
                db.collection(FRAUD_PATTERNS)
                .where(filter=FieldFilter("scam_type", "==", scam_type))
                .limit(limit)
                .stream()
            )
            return [doc.to_dict() for doc in docs]

        embedding = _get_embedding_vector(query_text)
        if not embedding:
            return []

        base_query = db.collection(FRAUD_PATTERNS).where(filter=FieldFilter("active", "==", True))
        if scam_type:
            base_query = base_query.where(filter=FieldFilter("scam_type", "==", scam_type))

        vector_query = base_query.find_nearest(
            vector_field="embedding",
            query_vector=Vector(embedding),
            limit=max(1, int(limit)),
            distance_measure=DistanceMeasure.COSINE,
            distance_result_field="vector_distance",
        )

        matches = []
        for doc in vector_query.stream():
            item = doc.to_dict() or {}
            distance = float(item.get("vector_distance", 2.0))
            score = _distance_to_score(distance, DistanceMeasure.COSINE)
            if score < min_score:
                continue
            item["score"] = score
            item["distance"] = distance
            matches.append(item)

        matches.sort(key=lambda x: x.get("score", 0), reverse=True)
        return matches[:limit]
    except Exception as e:
        logger.error(f"find_similar_patterns failed: {e}")
        return []


def save_threat_intel(indicator: str, indicator_type: str, details: dict) -> bool:
    """Store IOC — mirrors AlloyDB 'threat_intelligence' table."""
    db = get_db()
    if not db:
        return False
    try:
        doc_id = hashlib.sha256(indicator.encode()).hexdigest()[:20]
        doc = {
            "indicator": indicator,
            "type": indicator_type,  # "domain", "ip", "phone", "apk_hash"
            "details": details,
            "first_seen": datetime.now(timezone.utc).isoformat(),
        }
        db.collection(THREAT_INTEL).document(doc_id).set(doc, merge=True)
        return True
    except Exception as e:
        logger.error(f"save_threat_intel failed: {e}")
        return False


def check_threat_intel(indicator: str) -> dict | None:
    """Check if an IOC is already in our database."""
    db = get_db()
    if not db:
        return None
    try:
        doc_id = hashlib.sha256(indicator.encode()).hexdigest()[:20]
        doc = db.collection(THREAT_INTEL).document(doc_id).get()
        return doc.to_dict() if doc.exists else None
    except Exception as e:
        logger.error(f"check_threat_intel failed: {e}")
        return None


def get_osint_cache(indicator: str) -> dict | None:
    """Return cached OSINT result to avoid redundant lookups."""
    db = get_db()
    if not db:
        return None
    try:
        doc_id = hashlib.sha256(indicator.encode()).hexdigest()[:20]
        doc = db.collection(OSINT_CACHE).document(doc_id).get()
        return doc.to_dict() if doc.exists else None
    except Exception as e:
        logger.error(f"get_osint_cache failed: {e}")
        return None


def save_osint_cache(indicator: str, result: dict) -> bool:
    """Cache OSINT result — mirrors AlloyDB 'osint_cache' table."""
    db = get_db()
    if not db:
        return False
    try:
        doc_id = hashlib.sha256(indicator.encode()).hexdigest()[:20]
        doc = {
            "indicator": indicator,
            "result": result,
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }
        db.collection(OSINT_CACHE).document(doc_id).set(doc)
        return True
    except Exception as e:
        logger.error(f"save_osint_cache failed: {e}")
        return False


def get_case_stats() -> dict:
    """Dashboard stats — total cases, scam type breakdown."""
    db = get_db()
    if not db:
        return {"total_cases": 0, "breakdown": {}}
    try:
        docs = db.collection(CASES).stream()
        cases = [doc.to_dict() for doc in docs]
        breakdown = {}
        for c in cases:
            st = c.get("scam_type", "UNKNOWN")
            breakdown[st] = breakdown.get(st, 0) + 1
        return {"total_cases": len(cases), "breakdown": breakdown}
    except Exception as e:
        logger.error(f"get_case_stats failed: {e}")
        return {"total_cases": 0, "breakdown": {}}


def get_fraud_patterns_count(
    active_only: bool = True,
    cache_ttl_seconds: int = 600,
    source: str | None = None,
) -> int:
    """Return count of fraud pattern docs.

    Used to power demo stats like "Similar Cases" without running a full scan
    on every request.
    """
    ttl = max(1, int(cache_ttl_seconds))
    bucket = int(time.time() // ttl)
    source_key = str(source).strip() if source else ""
    return _get_fraud_patterns_count_cached(active_only, source_key, bucket)


@lru_cache(maxsize=16)
def _get_fraud_patterns_count_cached(active_only: bool, source: str, _bucket: int) -> int:
    db = get_db()
    if not db:
        return 0
    try:
        q = db.collection(FRAUD_PATTERNS)
        if active_only:
            q = q.where(filter=FieldFilter("active", "==", True))
        if source:
            q = q.where(filter=FieldFilter("source", "==", source))
        q = q.select([])
        count = 0
        for _ in q.stream():
            count += 1
        return count
    except Exception as e:
        logger.error(f"get_fraud_patterns_count failed: {e}")
        return 0


def get_fraud_patterns_count_by_type(
    scam_type: str,
    active_only: bool = True,
    cache_ttl_seconds: int = 600,
    source: str | None = None,
) -> int:
    """Return count of fraud pattern docs for a given scam type.

    This is used for demo-friendly stats like "312 similar KYC fraud cases",
    while still keeping a separate total corpus size.
    """
    key = str(scam_type or "").strip()
    if not key:
        return 0
    ttl = max(1, int(cache_ttl_seconds))
    bucket = int(time.time() // ttl)
    source_key = str(source).strip() if source else ""
    return _get_fraud_patterns_count_by_type_cached(key, active_only, source_key, bucket)


@lru_cache(maxsize=96)
def _get_fraud_patterns_count_by_type_cached(scam_type: str, active_only: bool, source: str, _bucket: int) -> int:
    db = get_db()
    if not db:
        return 0
    try:
        q = db.collection(FRAUD_PATTERNS).where(filter=FieldFilter("scam_type", "==", scam_type))
        if active_only:
            q = q.where(filter=FieldFilter("active", "==", True))
        if source:
            q = q.where(filter=FieldFilter("source", "==", source))
        q = q.select([])
        count = 0
        for _ in q.stream():
            count += 1
        return count
    except Exception as e:
        logger.error(f"get_fraud_patterns_count_by_type failed: {e}")
        return 0


def _distance_to_score(distance: float, metric: DistanceMeasure) -> int:
    if metric == DistanceMeasure.COSINE:
        similarity = 1.0 - min(max(distance, 0.0), 2.0) / 2.0
    elif metric == DistanceMeasure.DOT_PRODUCT:
        similarity = min(max((distance + 1.0) / 2.0, 0.0), 1.0)
    else:
        similarity = 1.0 / (1.0 + max(distance, 0.0))
    return int(round(similarity * 100))


def _build_pattern_embedding_text(pattern: dict) -> str:
    trigger_blob = " ".join(str(x) for x in pattern.get("trigger_phrases", []))
    red_flag_blob = " ".join(str(x) for x in pattern.get("red_flags", []))
    example_blob = " ".join(str(x) for x in pattern.get("example_messages", []))
    return " | ".join(
        [
            str(pattern.get("scam_type", "")),
            str(pattern.get("sub_type", "")),
            str(pattern.get("official_category", "")),
            trigger_blob,
            red_flag_blob,
            example_blob,
            str(pattern.get("modus_operandi", "")),
        ]
    )[:8000]


@lru_cache(maxsize=1024)
def _get_embedding_vector(text: str) -> tuple[float, ...] | None:
    clean = (text or "").strip()
    if not clean:
        return None
    if _embed_client is None:
        logger.error("Embedding client unavailable; verify google-genai dependency")
        return None
    for attempt in range(3):
        try:
            response = _embed_client.models.embed_content(
                model=MODEL_EMBEDDING,
                contents=clean,
                config={"output_dimensionality": EMBEDDING_DIMENSION},
            )
            if getattr(response, "embeddings", None):
                values = response.embeddings[0].values
            elif getattr(response, "embedding", None):
                values = response.embedding.values
            else:
                return None
            return tuple(float(v) for v in values)
        except Exception as e:
            if "429" in str(e) and attempt < 2:
                wait_seconds = 2 ** attempt
                logger.warning(f"Embedding quota throttled; retrying in {wait_seconds}s")
                time.sleep(wait_seconds)
                continue
            logger.error(f"Embedding generation failed: {e}")
            return None
    return None


def _severity_from_confidence(confidence: float) -> str:
    c = float(confidence or 0)
    if c >= 85:
        return "CRITICAL"
    if c >= 70:
        return "HIGH"
    if c >= 40:
        return "MEDIUM"
    return "LOW"


def _extract_phrases(text: str) -> list[str]:
    text_l = (text or "").lower()
    known_triggers = [
        "otp",
        "account blocked",
        "kyc",
        "lottery",
        "urgent",
        "verify",
        "prize",
        "upi",
        "police",
        "rbi",
        "sbi",
        "hdfc",
        "digital arrest",
    ]
    return [phrase for phrase in known_triggers if phrase in text_l]

def get_recent_cases(limit: int = 10) -> list[dict]:
    db = get_db()
    if not db:
        return []
    try:
        from google.cloud.firestore import Query
        docs = db.collection(CASES).order_by("timestamp", direction=Query.DESCENDING).limit(limit).stream()
        return [doc.to_dict() for doc in docs]
    except Exception as e:
        import logging
        logging.error(f"Error fetching recent cases: {e}")
        return []
