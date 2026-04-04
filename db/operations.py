from db.client import get_db
from datetime import datetime, timezone
import hashlib
import logging
import re
from difflib import SequenceMatcher

from google.cloud.firestore_v1.base_query import FieldFilter

logger = logging.getLogger(__name__)

# Collection names (mirrors your original 4 AlloyDB tables)
FRAUD_PATTERNS = "fraud_patterns"
THREAT_INTEL = "threat_intelligence"
CASES = "cases"
OSINT_CACHE = "osint_cache"


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
        doc = {
            "acknowledgment_id": acknowledgment_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scam_type": case_data.get("scam_type", "UNKNOWN"),
            "risk_level": case_data.get("risk_level", "UNKNOWN"),
            "confidence": case_data.get("confidence", 0),
            "golden_hour_active": case_data.get("golden_hour_active", False),
            "input_type": case_data.get("input_type", "text"),
            "summary": case_data.get("summary", ""),
        }
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
    """Find semantically similar fraud patterns using phrase overlap and fuzzy matching."""
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

        query_tokens = _tokenize(query_text)
        corpus = db.collection(FRAUD_PATTERNS).limit(400).stream()

        scored = []
        for doc in corpus:
            item = doc.to_dict() or {}
            score = _score_pattern_match(
                query_text=query_text,
                query_tokens=query_tokens,
                pattern=item,
                scam_type=scam_type,
            )
            if score >= min_score:
                scored.append({**item, "score": score})

        scored.sort(key=lambda x: x.get("score", 0), reverse=True)
        return scored[:limit]
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


def _score_pattern_match(
    query_text: str,
    query_tokens: set[str],
    pattern: dict,
    scam_type: str | None = None,
) -> int:
    query_l = query_text.lower().strip()
    score = 0.0

    pattern_scam = str(pattern.get("scam_type", "")).lower()
    if scam_type and pattern_scam and pattern_scam == scam_type.lower():
        score += 18

    trigger_phrases = [str(p).lower() for p in pattern.get("trigger_phrases", []) if p]
    phrase_hits = sum(1 for phrase in trigger_phrases if phrase and phrase in query_l)
    score += min(phrase_hits * 8, 48)

    examples = [str(x).lower() for x in pattern.get("example_messages", []) if x]
    if examples:
        best_ratio = max(SequenceMatcher(None, query_l, ex).ratio() for ex in examples)
        score += best_ratio * 26

    pattern_blob = " ".join(
        [
            str(pattern.get("preview", "")),
            str(pattern.get("modus_operandi", "")),
            " ".join(str(v) for v in pattern.get("red_flags", [])),
            " ".join(trigger_phrases),
        ]
    )
    pattern_tokens = _tokenize(pattern_blob)
    token_overlap = _jaccard(query_tokens, pattern_tokens)
    score += token_overlap * 22

    severity_bonus = {
        "CRITICAL": 8,
        "HIGH": 5,
        "MEDIUM": 2,
    }.get(str(pattern.get("severity", "")).upper(), 0)
    score += severity_bonus

    return int(min(score, 100))


def _tokenize(text: str) -> set[str]:
    if not text:
        return set()
    tokens = re.findall(r"[a-zA-Z0-9]+", text.lower())
    return {t for t in tokens if len(t) > 2}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a.intersection(b))
    union = len(a.union(b))
    return inter / union if union else 0.0


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
