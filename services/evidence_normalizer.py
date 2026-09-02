"""
Unified Evidence Normalization Pipeline for SATARK v2.
Transforms raw multimodal inputs (Text, Images, Audio, Video, PDF, APK)
into typed EvidenceItem records and extracts atomic entities before LLM reasoning.
"""
import base64
import hashlib
import re
from typing import List, Dict, Any, Tuple
from db.schema.models import EvidenceItem, DiscoveredEntity


class EvidenceNormalizer:
    """Normalizes raw citizen uploads into forensic evidence artifacts."""

    @staticmethod
    def compute_sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def normalize_text_input(cls, case_id: str, raw_text: str) -> Tuple[EvidenceItem, List[DiscoveredEntity]]:
        """Processes raw user text input and extracts immediate regex entities."""
        content_bytes = raw_text.encode("utf-8")
        sha = cls.compute_sha256(content_bytes)
        ev = EvidenceItem(
            case_id=case_id,
            evidence_type="TEXT",
            storage_uri="inline://text",
            sha256=sha,
            extracted_text=raw_text,
            language="en"
        )
        entities = cls.extract_atomic_entities(case_id, ev.id, raw_text)
        return ev, entities

    @classmethod
    def normalize_file_input(cls, case_id: str, file_name: str, file_type: str, base64_content: str) -> Tuple[EvidenceItem, List[DiscoveredEntity]]:
        """Decodes base64 file, classifies type, and runs initial deterministic parsing."""
        raw_b64 = base64_content.split(",")[-1] if "," in base64_content else base64_content
        data = base64.b64decode(raw_b64)
        sha = cls.compute_sha256(data)

        # Classify evidence type
        lower_name = file_name.lower()
        if lower_name.endswith(".apk") or "android" in file_type:
            ev_type = "APK"
        elif lower_name.endswith(".pdf") or "pdf" in file_type:
            ev_type = "PDF"
        elif any(lower_name.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".webp"]) or "image" in file_type:
            ev_type = "IMAGE"
        elif any(lower_name.endswith(ext) for ext in [".mp3", ".wav", ".m4a", ".ogg"]) or "audio" in file_type:
            ev_type = "AUDIO"
        elif any(lower_name.endswith(ext) for ext in [".mp4", ".mov", ".avi", ".mkv"]) or "video" in file_type:
            ev_type = "VIDEO"
        else:
            ev_type = "TEXT"

        metadata = {
            "file_name": file_name,
            "file_type": file_type,
            "byte_size": len(data)
        }

        extracted_text = ""
        entities: List[DiscoveredEntity] = []

        if ev_type == "TEXT":
            try:
                extracted_text = data.decode("utf-8", errors="ignore")
            except Exception:
                extracted_text = ""
            entities = cls.extract_atomic_entities(case_id, "pending", extracted_text)

        ev = EvidenceItem(
            case_id=case_id,
            evidence_type=ev_type,
            storage_uri=f"evidence://{sha}/{file_name}",
            sha256=sha,
            metadata=metadata,
            extracted_text=extracted_text or None
        )

        for ent in entities:
            ent.first_seen_evidence_id = ev.id

        return ev, entities

    @staticmethod
    def extract_atomic_entities(case_id: str, evidence_id: str, text: str) -> List[DiscoveredEntity]:
        """Deterministic entity extraction across Indian cybercrime indicators."""
        if not text:
            return []
        entities: List[DiscoveredEntity] = []

        # 1. Phone numbers (10 digits, optional +91 / 0)
        phone_matches = re.finditer(r'(?:(?:\+91|0)?[6-9]\d{9})', text)
        for m in phone_matches:
            val = m.group(0)
            norm = val[-10:]
            entities.append(DiscoveredEntity(
                case_id=case_id,
                entity_type="PHONE_NUMBER",
                entity_value=val,
                normalized_value=norm,
                first_seen_evidence_id=evidence_id,
                metadata={"raw_span": m.span()}
            ))

        # 2. UPI IDs (e.g. user@okhdfcbank, 9876543210@paytm)
        upi_matches = re.finditer(r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}', text)
        for m in upi_matches:
            val = m.group(0).lower()
            if not any(val.endswith(x) for x in ['.com', '.org', '.net', '.edu']):
                entities.append(DiscoveredEntity(
                    case_id=case_id,
                    entity_type="UPI_ID",
                    entity_value=val,
                    normalized_value=val,
                    first_seen_evidence_id=evidence_id
                ))

        # 3. URLs and Domains
        url_matches = re.finditer(r'https?://(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_+.~#?&/=]*)', text)
        for m in url_matches:
            val = m.group(0)
            entities.append(DiscoveredEntity(
                case_id=case_id,
                entity_type="URL",
                entity_value=val,
                normalized_value=val.lower().rstrip("/"),
                first_seen_evidence_id=evidence_id
            ))

        # 4. Currency amounts (e.g. ₹25,000 or Rs. 11,000 or 11000 INR)
        amt_matches = re.finditer(r'(?:[₹]|Rs\.?|INR)\s*([0-9,]+(?:\.\d{2})?)', text, re.IGNORECASE)
        for m in amt_matches:
            val = m.group(1).replace(",", "")
            entities.append(DiscoveredEntity(
                case_id=case_id,
                entity_type="AMOUNT",
                entity_value=m.group(0),
                normalized_value=val,
                first_seen_evidence_id=evidence_id
            ))

        return entities
