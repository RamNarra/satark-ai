"""
Multimodal Evidence Normalizer Pipeline.
Parses Text, PDF, APK, and Image artifacts (via OCR) into normalized text and extracted atomic entities.
"""
import io
import os
import re
import subprocess
import tempfile
from typing import List, Tuple, Optional
from PIL import Image
from db.schema.models import DiscoveredEntity


def extract_regex_entities(case_id: str, evidence_id: str, text: str) -> List[DiscoveredEntity]:
    """Extracts raw candidate cyber entities from text for grounding."""
    if not text:
        return []
    entities: List[DiscoveredEntity] = []

    # 1. Phone numbers (10 digits starting with 6-9, optional +91/0)
    for m in re.finditer(r'(?:(?:\+91|0)?[6-9]\d{9})', text):
        val = m.group(0)
        norm = val[-10:]
        entities.append(DiscoveredEntity(
            case_id=case_id,
            entity_type="PHONE_NUMBER",
            entity_value=val,
            normalized_value=norm,
            first_seen_evidence_id=evidence_id
        ))

    # 2. UPI IDs
    for m in re.finditer(r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}', text):
        val = m.group(0).lower()
        if not any(val.endswith(x) for x in ['.com', '.org', '.net', '.edu', '.gov', '.in']):
            entities.append(DiscoveredEntity(
                case_id=case_id,
                entity_type="UPI_ID",
                entity_value=val,
                normalized_value=val,
                first_seen_evidence_id=evidence_id
            ))

    # 3. Phishing URLs / Domains
    for m in re.finditer(r'https?://[^\s/$.?#].[^\s]*', text):
        val = m.group(0).rstrip('.,;)"\'')
        entities.append(DiscoveredEntity(
            case_id=case_id,
            entity_type="URL",
            entity_value=val,
            normalized_value=val.lower(),
            first_seen_evidence_id=evidence_id
        ))

    # 4. Currency amounts
    for m in re.finditer(r'(?:[₹]|Rs\.?|INR)\s*([0-9,]+(?:\.\d{2})?)', text, re.IGNORECASE):
        raw_val = m.group(0)
        norm = m.group(1).replace(",", "")
        entities.append(DiscoveredEntity(
            case_id=case_id,
            entity_type="AMOUNT",
            entity_value=raw_val,
            normalized_value=norm,
            first_seen_evidence_id=evidence_id
        ))

    return entities


class EvidenceParserService:
    """Parses raw artifact bytes based on detected MIME / file type."""

    @staticmethod
    def parse_image(data: bytes) -> str:
        """Extracts text from screenshots using local Tesseract OCR engine."""
        try:
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            # Run tesseract directly
            result = subprocess.run(
                ["tesseract", tmp_path, "stdout", "-l", "eng", "--oem", "1"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10
            )
            os.unlink(tmp_path)
            extracted = result.stdout.decode("utf-8", errors="ignore").strip()
            return extracted if extracted else "[OCR extracted no readable text]"
        except Exception as e:
            return f"[OCR Error: {e}]"

    @staticmethod
    def parse_pdf(data: bytes) -> str:
        """Extracts text streams from PDF documents."""
        try:
            import pypdf
            reader = pypdf.PdfReader(io.BytesIO(data))
            text_parts = []
            for i, page in enumerate(reader.pages):
                extracted = page.extract_text() or ""
                if extracted.strip():
                    text_parts.append(f"[Page {i+1}]\n{extracted}")
            return "\n\n".join(text_parts)
        except Exception as e:
            return f"[PDF Parsing Error: {e}]"

    @staticmethod
    def parse_apk(data: bytes) -> Tuple[str, dict]:
        """Extracts package name, permissions, and strings from APK."""
        try:
            from agents.apk_analyzer.agent import run_static_analysis
            result = run_static_analysis(data, filename="upload.apk")
            summary_text = (
                f"Package: {result.get('package_name', 'unknown')}\n"
                f"Permissions: {', '.join(result.get('permissions', {}).get('declared', [])[:10])}\n"
                f"Dangerous: {', '.join(result.get('permissions', {}).get('dangerous', []))}"
            )
            return summary_text, result
        except Exception as e:
            return f"[APK Parsing Error: {e}]", {}
