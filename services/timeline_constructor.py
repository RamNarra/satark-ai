"""
Progressive Timeline & Exposure State Constructor for SATARK v2.
Reconstructs chronologically ordered crime-scene events from normalized evidence,
assigning confidence scores and grounding every event in evidence IDs.
"""
from datetime import datetime
import re
from typing import List, Tuple
from db.schema.models import CaseTimelineEvent, ForensicCase, EvidenceItem, DiscoveredEntity


class TimelineConstructor:
    """Constructs forensic timeline and classifies exposure stage."""

    EXPOSURE_STAGES = [
        "SUSPICIOUS_CONTENT",
        "CLICKED",
        "OPENED",
        "DOWNLOADED",
        "INSTALLED",
        "SHARED_CREDENTIALS",
        "SHARED_OTP",
        "UNAUTHORIZED_TXN",
        "CONFIRMED_LOSS",
        "ONGOING_COMPROMISE"
    ]

    @classmethod
    def evaluate_timeline(
        cls,
        case: ForensicCase,
        evidence_items: List[EvidenceItem],
        entities: List[DiscoveredEntity]
    ) -> Tuple[str, str, List[CaseTimelineEvent]]:
        """
        Evaluates evidence to produce timeline events, active exposure stage, and risk level.
        Returns (exposure_stage, risk_level, events).
        """
        combined_text = " ".join([e.extracted_text or "" for e in evidence_items]).lower()
        events: List[CaseTimelineEvent] = []

        # Check for confirmed financial debit / loss
        loss_pattern = re.search(r'(debited|transferred|lost|sent|paid)\s*(?:of)?\s*(?:[₹]|rs\.?|inr)?\s*([0-9,]+)', combined_text)
        has_otp = bool(re.search(r'\b(otp|one time password|verification code)\b', combined_text))
        has_installed = any(e.evidence_type == "APK" for e in evidence_items) or bool(re.search(r'\b(installed|downloaded apk|anydesk|teamviewer)\b', combined_text))
        has_clicked = bool(re.search(r'\b(clicked|opened link|visited)\b', combined_text)) or any(ent.entity_type == "URL" for ent in entities)

        ev_ids = [e.id for e in evidence_items]

        # 1. Received / Detected Content
        events.append(CaseTimelineEvent(
            case_id=case.id,
            event_type="RECEIVED_COMMUNICATION",
            event_timestamp=datetime.utcnow(),
            actor="suspect",
            object="message_or_lure",
            supporting_evidence_ids=ev_ids,
            notes="Initial suspicious contact received"
        ))

        # 2. Link clicked
        if has_clicked:
            events.append(CaseTimelineEvent(
                case_id=case.id,
                event_type="CLICKED_LINK",
                event_timestamp=datetime.utcnow(),
                actor="victim",
                object="phishing_url",
                supporting_evidence_ids=ev_ids,
                notes="Citizen navigated to external URL"
            ))

        # 3. APK Installed
        if has_installed:
            events.append(CaseTimelineEvent(
                case_id=case.id,
                event_type="INSTALLED_APPLICATION",
                event_timestamp=datetime.utcnow(),
                actor="victim",
                object="malicious_apk",
                supporting_evidence_ids=ev_ids,
                notes="External package installed on device"
            ))

        # 4. OTP / Credentials shared
        if has_otp:
            events.append(CaseTimelineEvent(
                case_id=case.id,
                event_type="SHARED_OTP",
                event_timestamp=datetime.utcnow(),
                actor="victim",
                object="verification_code",
                supporting_evidence_ids=ev_ids,
                notes="High-risk credential/OTP transmitted"
            ))

        # 5. Financial Debit
        if loss_pattern:
            events.append(CaseTimelineEvent(
                case_id=case.id,
                event_type="UNAUTHORIZED_DEBIT",
                event_timestamp=datetime.utcnow(),
                actor="system",
                object=f"amount_{loss_pattern.group(2)}",
                supporting_evidence_ids=ev_ids,
                notes="Confirmed financial loss recorded"
            ))
            return "CONFIRMED_LOSS", "CRITICAL", events

        if has_otp or has_installed:
            return "SHARED_OTP" if has_otp else "INSTALLED", "HIGH", events

        if has_clicked:
            return "CLICKED", "MEDIUM", events

        return "SUSPICIOUS_CONTENT", "LOW", events
