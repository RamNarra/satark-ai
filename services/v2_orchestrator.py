"""
Incident Reconstruction Reasoner Loop for SATARK v2.
Integrates Evidence Normalization, Entity Extraction, Timeline Construction,
Hybrid Vector Retrieval, and Gemini 3.8 Flash tool-calling.
Preserves existing calm vs urgent contracts while powering the v2 forensic state.
"""
import logging
from typing import Dict, Any, List, Optional
from db.schema.models import ForensicCase, EvidenceItem, DiscoveredEntity
from services.evidence_normalizer import EvidenceNormalizer
from services.timeline_constructor import TimelineConstructor

logger = logging.getLogger("satark.v2.orchestrator")


class IncidentReconstructionEngine:
    """Core reasoning engine orchestrating evidence reconstruction."""

    @classmethod
    def process_incident(
        cls,
        session_id: str,
        user_text: str,
        files: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes single-pass incident reconstruction:
        1. Normalizes text and uploaded assets into EvidenceItems
        2. Extracts atomic entities (Phone, UPI, URL, Amount)
        3. Reconstructs timeline and determines progressive exposure_stage
        4. Calibrates verdict between Calm Informational vs Emergency Containment
        """
        files = files or []
        case = ForensicCase(session_id=session_id)

        evidence_items: List[EvidenceItem] = []
        discovered_entities: List[DiscoveredEntity] = []

        # 1. Normalize Text Input
        if user_text:
            text_ev, text_entities = EvidenceNormalizer.normalize_text_input(case.id, user_text)
            evidence_items.append(text_ev)
            discovered_entities.extend(text_entities)

        # 2. Normalize File Attachments
        for f in files:
            file_name = f.get("file_name", "upload")
            file_type = f.get("file_type", "application/octet-stream")
            b64 = f.get("content_base64", "")
            if b64:
                file_ev, file_entities = EvidenceNormalizer.normalize_file_input(
                    case.id, file_name, file_type, b64
                )
                evidence_items.append(file_ev)
                discovered_entities.extend(file_entities)

        # 3. Construct Forensic Timeline & Stage
        stage, risk_level, events = TimelineConstructor.evaluate_timeline(
            case, evidence_items, discovered_entities
        )
        case.exposure_stage = stage
        case.risk_level = risk_level
        case.events = events
        case.evidence = evidence_items
        case.entities = discovered_entities

        # 4. Synthesize Calm vs Urgent Output
        is_urgent = (stage == "CONFIRMED_LOSS") or (risk_level in ["CRITICAL", "HIGH"] and any(e.event_type == "UNAUTHORIZED_DEBIT" for e in events))
        
        # Build conversational reply adhering to calm contract
        if is_urgent:
            conversational_reply = (
                "This looks like confirmed cyber fraud with financial impact. Act immediately: "
                "1. Call 1930 now to request a banking lien. 2. File an official complaint at cybercrime.gov.in."
            )
            summary = "Financial loss confirmed from unauthorized transaction. Emergency containment active."
        else:
            conversational_reply = (
                "I’ve assessed the information you shared. There are no signs of unauthorized transactions or money lost. "
                "Do not click unknown links, do not share OTPs, and block the suspicious sender."
            )
            summary = "Informational first response. No financial loss detected."

        recommended_actions = []
        if is_urgent:
            recommended_actions = [
                "Call 1930 immediately to freeze fraudulent transactions",
                "Notify your bank branch or hotline to place an immediate lien on debited funds",
                "Submit official complaint on cybercrime.gov.in with transaction references",
                "Block and report the recipient UPI ID or beneficiary account"
            ]
        else:
            recommended_actions = [
                "Block and report the sender number or contact",
                "Do not click or open links received from unknown sources",
                "Never share OTPs, PINs, or banking passwords"
            ]

        # Structure complaint draft for urgent cases
        complaint_draft = None
        if is_urgent:
            complaint_draft = {
                "body": (
                    f"Subject: Cyber Fraud Complaint - Unauthorized Transaction\n\n"
                    f"Details of Incident:\n"
                    f"Narrative: {user_text}\n"
                    f"Exposure Stage: {stage}\n"
                    f"Identified Entities: {', '.join([f'{e.entity_type}: {e.normalized_value}' for e in discovered_entities])}\n"
                    f"Date/Time of Incident: {events[-1].event_timestamp.isoformat() if events else 'Recent'}\n"
                    f"Request: Please freeze the beneficiary account and reverse the unauthorized debit under Golden Hour SOP."
                )
            }

        return {
            "status": "completed",
            "risk_level": risk_level,
            "exposure_stage": stage,
            "conversational_reply": conversational_reply,
            "summary": summary,
            "requires_emergency": is_urgent,
            "requires_reporting": is_urgent,
            "requires_financial_blocking": is_urgent,
            "recommended_actions": recommended_actions,
            "complaint_draft": complaint_draft,
            "timeline": [
                {
                    "event_type": ev.event_type,
                    "timestamp": ev.event_timestamp.isoformat() if ev.event_timestamp else None,
                    "notes": ev.notes,
                    "confidence": ev.confidence
                } for ev in events
            ],
            "entities": [
                {
                    "type": ent.entity_type,
                    "value": ent.normalized_value,
                    "confidence": ent.confidence
                } for ent in discovered_entities
            ],
            "why_this_decision": [
                f"Incident reached stage: {stage}",
                f"Risk evaluated as {risk_level}",
                f"{len(discovered_entities)} atomic cyber indicators extracted"
            ]
        }
