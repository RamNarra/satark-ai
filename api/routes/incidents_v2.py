"""
SATARK v2 Incidents API Router.
Authoritative implementation powered by PostgreSQL CasesRepository,
Durable Storage, OCR/PDF/APK Normalizers, and Gemini Reasoner.
"""
import uuid
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from pydantic import BaseModel

from db.cases_repo import CasesRepository
from db.schema.models import ForensicCase, EvidenceItem, CaseTimelineEvent, FinancialLossStatus
from services.storage import EvidenceStorageService
from services.normalizers import EvidenceParserService, extract_regex_entities
from services.reasoner import ForensicReasoner

router = APIRouter(prefix="/v2/incidents", tags=["Forensic Incidents v2"])

cases_repo = CasesRepository()
storage = EvidenceStorageService()
reasoner = ForensicReasoner()


class CreateIncidentRequest(BaseModel):
    session_id: Optional[str] = None
    title: Optional[str] = "Incident First Response"
    narrative: Optional[str] = None


@router.post("", status_code=201)
async def create_incident(req: CreateIncidentRequest):
    """Creates a new case record in PostgreSQL and saves initial narrative."""
    session_id = req.session_id or f"sess_{str(uuid.uuid4())[:8]}"
    case = cases_repo.create_case(session_id=session_id, title=req.title, narrative=req.narrative)

    if req.narrative and req.narrative.strip():
        data = req.narrative.encode("utf-8")
        rel_path, sha, size = storage.store_bytes(case.id, "initial_narrative.txt", data)
        ev = EvidenceItem(
            case_id=case.id,
            evidence_type="TEXT",
            storage_path=rel_path,
            sha256=sha,
            mime_type="text/plain",
            byte_size=size,
            original_filename="initial_narrative.txt",
            extracted_text=req.narrative
        )
        cases_repo.add_evidence(ev)
        entities = extract_regex_entities(case.id, ev.id, req.narrative)
        cases_repo.add_entities(entities)

    return {
        "case_id": case.id,
        "session_id": case.session_id,
        "status": case.status,
        "exposure_stage": case.exposure_stage,
        "financial_loss_status": case.financial_loss_status
    }


@router.post("/{case_id}/evidence", status_code=201)
async def upload_evidence(case_id: str, file: UploadFile = File(...)):
    """Uploads and normalizes raw evidence artifact with SHA-256 integrity into PostgreSQL."""
    case = cases_repo.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Incident case not found")

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds 50MB ceiling")

    filename = file.filename or "artifact"
    rel_path, sha, size = storage.store_bytes(case_id, filename, content)

    # Classify MIME & parse text
    lower_name = filename.lower()
    extracted_text = ""
    metadata = {}
    
    if lower_name.endswith(".pdf"):
        ev_type = "PDF"
        mime = "application/pdf"
        extracted_text = EvidenceParserService.parse_pdf(content)
    elif lower_name.endswith(".apk"):
        ev_type = "APK"
        mime = "application/vnd.android.package-archive"
        extracted_text, metadata = EvidenceParserService.parse_apk(content)
    elif any(lower_name.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".webp"]):
        ev_type = "IMAGE"
        mime = "image/png"
        extracted_text = EvidenceParserService.parse_image(content)
    else:
        ev_type = "TEXT"
        mime = "text/plain"
        extracted_text = content.decode("utf-8", errors="ignore")

    ev = EvidenceItem(
        case_id=case_id,
        evidence_type=ev_type,
        storage_path=rel_path,
        sha256=sha,
        mime_type=mime,
        byte_size=size,
        original_filename=filename,
        extracted_text=extracted_text,
        metadata=metadata
    )
    cases_repo.add_evidence(ev)

    entities = extract_regex_entities(case_id, ev.id, extracted_text)
    cases_repo.add_entities(entities)

    return {
        "evidence_id": ev.id,
        "sha256": ev.sha256,
        "evidence_type": ev.evidence_type,
        "entities_extracted": len(entities),
        "extracted_snippet": extracted_text[:120] if extracted_text else ""
    }


@router.post("/{case_id}/reconstruct")
async def reconstruct_incident(case_id: str):
    """Executes Gemini 3.8 Forensic Reasoner loop over PostgreSQL case evidence."""
    case = cases_repo.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Incident case not found")

    ev_payloads = [
        {
            "id": e.id,
            "type": e.evidence_type,
            "filename": e.original_filename,
            "extracted_text": e.extracted_text
        } for e in case.evidence
    ]
    ent_payloads = [
        {
            "type": ent.entity_type,
            "value": ent.normalized_value,
            "evidence_id": ent.first_seen_evidence_id
        } for ent in case.entities
    ]

    analysis = reasoner.analyze_incident(ev_payloads, ent_payloads)

    stage = analysis.get("exposure_stage", "UNASSESSED")
    loss_status = analysis.get("financial_loss_status", FinancialLossStatus.UNKNOWN.value)
    risk = analysis.get("risk_level", "UNKNOWN")
    summary = analysis.get("summary", "")

    # Convert event dicts to CaseTimelineEvent dataclasses
    timeline_events: List[CaseTimelineEvent] = []
    for ed in analysis.get("events", []):
        timeline_events.append(CaseTimelineEvent(
            case_id=case_id,
            event_type=ed.get("event_type", "EVENT"),
            actor=ed.get("actor"),
            object=ed.get("object"),
            status=ed.get("status", "OBSERVED"),
            evidence_refs=[ed["evidence_ref"]] if ed.get("evidence_ref") else [],
            reasoning_trace=ed.get("reasoning")
        ))

    cases_repo.save_reconstruction(
        case_id=case_id,
        stage=stage,
        loss_status=loss_status,
        risk=risk,
        summary=summary,
        events=timeline_events
    )

    is_emergency = loss_status == FinancialLossStatus.CONFIRMED_UNAUTHORIZED_TRANSACTION.value

    return {
        "case_id": case.id,
        "exposure_stage": stage,
        "financial_loss_status": loss_status,
        "risk_level": risk,
        "is_emergency": is_emergency,
        "conversational_reply": analysis.get("conversational_reply"),
        "summary": summary,
        "events": analysis.get("events", []),
        "entities": ent_payloads,
        "recommended_actions": analysis.get("recommended_actions", []),
        "complaint_narrative": analysis.get("complaint_narrative")
    }


@router.get("/{case_id}")
async def get_incident(case_id: str):
    """Fetches authoritative PostgreSQL incident state."""
    case = cases_repo.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Incident case not found")

    return {
        "case_id": case.id,
        "session_id": case.session_id,
        "status": case.status,
        "exposure_stage": case.exposure_stage,
        "financial_loss_status": case.financial_loss_status,
        "risk_level": case.risk_level,
        "summary": case.summary,
        "evidence": [
            {
                "id": e.id,
                "type": e.evidence_type,
                "filename": e.original_filename,
                "sha256": e.sha256,
                "size": e.byte_size
            } for e in case.evidence
        ],
        "entities": [
            {
                "type": ent.entity_type,
                "value": ent.normalized_value,
                "confidence": ent.confidence
            } for ent in case.entities
        ],
        "events": [
            {
                "type": evt.event_type,
                "actor": evt.actor,
                "object": evt.object,
                "status": evt.status,
                "evidence_refs": evt.evidence_refs
            } for evt in case.events
        ],
        "created_at": case.created_at.isoformat()
    }
