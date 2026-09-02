"""
SATARK v2 Incidents API Router.
Implements the core forensic spine:
POST /v2/incidents
POST /v2/incidents/{id}/evidence
POST /v2/incidents/{id}/reconstruct
GET  /v2/incidents/{id}
"""
import uuid
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from pydantic import BaseModel

from db.schema.models import ForensicCase, EvidenceItem, FinancialLossStatus
from services.storage import EvidenceStorageService
from services.normalizers import EvidenceParserService, extract_regex_entities
from services.reasoner import ForensicReasoner

router = APIRouter(prefix="/v2/incidents", tags=["Forensic Incidents v2"])

# In-memory case registry for rapid prototyping (can be backed by CasesRepository)
CASES_DB: Dict[str, ForensicCase] = {}
storage = EvidenceStorageService()
reasoner = ForensicReasoner()


class CreateIncidentRequest(BaseModel):
    session_id: Optional[str] = None
    title: Optional[str] = "Incident First Response"
    narrative: Optional[str] = None


@router.post("", status_code=201)
async def create_incident(req: CreateIncidentRequest):
    """Creates a new forensic case container."""
    case_id = str(uuid.uuid4())
    case = ForensicCase(
        id=case_id,
        session_id=req.session_id or f"sess_{case_id[:8]}",
        title=req.title,
        status="ACTIVE"
    )

    if req.narrative and req.narrative.strip():
        data = req.narrative.encode("utf-8")
        rel_path, sha, size = storage.store_bytes(case_id, "initial_narrative.txt", data)
        ev = EvidenceItem(
            case_id=case_id,
            evidence_type="TEXT",
            storage_path=rel_path,
            sha256=sha,
            mime_type="text/plain",
            byte_size=size,
            original_filename="initial_narrative.txt",
            extracted_text=req.narrative
        )
        case.evidence.append(ev)
        entities = extract_regex_entities(case_id, ev.id, req.narrative)
        case.entities.extend(entities)

    CASES_DB[case_id] = case
    return {
        "case_id": case_id,
        "session_id": case.session_id,
        "status": case.status,
        "evidence_count": len(case.evidence)
    }


@router.post("/{case_id}/evidence", status_code=201)
async def upload_evidence(case_id: str, file: UploadFile = File(...)):
    """Uploads and normalizes raw evidence artifact with SHA-256 integrity."""
    case = CASES_DB.get(case_id)
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
        extracted_text = f"[Image artifact: {filename}]"
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
    case.evidence.append(ev)

    entities = extract_regex_entities(case_id, ev.id, extracted_text)
    case.entities.extend(entities)

    return {
        "evidence_id": ev.id,
        "sha256": ev.sha256,
        "evidence_type": ev.evidence_type,
        "entities_extracted": len(entities)
    }


@router.post("/{case_id}/reconstruct")
async def reconstruct_incident(case_id: str):
    """Executes Gemini 3.8 Forensic Reasoner loop over all case evidence."""
    case = CASES_DB.get(case_id)
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

    # Update case state
    case.exposure_stage = analysis.get("exposure_stage", "UNASSESSED")
    case.financial_loss_status = analysis.get("financial_loss_status", FinancialLossStatus.UNKNOWN.value)
    case.risk_level = analysis.get("risk_level", "UNKNOWN")
    case.summary = analysis.get("summary")

    is_emergency = case.financial_loss_status == FinancialLossStatus.CONFIRMED_UNAUTHORIZED_TRANSACTION.value

    return {
        "case_id": case.id,
        "exposure_stage": case.exposure_stage,
        "financial_loss_status": case.financial_loss_status,
        "risk_level": case.risk_level,
        "is_emergency": is_emergency,
        "conversational_reply": analysis.get("conversational_reply"),
        "summary": case.summary,
        "events": analysis.get("events", []),
        "entities": ent_payloads,
        "recommended_actions": analysis.get("recommended_actions", []),
        "complaint_narrative": analysis.get("complaint_narrative")
    }


@router.get("/{case_id}")
async def get_incident(case_id: str):
    """Fetches complete grounded incident state."""
    case = CASES_DB.get(case_id)
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
        "evidence_count": len(case.evidence),
        "entities_count": len(case.entities),
        "created_at": case.created_at.isoformat()
    }
