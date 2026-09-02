"""
Data models for SATARK v2 Incident Reconstruction Engine.
Typed dataclasses representing Cases, Evidence, Entities, CaseEvents, and Relationships.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class EvidenceItem:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = ""
    evidence_type: str = "TEXT"  # TEXT, IMAGE, AUDIO, VIDEO, PDF, APK
    storage_uri: str = ""
    sha256: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    extracted_text: Optional[str] = None
    language: str = "en"
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DiscoveredEntity:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = ""
    entity_type: str = ""  # PHONE_NUMBER, UPI_ID, BANK_ACCOUNT, URL, DOMAIN, IP, APP_NAME, ACTOR, AMOUNT
    entity_value: str = ""
    normalized_value: str = ""
    confidence: float = 1.0
    first_seen_evidence_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class CaseTimelineEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = ""
    event_type: str = ""  # RECEIVED_MESSAGE, CLICKED_LINK, ENTERED_CREDENTIALS, SHARED_OTP, MONEY_DEBITED
    event_timestamp: Optional[datetime] = None
    actor: Optional[str] = None
    object: Optional[str] = None
    confidence: float = 1.0
    supporting_evidence_ids: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class EntityRelationship:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = ""
    source_entity_id: str = ""
    target_entity_id: str = ""
    relation_type: str = ""  # CONTAINS_URL, REDIRECTS_TO, OWNS_UPI, REQUESTS_OTP, DEBITS_ACCOUNT, PRECEDES
    confidence: float = 1.0
    supporting_evidence_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ForensicCase:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    user_id: Optional[str] = None
    title: Optional[str] = None
    status: str = "ACTIVE"
    exposure_stage: str = "UNASSESSED"
    risk_level: str = "UNKNOWN"
    summary: Optional[str] = None
    evidence: List[EvidenceItem] = field(default_factory=list)
    entities: List[DiscoveredEntity] = field(default_factory=list)
    events: List[CaseTimelineEvent] = field(default_factory=list)
    relationships: List[EntityRelationship] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
