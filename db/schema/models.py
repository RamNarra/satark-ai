"""
SATARK v2 Forensic Data Models.
Distinguishes observed evidence, atomic entities, and inferred/observed timeline events.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class FinancialLossStatus(str, Enum):
    NO_EVIDENCE_OF_LOSS = "NO_EVIDENCE_OF_LOSS"
    CREDENTIAL_COMPROMISE_WITHOUT_LOSS = "CREDENTIAL_COMPROMISE_WITHOUT_LOSS"
    SUSPECTED_UNAUTHORIZED_TRANSACTION = "SUSPECTED_UNAUTHORIZED_TRANSACTION"
    CONFIRMED_UNAUTHORIZED_TRANSACTION = "CONFIRMED_UNAUTHORIZED_TRANSACTION"
    RECOVERED_OR_LIEN_PLACED = "RECOVERED_OR_LIEN_PLACED"
    UNKNOWN = "UNKNOWN"


class EventStatus(str, Enum):
    OBSERVED = "OBSERVED"        # Directly stated or proven in raw artifact
    INFERRED = "INFERRED"        # Strongly inferred by causal reasoning
    HYPOTHESIS = "HYPOTHESIS"    # Plausible assumption requiring confirmation


@dataclass
class EvidenceItem:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = ""
    evidence_type: str = "TEXT"  # TEXT, IMAGE, AUDIO, VIDEO, PDF, APK
    storage_path: str = ""
    sha256: str = ""
    mime_type: str = "text/plain"
    byte_size: int = 0
    original_filename: str = ""
    extracted_text: Optional[str] = None
    language: str = "en"
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DiscoveredEntity:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = ""
    entity_type: str = ""  # PHONE_NUMBER, UPI_ID, BANK_ACCOUNT, URL, DOMAIN, IP, APP_NAME, AMOUNT
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
    event_type: str = ""
    event_timestamp: Optional[datetime] = None
    timestamp_precision: str = "UNKNOWN"  # EXACT, ESTIMATED, RELATIVE, UNKNOWN
    actor: Optional[str] = None           # victim, suspect, bank, authority
    object: Optional[str] = None
    status: str = EventStatus.OBSERVED.value
    confidence: float = 1.0
    evidence_refs: List[str] = field(default_factory=list)
    reasoning_trace: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ForensicCase:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    user_id: Optional[str] = None
    title: Optional[str] = None
    status: str = "ACTIVE"
    exposure_stage: str = "UNASSESSED"
    financial_loss_status: str = FinancialLossStatus.UNKNOWN.value
    risk_level: str = "UNKNOWN"
    summary: Optional[str] = None
    evidence: List[EvidenceItem] = field(default_factory=list)
    entities: List[DiscoveredEntity] = field(default_factory=list)
    events: List[CaseTimelineEvent] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
