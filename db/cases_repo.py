"""
Repository for Cases, Evidence, Entities, CaseEvents, and Relationships in PostgreSQL.
"""
import json
import logging
from typing import List, Optional, Dict, Any
from sqlalchemy import text
from db.client import get_engine
from db.schema.models import (
    ForensicCase,
    EvidenceItem,
    DiscoveredEntity,
    CaseTimelineEvent,
    EntityRelationship,
)

logger = logging.getLogger("satark.repo.cases")


class CasesRepository:
    """Handles CRUD and relational graph lookups for forensic cases."""

    def __init__(self):
        self.engine = get_engine()

    def create_or_get_case(self, session_id: str, user_id: Optional[str] = None, title: Optional[str] = None) -> ForensicCase:
        """Retrieves existing active case for session or creates a new one."""
        with self.engine.begin() as conn:
            row = conn.execute(
                text("SELECT id, session_id, user_id, title, status, exposure_stage, risk_level, summary, created_at, updated_at "
                     "FROM cases WHERE session_id = :sid AND status = 'ACTIVE' ORDER BY created_at DESC LIMIT 1"),
                {"sid": session_id}
            ).mappings().first()

            if row:
                return ForensicCase(**dict(row))

            insert_stmt = text(
                "INSERT INTO cases (session_id, user_id, title) "
                "VALUES (:sid, :uid, :title) "
                "RETURNING id, session_id, user_id, title, status, exposure_stage, risk_level, summary, created_at, updated_at"
            )
            created = conn.execute(
                insert_stmt,
                {"sid": session_id, "uid": user_id, "title": title or "Incident First Response"}
            ).mappings().one()
            return ForensicCase(**dict(created))

    def update_case_stage(self, case_id: str, stage: str, risk_level: str, summary: Optional[str] = None) -> None:
        """Updates progressive exposure stage and risk level."""
        with self.engine.begin() as conn:
            conn.execute(
                text("UPDATE cases SET exposure_stage = :stg, risk_level = :risk, summary = COALESCE(:sum, summary), updated_at = NOW() "
                     "WHERE id = :cid"),
                {"cid": case_id, "stg": stage, "risk": risk_level, "sum": summary}
            )

    def add_evidence(self, evidence: EvidenceItem) -> str:
        """Stores normalized raw evidence record."""
        with self.engine.begin() as conn:
            stmt = text(
                "INSERT INTO evidence (id, case_id, evidence_type, storage_uri, sha256, metadata, extracted_text, language) "
                "VALUES (:id, :cid, :type, :uri, :sha, :meta, :text, :lang) RETURNING id"
            )
            res = conn.execute(stmt, {
                "id": evidence.id,
                "cid": evidence.case_id,
                "type": evidence.evidence_type,
                "uri": evidence.storage_uri,
                "sha": evidence.sha256,
                "meta": json.dumps(evidence.metadata),
                "text": evidence.extracted_text,
                "lang": evidence.language
            }).scalar()
            return str(res)

    def add_entities(self, entities: List[DiscoveredEntity]) -> None:
        """Batch inserts discovered atomic entities."""
        if not entities:
            return
        with self.engine.begin() as conn:
            for ent in entities:
                conn.execute(
                    text("INSERT INTO entities (id, case_id, entity_type, entity_value, normalized_value, confidence, first_seen_evidence_id, metadata) "
                         "VALUES (:id, :cid, :type, :val, :norm, :conf, :ev_id, :meta) "
                         "ON CONFLICT (id) DO NOTHING"),
                    {
                        "id": ent.id,
                        "cid": ent.case_id,
                        "type": ent.entity_type,
                        "val": ent.entity_value,
                        "norm": ent.normalized_value,
                        "conf": ent.confidence,
                        "ev_id": ent.first_seen_evidence_id,
                        "meta": json.dumps(ent.metadata)
                    }
                )

    def add_event(self, event: CaseTimelineEvent) -> str:
        """Appends a grounded timeline event."""
        with self.engine.begin() as conn:
            stmt = text(
                "INSERT INTO case_events (id, case_id, event_type, event_timestamp, actor, object, confidence, supporting_evidence_ids, notes) "
                "VALUES (:id, :cid, :type, :ts, :actor, :obj, :conf, :ev_ids, :notes) RETURNING id"
            )
            res = conn.execute(stmt, {
                "id": event.id,
                "cid": event.case_id,
                "type": event.event_type,
                "ts": event.event_timestamp,
                "actor": event.actor,
                "obj": event.object,
                "conf": event.confidence,
                "ev_ids": event.supporting_evidence_ids,
                "notes": event.notes
            }).scalar()
            return str(res)

    def get_case_timeline(self, case_id: str) -> List[CaseTimelineEvent]:
        """Fetches chronologically sorted timeline events for a case."""
        with self.engine.begin() as conn:
            rows = conn.execute(
                text("SELECT id, case_id, event_type, event_timestamp, actor, object, confidence, supporting_evidence_ids, notes, created_at "
                     "FROM case_events WHERE case_id = :cid ORDER BY COALESCE(event_timestamp, created_at) ASC"),
                {"cid": case_id}
            ).mappings().all()
            return [CaseTimelineEvent(**dict(r)) for r in rows]
