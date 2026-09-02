"""
Authoritative PostgreSQL Repository for Forensic Cases, Evidence, Entities, Events, and Graph Edges.
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
    """Manages transactional persistence for forensic cases in PostgreSQL."""

    def __init__(self):
        self.engine = get_engine()

    def create_case(self, session_id: str, title: Optional[str] = "Incident First Response", narrative: Optional[str] = None) -> ForensicCase:
        """Creates a new case record in PostgreSQL."""
        import uuid
        case_id = str(uuid.uuid4())
        with self.engine.begin() as conn:
            stmt = text(
                "INSERT INTO cases (id, session_id, title) "
                "VALUES (:id, :sid, :title)"
            )
            conn.execute(stmt, {"id": case_id, "sid": session_id, "title": title})
        return self.get_case(case_id)

    def get_case(self, case_id: str) -> Optional[ForensicCase]:
        """Loads a case and its full evidence, entities, and events from PostgreSQL."""
        with self.engine.begin() as conn:
            row = conn.execute(
                text("SELECT id, session_id, user_id, title, status, exposure_stage, financial_loss_status, risk_level, summary, created_at, updated_at "
                     "FROM cases WHERE id = :cid"),
                {"cid": case_id}
            ).mappings().first()

            if not row:
                return None

            case = ForensicCase(**dict(row))

            # Load Evidence
            ev_rows = conn.execute(
                text("SELECT id, case_id, evidence_type, storage_path, sha256, mime_type, byte_size, original_filename, extracted_text, language, metadata, created_at "
                     "FROM evidence WHERE case_id = :cid ORDER BY created_at ASC"),
                {"cid": case_id}
            ).mappings().all()
            case.evidence = [EvidenceItem(**dict(r)) for r in ev_rows]

            # Load Entities
            ent_rows = conn.execute(
                text("SELECT id, case_id, entity_type, entity_value, normalized_value, confidence, first_seen_evidence_id, metadata, created_at "
                     "FROM entities WHERE case_id = :cid ORDER BY created_at ASC"),
                {"cid": case_id}
            ).mappings().all()
            case.entities = [DiscoveredEntity(**dict(r)) for r in ent_rows]

            # Load Events
            evt_rows = conn.execute(
                text("SELECT id, case_id, event_type, event_timestamp, timestamp_precision, actor, object, status, confidence, evidence_refs, reasoning_trace, created_at "
                     "FROM case_events WHERE case_id = :cid ORDER BY COALESCE(event_timestamp, created_at) ASC"),
                {"cid": case_id}
            ).mappings().all()
            case.events = [CaseTimelineEvent(**dict(r)) for r in evt_rows]

            return case

    def add_evidence(self, ev: EvidenceItem) -> str:
        """Stores evidence record in PostgreSQL."""
        with self.engine.begin() as conn:
            stmt = text(
                "INSERT INTO evidence (id, case_id, evidence_type, storage_path, sha256, mime_type, byte_size, original_filename, extracted_text, language, metadata) "
                "VALUES (:id, :cid, :type, :path, :sha, :mime, :size, :name, :text, :lang, :meta) RETURNING id"
            )
            res = conn.execute(stmt, {
                "id": ev.id,
                "cid": ev.case_id,
                "type": ev.evidence_type,
                "path": ev.storage_path,
                "sha": ev.sha256,
                "mime": ev.mime_type,
                "size": ev.byte_size,
                "name": ev.original_filename,
                "text": ev.extracted_text,
                "lang": ev.language,
                "meta": json.dumps(ev.metadata)
            }).scalar()
            return str(res)

    def add_entities(self, entities: List[DiscoveredEntity]) -> None:
        """Batch inserts discovered entities."""
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

    def save_reconstruction(
        self,
        case_id: str,
        stage: str,
        loss_status: str,
        risk: str,
        summary: str,
        events: List[CaseTimelineEvent],
        relationships: Optional[List[EntityRelationship]] = None
    ) -> None:
        """Persists validated timeline events and updates case status atomically."""
        with self.engine.begin() as conn:
            # 1. Update case status
            conn.execute(
                text("UPDATE cases SET exposure_stage = :stg, financial_loss_status = :fls, risk_level = :risk, summary = :sum, updated_at = CURRENT_TIMESTAMP "
                     "WHERE id = :cid"),
                {"cid": case_id, "stg": stage, "fls": loss_status, "risk": risk, "sum": summary}
            )

            # 2. Insert timeline events
            for evt in events:
                conn.execute(
                    text("INSERT INTO case_events (id, case_id, event_type, event_timestamp, timestamp_precision, actor, object, status, confidence, evidence_refs, reasoning_trace) "
                         "VALUES (:id, :cid, :type, :ts, :prec, :actor, :obj, :st, :conf, :ev_refs, :trace)"),
                    {
                        "id": evt.id,
                        "cid": case_id,
                        "type": evt.event_type,
                        "ts": evt.event_timestamp,
                        "prec": evt.timestamp_precision,
                        "actor": evt.actor,
                        "obj": evt.object,
                        "st": evt.status,
                        "conf": evt.confidence,
                        "ev_refs": json.dumps(evt.evidence_refs),
                        "trace": evt.reasoning_trace
                    }
                )

            # 3. Insert relationships if any
            if relationships:
                for rel in relationships:
                    conn.execute(
                        text("INSERT INTO entity_relationships (id, case_id, source_entity_id, target_entity_id, relation_type, confidence, supporting_evidence_id) "
                             "VALUES (:id, :cid, :src, :tgt, :type, :conf, :ev_id)"),
                        {
                            "id": rel.id,
                            "cid": case_id,
                            "src": rel.source_entity_id,
                            "tgt": rel.target_entity_id,
                            "type": rel.relation_type,
                            "conf": rel.confidence,
                            "ev_id": rel.supporting_evidence_id
                        }
                    )
