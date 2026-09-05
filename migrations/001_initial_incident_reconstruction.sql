-- SATARK v2 Forensic Incident Reconstruction Schema
-- PostgreSQL + pgvector + Temporal Knowledge Graph
-- Production schema matching db/schema/models.py exactly

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "vector";

-- 1. Cases: Master incident record
CREATE TABLE IF NOT EXISTS cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id TEXT NOT NULL,
    user_id TEXT,
    title TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, CONTAINED, REPORTED, CLOSED
    exposure_stage TEXT NOT NULL DEFAULT 'UNASSESSED',
    -- Stages: SUSPICIOUS_CONTENT, CLICKED, OPENED, DOWNLOADED, INSTALLED, 
    -- SHARED_CREDENTIALS, SHARED_OTP, UNAUTHORIZED_TXN, CONFIRMED_LOSS, ONGOING_COMPROMISE
    financial_loss_status TEXT NOT NULL DEFAULT 'UNKNOWN',
    -- Enums: NO_EVIDENCE_OF_LOSS, CREDENTIAL_COMPROMISE_WITHOUT_LOSS,
    -- SUSPECTED_UNAUTHORIZED_TRANSACTION, CONFIRMED_UNAUTHORIZED_TRANSACTION,
    -- RECOVERED_OR_LIEN_PLACED, UNKNOWN
    risk_level TEXT NOT NULL DEFAULT 'UNKNOWN', -- SAFE, LOW, MEDIUM, HIGH, CRITICAL
    summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cases_session_id ON cases(session_id);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_financial_loss ON cases(financial_loss_status);

-- 2. Evidence: Raw multimodal assets normalized into typed records
CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL, -- TEXT, IMAGE, AUDIO, VIDEO, PDF, APK
    storage_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    mime_type TEXT NOT NULL DEFAULT 'text/plain',
    byte_size BIGINT NOT NULL DEFAULT 0,
    original_filename TEXT NOT NULL,
    extracted_text TEXT,
    language TEXT NOT NULL DEFAULT 'en',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(evidence_type);

-- 3. Entities: Discovered atomic artifacts extracted from evidence
CREATE TABLE IF NOT EXISTS entities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL, -- PHONE_NUMBER, UPI_ID, BANK_ACCOUNT, URL, DOMAIN, IP, APP_NAME, AMOUNT
    entity_value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    confidence NUMERIC(4, 3) NOT NULL DEFAULT 1.000,
    first_seen_evidence_id UUID REFERENCES evidence(id) ON DELETE SET NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_entities_case_id ON entities(case_id);
CREATE INDEX IF NOT EXISTS idx_entities_type_norm ON entities(entity_type, normalized_value);

-- 4. Case Events: Discrete timeline events with provenance pointers
CREATE TABLE IF NOT EXISTS case_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    event_timestamp TIMESTAMPTZ,
    timestamp_precision TEXT NOT NULL DEFAULT 'UNKNOWN', -- EXACT, ESTIMATED, RELATIVE, UNKNOWN
    actor TEXT,
    object TEXT,
    status TEXT NOT NULL DEFAULT 'OBSERVED', -- OBSERVED, INFERRED, HYPOTHESIS
    confidence NUMERIC(4, 3) NOT NULL DEFAULT 1.000,
    evidence_refs UUID[] DEFAULT '{}',
    reasoning_trace TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_case_events_case_id ON case_events(case_id);
CREATE INDEX IF NOT EXISTS idx_case_events_timestamp ON case_events(event_timestamp);

-- 5. Entity Relationships: Graph edges connecting entities and events
CREATE TABLE IF NOT EXISTS entity_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    source_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL, -- CONTAINS_URL, REDIRECTS_TO, OWNS_UPI, REQUESTS_OTP, DEBITS_ACCOUNT, PRECEDES
    confidence NUMERIC(4, 3) NOT NULL DEFAULT 1.000,
    supporting_evidence_id UUID REFERENCES evidence(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_relationships_case_id ON entity_relationships(case_id);
CREATE INDEX IF NOT EXISTS idx_relationships_source ON entity_relationships(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_relationships_target ON entity_relationships(target_entity_id);

-- 6. Intelligence Corpus: Known historical scam patterns & vector embeddings
CREATE TABLE IF NOT EXISTS scam_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category TEXT NOT NULL,
    subtype TEXT NOT NULL,
    tactics TEXT[] NOT NULL DEFAULT '{}',
    indicators JSONB NOT NULL DEFAULT '{}',
    pattern_summary TEXT NOT NULL,
    remedy_template JSONB NOT NULL DEFAULT '{}',
    embedding vector(768),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scam_patterns_category ON scam_patterns(category);
CREATE INDEX IF NOT EXISTS idx_scam_patterns_embedding ON scam_patterns 
USING hnsw (embedding vector_cosine_ops) 
WITH (m = 16, ef_construction = 64);
CREATE INDEX IF NOT EXISTS idx_scam_patterns_fts ON scam_patterns USING gin(to_tsvector('english', pattern_summary));
