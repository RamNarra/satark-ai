-- SATARK v2 Forensic Incident Reconstruction Schema
-- PostgreSQL + pgvector + Temporal Knowledge Graph
-- Strict production schema with pgvector, HNSW indexing, and foreign key integrity

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
    -- Progressive stages:
    -- 1. SUSPICIOUS_CONTENT
    -- 2. CLICKED
    -- 3. OPENED
    -- 4. DOWNLOADED
    -- 5. INSTALLED
    -- 6. SHARED_CREDENTIALS
    -- 7. SHARED_OTP
    -- 8. UNAUTHORIZED_TXN
    -- 9. CONFIRMED_LOSS
    -- 10. ONGOING_COMPROMISE
    risk_level TEXT NOT NULL DEFAULT 'UNKNOWN', -- SAFE, LOW, MEDIUM, HIGH, CRITICAL
    summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cases_session_id ON cases(session_id);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_exposure_stage ON cases(exposure_stage);

-- 2. Evidence: Raw multimodal assets normalized into typed records
CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL, -- TEXT, IMAGE, AUDIO, VIDEO, PDF, APK
    storage_uri TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    extracted_text TEXT,
    language TEXT DEFAULT 'en',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(evidence_type);

-- 3. Entities: Discovered atomic artifacts extracted from evidence
CREATE TABLE IF NOT EXISTS entities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL, -- PHONE_NUMBER, UPI_ID, BANK_ACCOUNT, URL, DOMAIN, IP, APP_NAME, ACTOR, AMOUNT
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
    event_type TEXT NOT NULL, -- RECEIVED_MESSAGE, CLICKED_LINK, ENTERED_CREDENTIALS, SHARED_OTP, MONEY_DEBITED
    event_timestamp TIMESTAMPTZ,
    actor TEXT,
    object TEXT,
    confidence NUMERIC(4, 3) NOT NULL DEFAULT 1.000,
    supporting_evidence_ids UUID[] DEFAULT '{}',
    notes TEXT,
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
