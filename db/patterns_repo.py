"""
Repository for Vector Intelligence & Hybrid Retrieval on scam_patterns.
Combines pgvector HNSW cosine similarity with PostgreSQL Full-Text Search (FTS).
"""
import json
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy import text
from db.client import get_engine

logger = logging.getLogger("satark.repo.patterns")


class PatternsRepository:
    """Manages scam pattern taxonomy and hybrid vector/lexical search."""

    def __init__(self):
        self.engine = get_engine()

    def insert_pattern(
        self,
        category: str,
        subtype: str,
        tactics: List[str],
        indicators: Dict[str, Any],
        pattern_summary: str,
        remedy_template: Dict[str, Any],
        embedding: List[float]
    ) -> str:
        """Inserts a structured scam pattern with its 768-dim embedding."""
        with self.engine.begin() as conn:
            stmt = text(
                "INSERT INTO scam_patterns (category, subtype, tactics, indicators, pattern_summary, remedy_template, embedding) "
                "VALUES (:cat, :sub, :tac, :ind, :sum, :rem, :emb) RETURNING id"
            )
            res = conn.execute(stmt, {
                "cat": category,
                "sub": subtype,
                "tac": tactics,
                "ind": json.dumps(indicators),
                "sum": pattern_summary,
                "rem": json.dumps(remedy_template),
                "emb": f"[{','.join(str(x) for x in embedding)}]"
            }).scalar()
            return str(res)

    def hybrid_search(
        self,
        query_text: str,
        query_embedding: List[float],
        top_k: int = 5,
        vector_weight: float = 0.7
    ) -> List[Dict[str, Any]]:
        """
        Executes hybrid search:
        Combines Cosine Distance on HNSW vector index + ts_rank_cd on GIN FTS index.
        Score = vector_weight * (1 - cosine_dist) + (1 - vector_weight) * normalized_fts_rank
        """
        with self.engine.begin() as conn:
            stmt = text("""
                WITH semantic_search AS (
                    SELECT 
                        id,
                        1 - (embedding <=> :vec::vector) AS vector_similarity
                    FROM scam_patterns
                    ORDER BY embedding <=> :vec::vector
                    LIMIT :limit
                ),
                lexical_search AS (
                    SELECT 
                        id,
                        ts_rank_cd(to_tsvector('english', pattern_summary), plainto_tsquery('english', :query)) AS text_rank
                    FROM scam_patterns
                    WHERE to_tsvector('english', pattern_summary) @@ plainto_tsquery('english', :query)
                    LIMIT :limit
                )
                SELECT 
                    p.id,
                    p.category,
                    p.subtype,
                    p.tactics,
                    p.indicators,
                    p.pattern_summary,
                    p.remedy_template,
                    COALESCE(s.vector_similarity, 0.0) AS vector_score,
                    COALESCE(l.text_rank, 0.0) AS text_score,
                    (:vec_weight * COALESCE(s.vector_similarity, 0.0) + (1.0 - :vec_weight) * COALESCE(l.text_rank, 0.0)) AS combined_score
                FROM scam_patterns p
                LEFT JOIN semantic_search s ON p.id = s.id
                LEFT JOIN lexical_search l ON p.id = l.id
                WHERE s.id IS NOT NULL OR l.id IS NOT NULL
                ORDER BY combined_score DESC
                LIMIT :top_k
            """)

            rows = conn.execute(stmt, {
                "vec": f"[{','.join(str(x) for x in query_embedding)}]",
                "query": query_text,
                "limit": top_k * 2,
                "top_k": top_k,
                "vec_weight": vector_weight
            }).mappings().all()

            return [dict(r) for r in rows]
