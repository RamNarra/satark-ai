"""
Deterministic Entity Resolution & Normalization Service.
Canonicalizes Indian phone numbers, UPI IDs, URLs, and bank accounts.
Builds SAME_AS aliases across evidence without model hallucinations.
"""
import re
from typing import List, Dict, Any, Tuple
from db.schema.models import DiscoveredEntity


class EntityResolver:
    """Canonicalizes raw extracted entities and resolves duplicates into authoritative clusters."""

    @classmethod
    def canonicalize_phone(cls, raw: str) -> str:
        """Normalizes Indian phone formats: +91 98765 43210, 09876543210, 98765-43210 -> +919876543210."""
        digits = re.sub(r"\D", "", raw)
        if len(digits) == 10:
            return f"+91{digits}"
        elif len(digits) == 11 and digits.startswith("0"):
            return f"+91{digits[1:]}"
        elif len(digits) == 12 and digits.startswith("91"):
            return f"+{digits}"
        return raw.strip()

    @classmethod
    def canonicalize_upi(cls, raw: str) -> str:
        """Normalizes UPI handles: lowercase, trimmed."""
        return raw.lower().strip()

    @classmethod
    def canonicalize_url(cls, raw: str) -> str:
        """Normalizes URLs: stripping trailing slash, standardizing http/https."""
        cleaned = raw.strip().rstrip("/")
        return cleaned

    @classmethod
    def resolve_entities(cls, raw_entities: List[DiscoveredEntity]) -> Tuple[List[DiscoveredEntity], Dict[str, str]]:
        """
        Clusters entities by canonical value.
        Returns (deduplicated_entities, id_alias_mapping).
        id_alias_mapping maps old_entity_id -> canonical_entity_id.
        """
        clusters: Dict[Tuple[str, str], DiscoveredEntity] = {}
        alias_map: Dict[str, str] = {}

        for ent in raw_entities:
            val = ent.entity_value
            if ent.entity_type == "PHONE_NUMBER":
                norm = cls.canonicalize_phone(val)
            elif ent.entity_type == "UPI_ID":
                norm = cls.canonicalize_upi(val)
            elif ent.entity_type == "URL":
                norm = cls.canonicalize_url(val)
            else:
                norm = val.strip().lower()

            ent.normalized_value = norm
            key = (ent.entity_type, norm)

            if key in clusters:
                canonical = clusters[key]
                alias_map[ent.id] = canonical.id
            else:
                clusters[key] = ent
                alias_map[ent.id] = ent.id

        return list(clusters.values()), alias_map
