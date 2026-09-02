"""
Gemini Multi-Turn Investigator & Graph Constructor.
Reconstructs grounded incident timeline, maps entity relationships,
and verifies strict evidence provenance.
"""
import json
import logging
from typing import Dict, Any, List, Optional, Set
from config import get_genai_client, MODEL_PRO
from db.schema.models import CaseTimelineEvent, EntityRelationship, EventStatus, FinancialLossStatus
from services.intelligence import PatternIntelligenceService

logger = logging.getLogger("satark.reasoner")

FORENSIC_INVESTIGATOR_PROMPT = """
You are SATARK's Lead Forensic Cybercrime Investigator.
You analyze raw digital evidence artifacts provided by a victim of cybercrime in India.

CRITICAL FORENSIC RULES:
1. DISTINGUISH MENTION FROM ACTION:
   - If an SMS says "Do not share OTP", the victim DID NOT share OTP.
   - Only declare SHARED_OTP if the victim explicitly confirmed transmitting/telling the OTP, or an unauthorized transaction followed directly.
   - If an APK is attached or mentioned, DO NOT infer it was INSTALLED unless explicitly confirmed.
   - If a URL is present, DO NOT infer it was CLICKED unless explicitly stated.
2. FINANCIAL LOSS STATUS:
   - Must be strictly one of:
     * NO_EVIDENCE_OF_LOSS (victim resisted scam, blocked sender, asked for verification, or no money debited)
     * CREDENTIAL_COMPROMISE_WITHOUT_LOSS (credentials/OTP entered on phishing site, but no money debited yet)
     * SUSPECTED_UNAUTHORIZED_TRANSACTION (victim suspects debited money but no transaction receipt/SMS shown)
     * CONFIRMED_UNAUTHORIZED_TRANSACTION (actual debit confirmed by transaction SMS, bank statement, or victim testimony)
     * UNKNOWN (conflicting or ambiguous evidence)
3. GROUNDING & PROVENANCE:
   - For every timeline event, specify the exact evidence ID from the input that directly supports it.
   - If an event cannot be anchored to an evidence ID, DO NOT invent an ID.
   - Mark status as "OBSERVED" if directly stated in text/evidence, or "INFERRED" if deduced from causality.
4. ENTITY RELATIONSHIP GRAPH:
   - Map explicit directed edges between extracted entities (e.g. source: suspect_phone, target: phishing_url, relation: SENDS_LURE).
5. TACTICAL HISTORICAL CONTEXT:
   - Use the provided historical pattern context to explain the scam MO to the victim.

Historical Pattern Context:
{patterns_json}

Input Evidence:
{evidence_json}

Discovered Entities:
{entities_json}

Output MUST be valid JSON adhering to this schema:
{{
  "exposure_stage": "SUSPICIOUS_CONTENT | CLICKED | DOWNLOADED | INSTALLED | SHARED_CREDENTIALS | SHARED_OTP | UNAUTHORIZED_TXN | CONFIRMED_LOSS",
  "financial_loss_status": "NO_EVIDENCE_OF_LOSS | CREDENTIAL_COMPROMISE_WITHOUT_LOSS | SUSPECTED_UNAUTHORIZED_TRANSACTION | CONFIRMED_UNAUTHORIZED_TRANSACTION | UNKNOWN",
  "risk_level": "SAFE | LOW | MEDIUM | HIGH | CRITICAL",
  "conversational_reply": "Clear, direct guidance in citizen-friendly language",
  "summary": "Forensic assessment summary",
  "events": [
    {{
      "event_type": "string",
      "actor": "victim | suspect | bank | system",
      "object": "string",
      "status": "OBSERVED | INFERRED | HYPOTHESIS",
      "evidence_ref": "evidence_id",
      "reasoning": "why this event happened"
    }}
  ],
  "relationships": [
    {{
      "source_entity": "string",
      "target_entity": "string",
      "relation_type": "CONTAINS_URL | OWNS_UPI | SENDS_LURE | REQUESTS_OTP | DEBITS_ACCOUNT",
      "supporting_evidence_id": "evidence_id"
    }}
  ],
  "recommended_actions": ["action 1", "action 2"],
  "complaint_narrative": "Formal narrative suitable for National Cyber Crime Portal (cybercrime.gov.in) if loss confirmed, else null"
}}
"""


class ForensicReasoner:
    """Executes Gemini reasoning loop with structured output and strict validation."""

    def __init__(self):
        self.client = get_genai_client()

    def analyze_incident(
        self,
        evidence_items: List[Dict[str, Any]],
        entities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Runs Gemini model to reconstruct incident from grounded artifacts."""
        combined_text = " ".join([e.get("extracted_text") or "" for e in evidence_items])
        matched_patterns = PatternIntelligenceService.match_patterns(combined_text)

        user_prompt = FORENSIC_INVESTIGATOR_PROMPT.format(
            patterns_json=json.dumps(matched_patterns, indent=2),
            evidence_json=json.dumps(evidence_items, indent=2),
            entities_json=json.dumps(entities, indent=2)
        )

        valid_evidence_ids = {e["id"] for e in evidence_items}

        try:
            models_to_try = [MODEL_PRO, "gemini-3.5-flash", "gemini-3.1-flash-lite"]
            response = None
            last_err = None
            for m in models_to_try:
                try:
                    response = self.client.models.generate_content(
                        model=m,
                        contents=user_prompt,
                        config={"response_mime_type": "application/json"}
                    )
                    if response and response.text:
                        break
                except Exception as ex:
                    last_err = ex
                    err_str = str(ex)
                    if "503" in err_str or "429" in err_str:
                        continue
                    raise

            if not response or not response.text:
                raise last_err or RuntimeError("No response from model pool")

            raw_text = (response.text or "{}").strip()
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:]
            elif raw_text.startswith("```"):
                raw_text = raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]
            raw_text = raw_text.strip()

            start = raw_text.find("{")
            end = raw_text.rfind("}")
            if start != -1 and end != -1 and end > start:
                raw_json = raw_text[start:end+1]
            else:
                raw_json = raw_text

            parsed = json.loads(raw_json)

            # Post-model validation: STRICT PROVENANCE ENFORCEMENT
            # An invalid reference is NEVER silently attached to unrelated evidence.
            validated_events = []
            for evt in parsed.get("events", []):
                ref = evt.get("evidence_ref")
                if ref not in valid_evidence_ids:
                    # Invalid/missing evidence link -> quarantine as HYPOTHESIS with no ref
                    evt["evidence_ref"] = None
                    evt["status"] = EventStatus.HYPOTHESIS.value
                validated_events.append(evt)
            parsed["events"] = validated_events

            # Post-model validation for relationships
            validated_rels = []
            for rel in parsed.get("relationships", []):
                ev_ref = rel.get("supporting_evidence_id")
                if ev_ref not in valid_evidence_ids:
                    rel["supporting_evidence_id"] = None
                validated_rels.append(rel)
            parsed["relationships"] = validated_rels

            return parsed
        except Exception as e:
            logger.error(f"Gemini Reasoner call failed: {e}")
            return self._safe_fallback_assessment(evidence_items, entities)

    def _safe_fallback_assessment(
        self,
        evidence_items: List[Dict[str, Any]],
        entities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Safe deterministic fallback when LLM is unavailable."""
        return {
            "exposure_stage": "SUSPICIOUS_CONTENT",
            "financial_loss_status": FinancialLossStatus.UNKNOWN.value,
            "risk_level": "LOW",
            "conversational_reply": (
                "I have recorded your evidence artifacts. To give you the safest guidance, "
                "please clarify: Did you click any links, enter banking credentials, or notice any debits from your account?"
            ),
            "summary": "Evidence logged. Insufficient verification to confirm loss status; clarification requested.",
            "events": [],
            "relationships": [],
            "recommended_actions": [
                "Do not share passwords, OTPs, or PINs",
                "Do not click unverified links received on SMS or WhatsApp",
                "Verify suspect phone numbers directly with official customer care"
            ],
            "complaint_narrative": None
        }
