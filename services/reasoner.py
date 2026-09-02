"""
Gemini Forensic Reasoner Loop with Strict Backend Provenance Verification.
Inspects grounded evidence artifacts, distinguishes observed actions from text mentions,
and post-validates all model claims against ground-truth evidence IDs.
"""
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from config import get_genai_client, MODEL_PRO
from db.schema.models import CaseTimelineEvent, EventStatus, FinancialLossStatus

logger = logging.getLogger("satark.reasoner")

FORENSIC_SYSTEM_INSTRUCTION = """
You are SATARK's Forensic Incident Investigator.
You analyze raw digital evidence artifacts provided by a victim of cybercrime in India.

CRITICAL FORENSIC RULES:
1. DISTINGUISH MENTION FROM ACTION:
   - If an SMS says "Do not share OTP", the victim DID NOT share OTP.
   - Only declare SHARED_OTP if the victim explicitly confirmed transmitting/telling the OTP, or a transaction followed directly.
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
   - For every timeline event, specify the exact evidence ID from the input that supports it.
   - Mark status as "OBSERVED" if directly stated in text/evidence, or "INFERRED" if deduced.
4. TONE & ADVISORY:
   - If NO_EVIDENCE_OF_LOSS: Stay calm, explain why it is a scam, give preventative blocking advice. DO NOT mention 1930 or police emergency.
   - If CONFIRMED_UNAUTHORIZED_TRANSACTION: State emergency steps clearly (Call 1930 immediately, request bank lien).

Output MUST be valid JSON adhering to this schema:
{
  "exposure_stage": "SUSPICIOUS_CONTENT | CLICKED | DOWNLOADED | INSTALLED | SHARED_CREDENTIALS | SHARED_OTP | UNAUTHORIZED_TXN | CONFIRMED_LOSS",
  "financial_loss_status": "NO_EVIDENCE_OF_LOSS | CREDENTIAL_COMPROMISE_WITHOUT_LOSS | SUSPECTED_UNAUTHORIZED_TRANSACTION | CONFIRMED_UNAUTHORIZED_TRANSACTION | UNKNOWN",
  "risk_level": "SAFE | LOW | MEDIUM | HIGH | CRITICAL",
  "conversational_reply": "Clear, direct guidance in citizen-friendly language",
  "summary": "Forensic assessment summary",
  "events": [
    {
      "event_type": "string",
      "actor": "victim | suspect | bank | system",
      "object": "string",
      "status": "OBSERVED | INFERRED | HYPOTHESIS",
      "evidence_ref": "evidence_id",
      "reasoning": "why this event happened"
    }
  ],
  "relationships": [
    {
      "source_entity": "string",
      "target_entity": "string",
      "relation_type": "CONTAINS_URL | OWNS_UPI | REQUESTS_OTP | DEBITS_ACCOUNT"
    }
  ],
  "recommended_actions": ["action 1", "action 2"],
  "complaint_narrative": "Formal narrative suitable for National Cyber Crime Portal (cybercrime.gov.in) if loss confirmed, else null"
}
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
        user_prompt = (
            f"Input Evidence:\n{json.dumps(evidence_items, indent=2)}\n\n"
            f"Discovered Entities:\n{json.dumps(entities, indent=2)}\n\n"
            f"Forensic Task: Reconstruct the incident timeline and assess financial loss status."
        )

        valid_evidence_ids = {e["id"] for e in evidence_items}

        try:
            response = self.client.models.generate_content(
                model=MODEL_PRO,
                contents=user_prompt,
                config={
                    "system_instruction": FORENSIC_SYSTEM_INSTRUCTION,
                    "response_mime_type": "application/json"
                }
            )
            raw_text = (response.text or "{}").strip()
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:]
            elif raw_text.startswith("```"):
                raw_text = raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]
            raw_text = raw_text.strip()

            try:
                parsed = json.loads(raw_text)
            except json.JSONDecodeError:
                start = raw_text.find("{")
                end = raw_text.rfind("}")
                if start != -1 and end != -1 and end > start:
                    parsed = json.loads(raw_text[start:end+1])
                else:
                    raise

            # Post-model validation: verify evidence provenance
            validated_events = []
            for evt in parsed.get("events", []):
                ref = evt.get("evidence_ref")
                if ref not in valid_evidence_ids:
                    # Model hallucinated an unknown ID; assign first valid evidence ID or omit
                    evt["evidence_ref"] = next(iter(valid_evidence_ids)) if valid_evidence_ids else None
                    evt["status"] = EventStatus.HYPOTHESIS.value
                validated_events.append(evt)
            parsed["events"] = validated_events

            return parsed
        except Exception as e:
            logger.error(f"Gemini Reasoner call failed: {e}")
            return self._safe_fallback_assessment(evidence_items, entities)

    def _safe_fallback_assessment(
        self,
        evidence_items: List[Dict[str, Any]],
        entities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Safe deterministic fallback:
        DOES NOT infer confirmed loss from keywords.
        Returns UNKNOWN if unclear and asks for clarification.
        """
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
