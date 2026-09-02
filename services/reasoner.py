"""
Gemini Forensic Reasoner Loop.
Inspects grounded evidence artifacts, distinguishes observed actions from text mentions,
and outputs a structured forensic interpretation.
"""
import json
import logging
from typing import Dict, Any, List, Optional
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
     * NO_EVIDENCE_OF_LOSS (victim resisted scam, blocked sender, or asked if it's fake)
     * CREDENTIAL_COMPROMISE_WITHOUT_LOSS (credentials/OTP entered on phishing site, but no money debited yet)
     * SUSPECTED_UNAUTHORIZED_TRANSACTION (victim suspects debited money but no transaction receipt/SMS shown)
     * CONFIRMED_UNAUTHORIZED_TRANSACTION (actual debit confirmed by transaction SMS, bank statement, or victim testimony)
3. GROUNDING & PROVENANCE:
   - For every timeline event, specify the exact evidence ID it was derived from.
   - Mark status as "OBSERVED" if directly stated, or "INFERRED" if strongly deduced.
4. TONE & ADVISORY:
   - If NO_EVIDENCE_OF_LOSS: Stay calm, explain why it is a scam, give preventative blocking advice. DO NOT mention 1930 or police emergency.
   - If CONFIRMED_UNAUTHORIZED_TRANSACTION: State emergency steps clearly (Call 1930 immediately, request bank lien).

Output MUST be valid JSON adhering to this schema:
{
  "exposure_stage": "SUSPICIOUS_CONTENT | CLICKED | DOWNLOADED | INSTALLED | SHARED_CREDENTIALS | SHARED_OTP | UNAUTHORIZED_TXN | CONFIRMED_LOSS",
  "financial_loss_status": "NO_EVIDENCE_OF_LOSS | CREDENTIAL_COMPROMISE_WITHOUT_LOSS | SUSPECTED_UNAUTHORIZED_TRANSACTION | CONFIRMED_UNAUTHORIZED_TRANSACTION",
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
  "recommended_actions": ["action 1", "action 2"],
  "complaint_narrative": "Formal narrative suitable for National Cyber Crime Portal (cybercrime.gov.in) if loss confirmed, else null"
}
"""


class ForensicReasoner:
    """Executes Gemini reasoning loop with structured output."""

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

            # If model appends multiple JSON blocks or trailing text, find first valid JSON block
            try:
                parsed = json.loads(raw_text)
            except json.JSONDecodeError:
                start = raw_text.find("{")
                end = raw_text.rfind("}")
                if start != -1 and end != -1 and end > start:
                    parsed = json.loads(raw_text[start:end+1])
                else:
                    raise

            return parsed
        except Exception as e:
            logger.error(f"Gemini Reasoner call failed: {e}")
            return self._fallback_grounded_assessment(evidence_items, entities)

    def _fallback_grounded_assessment(
        self,
        evidence_items: List[Dict[str, Any]],
        entities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Safe deterministic fallback when LLM quota or connection is unavailable."""
        corpus = " ".join([e.get("extracted_text", "") for e in evidence_items]).lower()
        
        has_debit = any(w in corpus for w in ["debited", "transferred", "lost money", "unauthorized payment"])
        has_otp_shared = "shared otp" in corpus or "entered otp" in corpus or "gave otp" in corpus

        if has_debit:
            fin_status = FinancialLossStatus.CONFIRMED_UNAUTHORIZED_TRANSACTION.value
            stage = "CONFIRMED_LOSS"
            risk = "CRITICAL"
            reply = "Confirmed financial debit detected. Immediately call 1930 to place a lien on fraudulent transfers."
            actions = ["Call 1930 immediately", "Notify your bank hotline", "File complaint at cybercrime.gov.in"]
        elif has_otp_shared:
            fin_status = FinancialLossStatus.CREDENTIAL_COMPROMISE_WITHOUT_LOSS.value
            stage = "SHARED_OTP"
            risk = "HIGH"
            reply = "High-risk credential compromise detected. Change your banking credentials immediately."
            actions = ["Block affected debit/credit cards", "Reset internet banking password", "Change UPI PIN"]
        else:
            fin_status = FinancialLossStatus.NO_EVIDENCE_OF_LOSS.value
            stage = "SUSPICIOUS_CONTENT"
            risk = "LOW"
            reply = "I have assessed your incident. No financial loss or unauthorized transactions were detected. Do not click suspicious links and block the sender."
            actions = ["Block sender number/account", "Do not open unverified links", "Never share OTPs"]

        return {
            "exposure_stage": stage,
            "financial_loss_status": fin_status,
            "risk_level": risk,
            "conversational_reply": reply,
            "summary": f"Fallback assessment: {fin_status}",
            "events": [],
            "recommended_actions": actions,
            "complaint_narrative": None
        }
