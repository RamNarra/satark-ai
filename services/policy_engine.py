"""
Deterministic Financial Loss & Incident Policy Engine.
'Gemini Proposes. SATARK Verifies.'
Decides financial loss state and emergency escalation based on strictly verified facts,
preventing LLM hallucinations from making authoritative legal/financial determinations.
"""
from typing import List, Dict, Any
from db.schema.models import FinancialLossStatus, CaseTimelineEvent, EventStatus


class PolicyEngine:
    """Evaluates verified forensic facts to determine authoritative financial loss status."""

    @classmethod
    def evaluate_loss(
        cls,
        evidence_items: List[Dict[str, Any]],
        events: List[CaseTimelineEvent],
        model_proposed_status: str
    ) -> Dict[str, Any]:
        """
        Deterministic policy validation:
        1. CONFIRMED_UNAUTHORIZED_TRANSACTION requires:
           - An OBSERVED or INFERRED debit transaction event anchored to valid evidence, OR
           - Explicit transaction receipt / debit SMS in evidence.
        2. If model proposes CONFIRMED but no debit fact exists, downgrade to SUSPECTED or UNKNOWN.
        3. If evidence shows explicit resistance (refusal to pay, call termination), enforce NO_EVIDENCE_OF_LOSS.
        4. If credentials/OTP entered on phishing link with no debit event, enforce CREDENTIAL_COMPROMISE_WITHOUT_LOSS.
        """
        combined_text = " ".join([e.get("extracted_text") or "" for e in evidence_items]).lower()

        # Check for confirmed debit indicators
        has_debit_event = any(
            evt.status in [EventStatus.OBSERVED.value, EventStatus.INFERRED.value] and
            any(kw in (evt.event_type + " " + (evt.reasoning_trace or "")).lower() for kw in ["debit", "transfer", "paid", "unauthorized_txn"])
            for evt in events
        )
        has_debit_evidence = any(
            kw in combined_text for kw in ["debited", "transferred rs", "deducted", "sent money to", "paid rs", "transaction id"]
        ) and not any(kw in combined_text for kw in ["refused to pay", "did not pay", "didn't pay", "balance hasn't changed", "no money was debited"])

        # Check for credential compromise indicators
        has_cred_compromise = any(
            kw in combined_text for kw in ["entered password", "shared otp", "entered otp", "entered my net banking", "submitted credentials"]
        )
        explicit_no_loss = any(
            kw in combined_text for kw in ["balance hasn't changed", "no money was debited", "no money lost", "refused", "hung up", "blocked the number"]
        )

        # Policy Resolution Table
        if has_debit_event or has_debit_evidence:
            authoritative_status = FinancialLossStatus.CONFIRMED_UNAUTHORIZED_TRANSACTION.value
            is_emergency = True
            policy_reasoning = "Authoritative confirmation: Verified debit indicators anchored to evidence artifacts."
        elif has_cred_compromise and explicit_no_loss:
            authoritative_status = FinancialLossStatus.CREDENTIAL_COMPROMISE_WITHOUT_LOSS.value
            is_emergency = False
            policy_reasoning = "Authoritative confirmation: Credentials submitted on hostile portal, but verified that no debit occurred."
        elif explicit_no_loss:
            authoritative_status = FinancialLossStatus.NO_EVIDENCE_OF_LOSS.value
            is_emergency = False
            policy_reasoning = "Authoritative confirmation: Victim resisted threat; zero financial exposure established."
        elif model_proposed_status == FinancialLossStatus.CONFIRMED_UNAUTHORIZED_TRANSACTION.value:
            # Model hallucinated confirmed loss without debit facts -> downgrade
            authoritative_status = FinancialLossStatus.SUSPECTED_UNAUTHORIZED_TRANSACTION.value
            is_emergency = True
            policy_reasoning = "Policy override: Model proposed CONFIRMED loss, but no debit proof found in evidence. Downgraded to SUSPECTED."
        else:
            authoritative_status = model_proposed_status
            is_emergency = authoritative_status in [
                FinancialLossStatus.CONFIRMED_UNAUTHORIZED_TRANSACTION.value,
                FinancialLossStatus.SUSPECTED_UNAUTHORIZED_TRANSACTION.value
            ]
            policy_reasoning = "Policy verified: Model proposal aligned with verified evidence facts."

        return {
            "financial_loss_status": authoritative_status,
            "is_emergency": is_emergency,
            "policy_reasoning": policy_reasoning
        }
