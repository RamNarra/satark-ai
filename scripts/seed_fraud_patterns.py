import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db.operations import upsert_fraud_pattern_record  # noqa: E402


# Curated patterns for initial intelligence corpus.
# Sources are captured as references for judges and demo narrative.
PATTERNS = [
    {
        "scam_type": "Investment Fraud",
        "sub_type": "Fake Trading Group",
        "official_category": "Investment/Trading Fraud",
        "national_cases": 100000,
        "loss_crore": 4000,
        "severity": "CRITICAL",
        "trigger_phrases": [
            "guaranteed returns",
            "vip trading group",
            "double your money",
            "limited slots",
            "withdrawal fee",
        ],
        "red_flags": [
            "Unrealistic monthly returns",
            "Telegram/WhatsApp closed group pressure",
            "Initial fake profit screenshots",
            "New deposit required to unlock withdrawals",
        ],
        "example_messages": [
            "Join our VIP stock group and get guaranteed 30 percent monthly returns.",
            "Your profit is ready. Pay processing fee to withdraw now.",
        ],
        "modus_operandi": "Fraudsters build trust with fake profits, then block withdrawals after repeated deposits.",
        "source": "I4C + media summaries (2024)",
    },
    {
        "scam_type": "Digital Arrest",
        "sub_type": "Fake CBI/ED Officer",
        "official_category": "Impersonation Fraud",
        "national_cases": 63481,
        "loss_crore": 1616,
        "severity": "CRITICAL",
        "trigger_phrases": [
            "digital arrest",
            "arrest warrant",
            "money laundering case",
            "stay on video call",
            "safe account transfer",
        ],
        "red_flags": [
            "Threat of immediate arrest",
            "Long coercive video call",
            "Demand for transfer to government safe account",
        ],
        "example_messages": [
            "This is cyber crime branch. Your Aadhaar is linked to money laundering.",
            "You are under digital arrest. Do not disconnect the call.",
        ],
        "modus_operandi": "Impersonation and fear are used to force urgent transfers under false legal threats.",
        "source": "I4C + state police advisories",
    },
    {
        "scam_type": "UPI Fraud",
        "sub_type": "Collect Request Scam",
        "official_category": "UPI/Payment Fraud",
        "national_cases": 632000,
        "loss_crore": 2800,
        "severity": "HIGH",
        "trigger_phrases": [
            "accept request to receive",
            "scan qr to get money",
            "olx buyer",
            "1 rupee verification",
        ],
        "red_flags": [
            "Collect request disguised as credit",
            "Fake buyer urgency",
            "Repeated insistence on QR/UPI approval",
        ],
        "example_messages": [
            "Please accept this UPI request to receive your payment.",
            "Scan this QR to collect your refund instantly.",
        ],
        "modus_operandi": "Victim approves a debit collect request while believing money is incoming.",
        "source": "NPCI fraud trends + police alerts",
    },
    {
        "scam_type": "KYC Fraud",
        "sub_type": "Bank KYC Update",
        "official_category": "Identity Theft",
        "severity": "CRITICAL",
        "trigger_phrases": [
            "kyc update",
            "account blocked",
            "verify aadhaar",
            "update pan",
            "bank compliance",
        ],
        "red_flags": [
            "Threatened account suspension",
            "Link to non-bank domain",
            "Request for OTP and account credentials",
        ],
        "example_messages": [
            "Your bank account will be blocked today. Complete KYC now.",
            "Update Aadhaar-PAN link via this urgent link.",
        ],
        "modus_operandi": "Victim enters credentials on phishing page and account is drained.",
        "source": "State cyber bulletins",
    },
    {
        "scam_type": "Part-Time Job Scam",
        "sub_type": "Task/Rating Scam",
        "official_category": "Job/Employment Fraud",
        "severity": "HIGH",
        "trigger_phrases": [
            "work from home",
            "like and earn",
            "hotel rating task",
            "prepaid task",
            "daily income",
        ],
        "red_flags": [
            "Easy money promise",
            "Small initial payout to build trust",
            "Deposit required to unlock commissions",
        ],
        "example_messages": [
            "Like videos and earn 5000 per day from home.",
            "Complete prepaid tasks to release your commission.",
        ],
        "modus_operandi": "Scammer lures victims with micro-tasks, then extracts repeated deposits.",
        "source": "NCRP trend analysis",
    },
    {
        "scam_type": "Lottery/Prize Fraud",
        "sub_type": "KBC Lucky Draw",
        "official_category": "Lottery/Prize Fraud",
        "severity": "HIGH",
        "trigger_phrases": [
            "you have won",
            "kbc lucky draw",
            "claim within 2 hours",
            "processing fee",
            "otp to verify prize",
        ],
        "red_flags": [
            "Unsolicited prize claim",
            "Urgent expiry window",
            "Request for sensitive data to release prize",
        ],
        "example_messages": [
            "Congratulations! You won 5 lakh in KBC lucky draw. Submit OTP now.",
            "Claim your government lottery reward before deadline.",
        ],
        "modus_operandi": "Fraudsters use fake winnings to harvest money and banking credentials.",
        "source": "NCRP + cyber advisory compilations",
    },
    {
        "scam_type": "Sextortion",
        "sub_type": "Recorded Video Call Blackmail",
        "official_category": "Sextortion/Blackmail",
        "severity": "CRITICAL",
        "trigger_phrases": [
            "i recorded your video",
            "pay or i send to family",
            "viral video",
            "urgent payment",
        ],
        "red_flags": [
            "Immediate blackmail demand",
            "Threat to expose private content",
            "Repeated extortion after payment",
        ],
        "example_messages": [
            "Pay 50,000 now or your video goes to all contacts.",
            "We will post your recording publicly if unpaid.",
        ],
        "modus_operandi": "Extortion follows a manipulated explicit call recording.",
        "source": "Police cyber extortion advisories",
    },
    {
        "scam_type": "Fake Customer Care",
        "sub_type": "Refund/Bank Support Impersonation",
        "official_category": "Customer Care Fraud",
        "severity": "CRITICAL",
        "trigger_phrases": [
            "refund processing",
            "share otp for verification",
            "install anydesk",
            "suspicious activity on your account",
        ],
        "red_flags": [
            "Impersonation of known brands",
            "Remote access app request",
            "OTP demand under pretext of security",
        ],
        "example_messages": [
            "This is bank support. Share OTP to secure your account.",
            "Install AnyDesk for instant refund assistance.",
        ],
        "modus_operandi": "Attackers impersonate support teams to gain device or account control.",
        "source": "Banking fraud advisories",
    },
    {
        "scam_type": "Loan App Fraud",
        "sub_type": "Predatory Instant Loan",
        "official_category": "Loan App Fraud",
        "severity": "HIGH",
        "trigger_phrases": [
            "instant loan",
            "no cibil",
            "approval in 5 minutes",
            "download app now",
        ],
        "red_flags": [
            "Excessive permissions",
            "Harassment for repayment",
            "Contact list misuse",
        ],
        "example_messages": [
            "Get instant loan with no documents. Install app now.",
            "Pre-approved loan offer for you today only.",
        ],
        "modus_operandi": "Apps abuse phone data and extort through harassment after disbursal.",
        "source": "RBI + state cyber warnings",
    },
    {
        "scam_type": "Matrimonial Fraud",
        "sub_type": "Fake NRI Profile",
        "official_category": "Matrimonial/Romance Fraud",
        "severity": "HIGH",
        "trigger_phrases": [
            "nri profile",
            "customs duty",
            "gift stuck at airport",
            "medical emergency transfer",
        ],
        "red_flags": [
            "Fast emotional trust building",
            "Move off platform to private chat",
            "Repeated emergency money requests",
        ],
        "example_messages": [
            "I sent a gift from abroad; pay customs fee to release it.",
            "Emergency surgery needed, please transfer urgently.",
        ],
        "modus_operandi": "Long-con emotional manipulation culminating in emergency transfer requests.",
        "source": "NCRP romance fraud trends",
    },
]


def seed() -> None:
    inserted = 0
    for item in PATTERNS:
        record = {
            **item,
            "year": 2024,
            "active": True,
            "version": "seed-2026-04",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        ok = upsert_fraud_pattern_record(record)
        if ok:
            inserted += 1
            print(f"[OK] {record['scam_type']} :: {record['sub_type']}")
        else:
            print(f"[FAIL] {record['scam_type']} :: {record['sub_type']}")

    print("-")
    print(f"Inserted/updated: {inserted}/{len(PATTERNS)} patterns")


if __name__ == "__main__":
    seed()
