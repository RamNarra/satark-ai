"""
Scam Pattern Intelligence Service.
Curated taxonomy of Indian cybercrime precedents.
Uses deterministic lexical scoring and keyword matching for tactical precedent injection.
"""
from typing import List, Dict, Any

SEED_PATTERNS = [
    {
        "category": "UTILITY_FRAUD",
        "subtype": "ELECTRICITY_BILL_DISCONNECTION",
        "tactics": ["urgency", "fake_officer", "disconnection_threat", "apk_lure"],
        "indicators": {"typical_amounts": ["under_100"], "lure_terms": ["electricity", "power", "disconnection", "bill", "current"]},
        "summary": "Victim receives SMS threatening immediate electricity disconnection tonight unless they call a phone number or install an app (often QuickSupport/AnyDesk).",
        "remedy": ["Never call numbers in disconnection SMS", "Verify status on official DISCOM portal", "Do not install remote access software"]
    },
    {
        "category": "BANK_IMPERSONATION",
        "subtype": "KYC_EXPIRY_PHISHING",
        "tactics": ["credential_harvesting", "fake_netbanking_portal", "otp_request"],
        "indicators": {"lure_terms": ["kyc", "pan card", "blocked", "account suspended", "sbi", "hdfc", "axis"]},
        "summary": "Victim receives SMS stating bank account or SIM KYC is blocked. Lures victim to fake banking URL to enter username, password, and OTP.",
        "remedy": ["Banks never send links for KYC updates", "Immediately block netbanking credentials if entered", "Place lien via 1930 if funds debited"]
    },
    {
        "category": "COURIER_CUSTOMS_SCAM",
        "subtype": "PARCEL_HELD_FEDEX_CUSTOMS",
        "tactics": ["impersonation", "coercion", "fake_police_call", "digital_arrest"],
        "indicators": {"lure_terms": ["customs", "illegal goods", "fedex", "drugs", "mumbai police", "narcotics", "parcel", "courier"]},
        "summary": "Suspect calls claiming parcel sent in victim's name contains contraband. Video calls or threatens arrest unless clearance fees or settlement amounts are transferred.",
        "remedy": ["Customs/Police never demand money via video call", "Terminate call immediately", "Report suspect number on Chakshu portal"]
    },
    {
        "category": "UPI_PAYMENT_REVERSAL",
        "subtype": "QR_CODE_COLLECT_FRAUD",
        "tactics": ["fake_credit_screenshot", "reverse_payment_request", "olx_marketplace"],
        "indicators": {"lure_terms": ["scan qr", "receive money", "pin to receive", "refund request", "phonepe", "paytm", "gpay"]},
        "summary": "Buyer on OLX or marketplace sends fake payment screenshot claiming excess money sent, then asks victim to scan QR code or approve UPI collect request to receive refund.",
        "remedy": ["UPI PIN is never required to receive money", "Decline UPI collect requests", "Report suspect UPI ID on NPCI portal"]
    }
]


class PatternIntelligenceService:
    """Provides taxonomic pattern matching and tactical precedents."""

    @classmethod
    def match_patterns(cls, narrative: str) -> List[Dict[str, Any]]:
        """Matches narrative against known tactical patterns via lexical overlap."""
        narrative_lower = narrative.lower()
        matched = []
        for p in SEED_PATTERNS:
            score = 0
            for term in p["indicators"]["lure_terms"]:
                if term in narrative_lower:
                    score += 1
            if score > 0:
                matched.append({**p, "relevance_score": score})
        matched.sort(key=lambda x: x["relevance_score"], reverse=True)
        return matched[:2]
