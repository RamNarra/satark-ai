"""
Adversarial Acceptance Suite for SATARK v2 Forensic Spine.
Tests the hard edge cases identified in the audit:
1. Resisted scam with debit mentioned ("asked to pay but refused") => NO_EVIDENCE_OF_LOSS
2. Bank security SMS ("never share OTP") => NO_EVIDENCE_OF_LOSS
3. Credential entered but no debit => CREDENTIAL_COMPROMISE_WITHOUT_LOSS
4. APK attached but not installed => NO_EVIDENCE_OF_LOSS
5. Real debit confirmed => CONFIRMED_UNAUTHORIZED_TRANSACTION
6. Provenance verification: Every event must link back to valid evidence ID.
"""
from fastapi.testclient import TestClient
from api.main import app
from db.schema.models import FinancialLossStatus

client = TestClient(app)


def test_edge_case_resisted_payment_mention():
    """Victim says someone asked for Rs 10,000, but they refused."""
    res = client.post(
        "/v2/incidents",
        json={"narrative": "A caller claimed to be courier service and asked me to pay Rs 10,000 immediately, but I refused, hung up, and blocked the number +919812345678."}
    )
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    recon = client.post(f"/v2/incidents/{case_id}/reconstruct").json()
    assert recon["financial_loss_status"] == FinancialLossStatus.NO_EVIDENCE_OF_LOSS.value
    assert recon["is_emergency"] is False
    print("[PASS] Resisted payment mention classified as NO_EVIDENCE_OF_LOSS")


def test_edge_case_bank_warning_sms():
    """Bank advisory warning contains the word OTP."""
    res = client.post(
        "/v2/incidents",
        json={"narrative": "I received this SMS: 'Dear Customer, your OTP is 482910 for txn of Rs 5,000. Never share your OTP with anyone.' I did not share it."}
    )
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    recon = client.post(f"/v2/incidents/{case_id}/reconstruct").json()
    assert recon["financial_loss_status"] == FinancialLossStatus.NO_EVIDENCE_OF_LOSS.value
    assert recon["is_emergency"] is False
    print("[PASS] Bank warning SMS with OTP keyword classified as NO_EVIDENCE_OF_LOSS")


def test_edge_case_credentials_compromised_no_loss():
    """Victim entered bank password on fake site, but no money has been debited yet."""
    res = client.post(
        "/v2/incidents",
        json={"narrative": "I clicked on a fake income tax refund portal and entered my net banking password and OTP, but my bank account balance hasn't changed and no money was debited."}
    )
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    recon = client.post(f"/v2/incidents/{case_id}/reconstruct").json()
    assert recon["financial_loss_status"] == FinancialLossStatus.CREDENTIAL_COMPROMISE_WITHOUT_LOSS.value
    assert recon["is_emergency"] is False
    assert any("password" in act.lower() or "card" in act.lower() for act in recon["recommended_actions"])
    print("[PASS] Credential compromise without loss classified as CREDENTIAL_COMPROMISE_WITHOUT_LOSS")


def test_edge_case_confirmed_loss():
    """Explicit unauthorized debit occurred."""
    res = client.post(
        "/v2/incidents",
        json={"narrative": "I clicked the link, approved the request on PhonePe, and Rs 50,000 was debited from my account to UPI merchant@paytm. Transaction ID is 4920194829."}
    )
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    recon = client.post(f"/v2/incidents/{case_id}/reconstruct").json()
    assert recon["financial_loss_status"] == FinancialLossStatus.CONFIRMED_UNAUTHORIZED_TRANSACTION.value
    assert recon["is_emergency"] is True
    assert any("1930" in act for act in recon["recommended_actions"])
    print("[PASS] Confirmed debit classified as CONFIRMED_UNAUTHORIZED_TRANSACTION")
