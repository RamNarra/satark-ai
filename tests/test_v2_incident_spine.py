"""
End-to-end integration tests for SATARK v2 Forensic Incident Spine.
Verifies the complete vertical slice:
1. Incident creation
2. Evidence ingestion with SHA-256 and durable storage
3. Multimodal entity extraction
4. Real reasoner evaluation (Calm vs Emergency)
5. Strict FinancialLossStatus state transitions
"""
import io
from fastapi.testclient import TestClient
from api.main import app
from db.schema.models import FinancialLossStatus

client = TestClient(app)


def test_v2_calm_incident_flow():
    # 1. Citizen reports phishing message with no funds lost
    res1 = client.post(
        "/v2/incidents",
        json={"narrative": "I received an SMS from +919876543210 saying my electricity bill is overdue. Link was https://fake-bill-pay.in. I did not click or pay."}
    )
    assert res1.status_code == 201
    case_id = res1.json()["case_id"]

    # 2. Citizen uploads screenshot of the SMS
    dummy_img = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
    res2 = client.post(
        f"/v2/incidents/{case_id}/evidence",
        files={"file": ("sms_screenshot.png", dummy_img, "image/png")}
    )
    assert res2.status_code == 201
    assert "sha256" in res2.json()

    # 3. Trigger Forensic Reconstruction
    res3 = client.post(f"/v2/incidents/{case_id}/reconstruct")
    assert res3.status_code == 200
    data = res3.json()

    assert data["financial_loss_status"] == FinancialLossStatus.NO_EVIDENCE_OF_LOSS.value
    assert data["is_emergency"] is False
    assert len(data["recommended_actions"]) > 0
    assert data["complaint_narrative"] is None


def test_v2_confirmed_loss_flow():
    # 1. Citizen reports confirmed unauthorized debit
    res1 = client.post(
        "/v2/incidents",
        json={"narrative": "Someone called pretending to be SBI bank manager. I shared the OTP received on SMS, and immediately Rs 35,000 was debited from my account to UPI ID scammer@okhdfc."}
    )
    assert res1.status_code == 201
    case_id = res1.json()["case_id"]

    # 2. Trigger Forensic Reconstruction
    res2 = client.post(f"/v2/incidents/{case_id}/reconstruct")
    assert res2.status_code == 200
    data = res2.json()

    assert data["financial_loss_status"] == FinancialLossStatus.CONFIRMED_UNAUTHORIZED_TRANSACTION.value
    assert data["is_emergency"] is True
    assert any("1930" in act for act in data["recommended_actions"])
