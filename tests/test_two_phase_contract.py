import unittest
from typing import Any

from fastapi.testclient import TestClient

from api import main


class TwoPhaseContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._original_orchestrate_run = main._orchestrate_run

        async def _noop_orchestrate(_run_id: str) -> None:
            return None

        main._orchestrate_run = _noop_orchestrate
        cls.client = TestClient(main.app)

    @classmethod
    def tearDownClass(cls) -> None:
        main._orchestrate_run = cls._original_orchestrate_run
        cls.client.close()

    def setUp(self) -> None:
        main.RUN_STORE.clear()

    def _payload(self, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        base = {
            "session_id": "sess_test",
            "user_input": {
                "text": "I got this suspicious SMS with a link https://example.com",
                "files": [],
            },
            "user_context": {
                "channel": "test",
                "locale": "en-IN",
            },
            "options": {
                "stream": True,
                "generate_report": True,
                "deep_analysis": True,
                "fast_first": False,
                "trigger_mcp_actions": True,
            },
        }
        if overrides:
            for k, v in overrides.items():
                if isinstance(v, dict) and isinstance(base.get(k), dict):
                    base[k].update(v)
                else:
                    base[k] = v
        return base

    def test_analyze_normalizes_to_triage_contract(self) -> None:
        response = self.client.post("/api/analyze", json=self._payload())
        self.assertEqual(response.status_code, 200)
        body = response.json()

        self.assertEqual(body["analysis_stage"], "triage")
        self.assertEqual(body["contract_version"], main.ANALYSIS_CONTRACT_VERSION)
        self.assertTrue(body["eligible_for_deep"])

        run_id = body["run_id"]
        run_ctx = main.RUN_STORE[run_id]
        options = run_ctx["request"]["options"]

        self.assertFalse(options["deep_analysis"])
        self.assertTrue(options["fast_first"])
        self.assertFalse(options["generate_report"])
        self.assertFalse(options["trigger_mcp_actions"])

        first_event = main.RUN_STORE[run_id]["events"][0]["data"]
        self.assertEqual(first_event["contract_version"], main.ANALYSIS_CONTRACT_VERSION)
        self.assertEqual(first_event["analysis_stage_version"], main.ANALYSIS_STAGE_VERSION)
        self.assertEqual(first_event["analysis_stage"], "triage")

    def test_deep_trigger_binds_existing_case(self) -> None:
        triage_response = self.client.post("/api/analyze", json=self._payload())
        triage_body = triage_response.json()
        triage_run_id = triage_body["run_id"]
        triage_case_id = triage_body["case_id"]

        deep_response = self.client.post(
            "/api/analyze/deep",
            json={
                "source_run_id": triage_run_id,
                "generate_report": True,
                "trigger_mcp_actions": True,
                "stream": True,
            },
        )
        self.assertEqual(deep_response.status_code, 200)
        deep_body = deep_response.json()

        self.assertEqual(deep_body["analysis_stage"], "deep")
        self.assertEqual(deep_body["source_run_id"], triage_run_id)
        self.assertEqual(deep_body["case_id"], triage_case_id)
        self.assertFalse(deep_body["eligible_for_deep"])
        self.assertEqual(deep_body["deep_reason_code"], "DEEP_ACCEPTED")

        deep_run = main.RUN_STORE[deep_body["run_id"]]
        deep_options = deep_run["request"]["options"]
        self.assertTrue(deep_options["deep_analysis"])
        self.assertFalse(deep_options["fast_first"])
        self.assertTrue(deep_options["generate_report"])
        self.assertTrue(deep_options["trigger_mcp_actions"])

    def test_deep_trigger_idempotency_key_replays_existing_run(self) -> None:
        triage_response = self.client.post("/api/analyze", json=self._payload())
        triage_run_id = triage_response.json()["run_id"]

        first = self.client.post(
            "/api/analyze/deep",
            json={"source_run_id": triage_run_id},
            headers={"Idempotency-Key": "idem-123"},
        )
        self.assertEqual(first.status_code, 200)
        first_body = first.json()
        self.assertFalse(first_body["idempotent_replay"])

        replay = self.client.post(
            "/api/analyze/deep",
            json={"source_run_id": triage_run_id},
            headers={"Idempotency-Key": "idem-123"},
        )
        self.assertEqual(replay.status_code, 200)
        replay_body = replay.json()
        self.assertTrue(replay_body["idempotent_replay"])
        self.assertEqual(replay_body["run_id"], first_body["run_id"])

    def test_deep_rejects_unknown_source_run_id(self) -> None:
        response = self.client.post(
            "/api/analyze/deep",
            json={"source_run_id": "run_missing_source"},
        )
        self.assertEqual(response.status_code, 404)

    def test_deep_requires_triage_source(self) -> None:
        triage_response = self.client.post("/api/analyze", json=self._payload())
        triage_run_id = triage_response.json()["run_id"]

        deep_response = self.client.post(
            "/api/analyze/deep",
            json={"source_run_id": triage_run_id},
        )
        self.assertEqual(deep_response.status_code, 200)
        deep_run_id = deep_response.json()["run_id"]

        invalid_response = self.client.post(
            "/api/analyze/deep",
            json={"source_run_id": deep_run_id},
        )
        self.assertEqual(invalid_response.status_code, 400)

    def test_deep_rejects_ineligible_triage_source(self) -> None:
        triage_response = self.client.post("/api/analyze", json=self._payload())
        triage_run_id = triage_response.json()["run_id"]

        main.RUN_STORE[triage_run_id]["status"] = "completed"
        main.RUN_STORE[triage_run_id]["result"] = {
            "analysis_stage": "triage",
            "eligible_for_deep": False,
        }

        response = self.client.post(
            "/api/analyze/deep",
            json={"source_run_id": triage_run_id},
        )
        self.assertEqual(response.status_code, 409)

    def test_result_stage_metadata_for_pending_failed_completed(self) -> None:
        triage_response = self.client.post("/api/analyze", json=self._payload())
        pending_run_id = triage_response.json()["run_id"]

        pending_response = self.client.get(f"/api/result/{pending_run_id}")
        self.assertEqual(pending_response.status_code, 202)
        pending_body = pending_response.json()
        self.assertEqual(pending_body["analysis_stage"], "triage")
        self.assertEqual(pending_body["contract_version"], main.ANALYSIS_CONTRACT_VERSION)
        self.assertTrue(pending_body["eligible_for_deep"])
        self.assertEqual(pending_body["deep_reason_code"], "TRIAGE_IN_PROGRESS")

        failed_run_id = "run_failed_contract"
        main.RUN_STORE[failed_run_id] = {
            "run_id": failed_run_id,
            "case_id": "case_failed_contract",
            "status": "failed",
            "created_at": main._utc_now(),
            "completed_at": main._utc_now(),
            "request": {"user_input": {"text": "", "files": []}, "options": {}},
            "result": None,
            "error": "forced failure",
            "analysis_stage": "deep",
            "source_run_id": pending_run_id,
            "events": [],
            "subscribers": [],
        }
        failed_response = self.client.get(f"/api/result/{failed_run_id}")
        self.assertEqual(failed_response.status_code, 200)
        failed_body = failed_response.json()
        self.assertEqual(failed_body["analysis_stage"], "deep")
        self.assertEqual(failed_body["contract_version"], main.ANALYSIS_CONTRACT_VERSION)
        self.assertFalse(failed_body["eligible_for_deep"])
        self.assertEqual(failed_body["deep_reason_code"], "DEEP_FAILED")

        completed_run_id = "run_completed_contract"
        user_input = {
            "text": "I got a suspicious SMS asking for bank verification.",
            "files": [],
        }
        options = {
            "recovery_answers": {},
            "preprocessed_context": {},
            "deep_analysis": False,
            "fast_first": True,
        }
        pipeline_result = main._build_first_pass_pipeline_result("text", user_input, options)
        run_ctx = {
            "run_id": completed_run_id,
            "case_id": "case_completed_contract",
            "status": "completed",
            "created_at": main._utc_now(),
            "completed_at": main._utc_now(),
            "request": {"user_input": user_input, "options": options},
            "analysis_stage": "triage",
            "source_run_id": None,
            "similar_patterns_count": 0,
            "similar_patterns": [],
            "events": [],
            "subscribers": [],
        }
        run_ctx["result"] = main._build_result_document(
            run_ctx,
            pipeline_result,
            "text",
            ["manager", "scam_detector", "golden_hour"],
        )
        main.RUN_STORE[completed_run_id] = run_ctx

        completed_response = self.client.get(f"/api/result/{completed_run_id}")
        self.assertEqual(completed_response.status_code, 200)
        completed_body = completed_response.json()
        self.assertEqual(completed_body["analysis_stage"], "triage")
        self.assertEqual(completed_body["contract_version"], main.ANALYSIS_CONTRACT_VERSION)
        self.assertTrue(completed_body["eligible_for_deep"])
        self.assertIn("deep_reason", completed_body)
        self.assertEqual(completed_body["deep_reason_code"], "TRIAGE_COMPLETE_DEEP_AVAILABLE")


if __name__ == "__main__":
    unittest.main()
