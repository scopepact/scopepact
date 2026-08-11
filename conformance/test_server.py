import unittest

import server


class ScopePactInspectorTests(unittest.TestCase):
    def test_exchange_runs_across_python_and_javascript(self) -> None:
        result = server.run_exchange(tamper=False)
        self.assertEqual(result["result"], "accepted")
        self.assertEqual(len(result["stages"]), 4)
        self.assertEqual(result["offer"]["payload"]["relationship"], "customer")
        self.assertTrue(result["reply"]["payload"]["accepted"])
        self.assertEqual(result["credential"]["identity"], "Native Ed25519")
        self.assertEqual(result["credential"]["authority"], "Capability grant")

    def test_tampered_payload_is_rejected(self) -> None:
        result = server.run_exchange(tamper=True)
        self.assertEqual(result["result"], "rejected")
        self.assertEqual(result["reason"], "payload digest mismatch")
        self.assertIsNone(result["reply"])

    def test_health_is_local_and_ready(self) -> None:
        payload = server.health()
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["host"], "127.0.0.1")
        self.assertEqual(payload["credential"]["federation"], "Not presented")
        self.assertTrue(payload["node"])
        self.assertEqual(payload["scenario_count"], 15)
        self.assertEqual(payload["scope"], "cross-language-wire-v0")
        self.assertEqual(payload["guard_evidence"]["release_status"], "pre-1.0 hardening")
        self.assertEqual(payload["guard_evidence"]["state_version"], 3)
        self.assertEqual(payload["guard_evidence"]["mcp_version"], "2025-06-18")

    def test_catalog_exposes_adoption_facing_protocol_rules(self) -> None:
        catalog = server.scenario_catalog()
        self.assertEqual(len(catalog), 15)
        self.assertEqual(len({scenario["id"] for scenario in catalog}), 15)
        self.assertTrue(all(scenario["rule"] for scenario in catalog))
        self.assertTrue(all(scenario["impact"] for scenario in catalog))

    def test_full_conformance_suite_reaches_every_expected_decision(self) -> None:
        suite = server.run_suite()
        self.assertEqual(suite["status"], "passed")
        self.assertEqual(suite["passed"], suite["total"])
        self.assertEqual(suite["total"], 15)
        decisions = {result["decision"] for result in suite["results"]}
        self.assertEqual(decisions, {"accepted", "rejected"})

    def test_replay_scenario_records_both_delivery_attempts(self) -> None:
        result = server.run_scenario("replayed_message")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["reason"], "replayed nonce")
        self.assertEqual({check["attempt"] for check in result["checks"]}, {1, 2})


if __name__ == "__main__":
    unittest.main()
