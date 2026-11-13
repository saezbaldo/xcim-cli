import datetime
import http.client
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import xcim_doctor as doctor

ROOT = Path(__file__).resolve().parents[1]
APP = "urn:xcim:app:example"
CAPS = {"protocol": "xcim-0.1", "consent": {"hosted": True}, "identity_evidence": {
    "supported_profiles": ["oidc-01"], "oidc_01": {"status": "supported"},
    "evp_01": {"delivery_modes": {"vendor_origin_handoff": {"status": "unavailable"}}},
}}


def sample():
    return {
        "requestId": "pr_example", "applicationId": APP, "requestStatus": "active", "registrationAvailable": True,
        "manifestPublicationRecorded": True, "exchangeEndpointActive": True, "pairwiseKeyConfigured": True,
        "observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(), "nextSourceCursor": None,
        "sources": [{"sourceId": "src_example", "applicationId": APP,
                     "domainVerificationRecorded": True, "returnRegistered": True, "oauthBindingActive": True,
                     "oauthReviewCurrent": True, "oauthBootstrapConfirmed": True}],
        "extraPrivateData": "must-not-appear",
    }


def esp_sample():
    return {
        "schema": "xcim-doctor/esp-snapshot/v1", "observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "credentialsEnabled": True, "listValidationEnabled": True, "eligibleRole": True, "mfaRequired": False,
        "partnerIdentityActive": True, "delegationAvailable": True,
    }


def check(report, id_):
    return next(row for row in report["checks"] if row["id"] == id_)


class DoctorTests(unittest.TestCase):
    def test_missing_snapshot_is_one_human_step_not_a_private_verdict(self):
        code, report = doctor.run(doctor.parse_args(["doctor"]), lambda origin: CAPS)
        self.assertEqual(code, 2)
        self.assertEqual(report["summary"]["human_required"], 1)
        manifest = next(row for row in report["checks"] if row["id"] == "manifest.publication")
        self.assertEqual(manifest["status"], "unknown")
        self.assertFalse(manifest["human_required"])

    def test_online_observation_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "setup.json"
            path.write_text(json.dumps(sample()), encoding="utf-8")
            opts = doctor.parse_args(["doctor", "--snapshot", str(path), "--profile", "oidc"])
            code, report = doctor.run(opts, lambda origin: CAPS)
            self.assertEqual(code, 0)
            self.assertEqual(report["summary"]["human_required"], 0)
            self.assertNotIn("ready", report)
            self.assertNotIn("must-not-appear", json.dumps(report))
            self.assertIn("current_permission", report["not_checked"])
            self.assertIn("site_managed_oidc_setup", report["not_checked"])
            self.assertIn("Emabled-hosted relay, not site-managed OIDC", report["notes"][0])

    def test_expired_and_untrusted_inputs(self):
        self.assertEqual(doctor.inspect_snapshot(dict(sample(), observedAt="2000-01-01T00:00:00Z")), "stale")
        self.assertEqual(doctor.inspect_snapshot(dict(sample(), observedAt="2026-02-30T00:00:00Z")), "invalid")
        self.assertEqual(doctor.inspect_snapshot(dict(sample(), observedAt="2099-01-01T00:00:00Z")), "invalid")
        for value in ("http://example.org", "https://user:pass@example.org", "https://example.org#x",
                      "https://example.org/a", "https://127.0.0.1", "https://example.org\n"):
            with self.assertRaises(ValueError):
                doctor.parse_args(["doctor", "--attester", value])

    def test_versioned_snapshot_allowlists_and_workflow_flags(self):
        company = sample()
        company.pop("extraPrivateData")
        company["schema"] = "xcim-doctor/company-snapshot/v1"
        self.assertEqual(doctor.inspect_snapshot(company), "fresh")
        self.assertEqual(doctor.inspect_snapshot(dict(company, cookie="not-allowed")), "invalid")
        self.assertEqual(doctor.inspect_snapshot(dict(company, sources=[dict(company["sources"][0], name="not-allowed")])), "invalid")
        esp = esp_sample()
        self.assertEqual(doctor.inspect_snapshot(esp), "invalid")
        self.assertEqual(doctor.inspect_snapshot(company, workflow="esp"), "invalid")
        self.assertEqual(doctor.inspect_snapshot(esp, workflow="esp"), "fresh")
        for changed in (dict(esp, schema="xcim-doctor/esp-snapshot/v2"), dict(esp, eligibleRole=1), dict(esp, partnerId="esp_example"),
                        dict(esp, observedAt="2026-11-12T12:00:00+00:60")):
            self.assertEqual(doctor.inspect_snapshot(changed, workflow="esp"), "invalid")
        self.assertEqual(doctor.inspect_snapshot(dict(esp, observedAt="2000-01-01T00:00:00Z"), workflow="esp"), "stale")
        for flags in (("--workflow", "esp", "--profile", "oidc"), ("--workflow", "esp", "--attester", "https://other.example"),
                      ("--workflow", "esp", "--intent", "test"), ("--intent", "test", "--profile", "evp"),
                      ("--workflow", "esp", "--oidc-mode", "site-managed"), ("--profile", "evp", "--oidc-mode", "hosted"),
                      ("--oidc-mode", "invalid"), ("--oidc-mode", "hosted", "--oidc-mode", "site-managed")):
            with self.assertRaises(ValueError):
                doctor.parse_args(["doctor", *flags])

    def test_connected_oidc_advisory_does_not_mask_missing_review(self):
        setup = sample()
        setup["sources"][0]["oauthReviewCurrent"] = False
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "setup.json"
            path.write_text(json.dumps(setup), encoding="utf-8")
            args = ["doctor", "--snapshot", str(path), "--profile", "oidc"]
            code, report = doctor.run(doctor.parse_args(args), lambda origin: CAPS)
            self.assertEqual(code, 0)
            self.assertEqual(report["summary"]["missing"], 1)
            self.assertEqual(report["summary"]["advisory"], 1)
            self.assertEqual(report["summary"]["blocking"], 0)
            self.assertEqual(check(report, "oidc.provider_review"), {
                "id": "oidc.provider_review", "status": "missing", "evidence": "console_snapshot",
                "human_required": False, "next_action": "review_before_new_oidc_test", "actor": "attester_operator",
                "severity": "advisory", "blocking": False,
            })
            code, report = doctor.run(doctor.parse_args([*args, "--intent", "test"]), lambda origin: CAPS)
            self.assertEqual(code, 2)
            self.assertTrue(check(report, "oidc.provider_review")["human_required"])
            self.assertTrue(check(report, "oidc.provider_review")["blocking"])

    def test_site_managed_oidc_does_not_require_hosted_relay_or_assert_readiness(self):
        setup = sample()
        setup["exchangeEndpointActive"] = False
        setup["sources"][0].update(oauthBindingActive=False, oauthReviewCurrent=False, oauthBootstrapConfirmed=False)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "setup.json"
            path.write_text(json.dumps(setup), encoding="utf-8")
            args = ["doctor", "--profile", "oidc", "--snapshot", str(path)]
            default_hosted = doctor.run(doctor.parse_args(args), lambda origin: CAPS)
            explicit_hosted = doctor.run(doctor.parse_args([*args, "--oidc-mode", "hosted"]), lambda origin: CAPS)
            self.assertEqual(default_hosted, explicit_hosted)
            self.assertEqual(default_hosted[1]["summary"]["blocking"], 4)
            for intent in ("operate", "test"):
                with self.subTest(intent=intent):
                    code, report = doctor.run(doctor.parse_args([*args, "--oidc-mode", "site-managed", "--intent", intent]), lambda origin: CAPS)
                    self.assertEqual(code, 2)
                    self.assertEqual(report["summary"]["blocking"], 1)
                    self.assertEqual(check(report, "oidc.site_managed_setup"), {
                        "id": "oidc.site_managed_setup", "status": "unknown", "evidence": "not_checked",
                        "human_required": False, "next_action": "verify_site_managed_oidc_setup", "actor": "agent",
                        "severity": "blocker", "blocking": True,
                    })
                    ids = {row["id"] for row in report["checks"]}
                    self.assertTrue(ids.isdisjoint({"oidc.exchange_endpoint", "oidc.provider_binding", "oidc.provider_review", "oidc.bootstrap"}))
                    self.assertEqual(check(report, "oidc.support")["status"], "configured")
                    self.assertIn("site_managed_oidc_setup", report["not_checked"])
                    self.assertIn("not assessed", report["notes"][0])
            report = doctor.diagnose(doctor.parse_args(["doctor", "--profile", "both", "--oidc-mode", "site-managed"]), CAPS,
                                     setup, "fresh", "observed")
            self.assertEqual(check(report, "evp.delivery_mode")["status"], "missing")
            self.assertEqual(check(report, "oidc.site_managed_setup")["status"], "unknown")
            relay_ready = sample()
            report = doctor.diagnose(doctor.parse_args(["doctor", "--profile", "oidc", "--oidc-mode", "site-managed"]),
                                     CAPS, relay_ready, "fresh", "observed")
            self.assertEqual(check(report, "oidc.site_managed_setup")["status"], "unknown")
            self.assertEqual(report["summary"]["blocking"], 1)
            setup["sources"][0]["oauthBootstrapConfirmed"] = False
            path.write_text(json.dumps(setup), encoding="utf-8")
            code, report = doctor.run(doctor.parse_args(args), lambda origin: CAPS)
            self.assertEqual(code, 2)
            self.assertTrue(check(report, "oidc.provider_review")["blocking"])

    def test_versioned_selected_source_and_explicit_override(self):
        company = sample()
        company.pop("extraPrivateData")
        company["schema"] = "xcim-doctor/company-snapshot/v1"
        company["selectedSourceId"] = "src_example"
        company["nextSourceCursor"] = "src_second"
        company["sources"].append(dict(company["sources"][0], sourceId="src_second", applicationId=None))
        self.assertEqual(doctor.inspect_snapshot(company), "fresh")
        self.assertEqual(doctor.inspect_snapshot(dict(company, selectedSourceId="src_unlisted")), "invalid")
        self.assertEqual(doctor.inspect_snapshot(dict(company, selectedSourceId=["src_example"])), "invalid")
        args = ["doctor", "--snapshot", "setup.json"]
        report = doctor.diagnose(doctor.parse_args(args), CAPS, company, "fresh", "observed")
        self.assertEqual(report["snapshot"]["source_id"], "src_example")
        self.assertEqual(check(report, "source.binding")["status"], "configured")
        report = doctor.diagnose(doctor.parse_args([*args, "--source", "src_second"]), CAPS, company, "fresh", "observed")
        self.assertEqual(report["snapshot"]["source_id"], "src_second")
        self.assertEqual(check(report, "source.binding")["status"], "missing")
        report = doctor.diagnose(doctor.parse_args(args), CAPS, dict(company, selectedSourceId=None, sources=[], nextSourceCursor=None),
                                 "fresh", "observed")
        self.assertEqual(check(report, "source.binding")["status"], "unknown")

    def test_esp_only_uses_snapshot_and_distinguishes_unknown(self):
        def transport(_):
            self.fail("ESP must not fetch company capabilities")

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "esp.json"
            path.write_text(json.dumps(esp_sample()), encoding="utf-8")
            args = ["doctor", "--workflow", "esp"]
            opts = doctor.parse_args([*args, "--snapshot", str(path)])
            code, report = doctor.run(opts, transport)
            self.assertEqual(code, 0)
            self.assertEqual(report["capabilities"], "not_checked")
            self.assertIsNone(report["snapshot"]["application_id"])
            self.assertIn("current_permission", report["not_checked"])
            path.write_text(json.dumps(dict(esp_sample(), mfaRequired=True, delegationAvailable=False)), encoding="utf-8")
            code, report = doctor.run(opts, transport)
            self.assertEqual(code, 2)
            self.assertEqual(check(report, "esp.mfa")["actor"], "browser_user")
            self.assertEqual(check(report, "esp.delegation")["actor"], "company_admin")
            path.write_text(json.dumps(dict(esp_sample(), delegationAvailable=None)), encoding="utf-8")
            code, report = doctor.run(opts, transport)
            self.assertEqual(code, 2)
            self.assertEqual(check(report, "esp.delegation")["status"], "unknown")
            self.assertFalse(check(report, "esp.delegation")["human_required"])
            code, report = doctor.run(doctor.parse_args(args), transport)
            self.assertEqual(code, 2)
            self.assertEqual(report["summary"]["human_required"], 1)

    def test_versioned_exchange_observes_selected_site_only(self):
        setup = sample()
        opts = doctor.parse_args(["doctor", "--profile", "oidc"])
        report = doctor.diagnose(opts, CAPS, setup, "fresh", "observed")
        self.assertEqual(check(report, "oidc.exchange_endpoint")["status"], "configured")
        setup.pop("extraPrivateData")
        setup.update(schema="xcim-doctor/company-snapshot/v1", selectedSourceId="src_example")
        source = setup["sources"][0]
        report = doctor.diagnose(opts, CAPS, setup, "fresh", "observed")
        self.assertEqual(check(report, "oidc.exchange_endpoint")["status"], "unknown")
        for value, expected in ((True, "configured"), (False, "missing"), (None, "unknown")):
            with self.subTest(value=value):
                source["exchangeEndpointVerified"] = value
                self.assertEqual(doctor.inspect_snapshot(setup), "fresh")
                report = doctor.diagnose(opts, CAPS, setup, "fresh", "observed")
                self.assertEqual(check(report, "oidc.exchange_endpoint")["status"], expected)
        source["exchangeEndpointVerified"] = 1
        self.assertEqual(doctor.inspect_snapshot(setup), "invalid")

    def test_get_uses_no_credentials_and_refuses_redirects(self):
        with patch.object(http.client, "HTTPSConnection") as factory:
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = 200
            response.getheader.return_value = "application/json"
            response.read.return_value = json.dumps(CAPS).encode()
            self.assertEqual(doctor.fetch_capabilities("https://api.emabled.com"), CAPS)
            connection.request.assert_called_once_with("GET", "/v1/capabilities", headers={"Accept": "application/json"})
            response.status = 302
            with self.assertRaises(ValueError):
                doctor.fetch_capabilities("https://api.emabled.com")
            self.assertEqual(connection.request.call_count, 2)

    @unittest.skipUnless(shutil.which("node"), "Node is needed for cross-edition parity")
    def test_native_cli_json_parity(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "setup.json"
            data = sample()
            data["sources"][0]["oauthReviewCurrent"] = False
            path.write_text(json.dumps(data), encoding="utf-8")
            data.pop("extraPrivateData")
            selected_path = Path(folder) / "selected.json"
            selected_path.write_text(json.dumps(dict(data, schema="xcim-doctor/company-snapshot/v1",
                                                      selectedSourceId="src_example", nextSourceCursor="src_later")), encoding="utf-8")
            scoped_path = Path(folder) / "scoped.json"
            data["sources"][0]["exchangeEndpointVerified"] = False
            scoped_path.write_text(json.dumps(dict(data, schema="xcim-doctor/company-snapshot/v1",
                                                    selectedSourceId="src_example")), encoding="utf-8")
            esp_path = Path(folder) / "esp.json"
            esp_path.write_text(json.dumps(dict(esp_sample(), delegationAvailable=None)), encoding="utf-8")
            invalid_path = Path(folder) / "invalid.json"
            invalid_path.write_text(json.dumps(dict(esp_sample(), token="must-not-appear")), encoding="utf-8")
            cases = [
                ["--offline"], ["--offline", "--snapshot", str(path)],
                ["--offline", "--snapshot", str(path), "--intent", "test"],
                ["--offline", "--snapshot", str(selected_path)],
                ["--offline", "--snapshot", str(selected_path), "--source", "src_unknown"],
                ["--offline", "--snapshot", str(scoped_path), "--profile", "oidc"],
                ["--offline", "--snapshot", str(scoped_path), "--profile", "oidc", "--oidc-mode", "site-managed"],
                ["--offline", "--snapshot", str(scoped_path), "--oidc-mode", "site-managed", "--intent", "test"],
                ["--offline", "--snapshot", str(scoped_path), "--profile", "oidc", "--oidc-mode", "hosted"],
                ["--offline", "--profile", "evp", "--oidc-mode", "hosted"],
                ["--workflow", "esp", "--oidc-mode", "site-managed"], ["--oidc-mode", "bad"],
                ["--offline", "--snapshot", str(path), "--source", "src_unknown"],
                ["--offline", "--snapshot", str(path), "--source", "src_example", "--profile", "evp", "--evp-mode", "hosted"],
                ["--offline", "--snapshot", str(Path(folder) / "not-found")],
                ["--offline", "--attester", "https://OTHER.example/"],
                ["--offline", "--attester", "https://user:secret@example.org"],
                ["--offline", "--source", "src_example"], ["--json"],
                ["--workflow", "esp"], ["--workflow", "esp", "--snapshot", str(esp_path)],
                ["--workflow", "esp", "--snapshot", str(invalid_path)],
                ["--workflow", "esp", "--snapshot", str(path)], ["--offline", "--snapshot", str(esp_path)],
            ]
            for options in cases:
                with self.subTest(options=options):
                    args = ["doctor", "--json", *options]
                    outputs = [subprocess.run([program, str(ROOT / file), *args], capture_output=True, text=True, timeout=10)
                               for program, file in (("node", "xcim.mjs"), (sys.executable, "xcim_doctor.py"))]
                    self.assertEqual(outputs[0].returncode, outputs[1].returncode)
                    self.assertEqual(json.loads(outputs[0].stdout), json.loads(outputs[1].stdout))
                    self.assertEqual(outputs[0].stderr + outputs[1].stderr, "")
                    self.assertNotIn("must-not-appear", outputs[0].stdout)


if __name__ == "__main__":
    unittest.main()
