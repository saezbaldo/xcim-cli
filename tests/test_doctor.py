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

    def test_expired_and_untrusted_inputs(self):
        self.assertEqual(doctor.inspect_snapshot(dict(sample(), observedAt="2000-01-01T00:00:00Z")), "stale")
        self.assertEqual(doctor.inspect_snapshot(dict(sample(), observedAt="2026-02-30T00:00:00Z")), "invalid")
        self.assertEqual(doctor.inspect_snapshot(dict(sample(), observedAt="2099-01-01T00:00:00Z")), "invalid")
        for value in ("http://example.org", "https://user:pass@example.org", "https://example.org#x",
                      "https://example.org/a", "https://127.0.0.1", "https://example.org\n"):
            with self.assertRaises(ValueError):
                doctor.parse_args(["doctor", "--attester", value])

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
            path.write_text(json.dumps(sample()), encoding="utf-8")
            cases = [
                ["--offline"], ["--offline", "--snapshot", str(path)],
                ["--offline", "--snapshot", str(path), "--source", "src_unknown"],
                ["--offline", "--snapshot", str(path), "--source", "src_example", "--profile", "evp", "--evp-mode", "hosted"],
                ["--offline", "--snapshot", str(Path(folder) / "not-found")],
                ["--offline", "--attester", "https://OTHER.example/"],
                ["--offline", "--attester", "https://user:secret@example.org"],
                ["--offline", "--source", "src_example"], ["--json"],
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
