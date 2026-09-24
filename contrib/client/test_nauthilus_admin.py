"""Hermetic command-to-HTTP contracts for reputation administration."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("nauthilus_admin", Path(__file__).with_name("nauthilus-admin.py"))
ADMIN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADMIN
SPEC.loader.exec_module(ADMIN)

CONVERTER_SPEC = importlib.util.spec_from_file_location(
    "static_conversion", Path(__file__).resolve().parents[2] / "scripts" / "convert-static-reputation.py")
CONVERTER = importlib.util.module_from_spec(CONVERTER_SPEC)
CONVERTER_SPEC.loader.exec_module(CONVERTER)

NOW = 1_800_000_000


class ReputationClientTest(unittest.TestCase):
    """Exercise the real parser, bearer selection and JSON HTTP boundary."""

    def test_reputation_operations_use_exact_authenticated_body_contracts(self):
        """Keep subjects out of URLs and preserve explicit TTL and audit fields."""
        cases = [
            (["lookup", "dns_domain", "example.test"], "POST", "lookup", {"kind": "dns_domain", "subject": "example.test"}),
            (["lookup", "ip", "192.0.2.8"], "POST", "lookup", {"kind": "ip", "subject": "192.0.2.8"}),
            (["override", "put", "ip", "192.0.2.8", "--band", "blocked", "--ttl-seconds", "0", "--reason", "incident", "--origin", "operator", "--audit-id", "ticket"], "PUT", "override", {"kind":"ip","subject":"192.0.2.8","band":"blocked","ttl_seconds":0,"reason":"incident","origin":"operator","audit_id":"ticket","slot":"active"}),
            (["override", "delete", "ip", "192.0.2.8", "--previous-audit", "ticket", "--reason", "resolved", "--origin", "operator", "--audit-id", "next"], "DELETE", "override", {"kind":"ip","subject":"192.0.2.8","previous_audit":"ticket","reason":"resolved","origin":"operator","audit_id":"next","slot":"active"}),
            (["allocation", "status"], "POST", "allocation", {"action":"status"}),
            (["allocation", "drain", "--reason", "key_rotation", "--origin", "operator", "--audit-id", "rotation"], "POST", "allocation", {"action":"drain","reason":"key_rotation","origin":"operator","audit_id":"rotation"}),
        ]
        for command, method, path, body in cases:
            with self.subTest(command=command):
                args = ADMIN.build_parser().parse_args(["--bearer-token", "synthetic", "reputation", *command])
                client = ADMIN.NauthilusClient(ADMIN.build_config(args))
                response = ADMIN.Response(200, "OK", {}, b"{}", {})
                with patch.object(client, "_send", return_value=response) as send:
                    self.assertIs(args.func(client, args), response)
                positional, keyword = send.call_args
                self.assertEqual(positional, (method, ADMIN.DEFAULT_URL + "/api/v1/custom/reputation/" + path))
                self.assertEqual(json.loads(keyword["body"]), body)
                self.assertEqual(keyword["headers"]["Authorization"], "Bearer synthetic")
                self.assertNotIn("creator", body)

    def test_definite_http_conflict_remains_visible(self):
        """An acknowledged revision conflict must not become an unknown transport outcome."""
        args = ADMIN.build_parser().parse_args(["--bearer-token", "synthetic", "reputation", "allocation", "drain", "--reason", "key_rotation", "--origin", "operator", "--audit-id", "rotation"])
        client = ADMIN.NauthilusClient(ADMIN.build_config(args))
        response = ADMIN.Response(409, "Conflict", {}, b'{}', {"error":"Conflict"})
        with patch.object(client, "_send", return_value=response):
            with self.assertRaisesRegex(ADMIN.ClientError, "HTTP 409"):
                args.func(client, args)

    def test_subject_files_never_truncate_or_exceed_utf8_limit(self):
        """Reject oversized exact inputs before requesting any token or remote state."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "subject"
            for text in ("a" * 512 + "\n" + "suffix", "é" * 300):
                path.write_text(text)
                args = ADMIN.build_parser().parse_args(["--bearer-token", "synthetic", "reputation", "lookup", "account", "--subject-file", str(path)])
                client = ADMIN.NauthilusClient(ADMIN.build_config(args))
                with patch.object(client, "_send") as send:
                    with self.assertRaises(ADMIN.ClientError):
                        args.func(client, args)
                    send.assert_not_called()

    def test_mutation_unknown_outcome_is_not_retried(self):
        """Transport uncertainty must remain visible and never repeat a mutation."""
        args = ADMIN.build_parser().parse_args(["--bearer-token", "synthetic", "reputation", "allocation", "drain", "--reason", "key_rotation", "--origin", "operator", "--audit-id", "rotation"])
        client = ADMIN.NauthilusClient(ADMIN.build_config(args))
        with patch.object(client, "_send", side_effect=TimeoutError("timeout")) as send:
            with self.assertRaisesRegex(ADMIN.ClientError, "outcome may be unknown"):
                args.func(client, args)
            self.assertEqual(send.call_count, 1)


class ReputationImportTest(unittest.TestCase):
    """Apply converter artifacts through the real CLI entrypoint and a mocked HTTP boundary."""

    @staticmethod
    def artifact(expiries):
        """Convert a synthetic snapshot and assign one absolute expiry per sorted override entry."""
        snapshot = {"domains": [{"domain": "a.example", "reputation": "blocked"}, {"domain": "b.example", "reputation": "neutral"}],
                    "client_networks": [{"cidr": "192.0.2.16/28", "reputation": "trusted"}]}
        result = CONVERTER.convert(snapshot, "converter-operator", "audit")
        for entry, expires_at in zip(result["overrides"], expiries):
            entry["expires_at"] = expires_at
        return result

    def run_import(self, artifact, *, times, send_effect=None, extra=()):
        """Run the import command and return exit code, stdout, stderr and the HTTP mock."""
        ok = ADMIN.Response(200, "OK", {}, b"{}", {})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            path.write_text(artifact if isinstance(artifact, str) else json.dumps(artifact))
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(ADMIN.NauthilusClient, "_send", side_effect=send_effect, return_value=ok) as send, \
                    patch.object(ADMIN.time, "time", side_effect=times), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = ADMIN.main(["--bearer-token", "synthetic", "--output", "json", "reputation", "override", "import",
                                   str(path), *extra])
        return code, stdout.getvalue(), stderr.getvalue(), send

    def test_entries_are_applied_in_order_with_ttl_computed_per_request(self):
        """Each request derives ttl_seconds from its own clock read; zero expiry stays non-expiring."""
        code, stdout, stderr, send = self.run_import(self.artifact([NOW + 3600, 0, NOW + 3600]),
                                                     times=[NOW, NOW + 10, NOW + 20, NOW + 29.5])
        self.assertEqual(code, 0)
        bodies = [json.loads(call.kwargs["body"]) for call in send.call_args_list]
        self.assertEqual([body["subject"] for body in bodies], ["a.example", "b.example", "192.0.2.16/28"])
        self.assertEqual([body["ttl_seconds"] for body in bodies], [3590, 0, 3570])
        self.assertEqual(bodies[0], {"kind": "dns_domain", "subject": "a.example", "band": "blocked", "reason": "static.classification",
                                     "origin": "cutover.static_dkim2_v4", "audit_id": bodies[0]["audit_id"], "slot": "active", "ttl_seconds": 3590})
        for call in send.call_args_list:
            self.assertEqual(call.args, ("PUT", ADMIN.DEFAULT_URL + "/api/v1/custom/reputation/override"))
            self.assertEqual(call.kwargs["headers"]["Authorization"], "Bearer synthetic")
            self.assertNotIn("creator", json.loads(call.kwargs["body"]))
        self.assertIn("'converter-operator' is ignored", stderr)
        self.assertEqual(json.loads(stdout)["applied"], 3)

    def test_expired_entries_are_skipped_and_never_sent_as_non_expiring(self):
        """An expiry at or before the current second is reported instead of becoming ttl_seconds 0."""
        code, stdout, stderr, send = self.run_import(self.artifact([NOW, NOW - 5, NOW + 60]),
                                                     times=[NOW - 0.5, NOW - 0.5, NOW - 0.5, NOW - 0.5])
        self.assertEqual(code, 0)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(json.loads(send.call_args.kwargs["body"])["ttl_seconds"], 60)
        summary = json.loads(stdout)
        self.assertEqual((summary["applied"], summary["skipped_expired"]), (1, 2))
        self.assertEqual(stderr.count("skipped-expired kind=dns_domain"), 2)

    def test_invalid_artifacts_are_rejected_before_any_request(self):
        """Schema or entry problems abort the whole import and name the offending entries."""
        valid = self.artifact([0, 0, 0])

        def mutated(change):
            result = json.loads(json.dumps(valid))
            change(result)
            return result

        cases = {
            "schema": mutated(lambda a: a.update(schema="reputation-static-import.v2")),
            "top-level field": mutated(lambda a: a.update(unexpected=True)),
            "overrides type": mutated(lambda a: a.update(overrides={})),
            "missing field": mutated(lambda a: a["overrides"][1].pop("band")),
            "unknown field": mutated(lambda a: a["overrides"][1].update(ttl_seconds=0)),
            "band": mutated(lambda a: a["overrides"][1].update(band="unknown")),
            "kind": mutated(lambda a: a["overrides"][1].update(kind="cidr")),
            "reason": mutated(lambda a: a["overrides"][1].update(reason="Static")),
            "expires_at type": mutated(lambda a: a["overrides"][1].update(expires_at="2030-01-01T00:00:00Z")),
            "expires_at bool": mutated(lambda a: a["overrides"][1].update(expires_at=True)),
            "expires_at range": mutated(lambda a: a["overrides"][1].update(expires_at=NOW + 2 * 31536000)),
            "duplicate subject": mutated(lambda a: a["overrides"][1].update(subject="a.example")),
            "duplicate key": json.dumps(valid)[:-1] + ', "schema": "reputation-static-import.v1"}',
            "not json": "{",
        }
        for name, artifact in cases.items():
            with self.subTest(name):
                code, stdout, stderr, send = self.run_import(artifact, times=[NOW])
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                self.assertIn("error:", stderr)
                send.assert_not_called()
                if isinstance(artifact, dict) and isinstance(artifact["overrides"], list) and name != "schema" and name != "top-level field":
                    self.assertIn("overrides[1]", stderr)

    def test_failure_stops_the_batch_without_retry_and_exits_non_zero(self):
        """An uncertain mutation is attempted once and the remaining entries are not sent."""
        ok = ADMIN.Response(200, "OK", {}, b"{}", {})
        code, stdout, stderr, send = self.run_import(self.artifact([0, 0, 0]), times=[NOW] * 4,
                                                     send_effect=[ok, TimeoutError("timeout"), ok])
        self.assertEqual(code, 1)
        self.assertEqual(send.call_count, 2)
        summary = json.loads(stdout)
        self.assertEqual([result["status"] for result in summary["results"]], ["applied", "failed", "not-attempted"])
        self.assertIn("outcome may be unknown", summary["results"][1]["error"])
        self.assertIn("failed kind=dns_domain subject=b.example", stderr)

    def test_continue_on_error_reports_each_failure_and_exits_non_zero(self):
        """A definite conflict is reported once and later independent entries are still applied."""
        ok = ADMIN.Response(200, "OK", {}, b"{}", {})
        conflict = ADMIN.Response(409, "Conflict", {}, b"{}", {"error": "Conflict"})
        code, stdout, _stderr, send = self.run_import(self.artifact([0, 0, 0]), times=[NOW] * 4,
                                                      send_effect=[conflict, ok, ok], extra=["--continue-on-error"])
        self.assertEqual(code, 1)
        self.assertEqual(send.call_count, 3)
        summary = json.loads(stdout)
        self.assertEqual([result["status"] for result in summary["results"]], ["failed", "applied", "applied"])
        self.assertIn("HTTP 409", summary["results"][0]["error"])


if __name__ == "__main__":
    unittest.main()
