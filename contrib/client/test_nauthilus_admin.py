"""Hermetic command-to-HTTP contracts for reputation administration."""

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
