#!/usr/bin/env python3
#
# Copyright (C) 2026 Christian Roessner
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Regression tests for the legacy-to-v2 config converter."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT_DIR / "scripts" / "convert-config-v1-to-v2.py"
FIXTURE_PATH = ROOT_DIR / "scripts" / "testdata" / "legacy-monolithic-config.yml"


class ConvertConfigV1ToV2Test(unittest.TestCase):
    """End-to-end validation for the config converter."""

    def test_convert_and_validate_legacy_config(self) -> None:
        env = os.environ.copy()
        env.setdefault("GOEXPERIMENT", "runtimesecret")
        env.setdefault("GEXPERIMENT", "runtimesecret")

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "converted.yml"
            report_path = Path(tmp_dir) / "conversion-report.txt"

            result = subprocess.run(
                (
                    "python3",
                    str(SCRIPT_PATH),
                    str(FIXTURE_PATH),
                    "--output",
                    str(output_path),
                    "--report",
                    str(report_path),
                    "--validate",
                ),
                cwd=ROOT_DIR,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual("", result.stdout)
            converted = output_path.read_text(encoding="utf-8")
            report = report_path.read_text(encoding="utf-8")

            self.assertIn("runtime:", converted)
            self.assertIn("storage:", converted)
            self.assertIn("auth:", converted)
            self.assertIn("identity:", converted)

            self.assertIn('primary:', converted)
            self.assertIn('"redis:6379"', converted)
            self.assertIn("backend_health_checks", converted)
            self.assertIn("allow_cleartext_networks", converted)
            self.assertIn("ip_allowlist", converted)
            self.assertIn("hooks:", converted)
            self.assertIn("http_location", converted)
            self.assertIn("scopes", converted)
            self.assertIn("remember_me_ttl", converted)
            self.assertIn("privacy_policy_url", converted)
            self.assertIn("optional_ldap_pools", FIXTURE_PATH.read_text(encoding="utf-8"))
            self.assertIn("pools:", converted)
            self.assertIn("list-account:", converted)
            self.assertIn("named_backends:", converted)
            self.assertIn("lookup-secondary:", converted)
            self.assertIn("oidc_bearer:", converted)
            self.assertIn("basic_auth:", converted)
            self.assertIn("keep_alive:", converted)
            self.assertIn("enabled: true", converted)
            self.assertIn("x-claim-email:", converted)
            self.assertIn("x-scope-profile:", converted)
            self.assertIn("when_no_auth: true", converted)

            self.assertNotRegex(converted, re.compile(r"^server:", re.MULTILINE))
            self.assertNotRegex(converted, re.compile(r"^ldap:", re.MULTILINE))
            self.assertNotRegex(converted, re.compile(r"^lua:", re.MULTILINE))
            self.assertNotRegex(converted, re.compile(r"^idp:", re.MULTILINE))
            self.assertNotIn("soft_whitelist", converted)
            self.assertNotIn("ip_whitelist", converted)
            self.assertNotIn("backend_server_monitoring", converted)

            self.assertIn("validation passed", report)
            self.assertIn("migrated paths", report)
            self.assertNotIn("no mapping rule", report)
            self.assertNotIn("Dropped legacy paths requiring manual review", report)
            self.assertNotIn("server.basic_auth.enabled", report)
            self.assertNotIn("server.keep_alive.enabled", report)
            self.assertNotIn("server.oidc_auth.enabled", report)

    def test_convert_dotted_legacy_keys(self) -> None:
        env = os.environ.copy()
        env.setdefault("GOEXPERIMENT", "runtimesecret")
        env.setdefault("GEXPERIMENT", "runtimesecret")

        legacy = """\
server:
  basic_auth.enabled: true
  oidc_auth.enabled: false
  keep_alive.enabled: true
"""

        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "legacy.yml"
            output_path = Path(tmp_dir) / "converted.yml"
            report_path = Path(tmp_dir) / "conversion-report.txt"
            input_path.write_text(legacy, encoding="utf-8")

            result = subprocess.run(
                (
                    "python3",
                    str(SCRIPT_PATH),
                    str(input_path),
                    "--output",
                    str(output_path),
                    "--report",
                    str(report_path),
                ),
                cwd=ROOT_DIR,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual("", result.stdout)

            converted = output_path.read_text(encoding="utf-8")
            report = report_path.read_text(encoding="utf-8")

            self.assertIn("basic_auth:", converted)
            self.assertIn("oidc_bearer:", converted)
            self.assertIn("keep_alive:", converted)
            self.assertIn("enabled: true", converted)
            self.assertIn("enabled: false", converted)
            self.assertNotIn("no mapping rule", report)
            self.assertNotIn("Dropped legacy paths requiring manual review", report)
            self.assertNotIn("server.basic_auth.enabled", report)
            self.assertNotIn("server.keep_alive.enabled", report)
            self.assertNotIn("server.oidc_auth.enabled", report)

    def test_semantic_auto_enable_does_not_duplicate_named_controls(self) -> None:
        env = os.environ.copy()
        env.setdefault("GOEXPERIMENT", "runtimesecret")
        env.setdefault("GEXPERIMENT", "runtimesecret")

        legacy = """\
server:
  features:
    - brute_force
    - name: tls_encryption
      when_no_auth: false
    - name: rbl
      when_no_auth: false
    - relay_domains
    - lua
    - backend_server_monitoring

realtime_blackhole_lists:
  threshold: 1
  lists:
    - name: "Spamhaus"
      rbl: "zen.spamhaus.org"
      ipv4: true
      return_codes:
        - "127.0.0.2"

cleartext_networks:
  - "127.0.0.0/8"
"""

        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "legacy.yml"
            output_path = Path(tmp_dir) / "converted.yml"
            report_path = Path(tmp_dir) / "conversion-report.txt"
            input_path.write_text(legacy, encoding="utf-8")

            result = subprocess.run(
                (
                    "python3",
                    str(SCRIPT_PATH),
                    str(input_path),
                    "--output",
                    str(output_path),
                    "--report",
                    str(report_path),
                ),
                cwd=ROOT_DIR,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual("", result.stdout)

            converted = output_path.read_text(encoding="utf-8")
            report = report_path.read_text(encoding="utf-8")

            self.assertIn('name: "tls_encryption"', converted)
            self.assertIn('name: "rbl"', converted)
            self.assertNotIn("- auto-enabled controls: rbl, tls_encryption", report)

    def test_convert_legacy_oidc_logout_keys(self) -> None:
        env = os.environ.copy()
        env.setdefault("GOEXPERIMENT", "runtimesecret")
        env.setdefault("GEXPERIMENT", "runtimesecret")

        legacy = """\
idp:
  oidc:
    enabled: true
    issuer: "https://issuer.example.test"
    front_channel_logout_supported: true
    front_channel_logout_session_supported: false
    back_channel_logout_supported: true
    back_channel_logout_session_supported: false
"""

        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "legacy.yml"
            output_path = Path(tmp_dir) / "converted.yml"
            report_path = Path(tmp_dir) / "conversion-report.txt"
            input_path.write_text(legacy, encoding="utf-8")

            result = subprocess.run(
                (
                    "python3",
                    str(SCRIPT_PATH),
                    str(input_path),
                    "--output",
                    str(output_path),
                    "--report",
                    str(report_path),
                ),
                cwd=ROOT_DIR,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual("", result.stdout)

            converted = output_path.read_text(encoding="utf-8")
            report = report_path.read_text(encoding="utf-8")

            self.assertIn("logout:", converted)
            self.assertIn("front_channel_supported: true", converted)
            self.assertIn("front_channel_session_supported: false", converted)
            self.assertIn("back_channel_supported: true", converted)
            self.assertIn("back_channel_session_supported: false", converted)
            self.assertNotIn("front_channel_logout_supported", converted)
            self.assertNotIn("back_channel_logout_supported", converted)
            self.assertNotIn("no mapping rule", report)
            self.assertNotIn("Dropped legacy paths requiring manual review", report)

    def test_preserves_root_extension_anchors_best_effort(self) -> None:
        env = os.environ.copy()
        env.setdefault("GOEXPERIMENT", "runtimesecret")
        env.setdefault("GEXPERIMENT", "runtimesecret")

        legacy = """\
x-claim-email: &x-claim-email
  claim: "email"
  attribute: "mail"
  type: "string"
x-oc-mappings:
  mappings:
    - *x-claim-email
"""

        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "legacy.yml"
            output_path = Path(tmp_dir) / "converted.yml"
            input_path.write_text(legacy, encoding="utf-8")

            result = subprocess.run(
                (
                    "python3",
                    str(SCRIPT_PATH),
                    str(input_path),
                    "--output",
                    str(output_path),
                ),
                cwd=ROOT_DIR,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual("", result.stdout)

            converted = output_path.read_text(encoding="utf-8")
            self.assertIn("x-claim-email: &x-claim-email", converted)
            self.assertIn("- *x-claim-email", converted)

    def test_preserves_mapping_order_from_legacy_yaml(self) -> None:
        env = os.environ.copy()
        env.setdefault("GOEXPERIMENT", "runtimesecret")
        env.setdefault("GEXPERIMENT", "runtimesecret")

        legacy = """\
x-order-test:
  zeta: "z"
  alpha: "a"
  middle: "m"
"""

        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "legacy.yml"
            output_path = Path(tmp_dir) / "converted.yml"
            input_path.write_text(legacy, encoding="utf-8")

            result = subprocess.run(
                (
                    "python3",
                    str(SCRIPT_PATH),
                    str(input_path),
                    "--output",
                    str(output_path),
                ),
                cwd=ROOT_DIR,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual("", result.stdout)

            converted = output_path.read_text(encoding="utf-8")
            zeta_index = converted.index('zeta: "z"')
            alpha_index = converted.index('alpha: "a"')
            middle_index = converted.index('middle: "m"')

            self.assertLess(zeta_index, alpha_index)
            self.assertLess(alpha_index, middle_index)

    def test_renders_multiline_ldap_filter_as_yaml_block_scalar(self) -> None:
        env = os.environ.copy()
        env.setdefault("GOEXPERIMENT", "runtimesecret")
        env.setdefault("GEXPERIMENT", "runtimesecret")

        legacy = """\
ldap:
  config:
    server_uri:
      - "ldap://ldap:389"
    auth_pool_size: 4
    lookup_pool_size: 4
  search:
    - protocol:
        - "imap"
      cache_name: "mail"
      base_dn: "dc=example,dc=org"
      scope: "sub"
      filter:
        user: |-
          (&(objectClass=person)
            (uid=%u))
      mapping:
        account_field: "uid"
"""

        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "legacy.yml"
            output_path = Path(tmp_dir) / "converted.yml"
            input_path.write_text(legacy, encoding="utf-8")

            result = subprocess.run(
                (
                    "python3",
                    str(SCRIPT_PATH),
                    str(input_path),
                    "--output",
                    str(output_path),
                ),
                cwd=ROOT_DIR,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual("", result.stdout)

            converted = output_path.read_text(encoding="utf-8")

            self.assertIn('user: |-', converted)
            self.assertIn('(&(objectClass=person)', converted)
            self.assertIn('(uid=%u))', converted)
            self.assertNotIn('\\n', converted)


if __name__ == "__main__":
    unittest.main()
