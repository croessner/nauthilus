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

"""Convert a legacy monolithic Nauthilus config into the current config-v2 layout."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parent.parent
YAML_READER_CMD = ("go", "run", "./scripts/read_yaml_as_json.go")
VALIDATE_CMD = ("go", "run", "./server")
V2_ROOTS = ("runtime", "observability", "storage", "auth", "identity")
LOADER_ROOTS = ("includes", "env", "patch")
TOP_LEVEL_ORDER = ("includes", "env", "patch", "runtime", "observability", "storage", "auth", "identity")
AUTHENTICATE_OPERATION = "authenticate"
LOOKUP_IDENTITY_OPERATION = "lookup_identity"
LIST_ACCOUNTS_OPERATION = "list_accounts"
STANDARD_AUTH_POLICY = "standard_auth"
LEGACY_SCHEDULER_KEYS = ("when_no_auth", "when_authenticated", "when_unauthenticated")
LUA_DEPENDENCY_KEY = "depends_on"

CONTROL_NAME_MAP = {
    "brute_force": "brute_force",
    "realtime_blackhole_lists": "rbl",
    "rbl": "rbl",
    "relay_domains": "relay_domains",
    "cleartext_networks": "tls_encryption",
    "tls_encryption": "tls_encryption",
    "lua": "lua",
}

SERVICE_NAME_MAP = {
    "backend_server_monitoring": "backend_health_checks",
    "backend_health_checks": "backend_health_checks",
}

PATH_RENAMES: dict[tuple[str, ...], tuple[str, ...]] = {
    ("server", "instance_name"): ("runtime", "instance_name"),
    ("server", "address"): ("runtime", "servers", "http", "address"),
    ("server", "http3"): ("runtime", "servers", "http", "http3"),
    ("server", "haproxy_v2"): ("runtime", "servers", "http", "haproxy_v2"),
    ("server", "trusted_proxies"): ("runtime", "servers", "http", "trusted_proxies"),
    ("server", "run_as_user"): ("runtime", "process", "run_as_user"),
    ("server", "run_as_group"): ("runtime", "process", "run_as_group"),
    ("server", "chroot"): ("runtime", "process", "chroot"),
    ("server", "rate_limit_burst"): ("runtime", "servers", "http", "rate_limit", "burst"),
    ("server", "rate_limit_per_second"): ("runtime", "servers", "http", "rate_limit", "per_second"),
    ("server", "insights", "enable_pprof"): ("observability", "profiles", "pprof", "enabled"),
    ("server", "insights", "enable_block_profile"): ("observability", "profiles", "block", "enabled"),
    ("server", "insights", "monitor_connections"): ("observability", "metrics", "monitor_connections"),
    ("server", "default_http_request_header"): ("auth", "request", "headers"),
    ("server", "basic_auth"): ("auth", "backchannel", "basic_auth"),
    ("server", "oidc_auth"): ("auth", "backchannel", "oidc_bearer"),
    ("server", "max_concurrent_requests"): ("auth", "pipeline", "max_concurrent_requests"),
    ("server", "max_login_attempts"): ("auth", "pipeline", "max_login_attempts"),
    ("server", "nginx_wait_delay"): ("auth", "pipeline", "wait_delay"),
    ("server", "local_cache_auth_ttl"): ("auth", "pipeline", "local_cache_ttl"),
    ("server", "max_password_history_entries"): ("auth", "pipeline", "password_history", "max_entries"),
    ("server", "master_user"): ("auth", "pipeline", "master_user"),
    ("server", "backends"): ("auth", "backends", "order"),
    ("server", "brute_force_protocols"): ("auth", "controls", "brute_force", "protocols"),
    ("server", "controls"): ("auth", "controls", "enabled"),
    ("server", "services"): ("auth", "services", "enabled"),
    ("server", "imap_backend_address"): ("auth", "upstreams", "imap", "address"),
    ("server", "imap_backend_port"): ("auth", "upstreams", "imap", "port"),
    ("server", "pop3_backend_address"): ("auth", "upstreams", "pop3", "address"),
    ("server", "pop3_backend_port"): ("auth", "upstreams", "pop3", "port"),
    ("server", "smtp_backend_address"): ("auth", "upstreams", "smtp", "address"),
    ("server", "smtp_backend_port"): ("auth", "upstreams", "smtp", "port"),
    ("server", "frontend", "html_static_content_path"): ("identity", "frontend", "assets", "html_static_content_path"),
    ("server", "frontend", "language_resources"): ("identity", "frontend", "assets", "language_resources"),
    ("server", "frontend", "languages"): ("identity", "frontend", "localization", "languages"),
    ("server", "frontend", "default_language"): ("identity", "frontend", "localization", "default_language"),
    ("server", "frontend", "password_forgotten_url"): ("identity", "frontend", "links", "password_forgotten_url"),
    ("server", "frontend", "privacy_policy_url"): ("identity", "frontend", "links", "privacy_policy_url"),
    ("server", "frontend", "terms_of_service_url"): ("identity", "frontend", "links", "terms_of_service_url"),
    ("server", "frontend", "totp_issuer"): ("identity", "mfa", "totp", "issuer"),
    ("server", "frontend", "totp_skew"): ("identity", "mfa", "totp", "skew"),
    ("server", "redis", "master"): ("storage", "redis", "primary"),
    ("storage", "redis", "master"): ("storage", "redis", "primary"),
    ("idp", "remember_me_ttl"): ("identity", "session", "remember_me_ttl"),
    ("idp", "terms_of_service_url"): ("identity", "frontend", "links", "terms_of_service_url"),
    ("idp", "privacy_policy_url"): ("identity", "frontend", "links", "privacy_policy_url"),
    ("idp", "password_forgotten_url"): ("identity", "frontend", "links", "password_forgotten_url"),
    ("idp", "oidc", "front_channel_logout_supported"): ("identity", "oidc", "logout", "front_channel_supported"),
    ("idp", "oidc", "front_channel_logout_session_supported"): ("identity", "oidc", "logout", "front_channel_session_supported"),
    ("idp", "oidc", "back_channel_logout_supported"): ("identity", "oidc", "logout", "back_channel_supported"),
    ("idp", "oidc", "back_channel_logout_session_supported"): ("identity", "oidc", "logout", "back_channel_session_supported"),
    ("idp", "slo_enabled"): ("identity", "saml", "slo", "enabled"),
    ("idp", "slo_front_channel_enabled"): ("identity", "saml", "slo", "front_channel_enabled"),
    ("idp", "slo_back_channel_enabled"): ("identity", "saml", "slo", "back_channel_enabled"),
    ("idp", "slo_back_channel_timeout"): ("identity", "saml", "slo", "request_timeout"),
    ("idp", "slo_back_channel_max_retries"): ("identity", "saml", "slo", "back_channel_max_retries"),
    ("backend_server_monitoring", "backend_servers"): ("auth", "services", "backend_health_checks", "targets"),
    ("identity", "saml", "slo_enabled"): ("identity", "saml", "slo", "enabled"),
    ("identity", "saml", "slo_front_channel_enabled"): ("identity", "saml", "slo", "front_channel_enabled"),
    ("identity", "saml", "slo_back_channel_enabled"): ("identity", "saml", "slo", "back_channel_enabled"),
    ("identity", "saml", "slo_back_channel_timeout"): ("identity", "saml", "slo", "request_timeout"),
    ("identity", "saml", "slo_back_channel_max_retries"): ("identity", "saml", "slo", "back_channel_max_retries"),
}

PREFIX_RENAMES: list[tuple[tuple[str, ...], tuple[str, ...]]] = [
    (("server", "tls"), ("runtime", "servers", "http", "tls")),
    (("server", "disabled_endpoints"), ("runtime", "servers", "http", "disabled_endpoints")),
    (("server", "middlewares"), ("runtime", "servers", "http", "middlewares")),
    (("server", "compression"), ("runtime", "servers", "http", "compression")),
    (("server", "keep_alive"), ("runtime", "servers", "http", "keep_alive")),
    (("server", "timeouts"), ("runtime", "timeouts")),
    (("server", "cors"), ("runtime", "servers", "http", "cors")),
    (("server", "security_txt"), ("runtime", "servers", "http", "security_txt")),
    (("server", "http_client"), ("runtime", "clients", "http")),
    (("server", "dns"), ("runtime", "clients", "dns")),
    (("server", "log"), ("observability", "log")),
    (("server", "insights", "tracing"), ("observability", "tracing")),
    (("server", "prometheus_timer"), ("observability", "metrics", "prometheus_timer")),
    (("server", "redis"), ("storage", "redis")),
    (("server", "frontend", "security_headers"), ("identity", "frontend", "security_headers")),
    (("server", "frontend"), ("identity", "frontend")),
    (("ldap", "config"), ("auth", "backends", "ldap", "default")),
    (("ldap", "pools"), ("auth", "backends", "ldap", "pools")),
    (("ldap", "optional_ldap_pools"), ("auth", "backends", "ldap", "pools")),
    (("ldap", "search"), ("auth", "backends", "ldap", "search")),
    (("lua", "config"), ("auth", "backends", "lua", "backend", "default")),
    (("lua", "optional_lua_backends"), ("auth", "backends", "lua", "backend", "named_backends")),
    (("lua", "optional_backends"), ("auth", "backends", "lua", "backend", "named_backends")),
    (("lua", "search"), ("auth", "backends", "lua", "backend", "search")),
    (("lua", "actions"), ("auth", "policy", "obligation_targets", "lua", "actions")),
    (("lua", "controls"), ("auth", "policy", "attribute_sources", "lua", "environment")),
    (("lua", "features"), ("auth", "policy", "attribute_sources", "lua", "environment")),
    (("lua", "filters"), ("auth", "policy", "attribute_sources", "lua", "subject")),
    (("lua", "custom_hooks"), ("auth", "controls", "lua", "hooks")),
    (("idp", "webauthn"), ("identity", "mfa", "webauthn")),
    (("idp", "oidc"), ("identity", "oidc")),
    (("idp", "saml2"), ("identity", "saml")),
    (("realtime_blackhole_lists",), ("auth", "controls", "rbl")),
    (("relay_domains",), ("auth", "controls", "relay_domains")),
    (("brute_force",), ("auth", "controls", "brute_force")),
    (("backend_server_monitoring",), ("auth", "services", "backend_health_checks")),
    (("cleartext_networks",), ("auth", "controls", "tls_encryption", "allow_cleartext_networks")),
]

SCALAR_TYPES = (str, int, float, bool, type(None))


@dataclass
class ConversionReport:
    """Collect conversion decisions, warnings, and follow-up hints."""

    migrated_paths: list[str] = field(default_factory=list)
    overwritten_paths: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    dropped_paths: list[str] = field(default_factory=list)
    auto_enabled_controls: list[str] = field(default_factory=list)
    auto_enabled_services: list[str] = field(default_factory=list)
    validation_output: str = ""

    def render(self) -> str:
        """Render a user-facing conversion report."""
        lines = [
            "Nauthilus legacy-to-v2 conversion report",
            "",
            f"- migrated paths: {len(self.migrated_paths)}",
            f"- warnings: {len(self.warnings)}",
            f"- dropped paths: {len(self.dropped_paths)}",
        ]

        if self.auto_enabled_controls:
            lines.append(f"- auto-enabled controls: {', '.join(self.auto_enabled_controls)}")

        if self.auto_enabled_services:
            lines.append(f"- auto-enabled services: {', '.join(self.auto_enabled_services)}")

        if self.overwritten_paths:
            lines.extend(["", "Overwritten current-v2 paths:"])
            lines.extend(f"- {entry}" for entry in self.overwritten_paths)

        if self.warnings:
            lines.extend(["", "Warnings:"])
            lines.extend(f"- {entry}" for entry in self.warnings)

        if self.dropped_paths:
            lines.extend(["", "Dropped legacy paths requiring manual review:"])
            lines.extend(f"- {entry}" for entry in self.dropped_paths)

        if self.validation_output:
            lines.extend(["", "Validation:"])
            lines.extend(self.validation_output.rstrip().splitlines())

        return "\n".join(lines) + "\n"


@dataclass
class AnchorRegistry:
    """Track top-level extension anchors and best-effort alias reuse targets."""

    path_to_anchor: dict[tuple[Any, ...], str] = field(default_factory=dict)
    fingerprint_to_anchor: dict[str, str] = field(default_factory=dict)


@dataclass
class PolicyCheckDescriptor:
    """Describe one generated policy check before YAML materialization."""

    name: str
    check_type: str
    stage: str
    config_ref: str
    output: str
    operations: list[str] = field(default_factory=list)
    after: list[str] = field(default_factory=list)
    run_if_auth_state: str | None = None
    script_name: str = ""

    def as_config(self) -> dict[str, Any]:
        """Return the policy check in config order."""
        config: dict[str, Any] = {
            "name": self.name,
            "type": self.check_type,
            "stage": self.stage,
        }

        if self.operations:
            config["operations"] = append_unique_items([], self.operations)

        if self.run_if_auth_state:
            config["run_if"] = {"auth_state": self.run_if_auth_state}

        if self.after:
            config["after"] = append_unique_items([], self.after)

        config["config_ref"] = self.config_ref
        config["output"] = self.output

        return config


class PolicyConversionPlanner:
    """Generate target auth.policy config from migrated mechanism config."""

    def __init__(
        self,
        document: dict[str, Any],
        report: ConversionReport,
        control_scheduler_hints: dict[str, dict[str, Any]] | None = None,
    ):
        self.document = document
        self.report = report
        self.control_scheduler_hints = control_scheduler_hints or {}
        self.checks: list[PolicyCheckDescriptor] = []
        self.lua_environment_checks: list[PolicyCheckDescriptor] = []
        self.lua_subject_checks: list[PolicyCheckDescriptor] = []
        self.backend_checks: list[PolicyCheckDescriptor] = []
        self.account_provider_check: PolicyCheckDescriptor | None = None

    def apply(self) -> None:
        """Apply generated target policy config and remove legacy scheduler keys."""
        policy_config = self._ensure_policy_section()
        self.checks = self._build_checks()
        self._merge_named_list(policy_config, "checks", [check.as_config() for check in self.checks])
        self._merge_named_list(policy_config, "policies", self._build_policies())
        self._strip_legacy_scheduler_surface()

    def _ensure_policy_section(self) -> dict[str, Any]:
        auth = ensure_mapping(self.document, ("auth",))
        policy_config = ensure_mapping(auth, ("policy",))

        policy_config.setdefault("mode", "enforce")
        policy_config.setdefault("default_policy", STANDARD_AUTH_POLICY)
        policy_config.setdefault("registry_scripts", [])

        sets = ensure_mapping(policy_config, ("sets",))
        sets.setdefault("networks", {})
        sets.setdefault("time_windows", {})

        report = ensure_mapping(policy_config, ("report",))
        report.setdefault("enabled", False)
        report.setdefault("include_fsm", True)
        report.setdefault("include_checks", True)
        report.setdefault("include_attributes", False)

        return policy_config

    def _build_checks(self) -> list[PolicyCheckDescriptor]:
        checks: list[PolicyCheckDescriptor] = []
        controls = self._enabled_control_items()

        if "brute_force" in controls:
            checks.append(
                builtin_check(
                    "brute_force",
                    "builtin.brute_force",
                    "pre_auth",
                    "auth.controls.brute_force",
                    [AUTHENTICATE_OPERATION],
                )
            )

        self.lua_environment_checks = self._lua_script_checks(
            ("auth", "policy", "attribute_sources", "lua", "environment"),
            "lua_environment",
            "lua.environment",
            "pre_auth",
            "auth.policy.attribute_sources.lua.environment",
        )
        checks.extend(self.lua_environment_checks)

        if "tls_encryption" in controls:
            checks.append(
                builtin_check(
                    "tls_encryption",
                    "builtin.tls_encryption",
                    "pre_auth",
                    "auth.controls.tls_encryption",
                    operations_from_lookup_flag(controls["tls_encryption"].get("when_no_auth")),
                )
            )

        if "relay_domains" in controls:
            checks.append(
                builtin_check(
                    "relay_domains",
                    "builtin.relay_domains",
                    "pre_auth",
                    "auth.controls.relay_domains",
                    [AUTHENTICATE_OPERATION],
                )
            )

        if "rbl" in controls:
            checks.append(
                builtin_check(
                    "rbl",
                    "builtin.rbl",
                    "pre_auth",
                    "auth.controls.rbl",
                    operations_from_lookup_flag(controls["rbl"].get("when_no_auth")),
                )
            )

        self.backend_checks = self._backend_checks()
        checks.extend(self.backend_checks)

        self.lua_subject_checks = self._lua_script_checks(
            ("auth", "policy", "attribute_sources", "lua", "subject"),
            "lua_subject",
            "lua.subject",
            "subject_analysis",
            "auth.policy.attribute_sources.lua.subject",
        )
        checks.extend(self.lua_subject_checks)

        self.account_provider_check = self._account_provider_check()
        if self.account_provider_check is not None:
            checks.append(self.account_provider_check)

        return checks

    def _enabled_control_items(self) -> dict[str, dict[str, Any]]:
        value, exists = get_nested_value(self.document, ("auth", "controls", "enabled"))
        if not exists or not isinstance(value, list):
            return {}

        controls: dict[str, dict[str, Any]] = {}
        for entry in value:
            if isinstance(entry, str):
                controls.setdefault(entry, {"name": entry})
                continue

            if not isinstance(entry, dict):
                continue

            name = entry.get("name")
            if isinstance(name, str) and name:
                controls[name] = copy.deepcopy(entry)

        for name, hints in self.control_scheduler_hints.items():
            controls.setdefault(name, {"name": name}).update(copy.deepcopy(hints))

        return controls

    def _lua_script_checks(
        self,
        path: tuple[str, ...],
        check_prefix: str,
        check_type: str,
        stage: str,
        config_prefix: str,
    ) -> list[PolicyCheckDescriptor]:
        scripts, exists = get_nested_value(self.document, path)
        if not exists or not isinstance(scripts, list):
            return []

        checks: list[PolicyCheckDescriptor] = []

        for script in scripts:
            if not isinstance(script, dict):
                continue

            name = script.get("name")
            if not isinstance(name, str) or not name:
                continue

            check_name = f"{check_prefix}_{name}"
            after = [
                f"{check_prefix}_{dependency}"
                for dependency in script.get(LUA_DEPENDENCY_KEY, [])
                if isinstance(dependency, str) and dependency
            ]
            checks.append(
                PolicyCheckDescriptor(
                    name=check_name,
                    check_type=check_type,
                    stage=stage,
                    operations=operations_from_lookup_flag(script.get("when_no_auth")),
                    run_if_auth_state=run_if_auth_state(script),
                    after=after,
                    config_ref=f"{config_prefix}.{name}",
                    output=f"checks.{check_name}",
                    script_name=name,
                )
            )

        return checks

    def _backend_checks(self) -> list[PolicyCheckDescriptor]:
        checks: list[PolicyCheckDescriptor] = []
        backend_order = self._backend_order()

        if "ldap" in backend_order or self._has_nonempty_result(("auth", "backends", "ldap")):
            checks.append(
                builtin_check(
                    "ldap_backend",
                    "backend.ldap",
                    "auth_backend",
                    "auth.backends.ldap",
                    [AUTHENTICATE_OPERATION, LOOKUP_IDENTITY_OPERATION],
                )
            )

        if "lua" in backend_order or self._has_nonempty_result(("auth", "backends", "lua", "backend")):
            checks.append(
                builtin_check(
                    "lua_backend",
                    "backend.lua",
                    "auth_backend",
                    "auth.backends.lua.backend",
                    [AUTHENTICATE_OPERATION, LOOKUP_IDENTITY_OPERATION],
                )
            )

        return checks

    def _backend_order(self) -> set[str]:
        value, exists = get_nested_value(self.document, ("auth", "backends", "order"))
        if not exists or not isinstance(value, list):
            return set()

        return {item for item in value if isinstance(item, str)}

    def _account_provider_check(self) -> PolicyCheckDescriptor | None:
        if not self._has_account_provider_material():
            return None

        return builtin_check(
            "account_provider",
            "backend.account_provider",
            "account_provider",
            "auth.backends",
            [LIST_ACCOUNTS_OPERATION],
        )

    def _has_account_provider_material(self) -> bool:
        if self._has_nonempty_result(("auth", "backends", "ldap", "pools")):
            return True

        if self._has_nonempty_result(("auth", "backends", "lua", "backend", "named_backends")):
            return True

        for path in (
            ("auth", "backends", "ldap", "search"),
            ("auth", "backends", "lua", "backend", "search"),
        ):
            value, exists = get_nested_value(self.document, path)
            if exists and contains_protocol(value, "list-account"):
                return True

        return False

    def _has_nonempty_result(self, path: tuple[str, ...]) -> bool:
        value, exists = get_nested_value(self.document, path)
        if not exists:
            return False

        return not is_empty_value(value)

    def _build_policies(self) -> list[dict[str, Any]]:
        policies: list[dict[str, Any]] = []
        check_names = {check.name: check for check in self.checks}

        if "brute_force" in check_names:
            policies.extend(brute_force_policies())

        if "tls_encryption" in check_names:
            policies.append(tls_policy(check_names["tls_encryption"].operations))

        if "relay_domains" in check_names:
            policies.extend(relay_domain_policies())

        if "rbl" in check_names:
            policies.extend(rbl_policies(check_names["rbl"].operations))

        for check in self.lua_environment_checks:
            policies.extend(lua_environment_policies(check))

        if self.backend_checks:
            policies.extend(backend_decision_policies())

        for check in self.lua_subject_checks:
            policies.extend(lua_subject_policies(check))

        if self.backend_checks:
            policies.extend(auth_result_policies())
            policies.extend(lookup_identity_policies())

        if self.account_provider_check is not None:
            policies.extend(list_accounts_policies())

        policies.append(default_deny_policy())

        return policies

    def _merge_named_list(self, policy_config: dict[str, Any], key: str, generated: list[dict[str, Any]]) -> None:
        existing = policy_config.get(key)
        if not isinstance(existing, list):
            existing = []

        merged = [copy.deepcopy(item) for item in existing]
        seen = {
            item.get("name")
            for item in merged
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }

        for item in generated:
            name = item.get("name")
            if isinstance(name, str) and name in seen:
                self.report.warnings.append(
                    f"generated auth.policy.{key} entry {name!r} already exists and was preserved"
                )

                continue

            if isinstance(name, str):
                seen.add(name)

            merged.append(copy.deepcopy(item))

        policy_config[key] = merged

    def _strip_legacy_scheduler_surface(self) -> None:
        controls, controls_exist = get_nested_value(self.document, ("auth", "controls", "enabled"))
        if controls_exist and isinstance(controls, list):
            stripped_controls = []
            for control in controls:
                if isinstance(control, dict) and isinstance(control.get("name"), str):
                    stripped_controls.append(control["name"])
                    continue

                stripped_controls.append(control)

            set_nested_value(self.document, ("auth", "controls", "enabled"), stripped_controls)

        for path in (
            ("auth", "policy", "attribute_sources", "lua", "environment"),
            ("auth", "policy", "attribute_sources", "lua", "subject"),
        ):
            self._strip_lua_script_fields(path)

    def _strip_lua_script_fields(self, path: tuple[str, ...]) -> None:
        scripts, exists = get_nested_value(self.document, path)
        if not exists or not isinstance(scripts, list):
            return

        sanitized: list[Any] = []
        for script in scripts:
            if not isinstance(script, dict):
                sanitized.append(script)
                continue

            cleaned = copy.deepcopy(script)
            for key in (*LEGACY_SCHEDULER_KEYS, LUA_DEPENDENCY_KEY):
                cleaned.pop(key, None)

            sanitized.append(cleaned)

        set_nested_value(self.document, path, sanitized)


class LegacyConfigConverter:
    """Convert old monolithic config layouts to the current config-v2 structure."""

    def __init__(self, source: dict[str, Any]):
        self.source = source
        self.report = ConversionReport()
        self.result: dict[str, Any] = {}
        self.handled_prefixes: set[tuple[str, ...]] = set()
        self.control_scheduler_hints: dict[str, dict[str, Any]] = {}

    def convert(self) -> tuple[dict[str, Any], ConversionReport]:
        """Convert the loaded source document."""
        self._copy_existing_current_roots()
        self._migrate_special_legacy_sections()

        for path, value in flatten_node(self.source):
            if not path:
                continue

            if self._is_preserved_root(path[0]) or self._is_handled_special_path(path):
                continue

            new_path, new_value = self._map_path(path, value)
            if new_path is None:
                self.report.dropped_paths.append(format_path(path))

                continue

            self._set_result_value(new_path, new_value, source_path=path)

        self._normalize_semantics()
        self.result = reorder_root_keys(self.result)

        return self.result, self.report

    def _copy_existing_current_roots(self) -> None:
        for root in (*LOADER_ROOTS, *V2_ROOTS):
            if root in self.source:
                self.result[root] = copy.deepcopy(self.source[root])

        for root, value in self.source.items():
            if isinstance(root, str) and root.startswith("x-"):
                self.result[root] = copy.deepcopy(value)
                self.handled_prefixes.add((root,))

    @staticmethod
    def _is_preserved_root(root: Any) -> bool:
        return isinstance(root, str) and (root in V2_ROOTS or root in LOADER_ROOTS or root.startswith("x-"))

    def _is_handled_special_path(self, path: tuple[Any, ...]) -> bool:
        str_path = tuple(part for part in path if isinstance(part, str))

        for prefix in self.handled_prefixes:
            if str_path[: len(prefix)] == prefix:
                return True

        return False

    def _migrate_special_legacy_sections(self) -> None:
        self._migrate_server_features()
        self._migrate_lua_features()

    def _migrate_server_features(self) -> None:
        features, exists = get_nested_value(self.source, ("server", "features"))
        if not exists or not isinstance(features, list):
            return

        self.handled_prefixes.add(("server", "features"))

        for index, item in enumerate(features):
            source_path = ("server", "features", index)
            name, when_no_auth, explicit_when_no_auth = self._parse_named_feature_item(item, source_path)
            if not name:
                continue

            destination = self._legacy_runtime_feature_destination(name, source_path)
            if destination is None:
                continue

            target_path, normalized_name = destination
            target_value: Any = normalized_name

            if target_path == ("auth", "controls", "enabled"):
                if explicit_when_no_auth:
                    target_value = {
                        "name": normalized_name,
                        "when_no_auth": when_no_auth,
                    }
                    self._record_control_scheduler_hint(normalized_name, "when_no_auth", when_no_auth)

            elif explicit_when_no_auth:
                self.report.warnings.append(
                    f"legacy path {format_path((*source_path, 'when_no_auth'))} applies only to controls and was ignored"
                )

            self._append_unique_value(target_path, target_value)
            self.report.migrated_paths.append(
                f"{format_path(source_path)} -> {'.'.join(target_path)}"
            )

    def _migrate_lua_features(self) -> None:
        features, exists = get_nested_value(self.source, ("lua", "features"))
        if not exists or not isinstance(features, list):
            return

        self.handled_prefixes.add(("lua", "features"))

        for index, item in enumerate(features):
            self._append_unique_value(("auth", "policy", "attribute_sources", "lua", "environment"), copy.deepcopy(item))
            self.report.migrated_paths.append(
                f"{format_path(('lua', 'features', index))} -> auth.policy.attribute_sources.lua.environment"
            )

    def _parse_named_feature_item(
        self,
        item: Any,
        source_path: tuple[Any, ...],
    ) -> tuple[str | None, bool, bool]:
        if isinstance(item, str):
            return item, False, False

        if not isinstance(item, dict):
            self.report.warnings.append(
                f"legacy path {format_path(source_path)} is not a supported feature item and requires manual review"
            )
            self.report.dropped_paths.append(format_path(source_path))

            return None, False, False

        name = item.get("name")
        if not isinstance(name, str) or not name:
            self.report.warnings.append(
                f"legacy path {format_path(source_path)} is missing a string name and requires manual review"
            )
            self.report.dropped_paths.append(format_path(source_path))

            return None, False, False

        when_no_auth = bool(item.get("when_no_auth", False))

        return name, when_no_auth, "when_no_auth" in item

    def _legacy_runtime_feature_destination(
        self,
        name: str,
        source_path: tuple[Any, ...],
    ) -> tuple[tuple[str, ...], str] | None:
        if name in CONTROL_NAME_MAP:
            return ("auth", "controls", "enabled"), CONTROL_NAME_MAP[name]

        if name in SERVICE_NAME_MAP:
            return ("auth", "services", "enabled"), SERVICE_NAME_MAP[name]

        self.report.warnings.append(
            f"legacy path {format_path(source_path)} references unsupported runtime feature {name!r}"
        )
        self.report.dropped_paths.append(format_path(source_path))

        return None

    def _record_control_scheduler_hint(self, name: str, key: str, value: Any) -> None:
        self.control_scheduler_hints.setdefault(name, {})[key] = value

    def _map_path(self, path: tuple[Any, ...], value: Any) -> tuple[tuple[Any, ...] | None, Any]:
        str_path = tuple(part for part in path if isinstance(part, str))

        if self._should_drop_legacy_path(str_path):
            self.report.warnings.append(
                f"legacy path {format_path(path)} has no current public config-v2 equivalent and requires manual review"
            )

            return None, value

        mapped_path = self._match_exact_or_prefix(path, str_path)
        if mapped_path is None:
            self.report.warnings.append(f"no mapping rule for legacy path {format_path(path)}")

            return None, value

        mapped_path, mapped_value = self._apply_alias_renames(mapped_path, value)

        return mapped_path, mapped_value

    @staticmethod
    def _should_drop_legacy_path(str_path: tuple[str, ...]) -> bool:
        if str_path[:2] == ("realtime_blackhole_lists", "soft_whitelist"):
            return True

        if str_path[:2] == ("realtime_blackhole_lists", "soft_allowlist"):
            return True

        return False

    def _match_exact_or_prefix(self, path: tuple[Any, ...], str_path: tuple[str, ...]) -> tuple[Any, ...] | None:
        for exact_old, exact_new in PATH_RENAMES.items():
            if tuple(str_path[: len(exact_old)]) == exact_old and len(path) >= len(exact_old):
                remainder = path[len(exact_old) :]

                return (*exact_new, *remainder)

        for old_prefix, new_prefix in PREFIX_RENAMES:
            if tuple(str_path[: len(old_prefix)]) == old_prefix and len(path) >= len(old_prefix):
                remainder = path[len(old_prefix) :]

                return (*new_prefix, *remainder)

        return None

    def _apply_alias_renames(self, path: tuple[Any, ...], value: Any) -> tuple[tuple[Any, ...], Any]:
        updated = list(path)

        for index, segment in enumerate(updated):
            if not isinstance(segment, str):
                continue

            if segment in ("soft_allowlist", "soft_whitelist"):
                updated[index] = "allowlist"

            elif segment == "ip_whitelist":
                updated[index] = "ip_allowlist"

            elif segment == "custom_hooks":
                updated[index] = "hooks"

            elif segment == "roles":
                updated[index] = "scopes"

            elif segment == "feature_vm_pool_size":
                updated[index] = "environment_vm_pool_size"

            elif segment == "filter_vm_pool_size":
                updated[index] = "subject_vm_pool_size"

        if updated and updated[-1] == "return_code":
            updated[-1] = "return_codes"
            if isinstance(value, str) and value:
                value = [value]

        return tuple(updated), value

    def _set_result_value(self, path: tuple[Any, ...], value: Any, source_path: tuple[Any, ...]) -> None:
        existing, exists = get_nested_value(self.result, path)

        if exists:
            if existing == value:
                return

            self.report.overwritten_paths.append(
                f"{format_path(path)} overwritten by legacy input {format_path(source_path)}"
            )

        set_nested_value(self.result, path, copy.deepcopy(value))
        self.report.migrated_paths.append(f"{format_path(source_path)} -> {format_path(path)}")

    def _normalize_semantics(self) -> None:
        self._normalize_list("auth.controls.enabled", CONTROL_NAME_MAP)
        self._normalize_list("auth.services.enabled", SERVICE_NAME_MAP)
        self._normalize_list("auth.controls.brute_force.learning", CONTROL_NAME_MAP)

        self._auto_enable_control("brute_force", self._has_nonempty_path(("brute_force",)) or self._has_nonempty_path(("server", "brute_force_protocols")))
        self._auto_enable_control("rbl", self._has_nonempty_path(("realtime_blackhole_lists",)))
        self._auto_enable_control("relay_domains", self._has_nonempty_path(("relay_domains",)))
        self._auto_enable_control("tls_encryption", self._has_nonempty_path(("cleartext_networks",)))
        self._auto_enable_control(
            "lua",
            any(
                self._has_nonempty_path(prefix)
                for prefix in (
                    ("lua", "actions"),
                    ("lua", "controls"),
                    ("lua", "features"),
                    ("lua", "filters"),
                    ("lua", "custom_hooks"),
                )
            ),
        )
        self._auto_enable_service("backend_health_checks", self._has_nonempty_path(("backend_server_monitoring",)))
        self._build_policy_target_config()

    def _build_policy_target_config(self) -> None:
        PolicyConversionPlanner(self.result, self.report, self.control_scheduler_hints).apply()

    def _normalize_list(self, dotted_path: str, rename_map: dict[str, str]) -> None:
        path = tuple(dotted_path.split("."))
        value, exists = get_nested_value(self.result, path)
        if not exists or not isinstance(value, list):
            return

        normalized: list[Any] = []
        seen: dict[Any, int] = {}

        for entry in value:
            normalized_entry = self._normalize_named_entry(entry, rename_map)
            key = self._entry_semantic_key(normalized_entry)
            existing_index = seen.get(key)
            if existing_index is not None:
                if self._is_named_mapping(normalized_entry) and isinstance(normalized[existing_index], str):
                    normalized[existing_index] = normalized_entry

                continue

            seen[key] = len(normalized)
            normalized.append(normalized_entry)

        set_nested_value(self.result, path, normalized)

    def _auto_enable_control(self, name: str, condition: bool) -> None:
        if not condition:
            return

        self._append_unique(("auth", "controls", "enabled"), name, self.report.auto_enabled_controls)

    def _auto_enable_service(self, name: str, condition: bool) -> None:
        if not condition:
            return

        self._append_unique(("auth", "services", "enabled"), name, self.report.auto_enabled_services)

    def _append_unique(self, path: tuple[str, ...], item: str, report_bucket: list[str]) -> None:
        value, exists = get_nested_value(self.result, path)
        if not exists or not isinstance(value, list):
            value = []

        item_key = self._entry_semantic_key(item)
        for existing in value:
            if self._entry_semantic_key(existing) == item_key:
                return

        value.append(item)
        set_nested_value(self.result, path, value)
        report_bucket.append(item)

    def _append_unique_value(self, path: tuple[str, ...], item: Any) -> None:
        value, exists = get_nested_value(self.result, path)
        if not exists or not isinstance(value, list):
            value = []

        item_key = self._entry_semantic_key(item)
        for index, existing in enumerate(value):
            if self._entry_semantic_key(existing) != item_key:
                continue

            if self._is_named_mapping(item) and isinstance(existing, str):
                value[index] = item
                set_nested_value(self.result, path, value)

                return

        value.append(item)
        set_nested_value(self.result, path, value)

    @staticmethod
    def _normalize_named_entry(entry: Any, rename_map: dict[str, str]) -> Any:
        if isinstance(entry, str):
            return rename_map.get(entry, entry)

        if not isinstance(entry, dict):
            return entry

        normalized = copy.deepcopy(entry)
        name = normalized.get("name")
        if isinstance(name, str):
            normalized["name"] = rename_map.get(name, name)

        return normalized

    @staticmethod
    def _is_named_mapping(entry: Any) -> bool:
        return isinstance(entry, dict) and isinstance(entry.get("name"), str)

    def _entry_semantic_key(self, entry: Any) -> Any:
        if isinstance(entry, str):
            return ("name", entry)

        if self._is_named_mapping(entry):
            return ("name", entry["name"])

        if isinstance(entry, (dict, list)):
            return json.dumps(entry, sort_keys=True)

        return entry

    def _has_nonempty_path(self, path: tuple[str, ...]) -> bool:
        value, exists = get_nested_value(self.source, path)
        if not exists:
            return False

        return not is_empty_value(value)


def append_unique_items(target: list[Any], items: Iterable[Any]) -> list[Any]:
    """Append items while preserving the first occurrence order."""
    for item in items:
        if item not in target:
            target.append(item)

    return target


def ensure_mapping(root: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    """Return a nested mapping, creating missing mappings on demand."""
    current: dict[str, Any] = root
    for part in path:
        value = current.get(part)
        if not isinstance(value, dict):
            value = {}
            current[part] = value

        current = value

    return current


def operations_from_lookup_flag(value: Any) -> list[str]:
    """Map old no-auth scheduling to target operation scoping."""
    operations = [AUTHENTICATE_OPERATION]
    if value is True:
        operations.append(LOOKUP_IDENTITY_OPERATION)

    return operations


def run_if_auth_state(script: dict[str, Any]) -> str | None:
    """Map old authenticated/unauthenticated scheduler flags to run_if.auth_state."""
    authenticated = script.get("when_authenticated") is True
    unauthenticated = script.get("when_unauthenticated") is True

    if authenticated and not unauthenticated:
        return "authenticated"

    if unauthenticated and not authenticated:
        return "unauthenticated"

    return None


def contains_protocol(value: Any, protocol: str) -> bool:
    """Report whether a protocol mapping contains the requested protocol."""
    if isinstance(value, dict):
        return any(contains_protocol(child, protocol) for child in value.values())

    if isinstance(value, list):
        return any(contains_protocol(child, protocol) for child in value)

    return value == protocol


def builtin_check(
    name: str,
    check_type: str,
    stage: str,
    config_ref: str,
    operations: list[str],
) -> PolicyCheckDescriptor:
    """Create a built-in policy check descriptor."""
    return PolicyCheckDescriptor(
        name=name,
        check_type=check_type,
        stage=stage,
        operations=operations,
        config_ref=config_ref,
        output=f"checks.{name}",
    )


def policy_rule(
    name: str,
    stage: str,
    condition: dict[str, Any],
    then: dict[str, Any],
    require_checks: list[str] | None = None,
    operations: list[str] | None = None,
) -> dict[str, Any]:
    """Create one ordered policy rule in stable config order."""
    rule: dict[str, Any] = {
        "name": name,
        "stage": stage,
    }

    if operations and operations != [AUTHENTICATE_OPERATION]:
        rule["operations"] = append_unique_items([], operations)

    if require_checks:
        rule["require_checks"] = require_checks

    rule["if"] = condition
    rule["then"] = then

    return rule


def attr_condition(attribute: str, value: bool) -> dict[str, Any]:
    """Create a boolean attribute condition."""
    return {
        "attribute": attribute,
        "is": value,
    }


def always_condition() -> dict[str, Any]:
    """Create an always-matching condition."""
    return {"always": True}


def all_condition(children: list[dict[str, Any]]) -> dict[str, Any]:
    """Create an all-composition condition."""
    return {"all": children}


def then_block(
    decision: str,
    outcome_marker: str,
    fsm_event_marker: str,
    response_marker: str | None = None,
    response_message: dict[str, Any] | None = None,
    obligations: list[dict[str, Any]] | None = None,
    control: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a policy then block in stable config order."""
    block: dict[str, Any] = {
        "decision": decision,
        "outcome_marker": outcome_marker,
        "fsm_event_marker": fsm_event_marker,
    }

    if response_marker:
        block["response_marker"] = response_marker

    if response_message:
        block["response_message"] = response_message

    if obligations:
        block["obligations"] = obligations

    if control:
        block["control"] = control

    return block


def response_message_from_attribute(attribute: str) -> dict[str, Any]:
    """Select a public Lua status_message detail with the current fallback text."""
    return {
        "from": "attribute_detail",
        "attribute": attribute,
        "detail": "status_message",
        "fallback": "Invalid login or password",
    }


def brute_force_policies() -> list[dict[str, Any]]:
    """Return generated standard-auth brute-force rules."""
    return [
        policy_rule(
            "standard_brute_force_error_tempfail",
            "pre_auth",
            attr_condition("auth.brute_force.error", True),
            then_block(
                "tempfail",
                "auth.outcome.brute_force_error",
                "auth.fsm.event.pre_auth_tempfail",
                "auth.response.tempfail",
            ),
            require_checks=["brute_force"],
        ),
        policy_rule(
            "standard_brute_force_deny",
            "pre_auth",
            attr_condition("auth.brute_force.triggered", True),
            then_block(
                "deny",
                "auth.outcome.brute_force_reject",
                "auth.fsm.event.pre_auth_deny",
                "auth.response.fail",
                obligations=[
                    {"id": "auth.obligation.brute_force.update"},
                    {
                        "id": "auth.obligation.lua_post_action.enqueue",
                        "args": {"action": "brute_force"},
                    },
                ],
            ),
            require_checks=["brute_force"],
        ),
    ]


def tls_policy(operations: list[str]) -> dict[str, Any]:
    """Return the generated standard-auth TLS rule."""
    return policy_rule(
        "standard_tls_enforcement",
        "pre_auth",
        attr_condition("auth.tls.secure", False),
        then_block(
            "tempfail",
            "auth.outcome.tls_required",
            "auth.fsm.event.pre_auth_tempfail",
            "auth.response.tempfail.no_tls",
        ),
        require_checks=["tls_encryption"],
        operations=operations,
    )


def relay_domain_policies() -> list[dict[str, Any]]:
    """Return generated standard-auth relay-domain rules."""
    return [
        policy_rule(
            "standard_relay_domain_error_tempfail",
            "pre_auth",
            attr_condition("auth.relay_domain.error", True),
            then_block(
                "tempfail",
                "auth.outcome.relay_domain_error",
                "auth.fsm.event.pre_auth_tempfail",
                "auth.response.tempfail",
            ),
            require_checks=["relay_domains"],
        ),
        policy_rule(
            "standard_relay_domain_reject",
            "pre_auth",
            all_condition(
                [
                    attr_condition("auth.relay_domain.present", True),
                    attr_condition("auth.relay_domain.known", False),
                ]
            ),
            then_block(
                "deny",
                "auth.outcome.relay_domain_reject",
                "auth.fsm.event.pre_auth_deny",
                "auth.response.fail",
            ),
            require_checks=["relay_domains"],
        ),
    ]


def rbl_policies(operations: list[str]) -> list[dict[str, Any]]:
    """Return generated standard-auth RBL rules."""
    return [
        policy_rule(
            "standard_rbl_error_tempfail",
            "pre_auth",
            attr_condition("auth.rbl.error", True),
            then_block(
                "tempfail",
                "auth.outcome.rbl_error",
                "auth.fsm.event.pre_auth_tempfail",
                "auth.response.tempfail",
            ),
            require_checks=["rbl"],
            operations=operations,
        ),
        policy_rule(
            "standard_rbl_reject",
            "pre_auth",
            attr_condition("auth.rbl.threshold_reached", True),
            then_block(
                "deny",
                "auth.outcome.rbl_reject",
                "auth.fsm.event.pre_auth_deny",
                "auth.response.fail",
            ),
            require_checks=["rbl"],
            operations=operations,
        ),
    ]


def lua_environment_policies(check: PolicyCheckDescriptor) -> list[dict[str, Any]]:
    """Return generated standard-auth policies for one Lua environment source."""
    prefix = f"auth.lua.environment.{check.script_name}"

    return [
        policy_rule(
            f"standard_lua_environment_{check.script_name}_error",
            "pre_auth",
            attr_condition(f"{prefix}.error", True),
            then_block(
                "tempfail",
                f"auth.outcome.lua_environment.{check.script_name}.error",
                "auth.fsm.event.pre_auth_tempfail",
                "auth.response.tempfail",
            ),
            require_checks=[check.name],
            operations=check.operations,
        ),
        policy_rule(
            f"standard_lua_environment_{check.script_name}_trigger",
            "pre_auth",
            attr_condition(f"{prefix}.triggered", True),
            then_block(
                "deny",
                f"auth.outcome.lua_environment.{check.script_name}.reject",
                "auth.fsm.event.pre_auth_deny",
                "auth.response.fail",
                response_message=response_message_from_attribute(f"{prefix}.triggered"),
            ),
            require_checks=[check.name],
            operations=check.operations,
        ),
        policy_rule(
            f"standard_lua_environment_{check.script_name}_abort",
            "pre_auth",
            attr_condition(f"{prefix}.abort", True),
            then_block(
                "neutral",
                "auth.outcome.pre_auth_ok",
                "auth.fsm.event.pre_auth_ok",
                control={"skip_remaining_stage_checks": True},
            ),
            require_checks=[check.name],
            operations=check.operations,
        ),
    ]


def backend_decision_policies() -> list[dict[str, Any]]:
    """Return generated standard-auth backend technical-result rules."""
    return [
        policy_rule(
            "standard_backend_tempfail",
            "auth_decision",
            attr_condition("auth.backend.tempfail", True),
            then_block(
                "tempfail",
                "auth.outcome.backend_tempfail",
                "auth.fsm.event.auth_tempfail",
                "auth.response.tempfail",
            ),
            operations=[AUTHENTICATE_OPERATION, LOOKUP_IDENTITY_OPERATION],
        ),
        policy_rule(
            "standard_empty_username",
            "auth_decision",
            attr_condition("auth.backend.empty_username", True),
            then_block(
                "tempfail",
                "auth.outcome.empty_username",
                "auth.fsm.event.auth_empty_user",
                "auth.response.tempfail",
            ),
            operations=[AUTHENTICATE_OPERATION, LOOKUP_IDENTITY_OPERATION],
        ),
        policy_rule(
            "standard_empty_password",
            "auth_decision",
            attr_condition("auth.backend.empty_password", True),
            then_block(
                "deny",
                "auth.outcome.empty_password",
                "auth.fsm.event.auth_empty_pass",
                "auth.response.fail",
            ),
        ),
    ]


def lua_subject_policies(check: PolicyCheckDescriptor) -> list[dict[str, Any]]:
    """Return generated standard-auth policies for one Lua subject source."""
    prefix = f"auth.lua.subject.{check.script_name}"

    return [
        policy_rule(
            f"standard_lua_subject_{check.script_name}_error",
            "auth_decision",
            attr_condition(f"{prefix}.error", True),
            then_block(
                "tempfail",
                f"auth.outcome.lua_subject.{check.script_name}.error",
                "auth.fsm.event.auth_tempfail",
                "auth.response.tempfail",
            ),
            require_checks=[check.name],
            operations=check.operations,
        ),
        policy_rule(
            f"standard_lua_subject_{check.script_name}_reject",
            "auth_decision",
            attr_condition(f"{prefix}.rejected", True),
            then_block(
                "deny",
                f"auth.outcome.lua_subject.{check.script_name}.reject",
                "auth.fsm.event.auth_deny",
                "auth.response.fail",
                response_message=response_message_from_attribute(f"{prefix}.rejected"),
            ),
            require_checks=[check.name],
            operations=check.operations,
        ),
    ]


def auth_result_policies() -> list[dict[str, Any]]:
    """Return generated standard-auth authenticate result rules."""
    return [
        policy_rule(
            "standard_auth_success",
            "auth_decision",
            attr_condition("auth.authenticated", True),
            then_block(
                "permit",
                "auth.outcome.auth_success",
                "auth.fsm.event.auth_permit",
                "auth.response.ok",
            ),
        ),
        policy_rule(
            "standard_auth_failure",
            "auth_decision",
            attr_condition("auth.authenticated", False),
            then_block(
                "deny",
                "auth.outcome.auth_failure",
                "auth.fsm.event.auth_deny",
                "auth.response.fail",
            ),
        ),
    ]


def lookup_identity_policies() -> list[dict[str, Any]]:
    """Return generated standard-auth lookup-identity result rules."""
    return [
        policy_rule(
            "standard_lookup_identity_success",
            "auth_decision",
            attr_condition("auth.identity.found", True),
            then_block(
                "permit",
                "auth.outcome.lookup_identity_success",
                "auth.fsm.event.auth_permit",
                "auth.response.ok",
            ),
            operations=[LOOKUP_IDENTITY_OPERATION],
        ),
        policy_rule(
            "standard_lookup_identity_failure",
            "auth_decision",
            attr_condition("auth.identity.found", False),
            then_block(
                "deny",
                "auth.outcome.lookup_identity_failure",
                "auth.fsm.event.auth_deny",
                "auth.response.fail",
            ),
            operations=[LOOKUP_IDENTITY_OPERATION],
        ),
    ]


def list_accounts_policies() -> list[dict[str, Any]]:
    """Return generated standard-auth list-account rules."""
    return [
        policy_rule(
            "standard_list_accounts_tempfail",
            "auth_decision",
            attr_condition("auth.account_provider.tempfail", True),
            then_block(
                "tempfail",
                "auth.outcome.list_accounts_tempfail",
                "auth.fsm.event.auth_tempfail",
                "auth.response.tempfail",
            ),
            require_checks=["account_provider"],
            operations=[LIST_ACCOUNTS_OPERATION],
        ),
        policy_rule(
            "standard_list_accounts_success",
            "auth_decision",
            attr_condition("auth.account_provider.completed", True),
            then_block(
                "permit",
                "auth.outcome.list_accounts_success",
                "auth.fsm.event.auth_permit",
                "auth.response.list_accounts.ok",
            ),
            require_checks=["account_provider"],
            operations=[LIST_ACCOUNTS_OPERATION],
        ),
        policy_rule(
            "standard_list_accounts_failure",
            "auth_decision",
            attr_condition("auth.account_provider.completed", False),
            then_block(
                "deny",
                "auth.outcome.list_accounts_failure",
                "auth.fsm.event.auth_deny",
                "auth.response.fail",
            ),
            require_checks=["account_provider"],
            operations=[LIST_ACCOUNTS_OPERATION],
        ),
    ]


def default_deny_policy() -> dict[str, Any]:
    """Return the final deny-biased decision rule."""
    return policy_rule(
        "standard_default_deny",
        "auth_decision",
        always_condition(),
        then_block(
            "deny",
            "auth.outcome.default_deny",
            "auth.fsm.event.auth_deny",
            "auth.response.fail",
        ),
        operations=[AUTHENTICATE_OPERATION, LOOKUP_IDENTITY_OPERATION, LIST_ACCOUNTS_OPERATION],
    )


def flatten_node(node: Any, path: tuple[Any, ...] = ()) -> Iterable[tuple[tuple[Any, ...], Any]]:
    """Yield leaf and explicitly empty nodes with their full path."""
    if isinstance(node, dict):
        if not node:
            yield path, {}

            return

        for key, value in node.items():
            yield from flatten_node(value, (*path, key))

        return

    if isinstance(node, list):
        if not node:
            yield path, []

            return

        for index, value in enumerate(node):
            yield from flatten_node(value, (*path, index))

        return

    yield path, node


def get_nested_value(root: Any, path: tuple[Any, ...]) -> tuple[Any, bool]:
    """Read a nested value from dict/list structures."""
    current = root
    for part in path:
        if isinstance(part, int):
            if not isinstance(current, list) or part >= len(current):
                return None, False
            current = current[part]
            continue

        if not isinstance(current, dict) or part not in current:
            return None, False
        current = current[part]

    return current, True


def set_nested_value(root: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    """Set a nested value inside dict/list structures, creating parents as needed."""
    current: Any = root

    for index, part in enumerate(path[:-1]):
        next_part = path[index + 1]

        if isinstance(part, int):
            while len(current) <= part:
                current.append([] if isinstance(next_part, int) else {})
            if current[part] is None:
                current[part] = [] if isinstance(next_part, int) else {}
            current = current[part]
            continue

        if part not in current or current[part] is None:
            current[part] = [] if isinstance(next_part, int) else {}
        current = current[part]

    last = path[-1]
    if isinstance(last, int):
        while len(current) <= last:
            current.append(None)
        current[last] = value
    else:
        current[last] = value


def is_empty_value(value: Any) -> bool:
    """Report whether a config value is empty enough to skip auto-enabling."""
    if value in (None, "", [], {}):
        return True

    return False


def format_path(path: Iterable[Any]) -> str:
    """Format tuple paths using dotted names plus list indexes."""
    result = []
    for part in path:
        if isinstance(part, int):
            if not result:
                result.append(f"[{part}]")
            else:
                result[-1] = result[-1] + f"[{part}]"
            continue

        result.append(str(part))

    return ".".join(result)


def reorder_root_keys(document: dict[str, Any]) -> dict[str, Any]:
    """Keep top-level keys in a stable human-facing order."""
    ordered: dict[str, Any] = {}
    for key in TOP_LEVEL_ORDER:
        if key in document:
            ordered[key] = document[key]

    for key, value in document.items():
        if key not in ordered:
            ordered[key] = value

    return ordered


def build_anchor_registry(document: dict[str, Any]) -> AnchorRegistry:
    """Build a best-effort anchor registry for preserved top-level `x-*` roots."""
    registry = AnchorRegistry()
    counts = count_node_fingerprints(document)

    for key, value in document.items():
        if not isinstance(key, str) or not key.startswith("x-"):
            continue

        fingerprint = node_fingerprint(value)
        if counts.get(fingerprint, 0) <= 1:
            continue

        registry.path_to_anchor[(key,)] = key
        registry.fingerprint_to_anchor[fingerprint] = key

    return registry


def node_fingerprint(node: Any) -> str:
    """Create a semantic fingerprint for matching preserved alias targets."""
    return json.dumps(node, ensure_ascii=False, sort_keys=True)


def count_node_fingerprints(node: Any, counts: dict[str, int] | None = None) -> dict[str, int]:
    """Count reusable dict/list subtrees for best-effort alias reconstruction."""
    if counts is None:
        counts = {}

    if isinstance(node, dict):
        counts[node_fingerprint(node)] = counts.get(node_fingerprint(node), 0) + 1
        for value in node.values():
            count_node_fingerprints(value, counts)
    elif isinstance(node, list):
        counts[node_fingerprint(node)] = counts.get(node_fingerprint(node), 0) + 1
        for item in node:
            count_node_fingerprints(item, counts)

    return counts


def yaml_scalar(value: Any) -> str:
    """Render a YAML scalar using a conservative, always-valid representation."""
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, (int, float)):
        return str(value)

    return json.dumps(str(value), ensure_ascii=False)


def is_multiline_string(value: Any) -> bool:
    """Report whether a value should be rendered as a YAML block scalar."""
    return isinstance(value, str) and "\n" in value


def yaml_block_header(value: str) -> str:
    """Choose the YAML literal block indicator preserving trailing newline semantics."""
    return "|" if value.endswith("\n") else "|-"


def yaml_block_body(value: str, indent: int) -> str:
    """Render a YAML literal block body with the requested indentation."""
    content = value[:-1] if value.endswith("\n") else value
    lines = content.split("\n")
    prefix = " " * indent

    return "\n".join(f"{prefix}{line}" for line in lines)


def yaml_dump(
    node: Any,
    indent: int = 0,
    path: tuple[Any, ...] = (),
    anchors: AnchorRegistry | None = None,
) -> str:
    """Serialize Python data structures into readable block-style YAML."""
    prefix = " " * indent

    if isinstance(node, dict):
        if not node:
            return "{}\n"

        lines: list[str] = []
        for key, value in node.items():
            child_path = (*path, key)
            anchor_name = anchor_name_for_path(child_path, anchors)
            alias_name = alias_name_for_node(value, child_path, anchors)
            if alias_name:
                lines.append(f"{prefix}{key}: *{alias_name}")
                continue

            if isinstance(value, SCALAR_TYPES) or value in ([], {}):
                if is_multiline_string(value):
                    header = yaml_block_header(value)
                    if anchor_name:
                        lines.append(f"{prefix}{key}: &{anchor_name} {header}")
                    else:
                        lines.append(f"{prefix}{key}: {header}")

                    lines.append(yaml_block_body(value, indent + 2))

                    continue

                rendered = yaml_scalar(value) if value not in ([], {}) else ("[]" if value == [] else "{}")
                if anchor_name:
                    lines.append(f"{prefix}{key}: &{anchor_name} {rendered}")
                else:
                    lines.append(f"{prefix}{key}: {rendered}")
                continue

            if anchor_name:
                lines.append(f"{prefix}{key}: &{anchor_name}")
            else:
                lines.append(f"{prefix}{key}:")

            lines.append(yaml_dump(value, indent + 2, child_path, anchors).rstrip("\n"))

        return "\n".join(lines) + "\n"

    if isinstance(node, list):
        if not node:
            return "[]\n"

        lines = []
        for index, item in enumerate(node):
            child_path = (*path, index)
            alias_name = alias_name_for_node(item, child_path, anchors)
            if alias_name:
                lines.append(f"{prefix}- *{alias_name}")
                continue

            if isinstance(item, SCALAR_TYPES) or item in ([], {}):
                if is_multiline_string(item):
                    lines.append(f"{prefix}- {yaml_block_header(item)}")
                    lines.append(yaml_block_body(item, indent + 2))

                    continue

                rendered = yaml_scalar(item) if item not in ([], {}) else ("[]" if item == [] else "{}")
                lines.append(f"{prefix}- {rendered}")
                continue

            if isinstance(item, dict) and item:
                first_key = next(iter(item))
                first_value = item[first_key]
                rest = dict(list(item.items())[1:])
                first_path = (*child_path, first_key)
                anchor_name = anchor_name_for_path(first_path, anchors)
                first_alias = alias_name_for_node(first_value, first_path, anchors)

                if first_alias:
                    lines.append(f"{prefix}- {first_key}: *{first_alias}")
                elif isinstance(first_value, SCALAR_TYPES) or first_value in ([], {}):
                    if is_multiline_string(first_value):
                        header = yaml_block_header(first_value)
                        if anchor_name:
                            lines.append(f"{prefix}- {first_key}: &{anchor_name} {header}")
                        else:
                            lines.append(f"{prefix}- {first_key}: {header}")

                        lines.append(yaml_block_body(first_value, indent + 4))
                    else:
                        rendered = yaml_scalar(first_value) if first_value not in ([], {}) else ("[]" if first_value == [] else "{}")
                        if anchor_name:
                            lines.append(f"{prefix}- {first_key}: &{anchor_name} {rendered}")
                        else:
                            lines.append(f"{prefix}- {first_key}: {rendered}")
                else:
                    if anchor_name:
                        lines.append(f"{prefix}- {first_key}: &{anchor_name}")
                    else:
                        lines.append(f"{prefix}- {first_key}:")

                    lines.append(yaml_dump(first_value, indent + 4, first_path, anchors).rstrip("\n"))

                if rest:
                    lines.append(yaml_dump(rest, indent + 2, child_path, anchors).rstrip("\n"))
                continue

            lines.append(f"{prefix}-")
            lines.append(yaml_dump(item, indent + 2, child_path, anchors).rstrip("\n"))

        return "\n".join(lines) + "\n"

    return f"{prefix}{yaml_scalar(node)}\n"


def anchor_name_for_path(path: tuple[Any, ...], anchors: AnchorRegistry | None) -> str | None:
    """Return the configured anchor name for an exact path."""
    if anchors is None:
        return None

    return anchors.path_to_anchor.get(path)


def alias_name_for_node(node: Any, path: tuple[Any, ...], anchors: AnchorRegistry | None) -> str | None:
    """Return an alias target when the current node matches a preserved top-level extension root."""
    if anchors is None or path in anchors.path_to_anchor:
        return None

    if not isinstance(node, (dict, list)):
        return None

    return anchors.fingerprint_to_anchor.get(node_fingerprint(node))


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Convert a legacy monolithic Nauthilus config file to the current config-v2 layout."
    )
    parser.add_argument("input", type=Path, help="Legacy monolithic YAML configuration file.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write the converted YAML to this file. Defaults to stdout when omitted.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Write a detailed conversion report to this file.",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print the converted YAML to stdout even when --output is used.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not write files; only print the report and optionally the converted YAML.",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate the converted output with `nauthilus --config-check` after conversion.",
    )

    return parser.parse_args()


def load_legacy_yaml(path: Path) -> dict[str, Any]:
    """Load YAML through the vendored Go YAML stack and return JSON-decoded data."""
    env = os.environ.copy()
    env.setdefault("GOEXPERIMENT", "runtimesecret")
    result = subprocess.run(
        (*YAML_READER_CMD, str(path)),
        cwd=ROOT_DIR,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    loaded = json.loads(result.stdout)
    if not isinstance(loaded, dict):
        raise ValueError("legacy config root must be a YAML mapping")

    return expand_dotted_keys(loaded)


def expand_dotted_keys(node: Any) -> Any:
    """Expand dotted mapping keys like `server.oidc_auth.enabled` into nested mappings."""
    if isinstance(node, list):
        return [expand_dotted_keys(item) for item in node]

    if not isinstance(node, dict):
        return node

    expanded: dict[str, Any] = {}
    for raw_key, raw_value in node.items():
        value = expand_dotted_keys(raw_value)
        if isinstance(raw_key, str) and "." in raw_key:
            merge_dotted_key(expanded, tuple(raw_key.split(".")), value)
            continue

        if raw_key in expanded and isinstance(expanded[raw_key], dict) and isinstance(value, dict):
            expanded[raw_key] = merge_dicts(expanded[raw_key], value)
            continue

        expanded[raw_key] = value

    return expanded


def merge_dotted_key(root: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    """Merge a dotted-key value into the target mapping."""
    current = root
    for part in path[:-1]:
        existing = current.get(part)
        if not isinstance(existing, dict):
            current[part] = {}

        current = current[part]

    last = path[-1]
    existing = current.get(last)
    if isinstance(existing, dict) and isinstance(value, dict):
        current[last] = merge_dicts(existing, value)
        return

    current[last] = value


def merge_dicts(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Merge two dicts recursively, letting right-hand values win on conflicts."""
    merged = copy.deepcopy(left)
    for key, value in right.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = merge_dicts(merged[key], value)
            continue

        merged[key] = copy.deepcopy(value)

    return merged


def validate_converted_config(rendered_yaml: str, report: ConversionReport) -> int:
    """Run `nauthilus --config-check` on the converted YAML."""
    env = os.environ.copy()
    env.setdefault("GOEXPERIMENT", "runtimesecret")
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8") as handle:
        handle.write(rendered_yaml)
        temp_path = Path(handle.name)

    try:
        result = subprocess.run(
            (*VALIDATE_CMD, "--config", str(temp_path), "--config-check"),
            cwd=ROOT_DIR,
            env=env,
            capture_output=True,
            text=True,
        )
    finally:
        temp_path.unlink(missing_ok=True)

    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        report.validation_output = f"validation failed\n{output}".strip()

        return result.returncode

    report.validation_output = f"validation passed\n{output or 'configuration is valid'}"

    return 0


def write_text(path: Path, content: str) -> None:
    """Write UTF-8 text, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> int:
    """Convert the input file and optionally validate the result."""
    args = parse_args()
    source = load_legacy_yaml(args.input)

    converter = LegacyConfigConverter(source)
    converted, report = converter.convert()
    anchors = build_anchor_registry(converted)
    rendered_yaml = yaml_dump(converted, anchors=anchors)

    if args.output and not args.dry_run:
        write_text(args.output, rendered_yaml)

    validation_exit_code = 0
    if args.validate:
        validation_exit_code = validate_converted_config(rendered_yaml, report)

    if args.report:
        write_text(args.report, report.render())

    if args.stdout or args.dry_run or not args.output:
        sys.stdout.write(rendered_yaml)

    if report.warnings or report.dropped_paths:
        sys.stderr.write(report.render())

    return validation_exit_code


if __name__ == "__main__":
    raise SystemExit(main())
