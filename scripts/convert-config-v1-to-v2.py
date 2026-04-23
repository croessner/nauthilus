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
    ("server", "address"): ("runtime", "listen", "address"),
    ("server", "http3"): ("runtime", "listen", "http3"),
    ("server", "haproxy_v2"): ("runtime", "listen", "haproxy_v2"),
    ("server", "trusted_proxies"): ("runtime", "listen", "trusted_proxies"),
    ("server", "run_as_user"): ("runtime", "process", "run_as_user"),
    ("server", "run_as_group"): ("runtime", "process", "run_as_group"),
    ("server", "chroot"): ("runtime", "process", "chroot"),
    ("server", "rate_limit_burst"): ("runtime", "http", "rate_limit", "burst"),
    ("server", "rate_limit_per_second"): ("runtime", "http", "rate_limit", "per_second"),
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
    (("server", "tls"), ("runtime", "listen", "tls")),
    (("server", "disabled_endpoints"), ("runtime", "http", "disabled_endpoints")),
    (("server", "middlewares"), ("runtime", "http", "middlewares")),
    (("server", "compression"), ("runtime", "http", "compression")),
    (("server", "keep_alive"), ("runtime", "http", "keep_alive")),
    (("server", "timeouts"), ("runtime", "http", "timeouts")),
    (("server", "cors"), ("runtime", "http", "cors")),
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
    (("lua", "actions"), ("auth", "controls", "lua", "actions")),
    (("lua", "controls"), ("auth", "controls", "lua", "controls")),
    (("lua", "features"), ("auth", "controls", "lua", "controls")),
    (("lua", "filters"), ("auth", "controls", "lua", "filters")),
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


class LegacyConfigConverter:
    """Convert old monolithic config layouts to the current config-v2 structure."""

    def __init__(self, source: dict[str, Any]):
        self.source = source
        self.report = ConversionReport()
        self.result: dict[str, Any] = {}
        self.handled_prefixes: set[tuple[str, ...]] = set()

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
            self._append_unique_value(("auth", "controls", "lua", "controls"), copy.deepcopy(item))
            self.report.migrated_paths.append(
                f"{format_path(('lua', 'features', index))} -> auth.controls.lua.controls"
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
    env.setdefault("GEXPERIMENT", "runtimesecret")

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
    env.setdefault("GEXPERIMENT", "runtimesecret")

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
