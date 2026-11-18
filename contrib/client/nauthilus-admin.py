#!/usr/bin/env python3
"""Command-line client for Nauthilus REST backchannel operations."""

from __future__ import annotations

import argparse
import base64
import getpass
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import stat
import sys
import time
import urllib.parse
from dataclasses import dataclass, replace as dataclass_replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

DEFAULT_URL = "https://nauthilus.example.invalid"
DEFAULT_SCOPES = "nauthilus:authenticate nauthilus:admin nauthilus:security"
DEFAULT_TIMEOUT = 15.0

ACCOUNT_RESOLUTION_MAPPING = "account_mapping"

REPUTATION_KINDS = ("ip", "network", "asn", "dns_domain", "account", "service")
REPUTATION_BANDS = ("blocked", "trusted", "neutral")
REPUTATION_MAX_TTL = 31536000
REPUTATION_MAX_BODY = 4096
REPUTATION_IDENTIFIER = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
REPUTATION_IMPORT_SCHEMA = "reputation-static-import.v1"
REPUTATION_IMPORT_KEYS = frozenset(("schema", "overrides", "ip_override_networks", "identity_contracts", "policy_rules"))
REPUTATION_IMPORT_ENTRY_KEYS = frozenset(
    ("kind", "subject", "band", "reason", "creator", "audit_id", "origin", "expires_at"))
REPUTATION_IMPORT_MAX_BYTES = 4 * 1024 * 1024
REPUTATION_IMPORT_MAX_EXPIRES_AT = 100_000_000_000
REPUTATION_BEARER_REQUIRED = "reputation administration requires a backchannel bearer token with nauthilus:admin"

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_HISTORY_PARTIAL = 3
EXIT_HISTORY_UNAVAILABLE = 4
EXIT_QUERY_TOO_BROAD = 5

SUPPORT_PATH = "/api/v1/support/"
SUPPORT_SCHEMA_VERSION = "1"
SUPPORT_READ_SCOPE = "nauthilus:history_read"
SUPPORT_DETAIL_SCOPE = "nauthilus:history_detail"
SUPPORT_BEARER_REQUIRED = (f"support history requires a backchannel bearer token with {SUPPORT_READ_SCOPE}; "
                           "Basic credentials are rejected")
SUPPORT_MAX_WINDOW = timedelta(days=31)
SUPPORT_MAX_PAGES = 20
SUPPORT_ATTEMPT_LIMIT = 50
SUPPORT_BAN_LIMIT = 20
SUPPORT_AUDIT_REFERENCE = re.compile(r"[A-Za-z0-9._:/-]{1,64}")
SUPPORT_ATTEMPT_ID = re.compile(r"fl1\.[0-9a-f]{32}|rq1\.[A-Za-z0-9_-]{1,64}")
SUPPORT_BAN_REF = re.compile(r"[0-9a-f]{32}")
SUPPORT_DURATION = re.compile(r"([1-9][0-9]{0,5})([smhd])")
SUPPORT_DURATION_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
RFC3339_TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})")
SUPPORT_ERROR_EXIT_CODES = {
    **dict.fromkeys(("INVALID_REQUEST", "WINDOW_TOO_LARGE", "INVALID_CURSOR", "INVALID_ATTEMPT_ID", "UNAUTHORIZED",
                     "FORBIDDEN", "INTERNAL_ERROR"), EXIT_FAILURE),
    **dict.fromkeys(("HISTORY_BUSY", "HISTORY_NOT_CONFIGURED", "HISTORY_SOURCE_UNAVAILABLE", "HISTORY_READER_UNSAFE",
                     "HISTORY_TIMEOUT"), EXIT_HISTORY_UNAVAILABLE),
    "QUERY_TOO_BROAD": EXIT_QUERY_TOO_BROAD,
}
SUPPORT_STATUS_EXIT_CODES = {422: EXIT_QUERY_TOO_BROAD, 429: EXIT_HISTORY_UNAVAILABLE, 503: EXIT_HISTORY_UNAVAILABLE}
SUPPORT_ERROR_HINTS = {
    EXIT_HISTORY_UNAVAILABLE: "the history store is unavailable or busy; retry later",
    EXIT_QUERY_TOO_BROAD: "the query is too broad; narrow the window (--since or --from/--until) or add filters",
}
SUPPORT_SCOPE_HINT = (f"the bearer token needs {SUPPORT_READ_SCOPE}; attempt detail without --login/--account "
                      f"needs {SUPPORT_DETAIL_SCOPE}")
SUPPORT_EXIT_HELP = """exit codes:
  0  processed and history.availability is "available"
  3  processed, but history is partial (a stderr warning lists history.conditions)
  4  history unavailable or busy (HTTP 503 or 429)
  5  query too broad (HTTP 422); narrow the window or add filters
  1  any other error (local validation, HTTP 400/401/403/500, transport)
  2  command-line usage error

A historical login failure in the data is never a non-zero exit by itself.
An empty result does not prove that no login or ban happened."""


class ClientError(RuntimeError):
    """ClientError represents an operator-facing request or configuration failure."""

    def __init__(self, message: str, *, exit_code: int = EXIT_FAILURE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class HTTPClientError(ClientError):
    """Preserve an acknowledged HTTP status without changing existing error handling."""

    def __init__(self, message: str, status: int, response: "Response | None" = None) -> None:
        super().__init__(message)
        self.status = status
        self.response = response


@dataclass(frozen=True)
class Response:
    """Response stores the HTTP response after body decoding."""

    status: int
    reason: str
    headers: dict[str, str]
    body: bytes
    parsed: Any


@dataclass(frozen=True)
class CommandOutcome:
    """CommandOutcome lets a command choose its process exit code and stderr notes besides the rendered result; a
    command that renders its own compact text sets text instead of printing the response."""

    result: Any
    exit_code: int = EXIT_OK
    notes: tuple[str, ...] = ()
    text: str | None = None


@dataclass(frozen=True)
class ResolveOverride:
    """ResolveOverride pins a host and port to a concrete connect address."""

    host: str
    port: int
    address: str


@dataclass
class ClientConfig:
    """ClientConfig contains runtime API and authentication settings."""

    url: str
    token_url: str
    timeout: float
    scopes: str
    client_auth_method: str
    client_id: str | None = None
    client_secret: str | None = None
    bearer_token: str | None = None
    basic_user: str | None = None
    basic_password: str | None = None
    token_cache: Path | None = None
    insecure: bool = False
    resolve: tuple[ResolveOverride, ...] = ()


class ResolvedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that keeps TLS SNI while overriding the TCP address."""

    def __init__(
        self,
        host: str,
        port: int | None,
        *,
        timeout: float,
        context: ssl.SSLContext,
        connect_host: str | None = None,
        connect_port: int | None = None,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._connect_host = connect_host or host
        self._connect_port = connect_port or port or 443

    def connect(self) -> None:
        """Open the socket against the override while preserving original SNI."""

        sock = socket.create_connection((self._connect_host, self._connect_port), self.timeout, self.source_address)

        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        server_hostname = self.host if ssl.HAS_SNI else None
        self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)


class NauthilusClient:
    """NauthilusClient performs authenticated backchannel HTTP requests."""

    def __init__(self, config: ClientConfig) -> None:
        self.config = config
        self._ssl_context = self._build_ssl_context(config.insecure)

    def get(self, path: str, query: dict[str, str] | None = None) -> Response:
        """Send a GET request."""

        return self.request("GET", path, query=query)

    def post(self, path: str, body: Any | None = None, query: dict[str, str] | None = None) -> Response:
        """Send a JSON POST request."""

        return self.request("POST", path, body=body, query=query)

    def delete(self, path: str, body: Any | None = None, query: dict[str, str] | None = None) -> Response:
        """Send a DELETE request with an optional JSON body."""

        return self.request("DELETE", path, body=body, query=query)

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        body: Any | None = None,
        query: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> Response:
        """Send an HTTP request and parse JSON responses when possible."""

        url = self._absolute_url(path_or_url, query)
        request_headers = dict(headers or {})
        data: bytes | None = None

        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")

        if authenticated:
            request_headers.update(self._authorization_headers())

        response = self._send(method.upper(), url, body=data, headers=request_headers)
        if response.status >= 400:
            raise HTTPClientError(format_http_error(method.upper(), url, response), response.status, response)

        return response

    def token_status(self) -> dict[str, Any]:
        """Return cached token metadata without exposing the token value."""

        cached = self._load_cached_token()
        if cached is None:
            return {"cached": False}

        expires_at = int(cached.get("expires_at", 0))

        return {
            "cached": True,
            "expires_at": expires_at,
            "expires_in": max(0, expires_at - int(time.time())),
            "client_id": cached.get("client_id"),
            "scope": cached.get("scope"),
            "token_url": cached.get("token_url"),
        }

    def clear_token_cache(self) -> dict[str, Any]:
        """Delete the local token cache if it exists."""

        if self.config.token_cache is None:
            return {"removed": False, "reason": "token cache disabled"}

        try:
            self.config.token_cache.unlink()
            return {"removed": True, "path": str(self.config.token_cache)}
        except FileNotFoundError:
            return {"removed": False, "path": str(self.config.token_cache)}

    def _authorization_headers(self) -> dict[str, str]:
        if self.config.bearer_token:
            return {"Authorization": f"Bearer {self.config.bearer_token}"}

        if self.config.basic_user and self.config.basic_password:
            raw = f"{self.config.basic_user}:{self.config.basic_password}".encode("utf-8")
            return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}

        return {"Authorization": "Bearer " + self._get_access_token()}

    def _get_access_token(self) -> str:
        cached = self._load_cached_token()
        if cached is not None:
            token = cached.get("access_token")
            expires_at = int(cached.get("expires_at", 0))
            if isinstance(token, str) and token and time.time() < expires_at - 20:
                return token

        return self._fetch_access_token()

    def _fetch_access_token(self) -> str:
        if not self.config.client_id or not self.config.client_secret:
            raise ClientError(
                "missing OIDC client credentials; set client_id/client_secret, bearer_token, or basic auth")

        form = {
            "grant_type": "client_credentials",
            "scope": self.config.scopes,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        method = self.config.client_auth_method

        if method == "basic":
            raw = f"{self.config.client_id}:{self.config.client_secret}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        elif method == "post":
            form["client_id"] = self.config.client_id
            form["client_secret"] = self.config.client_secret
        else:
            raise ClientError(f"unsupported client auth method: {method}")

        data = urllib.parse.urlencode(form).encode("utf-8")
        response = self._send("POST", self.config.token_url, body=data, headers=headers)
        if response.status >= 400:
            raise ClientError(format_http_error("POST", self.config.token_url, response))

        if not isinstance(response.parsed, dict):
            raise ClientError("token endpoint did not return a JSON object")

        token = response.parsed.get("access_token")
        if not isinstance(token, str) or not token:
            raise ClientError("token endpoint response has no access_token")

        expires_in = int(response.parsed.get("expires_in", 60))
        self._save_cached_token(
            {
                "access_token": token,
                "expires_at": int(time.time()) + max(1, expires_in),
                "client_id": self.config.client_id,
                "scope": self.config.scopes,
                "token_url": self.config.token_url,
            }
        )

        return token

    def _send(self, method: str, url: str, *, body: bytes | None, headers: dict[str, str]) -> Response:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise ClientError(f"unsupported URL scheme: {parsed.scheme}")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        connection = self._connection(parsed.hostname or "", port, parsed.scheme)

        try:
            connection.request(method, path, body=body, headers=headers)
            http_response = connection.getresponse()
            response_body = http_response.read()
        finally:
            connection.close()

        response_headers = {key.lower(): value for key, value in http_response.getheaders()}
        parsed_body = parse_response_body(response_headers, response_body)

        return Response(
            status=http_response.status,
            reason=http_response.reason,
            headers=response_headers,
            body=response_body,
            parsed=parsed_body,
        )

    def _connection(self, host: str, port: int, scheme: str) -> http.client.HTTPConnection:
        override = self._resolve_override(host, port)
        if scheme == "https":
            return ResolvedHTTPSConnection(
                host,
                port,
                timeout=self.config.timeout,
                context=self._ssl_context,
                connect_host=override.address if override else None,
                connect_port=override.port if override else None,
            )

        connect_host = override.address if override else host
        connect_port = override.port if override else port

        return http.client.HTTPConnection(connect_host, port=connect_port, timeout=self.config.timeout)

    def _resolve_override(self, host: str, port: int) -> ResolveOverride | None:
        for item in self.config.resolve:
            if item.host == host and item.port == port:
                return item

        return None

    def _absolute_url(self, path_or_url: str, query: dict[str, str] | None) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            base = path_or_url
        else:
            base = self.config.url.rstrip("/") + "/" + path_or_url.lstrip("/")

        if not query:
            return base

        parsed = urllib.parse.urlsplit(base)
        current = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        current.update({key: value for key, value in query.items() if value is not None})
        new_query = urllib.parse.urlencode(current)

        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))

    def _load_cached_token(self) -> dict[str, Any] | None:
        path = self.config.token_cache
        if path is None:
            return None

        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError):
            return None

        if data.get("client_id") != self.config.client_id:
            return None

        if data.get("scope") != self.config.scopes:
            return None

        if data.get("token_url") != self.config.token_url:
            return None

        return data

    def _save_cached_token(self, data: dict[str, Any]) -> None:
        path = self.config.token_cache
        if path is None:
            return

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            with tmp.open("w", encoding="utf-8") as handle:
                json.dump(data, handle, separators=(",", ":"))
                handle.write("\n")
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            os.replace(tmp, path)
        except OSError:
            return

    @staticmethod
    def _build_ssl_context(insecure: bool) -> ssl.SSLContext:
        if insecure:
            return ssl._create_unverified_context()

        return ssl.create_default_context()


def parse_response_body(headers: dict[str, str], body: bytes) -> Any:
    """Decode JSON bodies and return text for non-JSON payloads."""

    if not body:
        return None

    content_type = headers.get("content-type", "")
    if "json" in content_type:
        try:
            return json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return body.decode("utf-8", errors="replace")

    return body.decode("utf-8", errors="replace")


def format_http_error(method: str, url: str, response: Response) -> str:
    """Format an HTTP error without leaking request credentials."""

    detail = response.parsed
    if isinstance(detail, (dict, list)):
        rendered = json.dumps(detail, ensure_ascii=False)
    elif detail is None:
        rendered = ""
    else:
        rendered = str(detail)

    return f"{method} {url} failed with HTTP {response.status} {response.reason}: {rendered}".rstrip()


def load_env_file(path: str | None) -> dict[str, str]:
    """Load KEY=VALUE settings from a small env-style file."""

    if not path:
        return {}

    values: dict[str, str] = {}
    env_path = Path(path)
    if not env_path.exists():
        raise ClientError(f"env file does not exist: {path}")

    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if "=" not in stripped:
            raise ClientError(f"invalid env file line: {line}")

        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        values[key] = value

    return values


def first_value(name: str, args: argparse.Namespace, env_file: dict[str, str],
                default: str | None = None) -> str | None:
    """Resolve a setting from CLI, process environment, env file, then default."""

    attr = name.lower()
    cli_value = getattr(args, attr, None)
    if isinstance(cli_value, bool):
        if cli_value:
            return "1"
    elif cli_value not in (None, ""):
        return cli_value

    env_name = "NAUTHILUS_" + name
    env_value = os.environ.get(env_name)
    if env_value not in (None, ""):
        return env_value

    file_value = env_file.get(env_name)
    if file_value not in (None, ""):
        return file_value

    return default


def read_optional_secret(value: str | None, file_value: str | None) -> str | None:
    """Read a secret from a direct value or file path."""

    if value:
        return value

    if file_value:
        return Path(file_value).read_text(encoding="utf-8").strip()

    return None


def parse_resolve(values: Iterable[str]) -> tuple[ResolveOverride, ...]:
    """Parse resolve overrides in host:port:address form."""

    result: list[ResolveOverride] = []
    for raw in values:
        if not raw:
            continue

        for item in raw.split(","):
            item = item.strip()
            if not item:
                continue

            parts = item.rsplit(":", 2)
            if len(parts) != 3:
                raise ClientError(f"invalid resolve override {item!r}; expected host:port:address")

            host, port, address = parts
            result.append(ResolveOverride(host=host, port=int(port), address=address))

    return tuple(result)


def default_token_cache() -> Path:
    """Return a user-private default token cache path."""

    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir:
        return Path(runtime_dir) / "nauthilus-admin-token.json"

    return Path.home() / ".cache" / "nauthilus-admin" / "token.json"


def build_config(args: argparse.Namespace) -> ClientConfig:
    """Build a client configuration from CLI flags, environment, and env-file."""

    env_file = load_env_file(args.env_file or os.environ.get("NAUTHILUS_ENV_FILE"))
    url = first_value("URL", args, env_file, DEFAULT_URL) or DEFAULT_URL
    token_url = first_value("TOKEN_URL", args, env_file, url.rstrip("/") + "/oidc/token")
    client_secret = read_optional_secret(
        first_value("CLIENT_SECRET", args, env_file),
        first_value("CLIENT_SECRET_FILE", args, env_file),
    )
    bearer_token = read_optional_secret(
        first_value("BEARER_TOKEN", args, env_file),
        first_value("BEARER_TOKEN_FILE", args, env_file),
    )
    basic_password = read_optional_secret(
        first_value("BASIC_PASSWORD", args, env_file),
        first_value("BASIC_PASSWORD_FILE", args, env_file),
    )

    cache_value = first_value("TOKEN_CACHE", args, env_file, str(default_token_cache()))
    token_cache = None if cache_value in ("", "none", "off", "false") else Path(cache_value or "")

    insecure_value = first_value("INSECURE", args, env_file, "0")
    # CLI values are repeatable; an explicit CLI list replaces environment defaults.
    resolve_values = list(args.resolve or [])
    if not resolve_values:
        env_resolve = first_value("RESOLVE", args, env_file)
        if env_resolve:
            resolve_values.append(env_resolve)

    return ClientConfig(
        url=url,
        token_url=token_url or url.rstrip("/") + "/oidc/token",
        timeout=float(first_value("TIMEOUT", args, env_file, str(DEFAULT_TIMEOUT)) or DEFAULT_TIMEOUT),
        scopes=first_value("SCOPES", args, env_file, DEFAULT_SCOPES) or DEFAULT_SCOPES,
        client_auth_method=(first_value("CLIENT_AUTH_METHOD", args, env_file, "basic") or "basic").lower(),
        client_id=first_value("CLIENT_ID", args, env_file),
        client_secret=client_secret,
        bearer_token=bearer_token,
        basic_user=first_value("BASIC_USER", args, env_file),
        basic_password=basic_password,
        token_cache=token_cache,
        insecure=insecure_value.lower() in {"1", "true", "yes", "on"},
        resolve=parse_resolve(resolve_values),
    )


def print_response(response: Response, args: argparse.Namespace) -> None:
    """Render a response according to the requested output mode."""

    if args.output == "headers":
        print(json.dumps({"status": response.status, "headers": response.headers}, indent=2, sort_keys=True))
        return

    if args.output == "body":
        sys.stdout.buffer.write(response.body)
        if response.body and not response.body.endswith(b"\n"):
            sys.stdout.write("\n")
        return

    payload = response.parsed
    if payload is None:
        payload = {"status": response.status, "reason": response.reason}

    if args.output == "json":
        print(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))
        return

    if isinstance(payload, (dict, list)):
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(str(payload))


def print_object(payload: Any, args: argparse.Namespace) -> None:
    """Render a local object using the same output settings as API responses."""

    if args.output == "json":
        print(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def read_json_argument(raw: str | None, file_path: str | None) -> Any:
    """Read a JSON argument from a string or file."""

    if raw and file_path:
        raise ClientError("use either --data or --data-file, not both")

    if file_path:
        text = sys.stdin.read() if file_path == "-" else Path(file_path).read_text(encoding="utf-8")
        return json.loads(text)

    if raw:
        return json.loads(raw)

    return None


def parse_key_values(items: list[str] | None) -> dict[str, str]:
    """Parse repeated key=value CLI arguments."""

    result: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise ClientError(f"expected key=value, got {item!r}")

        key, value = item.split("=", 1)
        result[key] = value

    return result


def cache_flush(client: NauthilusClient, args: argparse.Namespace) -> Any:
    """Flush cache state for one user."""

    path = "/api/v1/cache/flush/async" if args.async_mode else "/api/v1/cache/flush"
    response = client.delete(path, {"user": args.user})
    if args.wait:
        return wait_for_result(client, extract_job_id(response), args)

    return response


def cache_flush_file(client: NauthilusClient, args: argparse.Namespace) -> dict[str, Any]:
    """Flush cache state for every user listed in a file or stdin."""

    users = read_lines(args.file)
    if args.async_mode:
        return cache_flush_file_async(client, args, users)

    return cache_flush_file_sync(client, args, users)


def cache_flush_file_sync(client: NauthilusClient, args: argparse.Namespace, users: list[str]) -> dict[str, Any]:
    """Flush cache state synchronously for every user in the list."""

    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for user in users:
        try:
            response = client.delete("/api/v1/cache/flush", {"user": user})
            payload = response.parsed
            if args.summary_only:
                summary = summarize_flush_payload(payload)
                results.append({"user": user, "summary": summary})
                emit_live(args,
                          f"done user={user} status={summary.get('status')} removed={summary.get('removed_key_count')}")
            else:
                results.append({"user": user, "response": payload})
                emit_live(args, f"done user={user}")
        except Exception as exc:  # noqa: BLE001 - command should aggregate optional per-user failures.
            errors.append({"user": user, "error": str(exc)})
            emit_live(args, f"error user={user} msg={exc}")
            if not args.continue_on_error:
                break

    return {"requested": len(users), "succeeded": len(results), "failed": len(errors), "results": results,
            "errors": errors}


def cache_flush_file_async(client: NauthilusClient, args: argparse.Namespace, users: list[str]) -> dict[str, Any]:
    """Enqueue cache flush jobs for every user and optionally poll them together."""

    jobs: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for user in users:
        try:
            response = client.delete("/api/v1/cache/flush/async", {"user": user})
            job_id = extract_job_id(response)
            jobs.append({"user": user, "jobId": job_id, "status": "QUEUED"})
            emit_live(args, f"queued user={user} job={job_id}")
        except Exception as exc:  # noqa: BLE001 - command should aggregate optional per-user failures.
            errors.append({"user": user, "error": str(exc)})
            emit_live(args, f"error user={user} msg={exc}")
            if not args.continue_on_error:
                break

    if args.wait and jobs:
        poll_async_jobs(client, args, jobs)

    status_counts: dict[str, int] = {}
    for job in jobs:
        status = str(job.get("status", "UNKNOWN"))
        status_counts[status] = status_counts.get(status, 0) + 1

    return {
        "requested": len(users),
        "queued": len(jobs),
        "failed": len(errors),
        "status_counts": status_counts,
        "jobs": jobs,
        "errors": errors,
    }


def poll_async_jobs(client: NauthilusClient, args: argparse.Namespace, jobs: list[dict[str, Any]]) -> None:
    """Poll a batch of async jobs and update their status in place."""

    pending = {str(job["jobId"]): job for job in jobs}
    last_status = {str(job["jobId"]): str(job.get("status", "")) for job in jobs}
    deadline = time.time() + args.wait_timeout

    while pending and time.time() < deadline:
        for job_id, job in list(pending.items()):
            if time.time() >= deadline:
                break

            response = client.get(f"/api/v1/async/jobs/{urllib.parse.quote(job_id, safe='')}")
            payload = response.parsed if isinstance(response.parsed, dict) else {}
            result = payload.get("result") if isinstance(payload, dict) else {}
            if not isinstance(result, dict):
                continue

            status = str(result.get("status", "UNKNOWN"))
            job["status"] = status
            job["resultCount"] = result.get("resultCount")
            if result.get("error"):
                job["error"] = result.get("error")

            if status != last_status.get(job_id):
                emit_live(
                    args,
                    f"{status.lower()} user={job.get('user')} job={job_id} result_count={job.get('resultCount')}",
                )
                last_status[job_id] = status

            if status in {"DONE", "ERROR"}:
                pending.pop(job_id, None)

        if pending:
            emit_live(args, format_pending_summary(jobs, len(pending)))
            time.sleep(args.wait_interval)

    for job in pending.values():
        if getattr(args, "pending_ok", False):
            if job.get("status") in {"QUEUED", "INPROGRESS"}:
                job["status"] = "PENDING"
            emit_live(args, f"pending user={job.get('user')} job={job.get('jobId')}")
        else:
            job["status"] = "TIMEOUT"
            emit_live(args, f"timeout user={job.get('user')} job={job.get('jobId')}")


def emit_live(args: argparse.Namespace, message: str) -> None:
    """Emit live progress messages to stderr when requested."""

    if getattr(args, "live", False):
        print(message, file=sys.stderr, flush=True)


def format_pending_summary(jobs: list[dict[str, Any]], pending_count: int) -> str:
    """Format a compact live summary for a polled async batch."""

    counts: dict[str, int] = {}
    for job in jobs:
        status = str(job.get("status", "UNKNOWN"))
        counts[status] = counts.get(status, 0) + 1

    parts = [f"{status.lower()}={count}" for status, count in sorted(counts.items())]
    return f"pending_summary pending={pending_count} " + " ".join(parts)


def summarize_flush_payload(payload: Any) -> dict[str, Any]:
    """Summarize a cache flush response without carrying every removed key."""

    if not isinstance(payload, dict):
        return {"status": "unknown"}

    result = payload.get("result")
    if not isinstance(result, dict):
        return {"status": "unknown"}

    removed_keys = result.get("removed_keys")
    removed_count = len(removed_keys) if isinstance(removed_keys, list) else None

    return {
        "status": result.get("status"),
        "removed_key_count": removed_count,
    }


def read_lines(path: str) -> list[str]:
    """Read non-empty, non-comment lines from a path or stdin."""

    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def bruteforce_list(client: NauthilusClient, args: argparse.Namespace) -> Response:
    """List brute-force state with optional filters."""

    query: dict[str, str] = {}
    if args.limit is not None:
        query["limit"] = str(args.limit)
    if args.offset is not None:
        query["offset"] = str(args.offset)

    body: dict[str, Any] = {}
    if args.account:
        body["accounts"] = args.account
    if args.ip:
        body["ip_addresses"] = args.ip

    if args.via_mapping:
        if not args.account:
            raise ValueError("--via-mapping requires at least one --account")
        body["account_resolution"] = ACCOUNT_RESOLUTION_MAPPING
        return bruteforce_list_via_mapping(client, args, body, query)

    if body:
        return client.post("/api/v1/bruteforce/list", body, query=query)

    return client.get("/api/v1/bruteforce/list", query=query)


def bruteforce_list_via_mapping(client: NauthilusClient, args: argparse.Namespace, body: dict[str, Any],
                                query: dict[str, str]) -> Response:
    """List brute-force state with account-mapping resolution and never report an undecided all-clear."""

    try:
        response = client.post("/api/v1/bruteforce/list", body, query=query)
    except HTTPClientError as exc:
        section = account_section(exc.response.parsed if exc.response else None)
        if exc.status == 400 and "account_resolution" not in str(exc):
            # A current server names the field in its own validation errors; an older server with
            # OpenAPI request validation only reports a generic contract failure for the unknown field.
            raise ClientError(f"{exc}\nhint: if this is an older server, it rejects account_resolution; "
                              "retry without --via-mapping to check the literal names only") from exc
        if not section or "resolutions" not in section:
            raise
        print_response(exc.response, args)
        report_account_resolutions(section)
        raise ClientError(f"brute-force listing is incomplete (HTTP {exc.status}); "
                          "names marked undecided were not checked reliably") from exc

    section = account_section(response.parsed)
    if not section or section.get("account_resolution") != ACCOUNT_RESOLUTION_MAPPING:
        print_response(response, args)
        raise ClientError("server ignored account_resolution (older server?); "
                          "only the literal names were checked, no alias was resolved")

    report_account_resolutions(section)
    problem = undecided_account_resolutions(section, args.account)
    if problem:
        print_response(response, args)
        raise ClientError(problem)
    return response


def undecided_account_resolutions(section: dict[str, Any], requested: list[str]) -> str | None:
    """Return why a successful listing still leaves requested names undecided, if it does."""

    resolutions = [item for item in section.get("resolutions") or [] if isinstance(item, dict)]
    undecided = [str(item.get("input", "")) for item in resolutions if item.get("status") == "error"]
    reported = {item.get("input") for item in resolutions}
    missing = [name for name in dict.fromkeys(requested) if name and name not in reported]

    if undecided:
        return "undecided names despite a successful response: " + ", ".join(undecided)
    if missing:
        return "server reported no resolution for: " + ", ".join(missing)
    return None


def account_section(payload: Any) -> dict[str, Any] | None:
    """Return the blocked-account section of a brute-force list payload."""

    result = payload.get("result") if isinstance(payload, dict) else None
    if isinstance(result, list) and len(result) == 2 and isinstance(result[1], dict):
        return result[1]
    return None


def describe_account_resolution(resolution: dict[str, Any]) -> str:
    """Render one per-name resolution, leading with whether state was found."""

    name = resolution.get("input", "")
    status = resolution.get("status", "")
    matched = resolution.get("matched") or []
    accounts = resolution.get("accounts") or []
    found = f"state found for {', '.join(matched)}" if matched else "no brute-force state found"

    if status == "error":
        return f"{name}: UNDECIDED, account mapping could not be read: {resolution.get('error', 'unknown error')}"
    if status == "ambiguous":
        return f"{name}: {found}; AMBIGUOUS mapping to {', '.join(accounts)} (all checked; verify the owner)"
    if status == "mapped" and accounts:
        return f"{name}: {found}; stored mapping -> {accounts[0]} (not re-verified against the backend)"
    return (f"{name}: {found}; no stored mapping, only the literal name was checked "
            "(a never-used alias or different spelling may belong to an account listed under its canonical name)")


def report_account_resolutions(section: dict[str, Any]) -> None:
    """Print per-name resolution results to stderr so stdout stays machine-readable."""

    for resolution in section.get("resolutions") or []:
        print(describe_account_resolution(resolution), file=sys.stderr)


def bruteforce_flush(client: NauthilusClient, args: argparse.Namespace) -> Any:
    """Flush brute-force state for one rule and IP address."""

    body = {"ip_address": args.ip, "rule_name": args.rule}
    if args.protocol:
        body["protocol"] = args.protocol
    if args.oidc_cid:
        body["oidc_cid"] = args.oidc_cid

    path = "/api/v1/bruteforce/flush/async" if args.async_mode else "/api/v1/bruteforce/flush"
    response = client.delete(path, body)
    if args.wait:
        return wait_for_result(client, extract_job_id(response), args)

    return response


def extract_job_id(response: Response) -> str:
    """Extract a job ID from an async response envelope."""

    if not isinstance(response.parsed, dict):
        raise ClientError("async response was not a JSON object")

    result = response.parsed.get("result")
    if not isinstance(result, dict) or not result.get("jobId"):
        raise ClientError("async response did not contain result.jobId")

    return str(result["jobId"])


def wait_for_result(client: NauthilusClient, job_id: str, args: argparse.Namespace) -> Response:
    """Poll an async job until it reaches a terminal state."""

    deadline = time.time() + args.wait_timeout
    last_response: Response | None = None
    while time.time() < deadline:
        last_response = client.get(f"/api/v1/async/jobs/{urllib.parse.quote(job_id, safe='')}")
        status = ""
        if isinstance(last_response.parsed, dict):
            result = last_response.parsed.get("result")
            if isinstance(result, dict):
                status = str(result.get("status", ""))
        if status in {"DONE", "ERROR"}:
            return last_response
        time.sleep(args.wait_interval)

    raise ClientError(f"async job {job_id} did not finish within {args.wait_timeout:.1f}s")


def auth_json(client: NauthilusClient, args: argparse.Namespace) -> Response:
    """Call the JSON authentication endpoint for operational tests."""

    query: dict[str, str] = {}
    if args.mode:
        query["mode"] = args.mode
    if args.no_cache:
        query["cache"] = "0"
    if args.no_memory:
        query["in-memory"] = "0"

    body: dict[str, Any] = {}
    if args.user:
        body["username"] = args.user
    if args.password or args.password_file or args.ask_pass:
        body["password"] = read_password(args)
    if args.client_ip:
        body["client_ip"] = args.client_ip
    if args.client_port:
        body["client_port"] = args.client_port
    if args.protocol:
        body["protocol"] = args.protocol
    if args.method:
        body["method"] = args.method
    if args.auth_login_attempt is not None:
        body["auth_login_attempt"] = args.auth_login_attempt

    return client.post("/api/v1/auth/json", body, query=query)


def read_password(args: argparse.Namespace) -> str:
    """Read an authentication password from one of the supported sources."""

    sources = [bool(args.password), bool(args.password_file), bool(args.ask_pass)]
    if sum(sources) > 1:
        raise ClientError("use only one of --password, --password-file, or --ask-pass")

    if args.password_file:
        return Path(args.password_file).read_text(encoding="utf-8").rstrip("\n")

    if args.ask_pass:
        return getpass.getpass("Password: ")

    return args.password or ""


def oidc_sessions_list(client: NauthilusClient, args: argparse.Namespace) -> Response:
    """List OIDC sessions for a user identifier."""

    user_id = urllib.parse.quote(args.user_id, safe="")
    return client.get(f"/api/v1/oidc/sessions/{user_id}")


def oidc_sessions_delete(client: NauthilusClient, args: argparse.Namespace) -> Response:
    """Delete all or one OIDC session for a user identifier."""

    user_id = urllib.parse.quote(args.user_id, safe="")
    if args.token:
        token = urllib.parse.quote(args.token, safe="")
        return client.delete(f"/api/v1/oidc/sessions/{user_id}/{token}")

    return client.delete(f"/api/v1/oidc/sessions/{user_id}")


def raw_request(client: NauthilusClient, args: argparse.Namespace) -> Response:
    """Send a raw request to a backchannel endpoint."""

    body = read_json_argument(args.data, args.data_file)
    return client.request(
        args.method.upper(),
        args.path,
        body=body,
        query=parse_key_values(args.query),
        headers=parse_key_values(args.header),
        authenticated=not args.no_auth,
    )


def openapi_fetch(client: NauthilusClient, args: argparse.Namespace) -> Response:
    """Fetch the management OpenAPI document."""

    suffix = "yaml" if args.format == "yaml" else "json"
    return client.get(f"/api/v1/openapi.{suffix}")


def async_status(client: NauthilusClient, args: argparse.Namespace) -> Response:
    """Read one async job status."""

    return client.get(f"/api/v1/async/jobs/{urllib.parse.quote(args.job_id, safe='')}")


def token_status(client: NauthilusClient, _args: argparse.Namespace) -> dict[str, Any]:
    """Return token cache status."""

    return client.token_status()


def token_clear(client: NauthilusClient, _args: argparse.Namespace) -> dict[str, Any]:
    """Clear the token cache."""

    return client.clear_token_cache()


def add_wait_args(parser: argparse.ArgumentParser, *, include_switch: bool = True) -> None:
    """Add async wait controls to a subparser."""

    if include_switch:
        parser.add_argument("--wait", action="store_true", help="wait for async job completion")
    parser.add_argument("--wait-timeout", type=float, default=60.0, help="maximum seconds to wait")
    parser.add_argument("--wait-interval", type=float, default=1.0, help="seconds between status polls")


def require_bearer(client: NauthilusClient, requirement: str) -> None:
    """Reject Basic-only backchannel credentials for operations that accept bearer tokens only."""

    if not client.config.bearer_token and client.config.basic_user and client.config.basic_password:
        raise ClientError(requirement)


def require_reputation_bearer(client: NauthilusClient) -> None:
    """Reject Basic backchannel credentials, which cannot authorize reputation administration."""

    require_bearer(client, REPUTATION_BEARER_REQUIRED)


def send_reputation(client: NauthilusClient, method: str, path: str, body: dict[str, Any], *,
                    mutation: bool) -> Response:
    """Send one bounded administrative operation without retrying uncertain mutations."""

    require_reputation_bearer(client)
    if len(json.dumps(body).encode("utf-8")) > REPUTATION_MAX_BODY:
        raise ClientError(f"reputation request exceeds {REPUTATION_MAX_BODY} bytes")
    try:
        return client.request(method, "/api/v1/custom/reputation/" + path, body=body)
    except (ClientError, OSError, http.client.HTTPException) as exc:
        if isinstance(exc, HTTPClientError) and 400 <= exc.status < 500 and exc.status != 408:
            raise
        if mutation:
            raise ClientError("reputation mutation failed; outcome may be unknown. Inspect lookup/status before retrying the same change.") from exc
        raise


def reputation_request(client: NauthilusClient, args: argparse.Namespace) -> Response:
    """Build one administrative request from CLI arguments and send it once."""

    require_reputation_bearer(client)
    body = {field: getattr(args, field) for field in args.reputation_fields if getattr(args, field, None) is not None}
    if "kind" in body:
        if bool(args.subject) == bool(args.subject_file):
            raise ClientError("provide exactly one subject or --subject-file")
        body["subject"] = args.subject
        if args.subject_file:
            with Path(args.subject_file).open("rb") as source:
                subject = source.read(515)
                if len(subject) > 514:
                    raise ClientError("subject file exceeds the bounded input size")
                body["subject"] = subject.decode("utf-8").removesuffix("\n").removesuffix("\r")
        if not body["subject"] or len(body["subject"].encode("utf-8")) > 512:
            raise ClientError("subject must contain 1 to 512 UTF-8 bytes")
    if args.reputation_action:
        body["action"] = args.reputation_action
    return send_reputation(client, args.reputation_method, args.reputation_path, body,
                           mutation=args.reputation_mutation)


def reputation_ttl(value: str) -> int:
    """Require an explicit bounded lifetime; zero deliberately means no expiry."""

    seconds = int(value)
    if not 0 <= seconds <= REPUTATION_MAX_TTL:
        raise argparse.ArgumentTypeError(f"TTL must be between 0 and {REPUTATION_MAX_TTL} seconds")
    return seconds


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys so no artifact entry is silently shadowed."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reputation_import_ttl(expires_at: int, now: float) -> int | None:
    """Convert an absolute expiry into ttl_seconds; 0 stays non-expiring and None means already expired."""

    if expires_at == 0:
        return 0

    # Round the clock up so the relative lifetime never outlives the absolute expiry.
    remaining = expires_at - math.ceil(now)
    return remaining if remaining > 0 else None


def reputation_import_body(entry: dict[str, Any], ttl_seconds: int) -> dict[str, Any]:
    """Map one artifact entry to the override PUT body; creator is derived server-side and never sent."""

    body = {field: entry[field] for field in ("kind", "subject", "band", "reason", "origin", "audit_id")}
    body.update(slot="active", ttl_seconds=ttl_seconds)
    return body


def reputation_import_problem(entry: Any, now: float) -> str | None:
    """Return the first validation problem of one artifact entry, or None when it can be applied."""

    if not isinstance(entry, dict):
        return "entry must be a JSON object"
    missing, unknown = REPUTATION_IMPORT_ENTRY_KEYS - entry.keys(), entry.keys() - REPUTATION_IMPORT_ENTRY_KEYS
    if missing:
        return "missing fields: " + ", ".join(sorted(missing))
    if unknown:
        return "unknown fields: " + ", ".join(sorted(unknown))
    for field in ("kind", "subject", "band", "reason", "creator", "audit_id", "origin"):
        if not isinstance(entry[field], str):
            return f"{field} must be a string"
    if entry["kind"] not in REPUTATION_KINDS:
        return "kind must be one of " + ", ".join(REPUTATION_KINDS)
    if entry["band"] not in REPUTATION_BANDS:
        return "band must be one of " + ", ".join(REPUTATION_BANDS)
    if not 1 <= len(entry["subject"].encode("utf-8")) <= 512:
        return "subject must contain 1 to 512 UTF-8 bytes"
    for field in ("reason", "origin"):
        if not REPUTATION_IDENTIFIER.fullmatch(entry[field]):
            return f"{field} must match {REPUTATION_IDENTIFIER.pattern}"
    audit_id = entry["audit_id"]
    if not 1 <= len(audit_id.encode("utf-8")) <= 128 or audit_id.strip() != audit_id or any(
            ord(character) < 32 or ord(character) == 127 for character in audit_id):
        return "audit_id must contain 1 to 128 bytes without control characters or surrounding whitespace"
    expires_at = entry["expires_at"]
    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or not 0 <= expires_at <= REPUTATION_IMPORT_MAX_EXPIRES_AT:
        return "expires_at must be an absolute Unix time in seconds; 0 means non-expiring"
    ttl_seconds = reputation_import_ttl(expires_at, now)
    if ttl_seconds is not None and ttl_seconds > REPUTATION_MAX_TTL:
        return f"expires_at is more than {REPUTATION_MAX_TTL} seconds in the future"
    if len(json.dumps(reputation_import_body(entry, ttl_seconds or 0)).encode("utf-8")) > REPUTATION_MAX_BODY:
        return f"override request exceeds {REPUTATION_MAX_BODY} bytes"
    return None


def load_reputation_import(path: str, now: float) -> list[dict[str, Any]]:
    """Load and validate a whole static import artifact before any request is sent."""

    with Path(path).open("rb") as source:
        raw = source.read(REPUTATION_IMPORT_MAX_BYTES + 1)
    if len(raw) > REPUTATION_IMPORT_MAX_BYTES:
        raise ClientError(f"import artifact exceeds {REPUTATION_IMPORT_MAX_BYTES} bytes")
    try:
        artifact = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except ValueError as exc:
        raise ClientError(f"import artifact is not valid JSON: {exc}") from exc

    if not isinstance(artifact, dict) or artifact.get("schema") != REPUTATION_IMPORT_SCHEMA:
        raise ClientError(f"import artifact schema must be {REPUTATION_IMPORT_SCHEMA!r}")
    unknown = artifact.keys() - REPUTATION_IMPORT_KEYS
    if unknown:
        raise ClientError("import artifact has unknown top-level fields: " + ", ".join(sorted(unknown)))
    entries = artifact.get("overrides")
    if not isinstance(entries, list):
        raise ClientError("import artifact field 'overrides' must be a list")

    problems: list[str] = []
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        problem = reputation_import_problem(entry, now)
        if problem is None:
            key = (entry["kind"], entry["subject"])
            problem = "duplicate kind and subject" if key in seen else None
            seen.add(key)
        if problem is not None:
            problems.append(f"overrides[{index}]: {problem}")
    if problems:
        raise ClientError("invalid import artifact; nothing was applied:\n  " + "\n  ".join(problems))

    return entries


def reputation_override_import(client: NauthilusClient, args: argparse.Namespace) -> dict[str, Any]:
    """Apply every override of a validated static import artifact sequentially and without retries."""

    entries = load_reputation_import(args.artifact, time.time())
    require_reputation_bearer(client)
    creators = sorted({entry["creator"] for entry in entries})
    if creators:
        print("note: artifact creator " + ", ".join(map(repr, creators))
              + " is ignored; the server records the authenticated token identity", file=sys.stderr)

    results: list[dict[str, Any]] = []
    stopped = False
    for entry in entries:
        result: dict[str, Any] = {"kind": entry["kind"], "subject": entry["subject"], "audit_id": entry["audit_id"]}
        # Recompute the lifetime right before each request so slow batches do not extend expiries.
        ttl_seconds = reputation_import_ttl(entry["expires_at"], time.time())
        if stopped:
            result["status"] = "not-attempted"
        elif ttl_seconds is None:
            result.update(status="skipped-expired", expires_at=entry["expires_at"])
        else:
            try:
                send_reputation(client, "PUT", "override", reputation_import_body(entry, ttl_seconds), mutation=True)
                result.update(status="applied", ttl_seconds=ttl_seconds)
            except ClientError as exc:
                result.update(status="failed", error=str(exc))
                stopped = not args.continue_on_error
        results.append(result)
        details = " ".join(f"{key}={value}" for key, value in result.items() if key != "status")
        print(f"{result['status']} {details}", file=sys.stderr, flush=True)

    counts = {status: sum(1 for result in results if result["status"] == status)
              for status in ("applied", "skipped-expired", "failed", "not-attempted")}
    return {"requested": len(entries), "applied": counts["applied"], "skipped_expired": counts["skipped-expired"],
            "failed": counts["failed"], "not_attempted": counts["not-attempted"], "results": results}


def add_reputation_arguments(parser: argparse.ArgumentParser, *, subject: bool, audit: bool) -> list[str]:
    """Share exact subject and audit arguments without exposing actor or storage keys."""

    fields = []
    if subject:
        parser.add_argument("kind", choices=REPUTATION_KINDS)
        parser.add_argument("subject", nargs="?", help="exact subject; use --subject-file to keep it out of process arguments")
        parser.add_argument("--subject-file", help="read one exact subject from a private UTF-8 file")
        fields.append("kind")
    if audit:
        for field in ("reason", "origin", "audit_id"):
            parser.add_argument("--" + field.replace("_", "-"), required=True)
            fields.append(field)
    return fields


def add_reputation_commands(subcommands: Any) -> None:
    """Expose the supported Management API through the existing operator client."""

    reputation = subcommands.add_parser("reputation", help="administrative reputation lookup, overrides and allocation recovery")
    commands = reputation.add_subparsers(dest="reputation_command", required=True)
    lookup = commands.add_parser("lookup", help="inspect one exact subject through primary storage")
    lookup.set_defaults(func=reputation_request, reputation_fields=add_reputation_arguments(lookup, subject=True, audit=False),
                        reputation_method="POST", reputation_path="lookup", reputation_action=None, reputation_mutation=False)
    override = commands.add_parser("override", help="audited operator exceptions")
    overrides = override.add_subparsers(dest="override_command", required=True)
    for operation, method in (("put", "PUT"), ("delete", "DELETE")):
        command = overrides.add_parser(operation)
        fields = add_reputation_arguments(command, subject=True, audit=True)
        command.add_argument("--slot", choices=("active", "previous"), default="active")
        command.add_argument("--previous-audit", required=operation == "delete", help="current override audit ID for optimistic replacement/removal")
        fields.extend(("slot", "previous_audit"))
        if operation == "put":
            command.add_argument("--band", choices=REPUTATION_BANDS, required=True)
            command.add_argument("--ttl-seconds", type=reputation_ttl, required=True, help="explicit expiry; 0 means non-expiring")
            fields.extend(("band", "ttl_seconds"))
        command.set_defaults(func=reputation_request, reputation_fields=fields, reputation_method=method,
                             reputation_path="override", reputation_action=None, reputation_mutation=True)
    importer = overrides.add_parser("import", help=f"apply the overrides of a {REPUTATION_IMPORT_SCHEMA} artifact")
    importer.add_argument("artifact", help="artifact written by scripts/convert-static-reputation.py")
    importer.add_argument("--continue-on-error", action="store_true", help="continue after per-entry failures")
    importer.set_defaults(func=reputation_override_import, local_object=True, fail_on_entry_errors=True)
    allocation = commands.add_parser("allocation", help="inspect or fence writers before allocation-key rotation")
    allocations = allocation.add_subparsers(dest="allocation_command", required=True)
    for action in ("status", "drain"):
        command = allocations.add_parser(action)
        fields = add_reputation_arguments(command, subject=False, audit=action == "drain")
        command.set_defaults(func=reputation_request, reputation_fields=fields, reputation_method="POST",
                             reputation_path="allocation", reputation_action=action, reputation_mutation=action == "drain")


def json_path(payload: Any, *keys: str) -> Any:
    """Return a nested JSON object value, or None when a level is missing or not an object."""

    for key in keys:
        if not isinstance(payload, dict):
            return None
        payload = payload.get(key)

    return payload


def list_field(payload: Any, field: str) -> list[Any]:
    """Return a JSON list field, treating a missing or malformed field as empty."""

    value = json_path(payload, field)
    return value if isinstance(value, list) else []


def compact(fields: dict[str, Any]) -> dict[str, Any]:
    """Drop unset optional fields so a request body carries only what the operator asked for."""

    return {key: value for key, value in fields.items() if value is not None}


def checked_text(check: Callable[[str], bool], description: str) -> Callable[[str], str]:
    """Build an argparse type that keeps the operator's spelling but rejects values failing a cheap local check."""

    def parse(value: str) -> str:
        try:
            valid = check(value)
        except ValueError:
            valid = False

        if not valid:
            raise argparse.ArgumentTypeError(f"must be {description}")

        return value

    return parse


def pattern_check(pattern: re.Pattern[str]) -> Callable[[str], bool]:
    """Return a check that accepts full matches of pattern only."""

    return lambda value: pattern.fullmatch(value) is not None


def is_ip_address(value: str) -> bool:
    """Accept one literal IPv4 or IPv6 address; ipaddress raises ValueError otherwise."""

    return ipaddress.ip_address(value) is not None


def is_cidr_network(value: str) -> bool:
    """Accept one network in CIDR notation; host bits are left for the server to judge."""

    return "/" in value and ipaddress.ip_network(value, strict=False) is not None


def bounded_int(minimum: int, maximum: int) -> Callable[[str], int]:
    """Build an argparse type that accepts decimal integers within an inclusive range."""

    def parse(value: str) -> int:
        if not re.fullmatch(r"[0-9]{1,9}", value) or not minimum <= int(value) <= maximum:
            raise argparse.ArgumentTypeError(f"must be an integer between {minimum} and {maximum}")

        return int(value)

    return parse


def rfc3339_timestamp(value: str) -> datetime:
    """Parse an RFC3339 timestamp with an explicit offset; digits beyond microseconds are truncated."""

    match = RFC3339_TIMESTAMP.fullmatch(value)
    if match:
        base, fraction, offset = match.groups()
        micros = "." + fraction[:6].ljust(6, "0") if fraction else ""
        try:
            return datetime.fromisoformat(base + micros + ("+00:00" if offset == "Z" else offset))
        except ValueError:
            pass

    raise argparse.ArgumentTypeError("must be an RFC3339 timestamp with offset, for example 2026-11-17T08:00:00Z")


def format_rfc3339(value: datetime) -> str:
    """Render an aware timestamp as RFC3339, using Z for UTC."""

    text = value.isoformat()
    return text[:-6] + "Z" if text.endswith("+00:00") else text


def history_duration(value: str) -> timedelta:
    """Parse a positive --since duration such as 30m, 2h or 7d."""

    match = SUPPORT_DURATION.fullmatch(value)
    if not match:
        raise argparse.ArgumentTypeError("must be a duration such as 30m, 2h or 7d")

    return timedelta(seconds=int(match.group(1)) * SUPPORT_DURATION_SECONDS[match.group(2)])


def history_window(args: argparse.Namespace) -> dict[str, str]:
    """Resolve --since or --from/--until into a validated window of at most SUPPORT_MAX_WINDOW."""

    if args.since is not None and (args.window_from is not None or args.window_until is not None):
        raise ClientError("use either --since or --from/--until, not both")

    if args.since is not None:
        until = datetime.fromtimestamp(int(time.time()), tz=timezone.utc)
        start = until - args.since
    elif args.window_from is not None and args.window_until is not None:
        start, until = args.window_from, args.window_until
    else:
        raise ClientError("a time window is required: use --since DURATION or both --from and --until")

    if start >= until:
        raise ClientError("--from must be earlier than --until")

    if until - start > SUPPORT_MAX_WINDOW:
        raise ClientError(f"the time window exceeds {SUPPORT_MAX_WINDOW.days} days; narrow --since or --from/--until")

    return {"from": format_rfc3339(start), "until": format_rfc3339(until)}


def history_subject(args: argparse.Namespace) -> dict[str, str] | None:
    """Return the selected login or account subject, or None when neither was given."""

    if args.login:
        return {"login": args.login}

    if args.account:
        return {"account": args.account}

    return None


def history_page(args: argparse.Namespace) -> dict[str, Any]:
    """Return the page selector; an empty selector lets the server choose its default limit."""

    return compact({"limit": args.limit, "cursor": args.cursor})


def history_body(args: argparse.Namespace, fields: dict[str, Any]) -> dict[str, Any]:
    """Wrap command-specific fields in the versioned envelope shared by every history request."""

    return compact({"schema_version": SUPPORT_SCHEMA_VERSION, **fields, "audit_reference": args.audit_reference})


def attempts_search_body(args: argparse.Namespace) -> dict[str, Any]:
    """Build the body of an authentication-attempt search."""

    filters = {**history_window(args), "client_ip": args.client_ip, "protocol": args.protocol,
               "oidc_client_id": args.oidc_client_id, "saml_entity_id": args.saml_entity_id}
    output = {"include_ban_context": True if args.include_ban_context else None, "response_mode": args.response_mode}

    return history_body(args, {"subject": history_subject(args), "filter": compact(filters), "page": history_page(args),
                               **compact(output)})


def attempt_detail_body(args: argparse.Namespace) -> dict[str, Any]:
    """Build the body of an authentication-attempt detail lookup."""

    return history_body(args, {"attempt_id": args.attempt_id, "around": format_rfc3339(args.around),
                               "subject": history_subject(args)})


def bans_search_body(args: argparse.Namespace) -> dict[str, Any]:
    """Build the body of a brute-force ban search for exactly one IP address or network."""

    target = {"ip": args.ip} if args.ip else {"network": args.network}
    filters = {**history_window(args), "ban_ref": args.ban_ref}

    return history_body(args, {"target": target, "filter": compact(filters), "subject": history_subject(args),
                               "page": history_page(args)})


@dataclass(frozen=True)
class HistoryQuery:
    """HistoryQuery describes one support history endpoint, its request body and how followed pages merge."""

    build_body: Callable[[argparse.Namespace], dict[str, Any]]
    merge_fields: tuple[tuple[str, str | None], ...]
    path: str
    result_field: str
    empty_subject: str
    compact_field: str | None = None

    def results_field(self, payload: Any) -> str:
        """Name the list that carries the results of an answer: compact answers carry summaries, not attempts."""

        if self.compact_field and json_path(payload, "response_mode") == "compact":
            return self.compact_field

        return self.result_field


# HISTORY_COVERAGE_FIELDS are the coverage blocks a followed answer merges; ban_history exists only with the ban
# context.
HISTORY_COVERAGE_FIELDS = ("history", "ban_history")

ATTEMPTS_SEARCH = HistoryQuery(attempts_search_body, (("attempts", "attempt_id"), ("attempt_summaries", "attempt_id"),
                                                      ("ban_contexts", "request_id")),
                               "authentication-attempts/search", "attempts", "login", "attempt_summaries")
ATTEMPT_DETAIL = HistoryQuery(attempt_detail_body, (), "authentication-attempts/detail", "attempt", "login")
BANS_SEARCH = HistoryQuery(bans_search_body, (("bans", "ban_ref"), ("releases", None), ("counter_resets", None),
                                              ("unconfirmed_activations", None)),
                           "bruteforce-bans/search", "bans", "ban")


def require_history_credentials(client: NauthilusClient) -> None:
    """Reject credentials that can never authorize the read-only support history API."""

    require_bearer(client, SUPPORT_BEARER_REQUIRED)
    if not client.config.bearer_token and SUPPORT_READ_SCOPE not in client.config.scopes.split():
        raise ClientError(f"support history needs the {SUPPORT_READ_SCOPE} scope; request it with --scopes or "
                          "NAUTHILUS_SCOPES")


def history_http_error(exc: HTTPClientError) -> ClientError:
    """Map a rejected history query to its documented exit code, preferring the JSON error code over the status."""

    code = json_path(exc.response.parsed if exc.response else None, "error", "code")
    code = code if isinstance(code, str) and code else None
    exit_code = SUPPORT_ERROR_EXIT_CODES.get(code or "", SUPPORT_STATUS_EXIT_CODES.get(exc.status, EXIT_FAILURE))
    hint = SUPPORT_ERROR_HINTS.get(exit_code) or (SUPPORT_SCOPE_HINT if exc.status in (401, 403) else None)
    message = f"support history query failed with {code or 'HTTP ' + str(exc.status)}: {exc}"

    return ClientError(message + (f"\nhint: {hint}" if hint else ""), exit_code=exit_code)


def send_history(client: NauthilusClient, path: str, body: dict[str, Any]) -> Response:
    """POST one history query; subjects and filters travel only in the JSON body, never in the URL."""

    try:
        response = client.post(SUPPORT_PATH + path, body)
    except HTTPClientError as exc:
        raise history_http_error(exc) from exc
    except http.client.HTTPException as exc:
        raise ClientError(f"support history request failed: {exc!r}") from exc

    if not isinstance(response.parsed, dict):
        raise ClientError("support history response was not a JSON object")

    return response


def history_next_cursor(payload: Any) -> str | None:
    """Return the next page cursor of a processed answer, if any."""

    cursor = json_path(payload, "page", "next_cursor")
    return cursor if isinstance(cursor, str) and cursor else None


def fetch_history_pages(client: NauthilusClient, path: str, body: dict[str, Any], follow: bool) -> list[Response]:
    """Fetch one page, or follow next_cursor with an unchanged query for at most SUPPORT_MAX_PAGES pages."""

    pages = [send_history(client, path, body)]
    cursor = history_next_cursor(pages[-1].parsed)
    while follow and cursor and len(pages) < SUPPORT_MAX_PAGES:
        body = {**body, "page": {**body.get("page", {}), "cursor": cursor}}
        pages.append(send_history(client, path, body))
        cursor = history_next_cursor(pages[-1].parsed)

    return pages


def unique_items(items: Iterable[Any], key: str | None) -> list[Any]:
    """Keep the first occurrence of each item, identified by its key field or else by its canonical JSON form."""

    seen: set[str] = set()
    result: list[Any] = []
    for item in items:
        identity = json_path(item, key) if key else None
        marker = f"key:{identity}" if isinstance(identity, str) else "json:" + json.dumps(item, sort_keys=True)
        if marker not in seen:
            seen.add(marker)
            result.append(item)

    return result


def merge_history_blocks(blocks: list[Any]) -> Any:
    """Keep the last history block, but never let it hide partial availability or conditions of earlier pages."""

    history = blocks[-1]
    if not isinstance(history, dict):
        return history

    merged = dict(history)
    if merged.get("availability") == "available" and any(json_path(block, "availability") != "available"
                                                         for block in blocks):
        merged["availability"] = "partial"

    merged["conditions"] = unique_items((condition for block in blocks for condition in list_field(block, "conditions")),
                                        None)

    return merged


def merge_history_pages(query: HistoryQuery, pages: list[Response]) -> Response:
    """Merge followed pages into one answer: deduplicated lists, the last page's blocks and the page count."""

    payloads = [page.parsed for page in pages]
    merged = dict(payloads[-1])
    for field, key in query.merge_fields:
        if any(field in payload for payload in payloads):
            merged[field] = unique_items((item for payload in payloads for item in list_field(payload, field)), key)

    for field in HISTORY_COVERAGE_FIELDS:
        if any(field in payload for payload in payloads):
            merged[field] = merge_history_blocks([payload.get(field) for payload in payloads])
    if any(payload.get("result_basis") == "matches_found" for payload in payloads):
        merged["result_basis"] = "matches_found"

    merged["pages"] = len(pages)
    last = pages[-1]
    body = json.dumps(merged, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    return Response(last.status, last.reason, last.headers, body, merged)


def history_outcome(query: HistoryQuery, response: Response, follow: bool) -> CommandOutcome:
    """Classify a processed answer by availability; historical login failures never change the exit code."""

    payload = response.parsed
    availability = json_path(payload, "history", "availability")
    conditions = ", ".join(map(str, list_field(json_path(payload, "history"), "conditions"))) or "none"
    exit_code = EXIT_OK
    notes: list[str] = []
    if availability != "available":
        exit_code = EXIT_HISTORY_PARTIAL
        notes.append(f"warning: history availability is {availability or 'unknown'} (conditions: {conditions}); "
                     "the result may be incomplete")

    ban_availability = json_path(payload, "ban_history", "availability")
    if ban_availability not in (None, "available"):
        notes.append(f"warning: brute-force history availability is {ban_availability}; ban contexts may be incomplete")

    result_field = query.results_field(payload)
    if not payload.get(result_field):
        notes.append(f"note: no {result_field} returned (result_basis={payload.get('result_basis')}, "
                     f"conditions: {conditions}); an empty result does not prove that no {query.empty_subject} "
                     "happened")

    cursor = history_next_cursor(payload)
    if follow and cursor:
        notes.append(f"warning: stopped after {SUPPORT_MAX_PAGES} pages; more results remain, continue with "
                     f"--cursor {cursor}")

    return CommandOutcome(response, exit_code, tuple(notes))


def support_history(client: NauthilusClient, args: argparse.Namespace) -> CommandOutcome:
    """Run one read-only support history command and report incomplete history through the exit code."""

    require_history_credentials(client)
    query: HistoryQuery = args.history_query
    follow = getattr(args, "all_pages", False)
    pages = fetch_history_pages(client, query.path, query.build_body(args), follow)
    response = merge_history_pages(query, pages) if follow else pages[0]
    outcome = history_outcome(query, response, follow)

    if getattr(args, "summary", False):
        return dataclass_replace(outcome, text=summarize_history(response.parsed))

    return outcome


# SUMMARY_MISSING renders a field an answer does not carry; older answers lack newer fields, and an absent value
# must never read as a success.
SUMMARY_MISSING = "-"


def summary_value(value: Any) -> str:
    """Render one summary field: lists comma-joined, absent or empty values as SUMMARY_MISSING."""

    if value is None or value == "" or value == []:
        return SUMMARY_MISSING

    if isinstance(value, list):
        return ",".join(summary_value(item) for item in value)

    if isinstance(value, bool):
        return "true" if value else "false"

    return str(value)


def summarize_attempt(item: Any) -> str:
    """Render one attempt as a single line: outcome and its basis, progress, steps, OIDC completion, codes, gaps."""

    steps = (json_path(item, "steps", name) for name in ("primary", "second_factor", "code_issuance", "code_redemption"))
    findings = [json_path(finding, "code") for finding in list_field(item, "findings")]
    fields = [
        ("outcome", f"{summary_value(json_path(item, 'outcome'))}/{summary_value(json_path(item, 'outcome_basis'))}"),
        ("final", summary_value(json_path(item, "final_outcome_observed"))),
        ("progress", summary_value(json_path(item, "progress"))),
        ("steps", "/".join(summary_value(step) for step in steps)),
        ("completion", summary_value(json_path(item, "completion", "state"))),
        ("authentication", summary_value(json_path(item, "completion", "authentication"))),
        ("findings", summary_value(findings)),
        ("gaps", summary_value(list_field(json_path(item, "recording"), "known_gaps"))),
    ]

    return f"{summary_value(json_path(item, 'attempt_id'))} {summary_value(json_path(item, 'kind'))} " + \
        " ".join(f"{name}={value}" for name, value in fields)


def summarize_attempt_summary(item: Any) -> str:
    """Render one compact attempt summary of a compact answer as a single line."""

    fields = [
        ("outcome", f"{summary_value(json_path(item, 'outcome'))}/{summary_value(json_path(item, 'outcome_basis'))}"),
        ("final", summary_value(json_path(item, "final_outcome_observed"))),
        ("reason", summary_value(json_path(item, "reason"))),
        ("findings", summary_value(list_field(item, "finding_codes"))),
        ("ips", summary_value(list_field(item, "client_ips"))),
        ("requests", summary_value(list_field(item, "request_ids"))),
        ("gaps", summary_value(list_field(item, "known_gaps"))),
    ]

    return f"{summary_value(json_path(item, 'attempt_id'))} {summary_value(json_path(item, 'kind'))} " + \
        " ".join(f"{name}={value}" for name, value in fields)


def summarize_ban_context(context: Any) -> list[str]:
    """Render one ban context: a line for the rejected request, then one line per linked ban with its codes."""

    lines = [f"  ban-context {summary_value(json_path(context, 'request_id'))} "
             f"attempt={summary_value(json_path(context, 'attempt_id'))} "
             f"status={summary_value(json_path(context, 'status'))} "
             f"limitations={summary_value(list_field(context, 'limitations'))}"]
    for ban in list_field(context, "bans"):
        counts = json_path(ban, "attribution", "counts")
        subject = sum(value for value in (json_path(counts, "subject_by_account"), json_path(counts, "subject_by_login_claim"))
                      if isinstance(value, int))
        fields = [
            ("network", summary_value(json_path(ban, "network"))),
            ("rule", summary_value(json_path(ban, "rule"))),
            ("activated", summary_value(json_path(ban, "activated_at"))),
            ("planned_end", summary_value(json_path(ban, "planned_end"))),
            ("end", summary_value(json_path(ban, "end", "reason"))),
            ("relation", summary_value(json_path(ban, "subject_relation"))),
            ("attribution", summary_value(json_path(ban, "attribution", "code"))),
            ("others", summary_value(json_path(ban, "attribution", "other_contributors"))),
            ("subject", str(subject) if isinstance(counts, dict) else SUMMARY_MISSING),
            ("other_accounts", summary_value(json_path(counts, "other_accounts"))),
            ("completeness", summary_value(json_path(ban, "evidence", "completeness"))),
            ("limitations", summary_value(list_field(json_path(ban, "evidence"), "limitations"))),
        ]
        lines.append(f"    ban {summary_value(json_path(ban, 'ban_ref'))} " +
                     " ".join(f"{name}={value}" for name, value in fields))

    return lines


def summarize_event(event: Any) -> str:
    """Render one event of a detail answer, including the stored answered status of its decision."""

    message = json_path(event, "decision", "answered_status_message")
    fields = [
        ("stage", summary_value(json_path(event, "stage"))),
        ("code", summary_value(json_path(event, "code"))),
        ("answered", summary_value(json_path(event, "decision", "answered_status_code"))),
        ("message", json.dumps(message, ensure_ascii=False) if isinstance(message, str) else SUMMARY_MISSING),
        ("transport", summary_value(json_path(event, "context", "transport_status"))),
    ]

    return f"  #{summary_value(json_path(event, 'sequence'))} {summary_value(json_path(event, 'occurred_at'))} " + \
        " ".join(f"{name}={value}" for name, value in fields)


def summarize_history(payload: Any) -> str:
    """Render an attempt search or detail answer compactly: a header line, one line per attempt or server-side
    attempt summary, event lines for a detail answer, and ban-context lines. The JSON output stays the complete
    answer; this local rendering never replaces the server's response_mode."""

    attempts = list_field(payload, "attempts")
    detail = json_path(payload, "attempt")
    if isinstance(detail, dict):
        attempts = [detail]

    lines = [f"result_basis={summary_value(json_path(payload, 'result_basis'))} "
             f"availability={summary_value(json_path(payload, 'history', 'availability'))} "
             f"completion_since={summary_value(json_path(payload, 'history', 'oidc_completion_events_since'))}"]
    for item in attempts:
        lines.append(summarize_attempt(item))
        if isinstance(detail, dict):
            lines.extend(summarize_event(event) for event in list_field(item, "events"))

    lines.extend(summarize_attempt_summary(item) for item in list_field(payload, "attempt_summaries"))
    for context in list_field(payload, "ban_contexts"):
        lines.extend(summarize_ban_context(context))

    return "\n".join(lines)


def add_support_parser(container: Any, name: str, help_text: str) -> argparse.ArgumentParser:
    """Add one support parser whose help epilog documents the shared exit codes."""

    return container.add_parser(name, help=help_text, description=help_text, epilog=SUPPORT_EXIT_HELP,
                                formatter_class=argparse.RawDescriptionHelpFormatter)


def add_history_subject_arguments(parser: argparse.ArgumentParser, *, required: bool) -> None:
    """Add the mutually exclusive login/account subject selector."""

    subject = parser.add_mutually_exclusive_group(required=required)
    subject.add_argument("--login", help="login name as presented by the client")
    subject.add_argument("--account", help="resolved account name")


def add_history_window_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the time window flags; --since and --from/--until are exclusive alternatives."""

    parser.add_argument("--from", dest="window_from", type=rfc3339_timestamp, metavar="RFC3339",
                        help="window start (inclusive)")
    parser.add_argument("--until", dest="window_until", type=rfc3339_timestamp, metavar="RFC3339",
                        help="window end (exclusive)")
    parser.add_argument("--since", type=history_duration, metavar="DURATION",
                        help="window from now minus DURATION until now, for example 30m, 2h or 7d")


def add_history_page_arguments(parser: argparse.ArgumentParser, maximum: int) -> None:
    """Add page size, cursor and bounded page-following flags."""

    parser.add_argument("--limit", type=bounded_int(1, maximum), help=f"page size from 1 to {maximum}")
    parser.add_argument("--cursor", help="next_cursor of a previous page")
    parser.add_argument("--all", dest="all_pages", action="store_true",
                        help=f"follow next_cursor for at most {SUPPORT_MAX_PAGES} pages and merge them")


def add_support_commands(subcommands: Any) -> None:
    """Expose the read-only support history API as a separate, bearer-only command group."""

    support = add_support_parser(subcommands, "support", "read-only authentication and brute-force ban history")
    groups = support.add_subparsers(dest="support_command", required=True)
    attempts = add_support_parser(groups, "attempts", "recorded authentication attempts").add_subparsers(
        dest="attempts_command", required=True)
    search = add_support_parser(attempts, "search", "search the attempts of one login or account")
    add_history_subject_arguments(search, required=True)
    add_history_window_arguments(search)
    search.add_argument("--client-ip", type=checked_text(is_ip_address, "an IPv4 or IPv6 address"),
                        help="client IP address filter")
    search.add_argument("--protocol", help="protocol filter, for example imap")
    search.add_argument("--oidc-client-id", help="OIDC client_id filter")
    search.add_argument("--saml-entity-id", help="SAML service provider entity ID filter")
    search.add_argument("--include-ban-context", action="store_true",
                        help="ask the server to link brute-force rejected attempts to the recorded ban effective at "
                             "that time (ban_contexts)")
    search.add_argument("--response-mode", choices=("detailed", "compact"),
                        help="server-side presentation: detailed (default) attempts or compact attempt_summaries; "
                             "it never changes rights")
    add_history_page_arguments(search, SUPPORT_ATTEMPT_LIMIT)

    detail = add_support_parser(attempts, "detail", "show one attempt by attempt_id")
    detail.add_argument("--attempt-id", required=True, type=checked_text(
        pattern_check(SUPPORT_ATTEMPT_ID), "fl1.<32 lowercase hex> or rq1.<request id>"))
    detail.add_argument("--around", required=True, type=rfc3339_timestamp, metavar="RFC3339",
                        help="any instant of the attempt, for example started_at from a search")
    add_history_subject_arguments(detail, required=False)

    bans = add_support_parser(groups, "bans", "recorded brute-force bans").add_subparsers(
        dest="bans_command", required=True)
    ban_search = add_support_parser(bans, "search", "explain the bans of one IP address or network")
    target = ban_search.add_mutually_exclusive_group(required=True)
    target.add_argument("--ip", type=checked_text(is_ip_address, "an IPv4 or IPv6 address"))
    target.add_argument("--network", type=checked_text(is_cidr_network, "a network in CIDR notation"), metavar="CIDR")
    add_history_window_arguments(ban_search)
    ban_search.add_argument("--ban-ref", type=checked_text(pattern_check(SUPPORT_BAN_REF), "32 lowercase hex characters"))
    add_history_subject_arguments(ban_search, required=False)
    add_history_page_arguments(ban_search, SUPPORT_BAN_LIMIT)

    for parser in (search, detail):
        parser.add_argument("--summary", action="store_true",
                            help="print one compact line per attempt (and per event for detail) instead of JSON; "
                                 "fields an older answer lacks print as '-'")

    for parser, query in ((search, ATTEMPTS_SEARCH), (detail, ATTEMPT_DETAIL), (ban_search, BANS_SEARCH)):
        parser.add_argument("--audit-reference", help="ticket or case reference recorded in the server audit log",
                            type=checked_text(pattern_check(SUPPORT_AUDIT_REFERENCE), "1 to 64 of [A-Za-z0-9._:/-]"))
        parser.set_defaults(func=support_history, history_query=query)


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse command tree."""

    parser = argparse.ArgumentParser(description="Nauthilus REST backchannel client")
    parser.add_argument("--env-file", help="env-style config file; defaults to NAUTHILUS_ENV_FILE")
    parser.add_argument("--url", help="Nauthilus base URL")
    parser.add_argument("--token-url", help="OIDC token endpoint URL")
    parser.add_argument("--client-id", help="OIDC client ID")
    parser.add_argument("--client-secret", help="OIDC client secret")
    parser.add_argument("--client-secret-file", help="file containing OIDC client secret")
    parser.add_argument("--client-auth-method", choices=("basic", "post"), help="OIDC client auth method")
    parser.add_argument("--scopes", help="space-separated OIDC scopes")
    parser.add_argument("--bearer-token", help="pre-issued bearer token")
    parser.add_argument("--bearer-token-file", help="file containing pre-issued bearer token")
    parser.add_argument("--basic-user", help="backchannel Basic Auth username")
    parser.add_argument("--basic-password", help="backchannel Basic Auth password")
    parser.add_argument("--basic-password-file", help="file containing backchannel Basic Auth password")
    parser.add_argument("--token-cache", help="token cache path; use 'off' to disable")
    parser.add_argument("--timeout", help="HTTP timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="disable TLS verification")
    parser.add_argument("--resolve", action="append", help="connect override in host:port:address form")
    parser.add_argument("--output", choices=("pretty", "json", "body", "headers"), default="pretty")

    subcommands = parser.add_subparsers(dest="command", required=True)

    add_reputation_commands(subcommands)
    add_support_commands(subcommands)

    token = subcommands.add_parser("token", help="token cache helpers")
    token_sub = token.add_subparsers(dest="token_command", required=True)
    token_sub.add_parser("status", help="show token cache metadata").set_defaults(func=token_status, local_object=True)
    token_sub.add_parser("clear", help="delete cached token").set_defaults(func=token_clear, local_object=True)

    openapi = subcommands.add_parser("openapi", help="OpenAPI document")
    openapi.add_argument("format", choices=("json", "yaml"), nargs="?", default="json")
    openapi.set_defaults(func=openapi_fetch)

    cache = subcommands.add_parser("cache", help="cache management")
    cache_sub = cache.add_subparsers(dest="cache_command", required=True)
    cache_flush_parser = cache_sub.add_parser("flush", help="flush one user")
    cache_flush_parser.add_argument("user")
    cache_flush_parser.add_argument("--async", dest="async_mode", action="store_true", help="enqueue async flush")
    add_wait_args(cache_flush_parser)
    cache_flush_parser.set_defaults(func=cache_flush)

    cache_file_parser = cache_sub.add_parser("flush-file", help="flush users listed in a file or stdin")
    cache_file_parser.add_argument("file", help="file path or '-' for stdin")
    cache_file_parser.add_argument("--async", dest="async_mode", action="store_true", help="enqueue async flushes")
    cache_file_parser.add_argument("--continue-on-error", action="store_true", help="continue after per-user failures")
    cache_file_parser.add_argument("--summary-only", action="store_true", help="omit per-user removed key lists")
    cache_file_parser.add_argument("--live", action="store_true", help="print per-user progress to stderr")
    cache_file_parser.add_argument(
        "--pending-ok",
        action="store_true",
        help="with --async --wait, keep unfinished jobs as PENDING instead of TIMEOUT",
    )
    add_wait_args(cache_file_parser)
    cache_file_parser.set_defaults(func=cache_flush_file, local_object=True)

    brute = subcommands.add_parser("bruteforce", help="brute-force state management")
    brute_sub = brute.add_subparsers(dest="bruteforce_command", required=True)
    brute_list = brute_sub.add_parser("list", help="list bans and blocked accounts")
    brute_list.add_argument("--account", action="append", help="account filter; repeatable")
    brute_list.add_argument("--ip", action="append", help="IP filter; repeatable")
    brute_list.add_argument("--limit", type=int, default=100, help="page size (default: 100); inspect page.has_more")
    brute_list.add_argument("--offset", type=int)
    brute_list.add_argument(
        "--via-mapping", action="store_true",
        help="also check the accounts Nauthilus stored for each --account login name (needs a server with "
             "account_resolution support); per-name results go to stderr")
    brute_list.set_defaults(func=bruteforce_list)

    brute_flush = brute_sub.add_parser("flush", help="flush one brute-force rule")
    brute_flush.add_argument("--ip", required=True, help="IP address")
    brute_flush.add_argument("--rule", required=True, help="rule name")
    brute_flush.add_argument("--protocol", help="optional protocol")
    brute_flush.add_argument("--oidc-cid", help="optional OIDC client ID")
    brute_flush.add_argument("--async", dest="async_mode", action="store_true", help="enqueue async flush")
    add_wait_args(brute_flush)
    brute_flush.set_defaults(func=bruteforce_flush)

    async_parser = subcommands.add_parser("async", help="async jobs")
    async_sub = async_parser.add_subparsers(dest="async_command", required=True)
    async_status_parser = async_sub.add_parser("status", help="show job status")
    async_status_parser.add_argument("job_id")
    async_status_parser.set_defaults(func=async_status)
    async_wait = async_sub.add_parser("wait", help="wait for job completion")
    async_wait.add_argument("job_id")
    add_wait_args(async_wait, include_switch=False)
    async_wait.set_defaults(func=lambda client, args: wait_for_result(client, args.job_id, args))

    oidc = subcommands.add_parser("oidc", help="OIDC session management")
    oidc_sub = oidc.add_subparsers(dest="oidc_command", required=True)
    sessions = oidc_sub.add_parser("sessions", help="OIDC sessions")
    sessions_sub = sessions.add_subparsers(dest="sessions_command", required=True)
    sessions_list = sessions_sub.add_parser("list", help="list sessions for a user")
    sessions_list.add_argument("user_id")
    sessions_list.set_defaults(func=oidc_sessions_list)
    sessions_delete = sessions_sub.add_parser("delete", help="delete sessions for a user")
    sessions_delete.add_argument("user_id")
    sessions_delete.add_argument("--token", help="delete only this access token/session key")
    sessions_delete.set_defaults(func=oidc_sessions_delete)

    auth = subcommands.add_parser("auth", help="auth endpoint helpers")
    auth_sub = auth.add_subparsers(dest="auth_command", required=True)
    auth_json_parser = auth_sub.add_parser("json", help="call /api/v1/auth/json")
    auth_json_parser.add_argument("--mode", choices=("no-auth", "list-accounts"))
    auth_json_parser.add_argument("--user")
    auth_json_parser.add_argument("--password")
    auth_json_parser.add_argument("--password-file")
    auth_json_parser.add_argument("--ask-pass", action="store_true")
    auth_json_parser.add_argument("--client-ip")
    auth_json_parser.add_argument("--client-port")
    auth_json_parser.add_argument("--protocol", default="imap")
    auth_json_parser.add_argument("--method", default="plain")
    auth_json_parser.add_argument("--auth-login-attempt", type=int)
    auth_json_parser.add_argument("--no-cache", action="store_true", help="send cache=0")
    auth_json_parser.add_argument("--no-memory", action="store_true", help="send in-memory=0")
    auth_json_parser.set_defaults(func=auth_json)

    raw = subcommands.add_parser("raw", help="send an arbitrary management request")
    raw.add_argument("method")
    raw.add_argument("path", help="absolute URL or API path")
    raw.add_argument("--data", help="JSON body")
    raw.add_argument("--data-file", help="file containing JSON body or '-' for stdin")
    raw.add_argument("--query", action="append", help="query key=value; repeatable")
    raw.add_argument("--header", action="append", help="header key=value; repeatable")
    raw.add_argument("--no-auth", action="store_true", help="do not attach Authorization")
    raw.set_defaults(func=raw_request)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Program entrypoint."""

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        client = NauthilusClient(build_config(args))
        outcome = args.func(client, args)
        if not isinstance(outcome, CommandOutcome):
            outcome = CommandOutcome(outcome)

        if outcome.text is not None:
            print(outcome.text)
        elif getattr(args, "local_object", False):
            print_object(outcome.result, args)
            if getattr(args, "fail_on_entry_errors", False) and outcome.result.get("failed"):
                return EXIT_FAILURE
        else:
            print_response(outcome.result, args)

        for note in outcome.notes:
            print(note, file=sys.stderr)

        return outcome.exit_code
    except (ClientError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code if isinstance(exc, ClientError) else EXIT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
