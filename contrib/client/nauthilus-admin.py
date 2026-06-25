#!/usr/bin/env python3
"""Command-line client for Nauthilus REST backchannel operations."""

from __future__ import annotations

import argparse
import base64
import getpass
import http.client
import json
import os
import socket
import ssl
import stat
import sys
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

DEFAULT_URL = "https://nauthilus.example.invalid"
DEFAULT_SCOPES = "nauthilus:authenticate nauthilus:admin nauthilus:security"
DEFAULT_TIMEOUT = 15.0


class ClientError(RuntimeError):
    """ClientError represents an operator-facing request or configuration failure."""


@dataclass(frozen=True)
class Response:
    """Response stores the HTTP response after body decoding."""

    status: int
    reason: str
    headers: dict[str, str]
    body: bytes
    parsed: Any


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
            raise ClientError(format_http_error(method.upper(), url, response))

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
    resolve_values = list(args.resolve or [])
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

    if body:
        return client.post("/api/v1/bruteforce/list", body, query=query)

    return client.get("/api/v1/bruteforce/list", query=query)


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


def config_load(client: NauthilusClient, _args: argparse.Namespace) -> Response:
    """Load the runtime configuration."""

    return client.get("/api/v1/config/load")


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

    token = subcommands.add_parser("token", help="token cache helpers")
    token_sub = token.add_subparsers(dest="token_command", required=True)
    token_sub.add_parser("status", help="show token cache metadata").set_defaults(func=token_status, local_object=True)
    token_sub.add_parser("clear", help="delete cached token").set_defaults(func=token_clear, local_object=True)

    config = subcommands.add_parser("config", help="configuration endpoints")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    config_sub.add_parser("load", help="load runtime config").set_defaults(func=config_load)

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
    brute_list.add_argument("--limit", type=int)
    brute_list.add_argument("--offset", type=int)
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
        result = args.func(client, args)
        if getattr(args, "local_object", False):
            print_object(result, args)
        elif isinstance(result, Response):
            print_response(result, args)
        else:
            print_response(result, args)

        return 0
    except (ClientError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
