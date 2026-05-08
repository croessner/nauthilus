#!/usr/bin/env python3
"""Send a complete CBOR authentication request to Nauthilus."""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from importlib import import_module
from typing import Any


DEFAULT_URL = "http://127.0.0.1:8080/api/v1/auth/cbor"
CBOR_CONTENT_TYPE = "application/cbor"
AUTH_RESPONSE_KEYS = ("ok", "account_field", "totp_secret_field", "backend", "attributes")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send an application/cbor auth request to /api/v1/auth/cbor.",
    )
    parser.add_argument("--url", default=DEFAULT_URL, help=f"Endpoint URL. Default: {DEFAULT_URL}")
    parser.add_argument("--username", default="demo@example.test", help="Auth username.")
    parser.add_argument("--password", default="secret", help="Auth password.")
    parser.add_argument("--client-ip", default="192.0.2.10", help="Client IP address.")
    parser.add_argument("--client-port", default="54321", help="Client source port.")
    parser.add_argument("--client-hostname", default="client.example.test", help="Client hostname.")
    parser.add_argument("--client-id", default="cbor-test-client", help="Upstream client identifier.")
    parser.add_argument(
        "--external-session-id",
        default="cbor-test-session",
        help="External session ID for log correlation.",
    )
    parser.add_argument("--user-agent", default="nauthilus-cbor-test/1.0", help="Request user agent.")
    parser.add_argument("--local-ip", default="127.0.0.1", help="Local endpoint IP.")
    parser.add_argument("--local-port", default="143", help="Local endpoint port.")
    parser.add_argument("--protocol", default="imap", help="Protocol value, e.g. imap, smtp, pop3.")
    parser.add_argument("--method", default="plain", help="Authentication method.")
    parser.add_argument("--ssl", default="off", help="SSL/TLS marker.")
    parser.add_argument("--ssl-session-id", default="", help="SSL session ID.")
    parser.add_argument("--ssl-client-verify", default="NONE", help="SSL client verification result.")
    parser.add_argument("--ssl-client-dn", default="", help="SSL client DN.")
    parser.add_argument("--ssl-client-cn", default="", help="SSL client CN.")
    parser.add_argument("--ssl-issuer", default="", help="SSL issuer.")
    parser.add_argument("--ssl-client-notbefore", default="", help="SSL client certificate not-before.")
    parser.add_argument("--ssl-client-notafter", default="", help="SSL client certificate not-after.")
    parser.add_argument("--ssl-subject-dn", default="", help="SSL subject DN.")
    parser.add_argument("--ssl-issuer-dn", default="", help="SSL issuer DN.")
    parser.add_argument("--ssl-client-subject-dn", default="", help="SSL client subject DN.")
    parser.add_argument("--ssl-client-issuer-dn", default="", help="SSL client issuer DN.")
    parser.add_argument("--ssl-protocol", default="", help="SSL protocol.")
    parser.add_argument("--ssl-cipher", default="", help="SSL cipher.")
    parser.add_argument("--ssl-serial", default="", help="SSL certificate serial.")
    parser.add_argument("--ssl-fingerprint", default="", help="SSL certificate fingerprint.")
    parser.add_argument("--oidc-cid", default="", help="OIDC client ID.")
    parser.add_argument(
        "--auth-login-attempt",
        type=int,
        default=1,
        help="Auth login attempt marker.",
    )
    parser.add_argument(
        "--mode",
        choices=("auth", "no-auth", "list-accounts"),
        default="auth",
        help="Optional auth mode query parameter.",
    )
    parser.add_argument(
        "--http-method",
        choices=("POST", "GET"),
        default="POST",
        help="HTTP method to use. GET skips the request body and is intended for "
             "no-auth/list-accounts modes.",
    )
    parser.add_argument("--bearer-token", default="", help="Bearer token for protected API access.")
    parser.add_argument("--api-basic-user", default="", help="Basic auth username for protected API access.")
    parser.add_argument("--api-basic-password", default="", help="Basic auth password for protected API access.")
    parser.add_argument("--header", action="append", default=[], help="Additional HTTP header as Name: value.")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds.")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    parser.add_argument("--dump-payload-json", action="store_true", help="Print the request payload as JSON.")
    parser.add_argument(
        "--skip-response-check",
        action="store_true",
        help="Skip response shape validation for successful CBOR responses.",
    )
    parser.add_argument("--quiet", action="store_true", help="Only print the response body.")

    return parser.parse_args()


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "username": args.username,
        "password": args.password,
        "client_ip": args.client_ip,
        "client_port": args.client_port,
        "client_hostname": args.client_hostname,
        "client_id": args.client_id,
        "external_session_id": args.external_session_id,
        "user_agent": args.user_agent,
        "local_ip": args.local_ip,
        "local_port": args.local_port,
        "protocol": args.protocol,
        "method": args.method,
        "ssl": args.ssl,
        "ssl_session_id": args.ssl_session_id,
        "ssl_client_verify": args.ssl_client_verify,
        "ssl_client_dn": args.ssl_client_dn,
        "ssl_client_cn": args.ssl_client_cn,
        "ssl_issuer": args.ssl_issuer,
        "ssl_client_notbefore": args.ssl_client_notbefore,
        "ssl_client_notafter": args.ssl_client_notafter,
        "ssl_subject_dn": args.ssl_subject_dn,
        "ssl_issuer_dn": args.ssl_issuer_dn,
        "ssl_client_subject_dn": args.ssl_client_subject_dn,
        "ssl_client_issuer_dn": args.ssl_client_issuer_dn,
        "ssl_protocol": args.ssl_protocol,
        "ssl_cipher": args.ssl_cipher,
        "ssl_serial": args.ssl_serial,
        "ssl_fingerprint": args.ssl_fingerprint,
        "oidc_cid": args.oidc_cid,
        "auth_login_attempt": args.auth_login_attempt,
    }


def endpoint_url(args: argparse.Namespace) -> str:
    if args.mode == "auth":
        return args.url

    separator = "&" if "?" in args.url else "?"

    return f"{args.url}{separator}mode={args.mode}"


def load_cbor2() -> Any:
    try:
        return import_module("cbor2")
    except ImportError as exc:
        return None


def encode_type_and_value(major_type: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major_type << 5) | value])

    if value <= 0xFF:
        return bytes([(major_type << 5) | 24, value])

    if value <= 0xFFFF:
        return bytes([(major_type << 5) | 25]) + value.to_bytes(2, "big")

    if value <= 0xFFFFFFFF:
        return bytes([(major_type << 5) | 26]) + value.to_bytes(4, "big")

    return bytes([(major_type << 5) | 27]) + value.to_bytes(8, "big")


def fallback_cbor_dumps(value: Any) -> bytes:
    if value is None:
        return b"\xf6"

    if value is False:
        return b"\xf4"

    if value is True:
        return b"\xf5"

    if isinstance(value, int):
        if value >= 0:
            return encode_type_and_value(0, value)

        return encode_type_and_value(1, -1 - value)

    if isinstance(value, bytes):
        return encode_type_and_value(2, len(value)) + value

    if isinstance(value, str):
        encoded = value.encode("utf-8")

        return encode_type_and_value(3, len(encoded)) + encoded

    if isinstance(value, (list, tuple)):
        items = b"".join(fallback_cbor_dumps(item) for item in value)

        return encode_type_and_value(4, len(value)) + items

    if isinstance(value, dict):
        encoded_items = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise SystemExit(f"Fallback CBOR encoder only supports string map keys, got {type(key)!r}")

            encoded_items.append((fallback_cbor_dumps(key), fallback_cbor_dumps(item)))

        encoded_items.sort(key=lambda pair: pair[0])

        return encode_type_and_value(5, len(encoded_items)) + b"".join(
            key + item for key, item in encoded_items
        )

    raise SystemExit(f"Fallback CBOR encoder does not support value type {type(value)!r}")


def cbor_dumps(value: Any) -> bytes:
    cbor2 = load_cbor2()
    if cbor2 is not None:
        return cbor2.dumps(value, canonical=True)

    return fallback_cbor_dumps(value)


def read_type_and_value(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset >= len(data):
        raise ValueError("unexpected end of CBOR data")

    initial = data[offset]
    offset += 1
    major_type = initial >> 5
    additional = initial & 0x1F

    if additional < 24:
        return major_type, additional, offset

    if additional == 24:
        return major_type, data[offset], offset + 1

    if additional == 25:
        return major_type, int.from_bytes(data[offset : offset + 2], "big"), offset + 2

    if additional == 26:
        return major_type, int.from_bytes(data[offset : offset + 4], "big"), offset + 4

    if additional == 27:
        return major_type, int.from_bytes(data[offset : offset + 8], "big"), offset + 8

    raise ValueError("fallback CBOR decoder does not support indefinite length values")


def fallback_cbor_loads(data: bytes) -> Any:
    value, offset = fallback_cbor_load_value(data, 0)
    if offset != len(data):
        raise ValueError("trailing data after CBOR value")

    return value


def fallback_cbor_load_value(data: bytes, offset: int) -> tuple[Any, int]:
    major_type, value, offset = read_type_and_value(data, offset)

    if major_type == 0:
        return value, offset

    if major_type == 1:
        return -1 - value, offset

    if major_type == 2:
        end = offset + value

        return data[offset:end], end

    if major_type == 3:
        end = offset + value

        return data[offset:end].decode("utf-8"), end

    if major_type == 4:
        result = []
        for _ in range(value):
            item, offset = fallback_cbor_load_value(data, offset)
            result.append(item)

        return result, offset

    if major_type == 5:
        result = {}
        for _ in range(value):
            key, offset = fallback_cbor_load_value(data, offset)
            item, offset = fallback_cbor_load_value(data, offset)
            result[key] = item

        return result, offset

    if major_type == 7:
        if value == 20:
            return False, offset

        if value == 21:
            return True, offset

        if value == 22:
            return None, offset

    raise ValueError(f"fallback CBOR decoder does not support major type {major_type}")


def cbor_loads(data: bytes) -> Any:
    cbor2 = load_cbor2()
    if cbor2 is not None:
        return cbor2.loads(data)

    return fallback_cbor_loads(data)


def add_headers(request: urllib.request.Request, args: argparse.Namespace) -> None:
    if args.http_method == "POST":
        request.add_header("Content-Type", "application/cbor")

    request.add_header("Accept", "application/cbor, application/json;q=0.5, text/plain;q=0.1, */*;q=0.05")
    request.add_header("User-Agent", args.user_agent)

    if args.bearer_token:
        request.add_header("Authorization", f"Bearer {args.bearer_token}")
    elif args.api_basic_user or args.api_basic_password:
        token = f"{args.api_basic_user}:{args.api_basic_password}".encode()
        request.add_header("Authorization", "Basic " + base64.b64encode(token).decode("ascii"))

    for header in args.header:
        name, separator, value = header.partition(":")
        if not separator or not name.strip():
            raise SystemExit(f"Invalid --header value {header!r}; expected 'Name: value'")

        request.add_header(name.strip(), value.strip())


def decode_response(content_type: str, body: bytes) -> Any:
    if not body:
        return ""

    normalized = normalize_content_type(content_type)
    if normalized == CBOR_CONTENT_TYPE:
        return cbor_loads(body)

    if normalized == "application/json":
        return json.loads(body.decode("utf-8"))

    return body.decode("utf-8", errors="replace")


def normalize_content_type(content_type: str) -> str:
    return content_type.split(";", 1)[0].strip().lower()


def validate_success_response(headers: Any, decoded: Any, args: argparse.Namespace) -> None:
    if args.skip_response_check:
        return

    content_type = normalize_content_type(headers.get("Content-Type", ""))
    if content_type != CBOR_CONTENT_TYPE:
        raise SystemExit(f"Expected successful CBOR response, got Content-Type {content_type!r}")

    if args.mode == "list-accounts":
        if not isinstance(decoded, list):
            raise SystemExit(f"Expected CBOR list-accounts array, got {type(decoded).__name__}")

        return

    if not isinstance(decoded, dict):
        raise SystemExit(f"Expected CBOR auth response map, got {type(decoded).__name__}")

    missing = [key for key in AUTH_RESPONSE_KEYS if key not in decoded]
    if missing:
        raise SystemExit(f"CBOR auth response missing field(s): {', '.join(missing)}")

    if decoded.get("ok") is not True:
        raise SystemExit(f"Expected CBOR auth response ok=true, got {decoded.get('ok')!r}")

    if not isinstance(decoded.get("attributes"), dict):
        raise SystemExit("Expected CBOR auth response attributes to be a map")


def print_response(status: int, headers: Any, decoded: Any, quiet: bool) -> None:

    if quiet:
        if isinstance(decoded, str):
            print(decoded)
        else:
            print(json.dumps(decoded, indent=2, sort_keys=True))

        return

    print(f"HTTP {status}")
    for name, value in headers.items():
        print(f"{name}: {value}")

    print()
    if isinstance(decoded, str):
        print(decoded)
    else:
        print(json.dumps(decoded, indent=2, sort_keys=True))


def main() -> int:
    args = parse_args()
    payload = build_payload(args)

    if args.dump_payload_json:
        print(json.dumps(payload, indent=2, sort_keys=True), file=sys.stderr)

    if args.http_method == "POST":
        data = cbor_dumps(payload)
    else:
        data = None

    request = urllib.request.Request(endpoint_url(args), data=data, method=args.http_method)
    add_headers(request, args)

    context = None
    if args.insecure:
        context = ssl._create_unverified_context()  # noqa: SLF001

    try:
        with urllib.request.urlopen(request, timeout=args.timeout, context=context) as response:
            body = response.read()
            decoded = decode_response(response.headers.get("Content-Type", ""), body)
            validate_success_response(response.headers, decoded, args)
            print_response(response.status, response.headers, decoded, args.quiet)

            return 0 if 200 <= response.status < 300 else 1
    except urllib.error.HTTPError as exc:
        body = exc.read()
        decoded = decode_response(exc.headers.get("Content-Type", ""), body)
        print_response(exc.code, exc.headers, decoded, args.quiet)

        return 1


if __name__ == "__main__":
    raise SystemExit(main())
