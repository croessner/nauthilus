#!/usr/bin/env python3
"""Send a gRPC AuthService smoke request to Nauthilus."""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import subprocess
import sys
import tempfile
from importlib import import_module
from typing import Any


DEFAULT_TARGET = "127.0.0.1:9444"
PROTO_PATH = pathlib.Path("server/grpcapi/auth/v1/auth.proto")
RPC_TO_METHOD = {
    "authenticate": "Authenticate",
    "lookup-identity": "LookupIdentity",
    "list-accounts": "ListAccounts",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send a gRPC AuthService request to Nauthilus.",
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help=f"gRPC target. Default: {DEFAULT_TARGET}")
    parser.add_argument(
        "--rpc",
        choices=tuple(RPC_TO_METHOD),
        default="authenticate",
        help="AuthService RPC to call.",
    )
    parser.add_argument("--username", default="", help="Auth username.")
    parser.add_argument("--password", default="secret", help="Auth password for Authenticate.")
    parser.add_argument("--client-ip", default="192.0.2.10", help="Client IP address.")
    parser.add_argument("--client-port", default="54321", help="Client source port.")
    parser.add_argument("--client-hostname", default="client.example.test", help="Client hostname.")
    parser.add_argument("--client-id", default="grpc-smoke-client", help="Upstream client identifier.")
    parser.add_argument(
        "--external-session-id",
        default="grpc-smoke-session",
        help="External session ID for log correlation.",
    )
    parser.add_argument("--user-agent", default="nauthilus-grpc-smoke/1.0", help="Request user agent.")
    parser.add_argument("--local-ip", default="127.0.0.1", help="Local endpoint IP.")
    parser.add_argument("--local-port", default="9444", help="Local endpoint port.")
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
        help="Auth login attempt marker for Authenticate.",
    )
    parser.add_argument(
        "--request-json",
        default="",
        help="Optional JSON object file with proto field overrides. Use '-' for stdin.",
    )
    parser.add_argument("--basic-user", default="", help="Backchannel Basic auth username.")
    parser.add_argument("--basic-password", default="", help="Backchannel Basic auth password.")
    parser.add_argument("--bearer-token", default="", help="Backchannel Bearer token.")
    parser.add_argument("--tls", action="store_true", help="Use TLS instead of plaintext.")
    parser.add_argument("--ca-cert", default="", help="PEM CA bundle for TLS server verification.")
    parser.add_argument("--client-cert", default="", help="PEM client certificate for mTLS.")
    parser.add_argument("--client-key", default="", help="PEM client private key for mTLS.")
    parser.add_argument("--server-name", default="", help="TLS server name override.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds.")
    parser.add_argument("--dump-request-json", action="store_true", help="Print the request JSON before calling.")

    return parser.parse_args()


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    username = args.username
    if not username and args.rpc != "list-accounts":
        username = "demo@example.test"

    common = {
        "username": username,
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
        "oidc_cid": args.oidc_cid,
    }

    if args.rpc == "list-accounts":
        payload = common
    else:
        payload = {
            **common,
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
        }

    if args.rpc == "authenticate":
        payload["password"] = args.password
        payload["auth_login_attempt"] = args.auth_login_attempt

    overrides = load_request_overrides(args.request_json)
    payload.update(overrides)

    return payload


def load_request_overrides(path: str) -> dict[str, Any]:
    if not path:
        return {}

    if path == "-":
        data = sys.stdin.read()
    else:
        data = pathlib.Path(path).read_text(encoding="utf-8")

    value = json.loads(data)
    if not isinstance(value, dict):
        raise SystemExit("--request-json must contain a JSON object")

    return value


def load_generated_modules(repo_root: pathlib.Path, generated_dir: pathlib.Path) -> tuple[Any, Any, Any]:
    grpc = import_optional("grpc")
    import_optional("google.protobuf.json_format")
    import_optional("grpc_tools.protoc")

    proto_file = repo_root / PROTO_PATH
    if not proto_file.exists():
        raise SystemExit(f"Proto file not found: {proto_file}")

    command = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"-I{repo_root}",
        f"--python_out={generated_dir}",
        f"--grpc_python_out={generated_dir}",
        str(proto_file),
    ]
    subprocess.run(command, check=True)
    sys.path.insert(0, str(generated_dir))

    auth_pb2 = import_module("server.grpcapi.auth.v1.auth_pb2")
    auth_pb2_grpc = import_module("server.grpcapi.auth.v1.auth_pb2_grpc")

    return grpc, auth_pb2, auth_pb2_grpc


def import_optional(module_name: str) -> Any:
    try:
        return import_module(module_name)
    except ImportError as exc:
        raise SystemExit(
            "Missing optional Python gRPC dependency. Install with: "
            "python3 -m pip install grpcio grpcio-tools protobuf"
        ) from exc


def build_request(auth_pb2: Any, rpc: str, payload: dict[str, Any]) -> Any:
    request_type = {
        "authenticate": auth_pb2.AuthRequest,
        "lookup-identity": auth_pb2.LookupIdentityRequest,
        "list-accounts": auth_pb2.ListAccountsRequest,
    }[rpc]

    return request_type(**payload)


def build_channel(grpc: Any, args: argparse.Namespace) -> Any:
    if not args.tls:
        return grpc.insecure_channel(args.target)

    root_certificates = read_optional_bytes(args.ca_cert)
    certificate_chain = read_optional_bytes(args.client_cert)
    private_key = read_optional_bytes(args.client_key)
    credentials = grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain,
    )
    options = []
    if args.server_name:
        options.append(("grpc.ssl_target_name_override", args.server_name))

    return grpc.secure_channel(args.target, credentials, options=options)


def read_optional_bytes(path: str) -> bytes | None:
    if not path:
        return None

    return pathlib.Path(path).read_bytes()


def build_metadata(args: argparse.Namespace) -> list[tuple[str, str]]:
    metadata: list[tuple[str, str]] = []
    if args.basic_user or args.basic_password:
        token = base64.b64encode(f"{args.basic_user}:{args.basic_password}".encode("utf-8")).decode("ascii")
        metadata.append(("authorization", f"Basic {token}"))

    if args.bearer_token:
        metadata.append(("authorization", f"Bearer {args.bearer_token}"))

    return metadata


def response_to_json(response: Any) -> dict[str, Any]:
    json_format = import_module("google.protobuf.json_format")

    try:
        return json_format.MessageToDict(
            response,
            preserving_proto_field_name=True,
            always_print_fields_with_no_presence=True,
        )
    except TypeError:
        return json_format.MessageToDict(response, preserving_proto_field_name=True)


def main() -> int:
    args = parse_args()
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    payload = build_payload(args)

    if args.dump_request_json:
        print(json.dumps({"request": payload}, indent=2, sort_keys=True))

    with tempfile.TemporaryDirectory(prefix="nauthilus-grpc-smoke-") as tmp_dir:
        grpc, auth_pb2, auth_pb2_grpc = load_generated_modules(repo_root, pathlib.Path(tmp_dir))
        request = build_request(auth_pb2, args.rpc, payload)
        channel = build_channel(grpc, args)
        stub = auth_pb2_grpc.AuthServiceStub(channel)
        method = getattr(stub, RPC_TO_METHOD[args.rpc])

        try:
            response = method(request, timeout=args.timeout, metadata=build_metadata(args))
        except grpc.RpcError as exc:
            print(
                json.dumps(
                    {
                        "grpc_code": exc.code().name,
                        "details": exc.details(),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )

            return 1

    print(json.dumps(response_to_json(response), indent=2, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
