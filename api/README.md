# Public APIs

The `api/<domain>/v1` tree is the sole source and generated-code root for
public protobuf contracts. Public packages contain transport contracts and
generated DTOs only; handlers, application mappers, clients, connection
management, and internal test infrastructure remain server-owned.

Current public protobuf domains are:

- `common/v1` for shared transport messages;
- `auth/v1` for authentication RPCs;
- `identity/v1` for identity and MFA backend RPCs;
- `policy/v1`, the public unary Policy decision RPC.

Regenerate or verify all committed bindings through the central workflow:

```sh
make generate-grpc-proto
make generate-grpc-proto-check
make grpc-proto-compatibility-check
```
