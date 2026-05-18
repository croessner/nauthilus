# gRPC Auth API v1

This package owns the versioned gRPC contract for the Nauthilus auth API.
`auth.proto` is the source of truth; `auth.pb.go` and `auth_grpc.pb.go` are
generated files committed to the repository so normal builds do not require
`protoc`.

## Regenerating

Install the generator tools used for this contract:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
```

The generator also requires `protoc` in `PATH`. This contract was generated
with `libprotoc 34.1`; newer compatible patch releases are acceptable if the
generated output stays stable.

Regenerate all committed gRPC bindings from the repository root:

```sh
make generate-grpc-proto
```

The package-local `go:generate` directive is equivalent:

```sh
go generate ./server/grpcapi/auth/v1
```

After regenerating, run:

```sh
GOEXPERIMENT=runtimesecret go test ./server/grpcapi/auth/v1
```

## Optional Smoke Client

`contrib/auth-grpc-request.py` can call `Authenticate`, `LookupIdentity`, and
`ListAccounts` against a running local listener. It generates temporary Python
stubs from this proto file and requires the optional Python packages `grpcio`,
`grpcio-tools`, and `protobuf`.

Example with `temp/nauthilus-grpc-testing.yml`:

```sh
contrib/auth-grpc-request.py \
  --target 127.0.0.1:19444 \
  --basic-user admin \
  --basic-password 'Nauthilus-Test-Admin-Secret-2026!' \
  --rpc authenticate \
  --username grpc@example.test \
  --password secret
```

Run the full project guardrails before publishing changes:

```sh
GOEXPERIMENT=runtimesecret make guardrails
```
