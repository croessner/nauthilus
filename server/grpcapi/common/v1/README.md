# gRPC Common API v1

This package owns shared transport-only protobuf messages used by multiple
Nauthilus gRPC APIs. `common.proto` is the source of truth; `common.pb.go` is
generated and committed so normal builds do not require `protoc`.

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
go generate ./server/grpcapi/common/v1
```

After regenerating, run:

```sh
GOEXPERIMENT=runtimesecret go test ./server/grpcapi/common/v1
```

Run the full project guardrails before publishing changes:

```sh
GOEXPERIMENT=runtimesecret make guardrails
```
