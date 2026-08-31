# gRPC Identity Backend API v1

This package owns the versioned gRPC contract for authority-side identity and
MFA persistence operations. `identity_backend.proto` is the source of truth;
generated Go bindings are committed so normal builds do not require `protoc`.

## Regenerating

Install the generator tools used for this contract:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
```

The generator also requires `protoc` in `PATH`. The generated-drift check is
the compatibility authority across supported `protoc` patch releases.

Regenerate all committed gRPC bindings from the repository root:

```sh
make generate-grpc-proto
```

Verify the committed output without modifying the worktree:

```sh
make generate-grpc-proto-check
```

Verify common, auth, identity, and Policy wire descriptors against their
frozen, reviewed public API baselines:

```sh
make grpc-proto-compatibility-check
```

The package-local `go:generate` directive is equivalent:

```sh
go generate ./api/identity/v1
```

After regenerating, run:

```sh
GOEXPERIMENT=runtimesecret go test ./api/identity/v1
```

Run the full project guardrails before publishing changes:

```sh
GOEXPERIMENT=runtimesecret make guardrails
```
