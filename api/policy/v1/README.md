# Policy gRPC API v1

This directory reserves public protobuf ownership for the Policy API. The
Policy RPC and generated DTOs are intentionally not part of the public
protobuf layout change.

When the Policy contract is introduced, its protobuf source and generated Go
bindings must live here and participate in the central
`make generate-grpc-proto` workflow.
