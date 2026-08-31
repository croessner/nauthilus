# Nauthilus v4 Module Migration

Nauthilus v4 moves the Go module identity to
`github.com/croessner/nauthilus/v4`. This major version reflects the operator
configuration break introduced by the top-level Policy configuration model.

## Go Consumers

Go source that imports Nauthilus packages must replace the exact module prefix
`github.com/croessner/nauthilus/v3` with
`github.com/croessner/nauthilus/v4` and then update its module dependency.
Third-party module paths that independently use a `/v3` suffix are unrelated
and must not be rewritten.

## Native Plugins

Native `.so` plugins must be rebuilt against the v4 `pluginapi/v1` package and
the same Go toolchain, build tags, relevant build flags, and dependency sources
as the v4 host. An artifact built against the v3 module identity is not binary
compatible with the v4 host even though the semantic plugin API identifier
remains `nauthilus.plugin.v1`.

## gRPC Consumers

The Go `go_package` ownership metadata now points to the v4 module. The
protobuf package names, service names, method names, message field numbers,
and HTTP paths are unchanged. Clients that use independently generated stubs
therefore remain wire-compatible and do not need to adopt the Nauthilus Go
module solely for this migration.

Public descriptor checks normalize Go package ownership back to the reviewed
legacy metadata before comparing Common, Auth, and Identity with their frozen
baseline. Policy has its own frozen baseline and receives the same
normalization. Any other descriptor change remains a compatibility failure.

## Release Identity

Release tags must use the same major version as the module path. The release
metadata guard rejects a tag whose major differs from `go.mod`; for this module
the intended first prerelease is `v4.0.0-alpha.1`.
