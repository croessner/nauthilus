// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package pluginapi

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	// ErrInvalidRedisScriptName is returned when a named Redis script uses an unsafe or unstable name.
	ErrInvalidRedisScriptName = errors.New("invalid redis script name")

	// ErrRedisScriptNotFound is returned when a plugin tries to run a script that was not uploaded.
	ErrRedisScriptNotFound = errors.New("redis script not found")

	// ErrInvalidHTTPRequest is returned when a host-managed outbound HTTP request is malformed.
	ErrInvalidHTTPRequest = errors.New("invalid plugin http request")

	// ErrHTTPResponseTooLarge is returned when a host-managed HTTP response exceeds the configured body limit.
	ErrHTTPResponseTooLarge = errors.New("plugin http response too large")

	// ErrInvalidConnectionTarget is returned when a connection target is unsafe or malformed.
	ErrInvalidConnectionTarget = errors.New("invalid plugin connection target")

	// ErrConnectionTargetConflict is returned when a duplicate connection target registration is not idempotent.
	ErrConnectionTargetConflict = errors.New("plugin connection target conflict")
)

// BackendServers exposes immutable backend candidates from host monitoring state.
type BackendServers interface {
	List(context.Context) []BackendServerCandidate
}

// HTTPClient executes outbound HTTP requests through host-managed instrumentation.
type HTTPClient interface {
	Do(context.Context, HTTPRequest) (HTTPResponse, error)
}

// HTTPRequest describes one host-managed outbound HTTP call without exposing net/http objects.
type HTTPRequest struct {
	Headers          map[string][]string
	Body             []byte
	Method           string
	URL              string
	Service          string
	Timeout          time.Duration
	MaxResponseBytes int64
}

// HTTPResponse contains the bounded response returned by the host HTTP facade.
type HTTPResponse struct {
	Headers    map[string][]string
	Body       []byte
	StatusCode int
}

// MailMessage describes one host-managed SMTP or LMTP message send request.
type MailMessage struct {
	To       []string
	Server   string
	HeloName string
	Username string
	Password string
	From     string
	Subject  string
	Body     string
	Port     int
	TLS      bool
	StartTLS bool
	LMTP     bool
}

// Mailer sends SMTP or LMTP messages through host-managed transport.
type Mailer interface {
	Send(context.Context, MailMessage) error
}

// ConnectionTargetDirection describes which endpoint side should be counted.
type ConnectionTargetDirection string

const (
	// ConnectionTargetDirectionLocal counts local listening endpoints.
	ConnectionTargetDirectionLocal ConnectionTargetDirection = "local"

	// ConnectionTargetDirectionRemote counts remote outbound endpoints.
	ConnectionTargetDirectionRemote ConnectionTargetDirection = "remote"
)

// ConnectionTarget describes one named network target for host-owned observability.
type ConnectionTarget struct {
	Labels      map[string]string
	Name        string
	Address     string
	Description string
	Direction   ConnectionTargetDirection
}

// ConnectionTargets registers network targets for host-owned connection observability.
type ConnectionTargets interface {
	Register(context.Context, ConnectionTarget) error
	Count(context.Context, string) (int, bool)
}

// Redis exposes host-owned Redis command handles without exposing internal singletons.
type Redis interface {
	Read() redis.Cmdable
	Write() redis.Cmdable
	ReadPipeline() redis.Pipeliner
	WritePipeline() redis.Pipeliner
	Keys() RedisKeyBuilder
	Scripts() RedisScriptRegistry
}

// RedisKeyBuilder builds host-prefixed Redis keys and cluster-safe key groups.
type RedisKeyBuilder interface {
	Key(string) string
	Keys(...string) []string
	SameSlot([]string, string) []string
}

// RedisScriptRegistry uploads and runs host-managed named Redis scripts.
type RedisScriptRegistry interface {
	Upload(context.Context, string, string) (string, error)
	Run(context.Context, string, []string, ...any) (any, error)
}

// Cache exposes a process-local module cache shared by a plugin module's components.
type Cache interface {
	Set(context.Context, string, any, time.Duration)
	Get(context.Context, string) (any, bool)
	Delete(context.Context, string) bool
	Exists(context.Context, string) bool
	Push(context.Context, string, any) int
	PopAll(context.Context, string) []any
	Clear(context.Context)
}

// DeterministicHelpers exposes shared non-secret helper logic used by plugin ports.
type DeterministicHelpers interface {
	AccountTag(string) string
	CountryName(string) string
	ScopedIP(string, string) string
	IsRoutableIP(string) bool
}

// LDAPScope describes LDAP search scope.
type LDAPScope string

const (
	// LDAPScopeBase selects only the search base object.
	LDAPScopeBase LDAPScope = "base"

	// LDAPScopeOne selects one level below the search base.
	LDAPScopeOne LDAPScope = "one"

	// LDAPScopeSub selects the full subtree below the search base.
	LDAPScopeSub LDAPScope = "sub"
)

// LDAPModifyOperation describes the LDAP modify operation kind.
type LDAPModifyOperation string

const (
	// LDAPModifyAdd adds LDAP attribute values.
	LDAPModifyAdd LDAPModifyOperation = "add"

	// LDAPModifyDelete deletes LDAP attribute values.
	LDAPModifyDelete LDAPModifyOperation = "delete"

	// LDAPModifyReplace replaces LDAP attribute values.
	LDAPModifyReplace LDAPModifyOperation = "replace"
)

// LDAPSearchRequest describes one queued LDAP search.
type LDAPSearchRequest struct {
	Attributes []string
	PoolName   string
	BaseDN     string
	Filter     string
	Scope      LDAPScope
}

// LDAPSearchResult contains LDAP search entries and flattened attributes.
type LDAPSearchResult struct {
	Attributes map[string][]string
	Entries    []LDAPEntry
}

// LDAPModifyRequest describes one queued LDAP modify operation.
type LDAPModifyRequest struct {
	Attributes map[string][]string
	PoolName   string
	DN         string
	Operation  LDAPModifyOperation
}

// LDAPEntry contains one LDAP search result entry.
type LDAPEntry struct {
	Attributes map[string][]string
	DN         string
}

// LDAPEndpoint contains configured trace-safe endpoint metadata for one pool URI.
type LDAPEndpoint struct {
	PoolName string
	Scheme   string
	Host     string
	Port     int
}

// LDAP exposes host-owned queued LDAP operations.
type LDAP interface {
	Search(context.Context, LDAPSearchRequest) (LDAPSearchResult, error)
	Modify(context.Context, LDAPModifyRequest) error
	Endpoints(context.Context, string) ([]LDAPEndpoint, error)
}

// MetricDefinition describes one plugin-owned metric.
type MetricDefinition struct {
	Buckets []float64
	Labels  []string
	Name    string
	Help    string
	Type    MetricType
	// Compatibility requests an operator-allowlisted exact legacy collector in addition to the native metric.
	Compatibility bool
}

// MetricType identifies a Prometheus collector family without exposing Prometheus types.
type MetricType string

const (
	// MetricTypeCounter selects a monotonically increasing counter collector.
	MetricTypeCounter MetricType = "counter"
	// MetricTypeGauge selects a gauge collector.
	MetricTypeGauge MetricType = "gauge"
	// MetricTypeHistogram selects a histogram collector with explicit or default buckets.
	MetricTypeHistogram MetricType = "histogram"
	// MetricTypeSummary selects a summary collector.
	MetricTypeSummary MetricType = "summary"
)

// LabelValue binds one declared metric label to a value.
type LabelValue struct {
	Name  string
	Value string
}

// Counter records monotonically increasing plugin measurements.
type Counter interface {
	Add(context.Context, float64, ...LabelValue)
}

// Gauge records mutable plugin measurements.
type Gauge interface {
	Set(context.Context, float64, ...LabelValue)
	Add(context.Context, float64, ...LabelValue)
}

// Histogram records sampled plugin measurements into buckets.
type Histogram interface {
	Observe(context.Context, float64, ...LabelValue)
}

// Summary records sampled plugin measurements as quantiles.
type Summary interface {
	Observe(context.Context, float64, ...LabelValue)
}

// Metrics registers and returns host-owned plugin metric handles.
type Metrics interface {
	Counter(MetricDefinition) (Counter, error)
	Gauge(MetricDefinition) (Gauge, error)
	Histogram(MetricDefinition) (Histogram, error)
	Summary(MetricDefinition) (Summary, error)
}

// TraceAttribute is one low-cardinality tracing attribute.
type TraceAttribute struct {
	Key   string
	Value any
}

// SpanKind describes the relationship between a span and the operation it represents.
type SpanKind uint8

const (
	// SpanKindInternal identifies an in-process operation.
	SpanKindInternal SpanKind = iota
	// SpanKindServer identifies inbound request handling.
	SpanKindServer
	// SpanKindClient identifies an outbound client operation.
	SpanKindClient
	// SpanKindProducer identifies message production.
	SpanKindProducer
	// SpanKindConsumer identifies message consumption.
	SpanKindConsumer
)

// SpanStatus describes the explicit completion state of a span.
type SpanStatus uint8

const (
	// SpanStatusUnset leaves status inference to the tracing backend.
	SpanStatusUnset SpanStatus = iota
	// SpanStatusOK marks a completed operation as successful.
	SpanStatusOK
	// SpanStatusError marks a completed operation as failed.
	SpanStatusError
)

// SpanStartOptions contains value-only options for a plugin-owned span.
type SpanStartOptions struct {
	Attributes []TraceAttribute
	Kind       SpanKind
}

// Span records plugin-created tracing details through a host-owned tracer.
type Span interface {
	AddEvent(string, ...TraceAttribute)
	SetAttributes(...TraceAttribute)
	RecordError(error)
	SetStatus(SpanStatus, string)
	End()
}

// Tracer starts child spans from plugin call contexts.
type Tracer interface {
	Start(context.Context, string, ...TraceAttribute) (context.Context, Span)
	StartWithOptions(context.Context, string, SpanStartOptions) (context.Context, Span)
}
