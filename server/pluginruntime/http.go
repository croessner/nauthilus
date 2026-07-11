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

package pluginruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

const (
	defaultPluginHTTPTimeout          = 10 * time.Second
	defaultPluginHTTPMaxResponseBytes = int64(1 << 20)
	maxPluginHTTPRedirects            = 10
	maxHTTPMetricMethodLength         = 32
	httpLabelService                  = "service"
	httpLabelMethod                   = "method"
	httpLabelResult                   = "result"
	httpPeerService                   = "http"
	httpSchemeHTTP                    = "http"
	httpSchemeHTTPS                   = "https"
	httpResultUnknown                 = "unknown"
	httpResultBodyTooLarge            = "body_too_large"
	httpLogFieldDurationMS            = "duration_ms"
	httpLogMessageFailure             = "plugin HTTP request failed"
)

var forbiddenOutboundHTTPHeaders = map[string]struct{}{
	"Connection":        {},
	"Keep-Alive":        {},
	"Proxy-Connection":  {},
	"Trailer":           {},
	"Transfer-Encoding": {},
	"Upgrade":           {},
}

var _ pluginapi.HTTPClient = (*HTTPFacade)(nil)

// HTTPFacade executes plugin HTTP requests through host-owned instrumentation.
type HTTPFacade struct {
	client                  *http.Client
	tracer                  pluginapi.Tracer
	metrics                 httpMetricHandles
	logger                  pluginapi.Logger
	scope                   string
	defaultTimeout          time.Duration
	defaultMaxResponseBytes int64
}

// HTTPFacadeOption customizes the host-managed HTTP facade.
type HTTPFacadeOption func(*HTTPFacade)

// NewHTTPFacade returns a scoped host HTTP facade.
func NewHTTPFacade(scope string, options ...HTTPFacadeOption) *HTTPFacade {
	facade := &HTTPFacade{
		client:                  &http.Client{},
		tracer:                  NewTracerFacade(scope),
		metrics:                 newHTTPMetricHandles(noopMetrics{}),
		scope:                   scope,
		defaultTimeout:          defaultPluginHTTPTimeout,
		defaultMaxResponseBytes: defaultPluginHTTPMaxResponseBytes,
	}
	for _, option := range options {
		option(facade)
	}

	previousRedirectPolicy := facade.client.CheckRedirect
	facade.client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if err := pluginHTTPRedirectPolicy(request, via); err != nil {
			return err
		}

		if previousRedirectPolicy != nil {
			return previousRedirectPolicy(request, via)
		}

		return nil
	}

	return facade
}

// HTTPFacadeClient configures the HTTP client used by the facade.
func HTTPFacadeClient(client *http.Client) HTTPFacadeOption {
	return func(facade *HTTPFacade) {
		if client != nil {
			clientCopy := *client
			facade.client = &clientCopy
		}
	}
}

// pluginHTTPRedirectPolicy permits only bounded credential-free same-origin HTTPS redirects.
func pluginHTTPRedirectPolicy(request *http.Request, via []*http.Request) error {
	if request == nil || request.URL == nil || len(via) == 0 || via[0] == nil || via[0].URL == nil {
		return fmt.Errorf("%w: invalid redirect target", pluginapi.ErrInvalidHTTPRequest)
	}

	if len(via) >= maxPluginHTTPRedirects {
		return fmt.Errorf("%w: stopped after %d redirects", pluginapi.ErrInvalidHTTPRequest, maxPluginHTTPRedirects)
	}

	target := request.URL
	origin := via[0].URL

	if target.Scheme != httpSchemeHTTPS || target.User != nil {
		return fmt.Errorf("%w: redirects require credential-free HTTPS", pluginapi.ErrInvalidHTTPRequest)
	}

	if !strings.EqualFold(target.Hostname(), origin.Hostname()) || httpURLPort(target) != httpURLPort(origin) || origin.Scheme != httpSchemeHTTPS {
		return fmt.Errorf("%w: redirects must remain on the original HTTPS origin", pluginapi.ErrInvalidHTTPRequest)
	}

	return nil
}

// HTTPFacadeTracer configures the tracer used by the facade.
func HTTPFacadeTracer(tracer pluginapi.Tracer) HTTPFacadeOption {
	return func(facade *HTTPFacade) {
		if tracer != nil {
			facade.tracer = tracer
		}
	}
}

// HTTPFacadeMetrics configures the metrics facade used by the HTTP facade.
func HTTPFacadeMetrics(metrics pluginapi.Metrics) HTTPFacadeOption {
	return func(facade *HTTPFacade) {
		facade.metrics = newHTTPMetricHandles(metrics)
	}
}

// HTTPFacadeLogger configures the logger used by the facade.
func HTTPFacadeLogger(logger pluginapi.Logger) HTTPFacadeOption {
	return func(facade *HTTPFacade) {
		if logger != nil {
			facade.logger = logger
		}
	}
}

// HTTPFacadeDefaultTimeout configures the fallback timeout for requests without an explicit timeout.
func HTTPFacadeDefaultTimeout(timeout time.Duration) HTTPFacadeOption {
	return func(facade *HTTPFacade) {
		if timeout > 0 {
			facade.defaultTimeout = timeout
		}
	}
}

// HTTPFacadeMaxResponseBytes configures the fallback response body limit.
func HTTPFacadeMaxResponseBytes(limit int64) HTTPFacadeOption {
	return func(facade *HTTPFacade) {
		if limit > 0 {
			facade.defaultMaxResponseBytes = limit
		}
	}
}

// Do executes one host-managed outbound HTTP request.
func (f *HTTPFacade) Do(ctx context.Context, request pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	prepared, err := f.prepareRequest(request)
	if err != nil {
		return pluginapi.HTTPResponse{}, err
	}

	callCtx, cancel := context.WithTimeout(ctx, prepared.timeout)
	defer cancel()

	traceCtx, span := f.tracer.Start(callCtx, "plugin.http", prepared.traceAttributes()...)
	defer span.End()

	httpRequest, err := newHTTPRequest(traceCtx, prepared)
	if err != nil {
		span.RecordError(err)

		return pluginapi.HTTPResponse{}, err
	}

	otel.GetTextMapPropagator().Inject(traceCtx, propagation.HeaderCarrier(httpRequest.Header))

	started := time.Now()

	f.metrics.inflight.Add(callCtx, 1, pluginapi.LabelValue{Name: httpLabelService, Value: prepared.service})
	defer f.metrics.inflight.Add(context.Background(), -1, pluginapi.LabelValue{Name: httpLabelService, Value: prepared.service})

	response, err := f.client.Do(httpRequest)
	if err != nil {
		return f.failHTTP(callCtx, span, prepared, httpErrorResult(err), 0, started, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	body, err := readBoundedHTTPBody(response.Body, prepared.maxResponseBytes)
	if err != nil {
		return f.failHTTP(callCtx, span, prepared, httpResultBodyTooLarge, response.StatusCode, started, err)
	}

	return f.completeHTTP(callCtx, span, prepared, response, body, started), nil
}

// failHTTP records failure observability for one host-managed HTTP request.
func (f *HTTPFacade) failHTTP(
	ctx context.Context,
	span pluginapi.Span,
	request preparedHTTPRequest,
	result string,
	status int,
	started time.Time,
	err error,
) (pluginapi.HTTPResponse, error) {
	span.RecordError(err)
	f.observe(ctx, request, result, status, time.Since(started))
	f.logFailure(ctx, request, result, status, time.Since(started))

	return pluginapi.HTTPResponse{}, err
}

// completeHTTP records success observability and builds the plugin response value.
func (f *HTTPFacade) completeHTTP(
	ctx context.Context,
	span pluginapi.Span,
	request preparedHTTPRequest,
	response *http.Response,
	body []byte,
	started time.Time,
) pluginapi.HTTPResponse {
	result := httpStatusResult(response.StatusCode)
	span.SetAttributes(pluginapi.TraceAttribute{Key: "http.status_code", Value: response.StatusCode})
	f.observe(ctx, request, result, response.StatusCode, time.Since(started))
	f.logSuccess(ctx, request, result, response.StatusCode, time.Since(started))

	return pluginapi.HTTPResponse{
		StatusCode: response.StatusCode,
		Headers:    cloneHTTPHeaderMap(response.Header),
		Body:       body,
	}
}

// prepareRequest validates request fields and applies host defaults.
func (f *HTTPFacade) prepareRequest(request pluginapi.HTTPRequest) (preparedHTTPRequest, error) {
	method := normalizedHTTPMethod(request.Method)
	if !validHTTPToken(method) || len(method) > maxHTTPMetricMethodLength {
		return preparedHTTPRequest{}, fmt.Errorf("%w: method %q is not allowed", pluginapi.ErrInvalidHTTPRequest, request.Method)
	}

	parsed, err := parsePluginHTTPURL(request.URL)
	if err != nil {
		return preparedHTTPRequest{}, err
	}

	service := request.Service
	if service == "" {
		service = f.scope
	}

	if err := pluginapi.ValidateComponentName(service); err != nil {
		return preparedHTTPRequest{}, fmt.Errorf("%w: service %q is not a bounded label", pluginapi.ErrInvalidHTTPRequest, service)
	}

	timeout := request.Timeout
	if timeout == 0 {
		timeout = f.defaultTimeout
	}

	if timeout < 0 {
		return preparedHTTPRequest{}, fmt.Errorf("%w: timeout must not be negative", pluginapi.ErrInvalidHTTPRequest)
	}

	maxResponseBytes := request.MaxResponseBytes
	if maxResponseBytes == 0 {
		maxResponseBytes = f.defaultMaxResponseBytes
	}

	if maxResponseBytes < 0 {
		return preparedHTTPRequest{}, fmt.Errorf("%w: response body limit must not be negative", pluginapi.ErrInvalidHTTPRequest)
	}

	headers, err := validateAndCloneHTTPHeaders(request.Headers)
	if err != nil {
		return preparedHTTPRequest{}, err
	}

	return preparedHTTPRequest{
		parsedURL:        parsed,
		headers:          headers,
		body:             bytes.Clone(request.Body),
		method:           method,
		service:          service,
		timeout:          timeout,
		maxResponseBytes: maxResponseBytes,
	}, nil
}

// observe records low-cardinality HTTP metrics.
func (f *HTTPFacade) observe(ctx context.Context, request preparedHTTPRequest, result string, _ int, duration time.Duration) {
	labels := httpResultLabels(request, result)
	f.metrics.requests.Add(ctx, 1, labels...)
	f.metrics.duration.Observe(ctx, duration.Seconds(), labels...)
}

// logSuccess writes a bounded success record without URL, headers, or body data.
func (f *HTTPFacade) logSuccess(ctx context.Context, request preparedHTTPRequest, result string, status int, duration time.Duration) {
	if f.logger == nil {
		return
	}

	f.logger.Debug(ctx, "plugin HTTP request completed", httpLogFields(request, result, status, duration)...)
}

// logFailure writes a bounded failure record without raw transport error text.
func (f *HTTPFacade) logFailure(ctx context.Context, request preparedHTTPRequest, result string, status int, duration time.Duration) {
	if f.logger == nil {
		return
	}

	fields := append(httpLogFields(request, result, status, duration), pluginapi.LogField{Key: pluginLogFieldErrorClass, Value: result})
	f.logger.Error(ctx, httpLogMessageFailure, fields...)
}

type preparedHTTPRequest struct {
	parsedURL        *url.URL
	headers          map[string][]string
	body             []byte
	method           string
	service          string
	timeout          time.Duration
	maxResponseBytes int64
}

// traceAttributes returns bounded HTTP client span attributes.
func (r preparedHTTPRequest) traceAttributes() []pluginapi.TraceAttribute {
	attrs := []pluginapi.TraceAttribute{
		{Key: "peer.service", Value: httpPeerService},
		{Key: "rpc.system", Value: httpPeerService},
		{Key: "http.request.method", Value: r.method},
		{Key: "http.method", Value: r.method},
		{Key: "server.address", Value: r.parsedURL.Hostname()},
		{Key: "server.port", Value: httpURLPort(r.parsedURL)},
		{Key: "plugin.http.service", Value: r.service},
	}

	return attrs
}

type httpMetricHandles struct {
	requests pluginapi.Counter
	duration pluginapi.Histogram
	inflight pluginapi.Gauge
}

// newHTTPMetricHandles creates host HTTP metrics or no-op handles when registration fails.
func newHTTPMetricHandles(metrics pluginapi.Metrics) httpMetricHandles {
	handles := httpMetricHandles{
		requests: noopCounter{},
		duration: noopHistogram{},
		inflight: noopGauge{},
	}
	if metrics == nil {
		return handles
	}

	if counter, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   "host_http_client_requests_total",
		Help:   "Total host-managed plugin HTTP client requests",
		Labels: []string{httpLabelService, httpLabelMethod, httpLabelResult},
	}); err == nil {
		handles.requests = counter
	}

	if histogram, err := metrics.Histogram(pluginapi.MetricDefinition{
		Name:   "host_http_client_duration_seconds",
		Help:   "Duration of host-managed plugin HTTP client requests",
		Labels: []string{httpLabelService, httpLabelMethod, httpLabelResult},
	}); err == nil {
		handles.duration = histogram
	}

	if gauge, err := metrics.Gauge(pluginapi.MetricDefinition{
		Name:   "host_http_client_inflight",
		Help:   "Current host-managed plugin HTTP client requests",
		Labels: []string{httpLabelService},
	}); err == nil {
		handles.inflight = gauge
	}

	return handles
}

// newHTTPRequest converts the value-oriented API request into net/http for the internal transport.
func newHTTPRequest(ctx context.Context, request preparedHTTPRequest) (*http.Request, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, request.method, request.parsedURL.String(), bytes.NewReader(request.body))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", pluginapi.ErrInvalidHTTPRequest, err)
	}

	for name, values := range request.headers {
		for _, value := range values {
			httpRequest.Header.Add(name, value)
		}
	}

	return httpRequest, nil
}

// parsePluginHTTPURL validates absolute HTTP URLs without retaining secret-bearing query data in logs.
func parsePluginHTTPURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed URL", pluginapi.ErrInvalidHTTPRequest)
	}

	if parsed.Scheme != httpSchemeHTTP && parsed.Scheme != httpSchemeHTTPS {
		return nil, fmt.Errorf("%w: URL scheme must be http or https", pluginapi.ErrInvalidHTTPRequest)
	}

	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("%w: URL host is empty", pluginapi.ErrInvalidHTTPRequest)
	}

	return parsed, nil
}

// validateAndCloneHTTPHeaders copies caller headers after rejecting unsafe field names and hop-by-hop controls.
func validateAndCloneHTTPHeaders(headers map[string][]string) (map[string][]string, error) {
	if len(headers) == 0 {
		return nil, nil
	}

	cloned := make(map[string][]string, len(headers))
	for name, values := range headers {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical == "" || !validHTTPToken(canonical) {
			return nil, fmt.Errorf("%w: invalid header name", pluginapi.ErrInvalidHTTPRequest)
		}

		if _, forbidden := forbiddenOutboundHTTPHeaders[canonical]; forbidden {
			return nil, fmt.Errorf("%w: forbidden hop-by-hop header %q", pluginapi.ErrInvalidHTTPRequest, canonical)
		}

		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return nil, fmt.Errorf("%w: invalid header value for %q", pluginapi.ErrInvalidHTTPRequest, canonical)
			}

			cloned[canonical] = append(cloned[canonical], value)
		}
	}

	return cloned, nil
}

// normalizedHTTPMethod returns the default GET method or a normalized caller method.
func normalizedHTTPMethod(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return http.MethodGet
	}

	return method
}

// validHTTPToken validates HTTP method and header tokens.
func validHTTPToken(value string) bool {
	if value == "" {
		return false
	}

	for _, char := range value {
		if char > 127 || !isHTTPTokenChar(byte(char)) {
			return false
		}
	}

	return true
}

// isHTTPTokenChar reports whether char is allowed in an HTTP token.
func isHTTPTokenChar(char byte) bool {
	switch {
	case char >= 'a' && char <= 'z':
		return true
	case char >= 'A' && char <= 'Z':
		return true
	case char >= '0' && char <= '9':
		return true
	}

	switch char {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

// readBoundedHTTPBody reads the response body and fails closed when the limit is exceeded.
func readBoundedHTTPBody(body io.Reader, limit int64) ([]byte, error) {
	if body == nil {
		return nil, nil
	}

	limited, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}

	if int64(len(limited)) > limit {
		return nil, pluginapi.ErrHTTPResponseTooLarge
	}

	return limited, nil
}

// cloneHTTPHeaderMap copies response headers into API-level values.
func cloneHTTPHeaderMap(headers http.Header) map[string][]string {
	if len(headers) == 0 {
		return nil
	}

	cloned := make(map[string][]string, len(headers))
	for name, values := range headers {
		if _, forbidden := forbiddenOutboundHTTPHeaders[http.CanonicalHeaderKey(name)]; forbidden {
			continue
		}

		cloned[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
	}

	return cloned
}

// httpStatusResult maps status codes to bounded metric and log labels.
func httpStatusResult(status int) string {
	if status <= 0 {
		return httpResultUnknown
	}

	return fmt.Sprintf("%dxx", status/100)
}

// httpErrorResult maps transport errors to bounded labels.
func httpErrorResult(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "error"
	}
}

// httpResultLabels returns metric labels in declaration order.
func httpResultLabels(request preparedHTTPRequest, result string) []pluginapi.LabelValue {
	return []pluginapi.LabelValue{
		{Name: httpLabelService, Value: request.service},
		{Name: httpLabelMethod, Value: request.method},
		{Name: httpLabelResult, Value: result},
	}
}

// httpLogFields returns bounded log fields for one HTTP facade call.
func httpLogFields(request preparedHTTPRequest, result string, status int, duration time.Duration) []pluginapi.LogField {
	fields := []pluginapi.LogField{
		{Key: "http_service", Value: request.service},
		{Key: "http_method", Value: request.method},
		{Key: "http_result", Value: result},
		{Key: httpLogFieldDurationMS, Value: durationMilliseconds(duration)},
	}
	if status > 0 {
		fields = append(fields, pluginapi.LogField{Key: "http_status", Value: status})
	}

	return fields
}

// httpURLPort returns an explicit or default port for trace attributes.
func httpURLPort(parsed *url.URL) int {
	if parsed == nil {
		return 0
	}

	if port := parsed.Port(); port != "" {
		if value, err := strconv.Atoi(port); err == nil {
			return value
		}
	}

	if parsed.Scheme == httpSchemeHTTPS {
		return 443
	}

	return 80
}
