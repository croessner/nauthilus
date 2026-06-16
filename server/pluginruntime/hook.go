package pluginruntime

import (
	"net"
	"net/http"
	"slices"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/pluginregistry"
)

// HookRequestMetadata contains host-owned caller metadata for HTTP hooks.
type HookRequestMetadata struct {
	Session           string
	ExternalSessionID string
	Service           string
	Protocol          string
	Username          string
	Account           string
	ClientIP          string
	ClientPort        string
	ClientHost        string
	OIDCCID           string
	SAMLEntityID      string
	Authenticated     bool
	LocalRequest      bool
}

// Hooks returns registered native hook components in registration order.
func (r *Runner) Hooks() []pluginregistry.Component {
	if r == nil || r.registry == nil {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.registry.Hooks()
}

// NewHookRequestFromHTTPRequest builds the API-level hook request from an HTTP request.
func NewHookRequestFromHTTPRequest(
	request *http.Request,
	body []byte,
	metadata HookRequestMetadata,
	options ...SnapshotOption,
) pluginapi.HookRequest {
	opts := newSnapshotOptions(options...)
	headers := redactedHeaders(headersFromHTTPRequest(request), opts.secretHeaders)
	query := queryFromHTTPRequest(request)
	method, path, userAgent, remoteHost, remotePort := requestFields(request)

	if metadata.ClientIP == "" {
		metadata.ClientIP = remoteHost
	}

	if metadata.ClientPort == "" {
		metadata.ClientPort = remotePort
	}

	if metadata.ClientHost == "" && request != nil {
		metadata.ClientHost = request.Host
	}

	snapshotHeaders := cloneHeaderValues(headers)

	return pluginapi.HookRequest{
		Snapshot: pluginapi.RequestSnapshot{
			Headers:           snapshotHeaders,
			Session:           metadata.Session,
			ExternalSessionID: metadata.ExternalSessionID,
			Service:           metadata.Service,
			Protocol:          metadata.Protocol,
			Method:            method,
			Username:          metadata.Username,
			Account:           metadata.Account,
			ClientIP:          metadata.ClientIP,
			ClientPort:        metadata.ClientPort,
			ClientHost:        metadata.ClientHost,
			UserAgent:         userAgent,
			OIDCCID:           metadata.OIDCCID,
			SAMLEntityID:      metadata.SAMLEntityID,
			Runtime: pluginapi.RuntimeFlags{
				LocalRequest:  metadata.LocalRequest,
				Authenticated: metadata.Authenticated,
			},
		},
		Headers: cloneHeaderValues(headers),
		Query:   query,
		Body:    slices.Clone(body),
		Path:    path,
		Method:  method,
	}
}

// headersFromHTTPRequest returns request headers or an empty header map.
func headersFromHTTPRequest(request *http.Request) http.Header {
	if request == nil {
		return http.Header{}
	}

	return request.Header
}

// queryFromHTTPRequest copies parsed query values.
func queryFromHTTPRequest(request *http.Request) map[string][]string {
	if request == nil || request.URL == nil {
		return map[string][]string{}
	}

	return cloneHeaderValues(map[string][]string(request.URL.Query()))
}

// requestFields extracts immutable request metadata from net/http.
func requestFields(request *http.Request) (method string, path string, userAgent string, remoteHost string, remotePort string) {
	if request == nil {
		return "", "", "", "", ""
	}

	if request.URL != nil {
		path = request.URL.Path
	}

	remoteHost, remotePort = splitRemoteAddr(request.RemoteAddr)

	return request.Method, path, request.UserAgent(), remoteHost, remotePort
}

// splitRemoteAddr returns host and port when the request remote address is parseable.
func splitRemoteAddr(remoteAddr string) (string, string) {
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr, ""
	}

	return host, port
}

// cloneHeaderValues copies header or query maps so plugins cannot mutate host state.
func cloneHeaderValues(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return map[string][]string{}
	}

	cloned := make(map[string][]string, len(values))
	for key, value := range values {
		cloned[key] = slices.Clone(value)
	}

	return cloned
}
