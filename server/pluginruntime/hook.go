package pluginruntime

import (
	"net"
	"net/http"
	"slices"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
)

// HookRequestMetadata contains host-owned caller metadata for HTTP hooks.
type HookRequestMetadata struct {
	Session                  string
	ExternalSessionID        string
	Service                  string
	Protocol                 string
	Username                 string
	Account                  string
	AccountField             string
	UniqueUserID             string
	DisplayName              string
	ClientIP                 string
	ClientPort               string
	ClientNet                string
	ClientHost               string
	ClientID                 string
	LocalIP                  string
	LocalPort                string
	OIDCCID                  string
	SAMLEntityID             string
	IDP                      pluginapi.IDPInfo
	BruteForceName           string
	EnvironmentName          string
	StatusMessage            string
	BruteForceCounter        uint
	HTTPStatus               int
	AuthLoginAttempt         uint
	Authenticated            bool
	UserFound                bool
	Authorized               bool
	LocalRequest             bool
	NoAuth                   bool
	Debug                    bool
	Repeating                bool
	RWP                      bool
	EnvironmentRejected      bool
	EnvironmentStageExpected bool
	SubjectStageExpected     bool
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
	metadata = hookMetadataWithRequestDefaults(metadata, request, remoteHost, remotePort)

	return pluginapi.HookRequest{
		Snapshot: hookRequestSnapshot(method, userAgent, cloneStringSliceMap(headers), metadata),
		Headers:  cloneStringSliceMap(headers),
		Query:    query,
		Body:     slices.Clone(body),
		Path:     path,
		Method:   method,
	}
}

// hookMetadataWithRequestDefaults fills metadata from the HTTP request when absent.
func hookMetadataWithRequestDefaults(
	metadata HookRequestMetadata,
	request *http.Request,
	remoteHost string,
	remotePort string,
) HookRequestMetadata {
	if metadata.ClientIP == "" {
		metadata.ClientIP = remoteHost
	}

	if metadata.ClientPort == "" {
		metadata.ClientPort = remotePort
	}

	if metadata.ClientHost == "" && request != nil {
		metadata.ClientHost = request.Host
	}

	return metadata
}

// hookRequestSnapshot builds the immutable API-level hook request snapshot.
func hookRequestSnapshot(
	method string,
	userAgent string,
	headers map[string][]string,
	metadata HookRequestMetadata,
) pluginapi.RequestSnapshot {
	return pluginapi.RequestSnapshot{
		Headers:           headers,
		Session:           metadata.Session,
		ExternalSessionID: metadata.ExternalSessionID,
		Service:           metadata.Service,
		Protocol:          metadata.Protocol,
		Method:            method,
		Username:          metadata.Username,
		Account:           metadata.Account,
		AccountField:      metadata.AccountField,
		UniqueUserID:      metadata.UniqueUserID,
		DisplayName:       metadata.DisplayName,
		ClientIP:          metadata.ClientIP,
		ClientPort:        metadata.ClientPort,
		ClientNet:         metadata.ClientNet,
		ClientHost:        metadata.ClientHost,
		ClientID:          metadata.ClientID,
		UserAgent:         userAgent,
		LocalIP:           metadata.LocalIP,
		LocalPort:         metadata.LocalPort,
		OIDCCID:           metadata.OIDCCID,
		SAMLEntityID:      metadata.SAMLEntityID,
		AuthLoginAttempt:  metadata.AuthLoginAttempt,
		IDP:               idPInfoFromHookMetadata(metadata),
		Diagnostics:       hookRequestDiagnostics(metadata),
		Runtime:           hookRuntimeFlags(metadata),
	}
}

// hookRequestDiagnostics maps hook metadata to public request diagnostics.
func hookRequestDiagnostics(metadata HookRequestMetadata) pluginapi.RequestDiagnostics {
	return pluginapi.RequestDiagnostics{
		StatusMessage:     metadata.StatusMessage,
		BruteForceName:    metadata.BruteForceName,
		EnvironmentName:   metadata.EnvironmentName,
		BruteForceCounter: metadata.BruteForceCounter,
		HTTPStatus:        metadata.HTTPStatus,
	}
}

// hookRuntimeFlags maps hook metadata to public runtime flags.
func hookRuntimeFlags(metadata HookRequestMetadata) pluginapi.RuntimeFlags {
	return pluginapi.RuntimeFlags{
		Debug:                    metadata.Debug,
		LocalRequest:             metadata.LocalRequest || metadata.NoAuth,
		NoAuth:                   metadata.NoAuth || metadata.LocalRequest,
		UserFound:                metadata.UserFound,
		Authenticated:            metadata.Authenticated,
		Authorized:               metadata.Authorized,
		Repeating:                metadata.Repeating,
		RWP:                      metadata.RWP,
		EnvironmentRejected:      metadata.EnvironmentRejected,
		EnvironmentStageExpected: metadata.EnvironmentStageExpected,
		SubjectStageExpected:     metadata.SubjectStageExpected,
	}
}

// idPInfoFromHookMetadata clones IDP metadata for immutable hook snapshots.
func idPInfoFromHookMetadata(metadata HookRequestMetadata) pluginapi.IDPInfo {
	info := metadata.IDP
	info.RequestedScopes = cloneStrings(metadata.IDP.RequestedScopes)
	info.UserGroups = cloneStrings(metadata.IDP.UserGroups)
	info.AllowedClientScopes = cloneStrings(metadata.IDP.AllowedClientScopes)
	info.AllowedClientGrantTypes = cloneStrings(metadata.IDP.AllowedClientGrantTypes)

	if info.ClientID == "" {
		info.ClientID = metadata.OIDCCID
	}

	return info
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

	return cloneStringSliceMap(map[string][]string(request.URL.Query()))
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
