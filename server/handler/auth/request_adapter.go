// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package auth

import (
	"bytes"
	"encoding/base64"
	stdjson "encoding/json"
	stderrors "errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/encoding/cborcodec"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/model/authdto"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/util"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

const (
	httpAuthListener          = "http"
	httpAuthModeLookup        = "no-auth"
	httpAuthUnsupportedMedia  = "Unsupported media type"
	httpAuthPasswordFieldName = "Password"
)

type httpAuthInputBuilder struct {
	deps *handlerdeps.Deps
}

// newHTTPAuthInputBuilder constructs the shared value adapter for HTTP auth surfaces.
func newHTTPAuthInputBuilder(deps *handlerdeps.Deps) *httpAuthInputBuilder {
	return &httpAuthInputBuilder{deps: deps}
}

// Build converts one Gin request into transport-neutral authentication input.
func (b *httpAuthInputBuilder) Build(ctx *gin.Context) (core.AuthInput, bool) {
	if b == nil || b.deps == nil || ctx == nil || ctx.Request == nil {
		if ctx != nil {
			ctx.AbortWithStatus(http.StatusInternalServerError)
		}

		return core.AuthInput{}, false
	}

	service := ctx.GetString(definitions.CtxServiceKey)
	mode := authModeFromQuery(ctx.Query("mode"))

	input, structured, ok := b.surfaceInput(ctx, service, mode)
	if !ok {
		return core.AuthInput{}, false
	}

	input.Context = mergeHTTPAuthContext(b.baseContext(ctx), input.Context)
	input.CorrelationID = ctx.GetString(definitions.CtxGUIDKey)
	input.Mode = mode
	input.Service = service
	input.EntryPoint = core.AuthnEntryBackchannel
	input.DisableMemoryCache = ctx.Query("in-memory") == "0"
	input.DisableCache = ctx.Query("cache") == "0"

	if !validateHTTPAuthInput(ctx, input, structured) {
		return core.AuthInput{}, false
	}

	return input, true
}

// surfaceInput decodes only the credential and caller-supplied fields owned by one response surface.
func (b *httpAuthInputBuilder) surfaceInput(
	ctx *gin.Context,
	service string,
	mode core.AuthMode,
) (core.AuthInput, bool, bool) {
	switch service {
	case definitions.ServBasic:
		input, ok := b.basicInput(ctx, service, mode)

		return input, false, ok
	case definitions.ServHeader, definitions.ServNginx:
		input, ok := b.headerInput(ctx, service, mode)

		return input, false, ok
	case definitions.ServJSON, definitions.ServCBOR:
		input, structured, ok := b.bodyInput(ctx, service, mode)

		return input, structured, ok
	default:
		ctx.AbortWithStatus(http.StatusBadRequest)

		return core.AuthInput{}, false, false
	}
}

// basicInput decodes the optional Basic presentation once and removes it before metadata capture.
func (b *httpAuthInputBuilder) basicInput(
	ctx *gin.Context,
	service string,
	mode core.AuthMode,
) (core.AuthInput, bool) {
	header := strings.TrimSpace(ctx.GetHeader("Authorization"))
	scheme, encoded, found := strings.Cut(header, " ")

	ctx.Request.Header.Del("Authorization")

	if !found || !strings.EqualFold(strings.TrimSpace(scheme), "basic") {
		ctx.Header("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		ctx.AbortWithStatus(http.StatusUnauthorized)

		return core.AuthInput{}, false
	}

	presentation, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return core.AuthInput{}, false
	}
	defer clear(presentation)

	separator := bytes.IndexByte(presentation, ':')
	if separator < 0 {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return core.AuthInput{}, false
	}

	return core.AuthInput{
		Credentials: core.NewCredentials(
			core.WithUsername(string(presentation[:separator])),
			core.WithPassword(secret.FromBytes(presentation[separator+1:])),
		),
		Mode:    mode,
		Service: service,
	}, true
}

// bodyInput decodes JSON, CBOR, or form data without retaining the request credential body.
func (b *httpAuthInputBuilder) bodyInput(
	ctx *gin.Context,
	service string,
	mode core.AuthMode,
) (core.AuthInput, bool, bool) {
	if ctx.Request.Method != http.MethodPost {
		return core.AuthInput{Mode: mode, Service: service}, false, true
	}

	contentType := ctx.GetHeader("Content-Type")
	switch {
	case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"):
		return b.formInput(ctx, service, mode), false, true
	case strings.HasPrefix(contentType, "application/json"):
		input, ok := b.structuredInput(ctx, service, mode, decodeStrictHTTPAuthJSON)

		return input, true, ok
	case strings.HasPrefix(contentType, "application/cbor"):
		input, ok := b.structuredInput(ctx, service, mode, decodeHTTPAuthCBOR)

		return input, true, ok
	default:
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": httpAuthUnsupportedMedia})

		return core.AuthInput{}, false, false
	}
}

type httpAuthStructuredDecoder func(*gin.Context, *authdto.Request) error

// structuredInput maps one structured DTO and clears the consumed request body.
func (b *httpAuthInputBuilder) structuredInput(
	ctx *gin.Context,
	service string,
	mode core.AuthMode,
	decode httpAuthStructuredDecoder,
) (core.AuthInput, bool) {
	var request authdto.Request
	if err := decode(ctx, &request); err != nil {
		core.HandleJSONError(ctx, err)

		return core.AuthInput{}, false
	}

	input := core.NewAuthInputFromStructuredRequest(service, mode, request)
	request.Password = ""
	ctx.Request.Body = http.NoBody
	ctx.Request.ContentLength = 0

	return input, true
}

// formInput maps the established urlencoded auth fields and removes password form values.
func (b *httpAuthInputBuilder) formInput(ctx *gin.Context, service string, mode core.AuthMode) core.AuthInput {
	username := ctx.PostForm("username")
	if realm := ctx.PostForm("realm"); realm != "" {
		username += "@" + realm
	}

	request := authdto.Request{
		Username:     username,
		Password:     ctx.PostForm("password"),
		Method:       ctx.PostForm("method"),
		UserAgent:    ctx.PostForm("user_agent"),
		LocalIP:      definitions.Localhost4,
		LocalPort:    ctx.PostForm("port"),
		Protocol:     ctx.PostForm("protocol"),
		XSSL:         ctx.PostForm("tls"),
		XSSLProtocol: ctx.PostForm("security"),
	}
	input := core.NewAuthInputFromStructuredRequest(service, mode, request)
	request.Password = ""

	if ctx.Request.PostForm != nil {
		ctx.Request.PostForm.Del("password")
	}

	if ctx.Request.Form != nil {
		ctx.Request.Form.Del("password")
	}

	return input
}

// headerInput maps configured header names, including legacy URL-safe base64 credentials.
func (b *httpAuthInputBuilder) headerInput(
	ctx *gin.Context,
	service string,
	mode core.AuthMode,
) (core.AuthInput, bool) {
	cfg := b.deps.Auth().Cfg
	if cfg == nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return core.AuthInput{}, false
	}

	username := decodedHTTPAuthHeader(ctx, cfg.GetUsername())
	passwordValue := decodedHTTPAuthHeader(ctx, cfg.GetPassword())
	encoded := decodedHTTPAuthHeader(ctx, cfg.GetPasswordEncoded())
	ctx.Request.Header.Del(cfg.GetPassword())
	ctx.Request.Header.Del(cfg.GetPasswordEncoded())

	passwordBytes := []byte(passwordValue)
	if encoded == "1" {
		padding := len(passwordValue) % 4
		if padding > 0 {
			passwordValue += string(bytes.Repeat([]byte("="), 4-padding))
		}

		decodedPassword, err := base64.URLEncoding.DecodeString(passwordValue)
		if err != nil {
			clear(passwordBytes)
			ctx.AbortWithStatus(http.StatusBadRequest)

			return core.AuthInput{}, false
		}

		clear(passwordBytes)
		passwordBytes = decodedPassword
	}

	credentials := core.NewCredentials(
		core.WithUsername(username),
		core.WithPassword(secret.FromBytes(passwordBytes)),
	)
	clear(passwordBytes)

	loginAttempt := uint(0)

	parsedLoginAttempt, parseErr := strconv.ParseInt(decodedHTTPAuthHeader(ctx, cfg.GetLoginAttempt()), 10, 32)
	if parseErr == nil && parsedLoginAttempt > 0 {
		loginAttempt = uint(parsedLoginAttempt)
	}

	return core.AuthInput{
		Credentials: credentials,
		Context: core.NewAuthContext(
			core.WithProtocol(decodedHTTPAuthHeader(ctx, cfg.GetProtocol())),
			core.WithMethod(decodedHTTPAuthHeader(ctx, cfg.GetAuthMethod())),
		),
		Mode:             mode,
		Service:          service,
		AuthLoginAttempt: loginAttempt,
	}, true
}

// baseContext collects common request and server-observed transport facts once.
func (b *httpAuthInputBuilder) baseContext(ctx *gin.Context) core.AuthContext {
	deps := b.deps.Auth()

	cfg := deps.Cfg
	if cfg == nil {
		return core.AuthContext{}
	}

	clientIP, clientPort := resolvedHTTPAuthClientEndpoint(ctx, deps)

	headers := cfg.GetServer().GetDefaultHTTPRequestHeader()

	transport := core.AuthTransportContext{
		Kind:         "http",
		Listener:     httpAuthListener,
		HTTPMethod:   ctx.Request.Method,
		HTTPRoute:    resolvedHTTPAuthRoute(ctx),
		Peer:         directHTTPAuthPeer(ctx.Request.RemoteAddr),
		MTLSIdentity: verifiedHTTPAuthMTLSIdentity(ctx.Request),
		Protected:    b.protected(ctx),
	}

	return core.NewAuthContext(
		core.WithUserAgent(ctx.Request.UserAgent()),
		core.WithClientIP(clientIP),
		core.WithClientPort(clientPort),
		core.WithClientHostname(decodedHTTPAuthHeader(ctx, cfg.GetClientHost())),
		core.WithClientID(decodedHTTPAuthHeader(ctx, cfg.GetClientID())),
		core.WithExternalSessionID(decodedHTTPAuthHeader(ctx, cfg.GetExternalSessionID())),
		core.WithLocalIP(decodedHTTPAuthHeader(ctx, cfg.GetLocalIP())),
		core.WithLocalPort(decodedHTTPAuthHeader(ctx, cfg.GetLocalPort())),
		core.WithXSSL(decodedHTTPAuthHeader(ctx, headers.GetSSL())),
		core.WithXSSLSessionID(decodedHTTPAuthHeader(ctx, headers.GetSSLSessionID())),
		core.WithXSSLClientVerify(decodedHTTPAuthHeader(ctx, headers.GetSSLVerify())),
		core.WithXSSLClientDN(decodedHTTPAuthHeader(ctx, headers.GetSSLSubject())),
		core.WithXSSLClientCN(decodedHTTPAuthHeader(ctx, headers.GetSSLClientCN())),
		core.WithXSSLIssuer(decodedHTTPAuthHeader(ctx, headers.GetSSLIssuer())),
		core.WithXSSLClientNotBefore(decodedHTTPAuthHeader(ctx, headers.GetSSLClientNotBefore())),
		core.WithXSSLClientNotAfter(decodedHTTPAuthHeader(ctx, headers.GetSSLClientNotAfter())),
		core.WithXSSLSubjectDN(decodedHTTPAuthHeader(ctx, headers.GetSSLSubjectDN())),
		core.WithXSSLIssuerDN(decodedHTTPAuthHeader(ctx, headers.GetSSLIssuerDN())),
		core.WithXSSLClientSubjectDN(decodedHTTPAuthHeader(ctx, headers.GetSSLClientSubjectDN())),
		core.WithXSSLClientIssuerDN(decodedHTTPAuthHeader(ctx, headers.GetSSLClientIssuerDN())),
		core.WithXSSLProtocol(decodedHTTPAuthHeader(ctx, headers.GetSSLProtocol())),
		core.WithXSSLCipher(decodedHTTPAuthHeader(ctx, headers.GetSSLCipher())),
		core.WithSSLSerial(decodedHTTPAuthHeader(ctx, headers.GetSSLSerial())),
		core.WithSSLFingerprint(decodedHTTPAuthHeader(ctx, headers.GetSSLFingerprint())),
		core.WithOIDCCID(decodedHTTPAuthHeader(ctx, cfg.GetOIDCCID())),
		core.WithAuthTransportContext(transport),
		core.WithRequestMetadata(core.SanitizeHTTPMetadata(ctx.Request.Header, cfg.GetPassword(), cfg.GetPasswordEncoded())),
	)
}

// resolvedHTTPAuthClientEndpoint accepts forwarded endpoint facts only from trusted peers.
func resolvedHTTPAuthClientEndpoint(ctx *gin.Context, deps core.AuthDeps) (string, string) {
	clientIP := ""
	clientPort := ""

	if util.DirectPeerIsTrustedProxy(ctx, deps.Cfg, deps.Logger) {
		clientIP = decodedHTTPAuthHeader(ctx, deps.Cfg.GetClientIP())
		clientPort = decodedHTTPAuthHeader(ctx, deps.Cfg.GetClientPort())
	}

	if clientIP == "" {
		clientIP = util.RequestClientIPWithConfig(ctx, deps.Cfg, deps.Logger)
	}

	return clientIP, clientPort
}

// protected resolves trusted proxy-aware transport evidence with direct TLS as a safe fallback.
func (b *httpAuthInputBuilder) protected(ctx *gin.Context) bool {
	if b.deps.PolicyTransport != nil {
		return b.deps.PolicyTransport.Protected(ctx)
	}

	return ctx.Request.TLS != nil
}

// authModeFromQuery maps the established HTTP query spelling to one application operation.
func authModeFromQuery(value string) core.AuthMode {
	switch value {
	case httpAuthModeLookup:
		return core.AuthModeLookupIdentity
	case string(core.AuthModeListAccounts):
		return core.AuthModeListAccounts
	default:
		return core.AuthModeAuthenticate
	}
}

// validateHTTPAuthInput preserves the legacy direct-endpoint credential checks.
func validateHTTPAuthInput(ctx *gin.Context, input core.AuthInput, structured bool) bool {
	if input.Mode == core.AuthModeListAccounts || input.Mode == core.AuthModeLookupIdentity {
		return true
	}

	if input.Credentials.Username == "" || !util.ValidateUsername(input.Credentials.Username) {
		ctx.AbortWithStatus(http.StatusBadRequest)

		return false
	}

	if input.Mode != core.AuthModeAuthenticate || !input.Credentials.Password.IsZero() {
		return true
	}

	if structured {
		core.HandleJSONValidationError(ctx, httpAuthPasswordFieldName, "This field is required")
	} else {
		ctx.AbortWithStatus(http.StatusBadRequest)
	}

	return false
}

// mergeHTTPAuthContext applies non-empty surface fields over common HTTP facts.
func mergeHTTPAuthContext(base core.AuthContext, surface core.AuthContext) core.AuthContext {
	fields := []struct {
		source string
		target *string
	}{
		{surface.Method, &base.Method},
		{surface.UserAgent, &base.UserAgent},
		{surface.ClientIP, &base.ClientIP},
		{surface.ClientPort, &base.ClientPort},
		{surface.ClientHostname, &base.ClientHostname},
		{surface.ClientID, &base.ClientID},
		{surface.ExternalSessionID, &base.ExternalSessionID},
		{surface.LocalIP, &base.LocalIP},
		{surface.LocalPort, &base.LocalPort},
		{surface.Protocol, &base.Protocol},
		{surface.XSSL, &base.XSSL},
		{surface.XSSLSessionID, &base.XSSLSessionID},
		{surface.XSSLClientVerify, &base.XSSLClientVerify},
		{surface.XSSLClientDN, &base.XSSLClientDN},
		{surface.XSSLClientCN, &base.XSSLClientCN},
		{surface.XSSLIssuer, &base.XSSLIssuer},
		{surface.XSSLClientNotBefore, &base.XSSLClientNotBefore},
		{surface.XSSLClientNotAfter, &base.XSSLClientNotAfter},
		{surface.XSSLSubjectDN, &base.XSSLSubjectDN},
		{surface.XSSLIssuerDN, &base.XSSLIssuerDN},
		{surface.XSSLClientSubjectDN, &base.XSSLClientSubjectDN},
		{surface.XSSLClientIssuerDN, &base.XSSLClientIssuerDN},
		{surface.XSSLProtocol, &base.XSSLProtocol},
		{surface.XSSLCipher, &base.XSSLCipher},
		{surface.SSLSerial, &base.SSLSerial},
		{surface.SSLFingerprint, &base.SSLFingerprint},
		{surface.OIDCCID, &base.OIDCCID},
		{surface.SAMLEntityID, &base.SAMLEntityID},
	}

	for _, field := range fields {
		if field.source != "" {
			*field.target = field.source
		}
	}

	return base
}

// decodeStrictHTTPAuthJSON accepts exactly one JSON value and validates binding tags.
func decodeStrictHTTPAuthJSON(ctx *gin.Context, request *authdto.Request) error {
	decoder := stdjson.NewDecoder(ctx.Request.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(request); err != nil {
		return err
	}

	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return stderrors.New("request body must contain a single JSON value")
		}

		return err
	}

	if binding.Validator == nil {
		return nil
	}

	return binding.Validator.ValidateStruct(request)
}

// decodeHTTPAuthCBOR decodes the established structured CBOR request.
func decodeHTTPAuthCBOR(ctx *gin.Context, request *authdto.Request) error {
	return cborcodec.DecodeReader(ctx.Request.Body, request)
}

// decodedHTTPAuthHeader reads one configured header with legacy partial URL decoding.
func decodedHTTPAuthHeader(ctx *gin.Context, name string) string {
	if ctx == nil || name == "" {
		return ""
	}

	return util.URLPartialDecode(ctx.GetHeader(name))
}

// resolvedHTTPAuthRoute returns the registered route without trusting the request URL as authority.
func resolvedHTTPAuthRoute(ctx *gin.Context) string {
	if route := ctx.FullPath(); route != "" {
		return route
	}

	if ctx.Request != nil && ctx.Request.URL != nil {
		return ctx.Request.URL.Path
	}

	return ""
}

// directHTTPAuthPeer extracts the immediate transport peer without forwarded-header interpretation.
func directHTTPAuthPeer(remoteAddress string) string {
	peer, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddress))
	if err == nil {
		return peer
	}

	return strings.TrimSpace(remoteAddress)
}

// verifiedHTTPAuthMTLSIdentity returns a URI SAN or subject only from a verified client chain.
func verifiedHTTPAuthMTLSIdentity(request *http.Request) string {
	if request == nil || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return ""
	}

	certificate := request.TLS.VerifiedChains[0][0]
	if len(certificate.URIs) > 0 && certificate.URIs[0] != nil {
		return certificate.URIs[0].String()
	}

	return strings.TrimSpace(certificate.Subject.String())
}
