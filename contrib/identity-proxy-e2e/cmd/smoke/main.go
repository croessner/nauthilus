// Copyright (C) 2026 Christian Rößner
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

// Package main runs the split identity proxy E2E smoke checks.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	authv1 "github.com/croessner/nauthilus/v3/server/grpcapi/auth/v1"
	commonv1 "github.com/croessner/nauthilus/v3/server/grpcapi/common/v1"
	identityv1 "github.com/croessner/nauthilus/v3/server/grpcapi/identity/v1"
	"github.com/croessner/nauthilus/v3/server/idp/clientauth"
	"github.com/croessner/nauthilus/v3/server/idp/signing"
	openapiclient "github.com/croessner/nauthilus/v3/server/openapi/client"
	management "github.com/croessner/nauthilus/v3/server/openapi/generated/management"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	modePreBrowser  = "pre-browser"
	modePostBrowser = "post-browser"

	smokeClientIP       = "192.0.2.10"
	smokeClientPort     = "54321"
	smokeClientHostname = "client.example.test"
	smokeClientID       = "split-e2e-smoke"
	smokeUserAgent      = "nauthilus-identity-proxy-e2e/1.0"
	smokeLocalIP        = "127.0.0.1"
	smokeLocalPort      = "19444"
	smokeProtocol       = "imap"
	smokeMethod         = "plain"

	openAPIManagementScenario     = "openapi-management-cache-flush-async-status"
	openAPIManagementUserSuffix   = ".openapi-management"
	openAPIManagementPollInterval = 100 * time.Millisecond
	openAPIManagementPollTimeout  = 10 * time.Second
)

var allAuthorityScopes = []string{
	definitions.ScopeAuthenticate,
	definitions.ScopeSecurity,
	definitions.ScopeLookupIdentity,
	definitions.ScopeListAccounts,
	definitions.ScopeMFARead,
	definitions.ScopeMFAVerify,
	definitions.ScopeMFAWrite,
	definitions.ScopeWebAuthnRead,
	definitions.ScopeWebAuthnWrite,
	definitions.ScopeAttributeRead,
}

type options struct {
	mode                   string
	authorityTokenURL      string
	authorityTokenAudience string
	authorityManagementURL string
	authorityGRPC          string
	authorityUnavailable   string
	workDir                string
	clientID               string
	clientKeyID            string
	edgeCluster            string
	edgeInstance           string
	serverName             string
	username               string
	password               string
	webauthnUsername       string
}

type runner struct {
	opts     options
	signer   signing.Signer
	conn     *grpc.ClientConn
	auth     authv1.AuthServiceClient
	identity identityv1.IdentityBackendServiceClient
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func main() {
	opts := parseOptions()
	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseOptions() options {
	var opts options

	flag.StringVar(&opts.mode, "mode", modePreBrowser, "smoke mode: pre-browser or post-browser")
	flag.StringVar(&opts.authorityTokenURL, "authority-token-url", "http://localhost:18081/oidc/token", "authority token endpoint URL reachable from the host")
	flag.StringVar(&opts.authorityTokenAudience, "authority-token-audience", "http://authority:18081/oidc/token", "private_key_jwt audience expected by the authority")
	flag.StringVar(&opts.authorityManagementURL, "authority-management-url", "http://localhost:18081", "authority management API base URL reachable from the host")
	flag.StringVar(&opts.authorityGRPC, "authority-grpc", "localhost:19444", "authority gRPC endpoint reachable from the host")
	flag.StringVar(&opts.authorityUnavailable, "authority-unavailable", "localhost:19445", "unused endpoint for unavailable-authority negative check")
	flag.StringVar(&opts.workDir, "work-dir", "contrib/identity-proxy-e2e/.work", "generated E2E material directory")
	flag.StringVar(&opts.clientID, "client-id", "nauthilus-edge-e2e", "authority service-principal client id")
	flag.StringVar(&opts.clientKeyID, "client-key-id", "edge-e2e-rs256", "authority service-principal key id")
	flag.StringVar(&opts.edgeCluster, "edge-cluster", "edge-e2e", "edge cluster metadata")
	flag.StringVar(&opts.edgeInstance, "edge-instance", "edge-a", "edge instance metadata")
	flag.StringVar(&opts.serverName, "server-name", "authority", "authority TLS server name")
	flag.StringVar(&opts.username, "username", "split-user@example.test", "smoke username")
	flag.StringVar(&opts.password, "password", "split-password", "smoke password")
	flag.StringVar(&opts.webauthnUsername, "webauthn-username", "split-user@example.test.mfa", "username registered by the browser WebAuthn smoke")
	flag.Parse()

	return opts
}

func run(opts options) error {
	smoke, err := newRunner(opts)
	if err != nil {
		return err
	}
	defer smoke.close()

	switch opts.mode {
	case modePreBrowser:
		return smoke.runPreBrowser(context.Background())
	case modePostBrowser:
		return smoke.runPostBrowser(context.Background())
	default:
		return fmt.Errorf("unknown mode %q", opts.mode)
	}
}

func newRunner(opts options) (*runner, error) {
	signer, err := loadSigner(filepath.Join(opts.workDir, "keys", "edge-authority-client.key"), opts.clientKeyID)
	if err != nil {
		return nil, err
	}

	transport, err := loadTransportCredentials(opts)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(opts.authorityGRPC, grpc.WithTransportCredentials(transport))
	if err != nil {
		return nil, fmt.Errorf("create authority gRPC client: %w", err)
	}

	return &runner{
		opts:     opts,
		signer:   signer,
		conn:     conn,
		auth:     authv1.NewAuthServiceClient(conn),
		identity: identityv1.NewIdentityBackendServiceClient(conn),
	}, nil
}

func loadSigner(path string, keyID string) (signing.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authority caller private key: %w", err)
	}

	signer, err := signing.NewRS256SignerFromPEM(string(raw), keyID)
	if err != nil {
		return nil, fmt.Errorf("load authority caller private key: %w", err)
	}

	return signer, nil
}

func loadTransportCredentials(opts options) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(opts.workDir, "certs", "edge-client.crt"),
		filepath.Join(opts.workDir, "certs", "edge-client.key"),
	)
	if err != nil {
		return nil, fmt.Errorf("load mTLS client certificate: %w", err)
	}

	caPEM, err := os.ReadFile(filepath.Join(opts.workDir, "certs", "e2e-ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read E2E CA certificate: %w", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("parse E2E CA certificate")
	}

	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   opts.serverName,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
	}), nil
}

func (r *runner) close() {
	if r.conn != nil {
		_ = r.conn.Close()
	}
}

func (r *runner) runPreBrowser(parent context.Context) error {
	token, err := r.acquireToken(parent, allAuthorityScopes)
	if err != nil {
		return err
	}

	authResp, lookupResp, err := r.runPreBrowserIdentityChecks(parent, token)
	if err != nil {
		return err
	}

	if err = r.runPreBrowserMFAChecks(parent, token, authResp.GetBackendRef()); err != nil {
		return err
	}

	if err = r.runOpenAPIManagementChecks(parent, token); err != nil {
		return err
	}

	ok(openAPIManagementScenario)

	return r.runPreBrowserNegativeChecks(parent, token, lookupResp.GetBackendRef())
}

func (r *runner) runPreBrowserIdentityChecks(parent context.Context, token string) (*authv1.AuthResponse, *authv1.AuthResponse, error) {
	authResp, err := r.authenticate(parent, token, r.opts.username, r.opts.password)
	if err != nil {
		return nil, nil, err
	}

	ok("grpc-authenticate")

	lookupResp, err := r.lookupIdentity(parent, token, r.opts.username)
	if err != nil {
		return nil, nil, err
	}

	ok("grpc-lookup-identity")

	if err := r.listAccounts(parent, token, r.opts.username); err != nil {
		return nil, nil, err
	}

	ok("grpc-list-accounts")

	if err := r.resolveUser(parent, token, lookupResp.GetBackendRef(), r.opts.username); err != nil {
		return nil, nil, err
	}

	ok("grpc-resolve-user")

	return authResp, lookupResp, nil
}

func (r *runner) runPreBrowserMFAChecks(parent context.Context, token string, authRef *commonv1.BackendRef) error {
	if err := r.recoveryCodes(parent, token, authRef); err != nil {
		return err
	}

	ok("recovery-code-generation-consumption")
	ok("idempotency-replay")

	if err := r.totpRegistration(parent, token); err != nil {
		return err
	}

	ok("grpc-totp-registration")

	return nil
}

func (r *runner) runPreBrowserNegativeChecks(parent context.Context, token string, lookupRef *commonv1.BackendRef) error {
	if err := r.expectMissingCallerAuth(parent); err != nil {
		return err
	}

	ok("missing-caller-auth")

	if err := r.expectMissingScope(parent); err != nil {
		return err
	}

	ok("missing-scope")

	if err := r.expectExpiredBackendRef(parent, token, lookupRef); err != nil {
		return err
	}

	ok("expired-backend-ref")

	if err := r.expectUnavailableAuthority(parent, token); err != nil {
		return err
	}

	ok("authority-unavailable")

	return nil
}

func (r *runner) runPostBrowser(parent context.Context) error {
	token, err := r.acquireToken(parent, allAuthorityScopes)
	if err != nil {
		return err
	}

	authResp, err := r.authenticate(parent, token, r.opts.webauthnUsername, r.opts.password)
	if err != nil {
		return err
	}

	credentials, err := r.webauthnCredentials(parent, token, authResp.GetBackendRef(), r.opts.webauthnUsername)
	if err != nil {
		return err
	}

	if len(credentials) == 0 {
		return errors.New("authority has no WebAuthn credentials for browser smoke user")
	}

	if credentials[0].GetSignCount() == 0 {
		return errors.New("authority WebAuthn sign count did not advance")
	}

	ok("authority-webauthn-sign-count")

	return nil
}

func (r *runner) acquireToken(parent context.Context, scopes []string) (string, error) {
	assertion, err := r.clientAssertion()
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", r.opts.clientID)
	form.Set("client_assertion_type", clientauth.AssertionTypeJWTBearer)
	form.Set("client_assertion", assertion)
	form.Set("scope", strings.Join(scopes, " "))

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.opts.authorityTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}

	request.Header.Set("content-type", "application/x-www-form-urlencoded")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("request authority caller token: %w", err)
	}

	defer func() {
		_ = response.Body.Close()
	}()

	var payload tokenResponse
	if err = json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode authority caller token response: %w", err)
	}

	if response.StatusCode != http.StatusOK || payload.AccessToken == "" {
		return "", fmt.Errorf("authority caller token failed: status=%d error=%s description=%s", response.StatusCode, payload.Error, payload.Description)
	}

	return payload.AccessToken, nil
}

func (r *runner) clientAssertion() (string, error) {
	jti, err := randomHex(16)
	if err != nil {
		return "", err
	}

	now := time.Now()

	return r.signer.Sign(jwt.MapClaims{
		"iss": r.opts.clientID,
		"sub": r.opts.clientID,
		"aud": r.opts.authorityTokenAudience,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": jti,
	})
}

func (r *runner) authenticate(parent context.Context, token string, username string, password string) (*authv1.AuthResponse, error) {
	ctx, cancel := r.rpcContext(parent, token)
	defer cancel()

	response, err := r.auth.Authenticate(ctx, &authv1.AuthRequest{
		Username:          username,
		Password:          password,
		ClientIp:          smokeClientIP,
		ClientPort:        smokeClientPort,
		ClientHostname:    smokeClientHostname,
		ClientId:          smokeClientID,
		ExternalSessionId: "split-e2e-authenticate",
		UserAgent:         smokeUserAgent,
		LocalIp:           smokeLocalIP,
		LocalPort:         smokeLocalPort,
		Protocol:          smokeProtocol,
		Method:            smokeMethod,
		Ssl:               "off",
		AuthLoginAttempt:  1,
	})
	if err != nil {
		return nil, fmt.Errorf("authenticate RPC failed: %w", err)
	}

	if !response.GetOk() || response.GetBackendRef().GetOpaqueToken() == "" {
		return nil, fmt.Errorf("authenticate returned ok=%v backend_ref=%q", response.GetOk(), response.GetBackendRef().GetOpaqueToken())
	}

	return response, nil
}

func (r *runner) lookupIdentity(parent context.Context, token string, username string) (*authv1.AuthResponse, error) {
	ctx, cancel := r.rpcContext(parent, token)
	defer cancel()

	response, err := r.auth.LookupIdentity(ctx, &authv1.LookupIdentityRequest{
		Username:          username,
		ClientIp:          smokeClientIP,
		ClientPort:        smokeClientPort,
		ClientHostname:    smokeClientHostname,
		ClientId:          smokeClientID,
		ExternalSessionId: "split-e2e-lookup",
		UserAgent:         smokeUserAgent,
		LocalIp:           smokeLocalIP,
		LocalPort:         smokeLocalPort,
		Protocol:          smokeProtocol,
		Method:            smokeMethod,
	})
	if err != nil {
		return nil, fmt.Errorf("lookup identity RPC failed: %w", err)
	}

	if !response.GetOk() || response.GetBackendRef().GetOpaqueToken() == "" {
		return nil, fmt.Errorf("lookup identity returned ok=%v backend_ref=%q", response.GetOk(), response.GetBackendRef().GetOpaqueToken())
	}

	return response, nil
}

func (r *runner) listAccounts(parent context.Context, token string, username string) error {
	ctx, cancel := r.rpcContext(parent, token)
	defer cancel()

	response, err := r.auth.ListAccounts(ctx, &authv1.ListAccountsRequest{
		Username:          username,
		ClientIp:          smokeClientIP,
		ClientPort:        smokeClientPort,
		ClientHostname:    smokeClientHostname,
		ClientId:          smokeClientID,
		ExternalSessionId: "split-e2e-list",
		UserAgent:         smokeUserAgent,
		LocalIp:           smokeLocalIP,
		LocalPort:         smokeLocalPort,
		Protocol:          smokeProtocol,
		Method:            smokeMethod,
	})
	if err != nil {
		return fmt.Errorf("list accounts RPC failed: %w", err)
	}

	if !slices.Contains(response.GetAccounts(), username) {
		return fmt.Errorf("list accounts missing %q in %v", username, response.GetAccounts())
	}

	return nil
}

func (r *runner) resolveUser(parent context.Context, token string, ref *commonv1.BackendRef, username string) error {
	ctx, cancel := r.rpcContext(parent, token)
	defer cancel()

	response, err := r.identity.ResolveUser(ctx, &identityv1.ResolveUserRequest{
		Context:    requestContext(username),
		Username:   username,
		Backend:    ref,
		Attributes: &identityv1.AttributeRequest{IncludeStandardIdentity: true},
	})
	if err != nil {
		return fmt.Errorf("resolve user RPC failed: %w", err)
	}

	if response.GetUser().GetUsername() == "" || response.GetUser().GetBackend().GetOpaqueToken() == "" {
		return fmt.Errorf("resolve user returned incomplete user snapshot: %#v", response.GetUser())
	}

	return nil
}

func (r *runner) recoveryCodes(parent context.Context, token string, ref *commonv1.BackendRef) error {
	key := "split-e2e-recovery-" + time.Now().UTC().Format("20060102150405")

	ctx, cancel := r.rpcContext(parent, token)
	defer cancel()

	generated, err := r.identity.GenerateRecoveryCodes(ctx, &identityv1.GenerateRecoveryCodesRequest{
		Context:        requestContext(r.opts.username),
		Username:       r.opts.username,
		Backend:        ref,
		Count:          3,
		IdempotencyKey: key,
	})
	if err != nil {
		return fmt.Errorf("generate recovery codes RPC failed: %w", err)
	}

	if len(generated.GetCodes()) != 3 {
		return fmt.Errorf("generate recovery codes returned %d codes, want 3", len(generated.GetCodes()))
	}

	if err = r.expectRecoveryReplay(parent, token, ref, key); err != nil {
		return err
	}

	return r.useRecoveryCode(parent, token, ref, generated.GetCodes()[0])
}

func (r *runner) expectRecoveryReplay(parent context.Context, token string, ref *commonv1.BackendRef, key string) error {
	ctx, cancel := r.rpcContext(parent, token)
	defer cancel()

	_, err := r.identity.GenerateRecoveryCodes(ctx, &identityv1.GenerateRecoveryCodesRequest{
		Context:        requestContext(r.opts.username),
		Username:       r.opts.username,
		Backend:        ref,
		Count:          3,
		IdempotencyKey: key,
	})

	return expectCode("idempotency replay", err, codes.AlreadyExists)
}

func (r *runner) useRecoveryCode(parent context.Context, token string, ref *commonv1.BackendRef, code string) error {
	ctx, cancel := r.rpcContext(parent, token)
	defer cancel()

	response, err := r.identity.UseRecoveryCode(ctx, &identityv1.UseRecoveryCodeRequest{
		Context:        requestContext(r.opts.username),
		Username:       r.opts.username,
		Backend:        ref,
		Code:           code,
		IdempotencyKey: "split-e2e-recovery-use-" + time.Now().UTC().Format("20060102150405"),
	})
	if err != nil {
		return fmt.Errorf("use recovery code RPC failed: %w", err)
	}

	if !response.GetValid() || response.GetRemainingRecoveryCodeCount() != 2 {
		return fmt.Errorf("use recovery code valid=%v remaining=%d, want true and 2", response.GetValid(), response.GetRemainingRecoveryCodeCount())
	}

	return nil
}

func (r *runner) totpRegistration(parent context.Context, token string) error {
	username := r.opts.username + ".grpc-totp"

	authResp, err := r.authenticate(parent, token, username, r.opts.password)
	if err != nil {
		return err
	}

	ctx, cancel := r.rpcContext(parent, token)
	defer cancel()

	beginKey := "split-e2e-totp-begin-" + time.Now().UTC().Format("20060102150405")

	begin, err := r.identity.BeginTOTPRegistration(ctx, &identityv1.BeginTOTPRegistrationRequest{
		Context:        requestContext(username),
		Username:       username,
		Backend:        authResp.GetBackendRef(),
		IdempotencyKey: beginKey,
	})
	if err != nil {
		return fmt.Errorf("begin TOTP registration RPC failed: %w", err)
	}

	if begin.GetPendingRegistrationId() == "" || begin.GetTotpSecret() == "" {
		return fmt.Errorf("begin TOTP registration returned pending=%q secret=%q", begin.GetPendingRegistrationId(), begin.GetTotpSecret())
	}

	code, err := totp.GenerateCodeCustom(begin.GetTotpSecret(), time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return fmt.Errorf("generate TOTP code: %w", err)
	}

	_, err = r.identity.FinishTOTPRegistration(ctx, &identityv1.FinishTOTPRegistrationRequest{
		Context:               requestContext(username),
		Username:              username,
		Backend:               authResp.GetBackendRef(),
		PendingRegistrationId: begin.GetPendingRegistrationId(),
		Code:                  code,
		IdempotencyKey:        "split-e2e-totp-finish-" + time.Now().UTC().Format("20060102150405"),
	})
	if err != nil {
		return fmt.Errorf("finish TOTP registration RPC failed: %w", err)
	}

	return nil
}

func (r *runner) webauthnCredentials(parent context.Context, token string, ref *commonv1.BackendRef, username string) ([]*identityv1.WebAuthnCredential, error) {
	ctx, cancel := r.rpcContext(parent, token)
	defer cancel()

	response, err := r.identity.GetWebAuthnCredentials(ctx, &identityv1.GetWebAuthnCredentialsRequest{
		Context:  requestContext(username),
		Username: username,
		Backend:  ref,
	})
	if err != nil {
		return nil, fmt.Errorf("get WebAuthn credentials RPC failed: %w", err)
	}

	return response.GetCredentials(), nil
}

func (r *runner) runOpenAPIManagementChecks(parent context.Context, token string) error {
	username := r.opts.username + openAPIManagementUserSuffix
	if _, err := r.authenticate(parent, token, username, r.opts.password); err != nil {
		return fmt.Errorf("prepare OpenAPI management cache user: %w", err)
	}

	client, err := r.openAPIManagementClient(token)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(parent, openAPIManagementPollTimeout)
	defer cancel()

	response, err := client.EnqueueUserCacheFlush(
		ctx,
		management.EnqueueUserCacheFlushJSONRequestBody{User: username},
	)
	if err != nil {
		return fmt.Errorf("enqueue OpenAPI management cache flush: %w", err)
	}

	if response.StatusCode() != http.StatusAccepted || response.JSON202 == nil {
		return fmt.Errorf("enqueue OpenAPI management cache flush status=%d body=%s", response.StatusCode(), string(response.Body))
	}

	jobID := response.JSON202.Result.JobId
	if jobID == "" {
		return errors.New("enqueue OpenAPI management cache flush returned empty job ID")
	}

	return r.waitOpenAPIManagementJob(ctx, client, jobID)
}

func (r *runner) openAPIManagementClient(token string) (*openapiclient.ManagementClient, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	client, err := openapiclient.NewManagementClient(
		r.opts.authorityManagementURL,
		openapiclient.BearerToken(token),
		management.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("create OpenAPI management client: %w", err)
	}

	return client, nil
}

func (r *runner) waitOpenAPIManagementJob(
	ctx context.Context,
	client *openapiclient.ManagementClient,
	jobID string,
) error {
	ticker := time.NewTicker(openAPIManagementPollInterval)
	defer ticker.Stop()

	for {
		done, err := r.checkOpenAPIManagementJob(ctx, client, jobID)
		if err != nil {
			return err
		}

		if done {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("OpenAPI management async job %q timed out: %w", jobID, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (r *runner) checkOpenAPIManagementJob(
	ctx context.Context,
	client *openapiclient.ManagementClient,
	jobID string,
) (bool, error) {
	response, err := client.GetAsyncJobStatus(ctx, jobID)
	if err != nil {
		return false, fmt.Errorf("get OpenAPI management async job status: %w", err)
	}

	if response.StatusCode() != http.StatusOK || response.JSON200 == nil {
		return false, fmt.Errorf("get OpenAPI management async job status=%d body=%s", response.StatusCode(), string(response.Body))
	}

	payload := response.JSON200.Result
	if payload.JobId == nil || *payload.JobId != jobID {
		return false, fmt.Errorf("OpenAPI management async job ID = %q, want %q", stringValue(payload.JobId), jobID)
	}

	if payload.Status == nil {
		return false, errors.New("OpenAPI management async job returned empty status")
	}

	switch *payload.Status {
	case management.AsyncJobStatusDone:
		return true, nil
	case management.AsyncJobStatusError:
		return false, fmt.Errorf("OpenAPI management async job failed: %s", stringValue(payload.Error))
	case management.AsyncJobStatusQueued, management.AsyncJobStatusInProgress:
		return false, nil
	default:
		return false, fmt.Errorf("OpenAPI management async job returned unknown status %q", *payload.Status)
	}
}

func (r *runner) expectMissingCallerAuth(parent context.Context) error {
	ctx, cancel := r.rpcContext(parent, "")
	defer cancel()

	_, err := r.auth.LookupIdentity(ctx, &authv1.LookupIdentityRequest{
		Username: r.opts.username,
		Protocol: smokeProtocol,
		Method:   smokeMethod,
	})

	return expectCode("missing caller auth", err, codes.Unauthenticated)
}

func (r *runner) expectMissingScope(parent context.Context) error {
	token, err := r.acquireToken(parent, []string{definitions.ScopeAuthenticate})
	if err != nil {
		return err
	}

	ctx, cancel := r.rpcContext(parent, token)
	defer cancel()

	_, err = r.auth.LookupIdentity(ctx, &authv1.LookupIdentityRequest{
		Username: r.opts.username,
		Protocol: smokeProtocol,
		Method:   smokeMethod,
	})

	return expectCode("missing scope", err, codes.PermissionDenied)
}

func (r *runner) expectExpiredBackendRef(parent context.Context, token string, ref *commonv1.BackendRef) error {
	stale := &commonv1.BackendRef{
		Type:        ref.GetType(),
		Name:        ref.GetName(),
		Protocol:    ref.GetProtocol(),
		Authority:   ref.GetAuthority(),
		OpaqueToken: "expired-local-smoke-ref",
	}

	ctx, cancel := r.rpcContext(parent, token)
	defer cancel()

	_, err := r.identity.ResolveUser(ctx, &identityv1.ResolveUserRequest{
		Context:  requestContext(r.opts.username),
		Username: r.opts.username,
		Backend:  stale,
	})

	return expectCode("expired backend ref", err, codes.FailedPrecondition)
}

func (r *runner) expectUnavailableAuthority(parent context.Context, token string) error {
	transport, err := loadTransportCredentials(options{
		workDir:    r.opts.workDir,
		serverName: r.opts.serverName,
	})
	if err != nil {
		return err
	}

	conn, err := grpc.NewClient(r.opts.authorityUnavailable, grpc.WithTransportCredentials(transport))
	if err != nil {
		return fmt.Errorf("create unavailable authority client: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	ctx, cancel := r.rpcContext(parent, token)
	defer cancel()

	_, err = authv1.NewAuthServiceClient(conn).LookupIdentity(ctx, &authv1.LookupIdentityRequest{
		Username: r.opts.username,
		Protocol: smokeProtocol,
		Method:   smokeMethod,
	})

	return expectCode("unavailable authority", err, codes.Unavailable)
}

func (r *runner) rpcContext(parent context.Context, token string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)

	values := []string{
		"x-nauthilus-authority", "authority",
		"x-nauthilus-edge-cluster", r.opts.edgeCluster,
		"x-nauthilus-edge-instance", r.opts.edgeInstance,
	}
	if token != "" {
		values = append(values, "authorization", "Bearer "+token)
	}

	return metadata.NewOutgoingContext(ctx, metadata.Pairs(values...)), cancel
}

func requestContext(username string) *identityv1.RequestContext {
	return &identityv1.RequestContext{
		Username:          username,
		ClientIp:          smokeClientIP,
		ClientPort:        smokeClientPort,
		ClientHostname:    smokeClientHostname,
		ClientId:          smokeClientID,
		ExternalSessionId: "split-e2e-identity",
		UserAgent:         smokeUserAgent,
		LocalIp:           smokeLocalIP,
		LocalPort:         smokeLocalPort,
		Protocol:          smokeProtocol,
		Method:            smokeMethod,
		EdgeInstance:      "edge-a",
		EdgeRequestId:     "split-e2e-request",
		RequestedLanguage: "en",
	}
}

func expectCode(name string, err error, want codes.Code) error {
	if status.Code(err) != want {
		return fmt.Errorf("%s returned code %s, want %s: %w", name, status.Code(err), want, err)
	}

	return nil
}

func ok(name string) {
	fmt.Printf("ok %s\n", name)
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

func randomHex(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return hex.EncodeToString(raw), nil
}
