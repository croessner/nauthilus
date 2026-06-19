// Package authority contains outbound gRPC authority client helpers.
package authority

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/idp/clientauth"
	"github.com/croessner/nauthilus/v3/server/idp/signing"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/segmentio/ksuid"
)

// BearerTokenSource returns bearer tokens for authority RPC caller auth.
type BearerTokenSource interface {
	Token(ctx context.Context) (string, error)
}

// BearerTokenSourceOptions contains dependencies for a bearer token source.
type BearerTokenSourceOptions struct {
	Config           *config.AuthorityOIDCBearerSection
	Redis            rediscli.Client
	HTTPClient       *http.Client
	Now              func() time.Time
	AuthorityName    string
	StrictSplitMode  bool
	StaticTokenFiles bool
}

type bearerTokenSource struct {
	cfg              *config.AuthorityOIDCBearerSection
	redis            rediscli.Client
	httpClient       *http.Client
	now              func() time.Time
	authorityName    string
	strictSplitMode  bool
	staticTokenFiles bool
}

type cachedBearerToken struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type tokenEndpointResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// NewBearerTokenSource constructs a Redis-backed authority bearer-token source.
func NewBearerTokenSource(opts BearerTokenSourceOptions) BearerTokenSource {
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &bearerTokenSource{
		cfg:              opts.Config,
		redis:            opts.Redis,
		httpClient:       httpClient,
		now:              now,
		authorityName:    opts.AuthorityName,
		strictSplitMode:  opts.StrictSplitMode,
		staticTokenFiles: opts.StaticTokenFiles,
	}
}

// Token returns a caller bearer token, refreshing it under a distributed lock when needed.
func (s *bearerTokenSource) Token(ctx context.Context) (string, error) {
	if err := s.validate(); err != nil {
		return "", err
	}

	token, handled, err := s.staticTokenIfConfigured()
	if handled {
		return token, err
	}

	cached, cacheOK := s.readCachedToken(ctx)
	if cacheOK && s.tokenFresh(cached) {
		return cached.AccessToken, nil
	}

	return s.refreshCachedToken(ctx, cached, cacheOK)
}

func (s *bearerTokenSource) validate() error {
	if s == nil || s.cfg == nil {
		return fmt.Errorf("authority bearer token source is not configured")
	}

	return nil
}

func (s *bearerTokenSource) staticTokenIfConfigured() (string, bool, error) {
	if s.cfg.GetStaticTokenFile() == "" {
		return "", false, nil
	}

	token, err := s.staticToken()

	return token, true, err
}

func (s *bearerTokenSource) refreshCachedToken(ctx context.Context, cached cachedBearerToken, cacheOK bool) (string, error) {
	locked, err := s.acquireRefreshLock(ctx)
	if err != nil {
		return "", err
	}

	if !locked {
		return s.cachedTokenDuringRefresh(cached, cacheOK)
	}

	defer s.releaseRefreshLock(ctx)

	fresh, err := s.fetchToken(ctx)
	if err != nil {
		return "", err
	}

	if err = s.writeCachedToken(ctx, fresh); err != nil {
		return "", err
	}

	return fresh.AccessToken, nil
}

func (s *bearerTokenSource) cachedTokenDuringRefresh(cached cachedBearerToken, cacheOK bool) (string, error) {
	if cacheOK && cached.AccessToken != "" && s.now().Before(cached.ExpiresAt) {
		return cached.AccessToken, nil
	}

	return "", fmt.Errorf("authority token refresh already in progress and no usable cached token is available")
}

func (s *bearerTokenSource) staticToken() (string, error) {
	if !s.staticTokenFiles {
		return "", fmt.Errorf("authority static token files are not enabled")
	}

	raw, err := os.ReadFile(s.cfg.GetStaticTokenFile())
	if err != nil {
		return "", fmt.Errorf("read authority static token file: %w", err)
	}

	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("authority static token file is empty")
	}

	if s.strictSplitMode && looksLikeJWT(token) {
		return "", fmt.Errorf("strict split mode rejects JWT caller tokens")
	}

	return token, nil
}

func (s *bearerTokenSource) readCachedToken(ctx context.Context) (cachedBearerToken, bool) {
	var cached cachedBearerToken
	if s.redis == nil || s.redis.GetReadHandle() == nil {
		return cached, false
	}

	raw, err := s.redis.GetReadHandle().Get(ctx, s.cacheKey()).Result()
	if err != nil {
		return cached, false
	}

	if err = json.Unmarshal([]byte(raw), &cached); err != nil {
		return cached, false
	}

	return cached, cached.AccessToken != ""
}

func (s *bearerTokenSource) tokenFresh(token cachedBearerToken) bool {
	return s.now().Add(s.cfg.GetTokenCache().GetRefreshBeforeExpiry()).Before(token.ExpiresAt)
}

func (s *bearerTokenSource) acquireRefreshLock(ctx context.Context) (bool, error) {
	if s.redis == nil || s.redis.GetWriteHandle() == nil {
		return true, nil
	}

	owner := s.authorityName
	if owner == "" {
		owner = s.cfg.GetClientID()
	}

	locked, err := s.redis.GetWriteHandle().SetNX(ctx, s.lockKey(), owner, s.cfg.GetTokenCache().GetRefreshLockTTL()).Result()
	if err != nil {
		return false, fmt.Errorf("authority token refresh lock: %w", err)
	}

	return locked, nil
}

func (s *bearerTokenSource) releaseRefreshLock(ctx context.Context) {
	if s.redis == nil || s.redis.GetWriteHandle() == nil {
		return
	}

	_ = s.redis.GetWriteHandle().Del(ctx, s.lockKey()).Err()
}

func (s *bearerTokenSource) writeCachedToken(ctx context.Context, token cachedBearerToken) error {
	if s.redis == nil || s.redis.GetWriteHandle() == nil {
		return nil
	}

	raw, err := json.Marshal(token)
	if err != nil {
		return err
	}

	ttl := time.Until(token.ExpiresAt)
	if s.now != nil {
		ttl = token.ExpiresAt.Sub(s.now())
	}

	if ttl <= 0 {
		ttl = time.Second
	}

	if err = s.redis.GetWriteHandle().Set(ctx, s.cacheKey(), string(raw), ttl).Err(); err != nil && err != redis.Nil {
		return fmt.Errorf("write authority token cache: %w", err)
	}

	return nil
}

func (s *bearerTokenSource) fetchToken(ctx context.Context) (cachedBearerToken, error) {
	form := s.tokenRequestForm()

	request, err := s.newTokenEndpointRequest(ctx, form)
	if err != nil {
		return cachedBearerToken{}, err
	}

	if err = s.applyTokenEndpointAuth(request, form); err != nil {
		return cachedBearerToken{}, err
	}

	tokenResponse, err := s.doTokenEndpointRequest(request)
	if err != nil {
		return cachedBearerToken{}, err
	}

	return s.cachedTokenFromResponse(tokenResponse)
}

func (s *bearerTokenSource) tokenRequestForm() url.Values {
	form := url.Values{}
	form.Set("grant_type", config.AuthorityClientCredentialsMode)
	form.Set("client_id", s.cfg.GetClientID())

	if len(s.cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(s.cfg.Scopes, " "))
	}

	if s.cfg.Audience != "" {
		form.Set("audience", s.cfg.Audience)
	}

	return form
}

func (s *bearerTokenSource) newTokenEndpointRequest(ctx context.Context, form url.Values) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.GetTokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return request, nil
}

func (s *bearerTokenSource) applyTokenEndpointAuth(request *http.Request, form url.Values) error {
	switch s.cfg.GetTokenEndpointAuthMethod() {
	case clientauth.MethodClientSecretBasic:
		request.SetBasicAuth(s.cfg.GetClientID(), s.clientSecret())
	case clientauth.MethodClientSecretPost:
		form.Set("client_secret", s.clientSecret())
		setFormBody(request, form)
	case clientauth.MethodPrivateKeyJWT:
		assertion, assertionErr := s.privateKeyJWT()
		if assertionErr != nil {
			return assertionErr
		}

		form.Set("client_assertion_type", clientauth.AssertionTypeJWTBearer)
		form.Set("client_assertion", assertion)
		setFormBody(request, form)
	default:
		return fmt.Errorf("unsupported authority token endpoint auth method %q", s.cfg.GetTokenEndpointAuthMethod())
	}

	return nil
}

func (s *bearerTokenSource) clientSecret() string {
	var secretValue string

	s.cfg.GetClientSecret().WithString(func(value string) {
		secretValue = value
	})

	return secretValue
}

func setFormBody(request *http.Request, form url.Values) {
	encoded := form.Encode()
	request.Body = io.NopCloser(strings.NewReader(encoded))
	request.ContentLength = int64(len(encoded))
}

func (s *bearerTokenSource) doTokenEndpointRequest(request *http.Request) (tokenEndpointResponse, error) {
	response, err := s.httpClient.Do(request)
	if err != nil {
		return tokenEndpointResponse{}, fmt.Errorf("authority token endpoint request failed: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return tokenEndpointResponse{}, fmt.Errorf("authority token endpoint returned status %d", response.StatusCode)
	}

	var tokenResponse tokenEndpointResponse
	if err = json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		return tokenEndpointResponse{}, fmt.Errorf("decode authority token response: %w", err)
	}

	return tokenResponse, nil
}

func (s *bearerTokenSource) cachedTokenFromResponse(tokenResponse tokenEndpointResponse) (cachedBearerToken, error) {
	if tokenResponse.AccessToken == "" {
		return cachedBearerToken{}, fmt.Errorf("authority token response is missing access_token")
	}

	if s.strictSplitMode && looksLikeJWT(tokenResponse.AccessToken) {
		return cachedBearerToken{}, fmt.Errorf("strict split mode rejects JWT caller tokens")
	}

	expiresIn := tokenResponse.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 60
	}

	return cachedBearerToken{
		AccessToken: tokenResponse.AccessToken,
		ExpiresAt:   s.now().Add(time.Duration(expiresIn) * time.Second),
	}, nil
}

func (s *bearerTokenSource) privateKeyJWT() (string, error) {
	raw, err := os.ReadFile(s.cfg.ClientPrivateKeyFile)
	if err != nil {
		return "", fmt.Errorf("read private_key_jwt key: %w", err)
	}

	alg := s.cfg.ClientAssertionAlg
	if alg == "" {
		alg = signing.AlgorithmRS256
	}

	var signer signing.Signer

	switch alg {
	case signing.AlgorithmEdDSA:
		signer, err = signing.NewEdDSASignerFromPEM(string(raw), s.cfg.ClientKeyID)
	case signing.AlgorithmRS256:
		signer, err = signing.NewRS256SignerFromPEM(string(raw), s.cfg.ClientKeyID)
	default:
		err = fmt.Errorf("unsupported private_key_jwt algorithm %q", alg)
	}

	if err != nil {
		return "", err
	}

	now := s.now()

	return signer.Sign(jwt.MapClaims{
		"iss": s.cfg.GetClientID(),
		"sub": s.cfg.GetClientID(),
		"aud": s.jwtAudience(),
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"jti": ksuid.New().String(),
	})
}

func (s *bearerTokenSource) jwtAudience() string {
	if s.cfg.Audience != "" {
		return s.cfg.Audience
	}

	return s.cfg.GetTokenEndpoint()
}

func (s *bearerTokenSource) cacheKey() string {
	return s.cfg.GetTokenCache().GetKeyPrefix() + s.authorityName + ":" + s.cfg.GetClientID()
}

func (s *bearerTokenSource) lockKey() string {
	return s.cacheKey() + ":lock"
}

func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

// StaticBearerTokenSource is a fixed bearer token source for tests and emergency wiring.
type StaticBearerTokenSource string

// Token returns the configured static bearer token.
func (s StaticBearerTokenSource) Token(context.Context) (string, error) {
	return string(s), nil
}
