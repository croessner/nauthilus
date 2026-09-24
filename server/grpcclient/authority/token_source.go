// Package authority contains outbound gRPC authority client helpers.
package authority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/idp/clientauth"
	"github.com/croessner/nauthilus/v4/server/idp/signing"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/segmentio/ksuid"
)

// BearerTokenSource returns bearer tokens for authority RPC caller auth.
type BearerTokenSource interface {
	Token(ctx context.Context) (string, error)
}

// RejectedTokenReplacer is implemented by token sources that can replace a caller token the authority
// rejected with UNAUTHENTICATED.
type RejectedTokenReplacer interface {
	// ReplaceRejectedToken discards rejected from the shared token cache when it is still the cached value
	// and returns a different usable token. It returns an error when no replacement is available.
	ReplaceRejectedToken(ctx context.Context, rejected string) (string, error)
}

// errStaticTokenNotReplaceable reports that a static caller token is never replaced after a rejection.
var errStaticTokenNotReplaceable = errors.New("authority static caller token cannot be replaced")

// compareAndDeleteTokenScript deletes the cached caller token only when its access_token still equals ARGV[1].
// It returns 1 after the delete, 0 when no token is cached, and the cached JSON value when another replica
// already replaced the token, so a token fetched elsewhere in the meantime is never discarded.
var compareAndDeleteTokenScript = redis.NewScript(`
local raw = redis.call("GET", KEYS[1])
if not raw then
    return 0
end

local ok, cached = pcall(cjson.decode, raw)
if ok and type(cached) == "table" and cached["access_token"] == ARGV[1] then
    redis.call("DEL", KEYS[1])
    return 1
end

return raw
`)

// BearerTokenSourceOptions contains dependencies for a bearer token source.
type BearerTokenSourceOptions struct {
	Config           *config.AuthorityOIDCBearerSection
	Artifacts        *config.ArtifactSnapshot
	Redis            rediscli.Client
	HTTPClient       *http.Client
	Now              func() time.Time
	AuthorityName    string
	StrictSplitMode  bool
	StaticTokenFiles bool
}

type bearerTokenSource struct {
	cfg               *config.AuthorityOIDCBearerSection
	redis             rediscli.Client
	httpClient        *http.Client
	now               func() time.Time
	privateKeySigner  signing.Signer
	preparationErr    error
	authorityName     string
	sealedStaticToken string
	strictSplitMode   bool
	staticTokenFiles  bool
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

	source := &bearerTokenSource{
		cfg:              opts.Config,
		redis:            opts.Redis,
		httpClient:       httpClient,
		now:              now,
		authorityName:    opts.AuthorityName,
		strictSplitMode:  opts.StrictSplitMode,
		staticTokenFiles: opts.StaticTokenFiles,
	}
	source.preparationErr = source.prepareSealedCredentials(opts.Artifacts)

	return source
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

// ReplaceRejectedToken discards a caller token that the authority rejected and returns a different one.
//
// The cached token is deleted with a compare-and-delete, so a token another replica cached in the meantime
// survives and is returned instead. Otherwise the regular refresh path fetches a new token under the
// distributed refresh lock. Static token files are never replaced.
func (s *bearerTokenSource) ReplaceRejectedToken(ctx context.Context, rejected string) (string, error) {
	if err := s.validate(); err != nil {
		return "", err
	}

	if s.cfg.GetStaticTokenFile() != "" {
		return "", errStaticTokenNotReplaceable
	}

	replacement, err := s.discardRejectedToken(ctx, rejected)
	if err != nil {
		return "", err
	}

	if replacement.AccessToken == "" || replacement.AccessToken == rejected {
		return s.refreshCachedToken(ctx, cachedBearerToken{}, false)
	}

	if s.tokenFresh(replacement) {
		return replacement.AccessToken, nil
	}

	return s.refreshCachedToken(ctx, replacement, true)
}

// discardRejectedToken deletes the cached token when it is still rejected and returns a cached replacement.
func (s *bearerTokenSource) discardRejectedToken(ctx context.Context, rejected string) (cachedBearerToken, error) {
	var replacement cachedBearerToken

	if s.redis == nil || s.redis.GetWriteHandle() == nil {
		return replacement, nil
	}

	result, err := compareAndDeleteTokenScript.Run(ctx, s.redis.GetWriteHandle(), []string{s.cacheKey()}, rejected).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return replacement, fmt.Errorf("discard rejected authority token: %w", err)
	}

	raw, ok := result.(string)
	if !ok {
		return replacement, nil
	}

	if err = json.Unmarshal([]byte(raw), &replacement); err != nil {
		return cachedBearerToken{}, nil
	}

	return replacement, nil
}

func (s *bearerTokenSource) validate() error {
	if s == nil || s.cfg == nil {
		return fmt.Errorf("authority bearer token source is not configured")
	}

	if s.preparationErr != nil {
		return s.preparationErr
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

	token := s.sealedStaticToken
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
	if s.privateKeySigner == nil {
		return "", fmt.Errorf("private_key_jwt signer is not prepared")
	}

	now := s.now()

	return s.privateKeySigner.Sign(jwt.MapClaims{
		"iss": s.cfg.GetClientID(),
		"sub": s.cfg.GetClientID(),
		"aud": s.jwtAudience(),
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"jti": ksuid.New().String(),
	})
}

// prepareSealedCredentials freezes token-file and private-key material during source construction.
func (s *bearerTokenSource) prepareSealedCredentials(artifacts *config.ArtifactSnapshot) error {
	if s == nil || s.cfg == nil {
		return nil
	}

	if path := s.cfg.GetStaticTokenFile(); path != "" {
		raw, err := readSealedAuthorityArtifact(artifacts, path, "authority static token file")
		if err != nil {
			return err
		}

		s.sealedStaticToken = strings.TrimSpace(string(raw))
		clear(raw)
	}

	if !s.cfg.IsEnabled() || s.cfg.GetTokenEndpointAuthMethod() != clientauth.MethodPrivateKeyJWT {
		return nil
	}

	raw, err := readSealedAuthorityArtifact(artifacts, s.cfg.ClientPrivateKeyFile, "private_key_jwt key")
	if err != nil {
		return err
	}
	defer clear(raw)

	s.privateKeySigner, err = newAuthorityPrivateKeySigner(s.cfg, string(raw))

	return err
}

// newAuthorityPrivateKeySigner parses one exact configured private_key_jwt key.
func newAuthorityPrivateKeySigner(cfg *config.AuthorityOIDCBearerSection, pemData string) (signing.Signer, error) {
	algorithm := cfg.ClientAssertionAlg
	if algorithm == "" {
		algorithm = signing.AlgorithmRS256
	}

	switch algorithm {
	case signing.AlgorithmEdDSA:
		return signing.NewEdDSASignerFromPEM(pemData, cfg.ClientKeyID)
	case signing.AlgorithmRS256:
		return signing.NewRS256SignerFromPEM(pemData, cfg.ClientKeyID)
	default:
		return nil, fmt.Errorf("unsupported private_key_jwt algorithm %q", algorithm)
	}
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
