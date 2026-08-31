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

package callerauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

const (
	maximumCallerIdentityBytes = 512
	transportKindGRPC          = "grpc"
)

var dummyBasicPasswordDigest = sha256.Sum256([]byte("nauthilus-policy-basic-dummy-verifier"))

// Authenticator owns compiled credential rules for exactly one runtime generation.
type Authenticator struct {
	tokenValidator           AccessTokenValidator
	throttler                BasicThrottler
	external                 map[string]*externalRule
	basic                    map[string]*externalRule
	internal                 map[string][]internalRule
	profileIDs               []string
	basicThrottleUnavailable atomic.Bool
	requireGRPCMTLS          bool
}

type externalRule struct {
	kinds       map[string]struct{}
	basic       *compiledBasicCredential
	principal   string
	requireMTLS bool
}

type compiledBasicCredential struct {
	username       string
	passwordDigest [32]byte
}

type internalRule struct {
	transports           map[string]struct{}
	principal            string
	expectedMTLSIdentity string
	capabilityDigest     [32]byte
	requireProtected     bool
}

// New validates, compiles, and deeply owns one caller-authentication generation.
func New(configuration Configuration) (*Authenticator, error) {
	if err := validateConfigurationDependencies(configuration); err != nil {
		return nil, err
	}

	authenticator := &Authenticator{
		tokenValidator:  configuration.TokenValidator,
		throttler:       configuration.Throttler,
		external:        make(map[string]*externalRule, len(configuration.ExternalProfiles)),
		basic:           make(map[string]*externalRule),
		internal:        make(map[string][]internalRule),
		requireGRPCMTLS: configuration.RequireGRPCMTLS,
	}

	hasBearer, hasBasic, err := authenticator.compileExternalProfiles(configuration.ExternalProfiles)
	if err != nil {
		return nil, err
	}

	if hasBearer && authenticator.tokenValidator == nil {
		return nil, configurationError("Bearer profiles require an issuer-validating token adapter")
	}

	if hasBasic && !configuration.TransportCapabilities.HTTPProtected && !configuration.TransportCapabilities.GRPCProtected {
		return nil, configurationError("Policy-Basic requires an enabled protected transport capability")
	}

	if configuration.TransportCapabilities.GRPCVerifiedClientCertificate && !configuration.TransportCapabilities.GRPCProtected {
		return nil, configurationError("verified gRPC client certificates require a protected gRPC transport capability")
	}

	if authenticator.requiresExternalMTLS() && !configuration.TransportCapabilities.GRPCVerifiedClientCertificate {
		return nil, configurationError("client-required mTLS needs an enabled gRPC transport with verified client certificates")
	}

	if configuration.RequireGRPCMTLS && !configuration.TransportCapabilities.GRPCVerifiedClientCertificate {
		return nil, configurationError("required gRPC mTLS needs an enabled gRPC transport with verified client certificates")
	}

	if err = authenticator.compileInternalCallers(configuration.InternalCallers); err != nil {
		return nil, err
	}

	sort.Strings(authenticator.profileIDs)

	return authenticator, nil
}

// requiresExternalMTLS reports whether any compiled client profile requires verified certificate identity.
func (a *Authenticator) requiresExternalMTLS() bool {
	for _, rule := range a.external {
		if rule.requireMTLS {
			return true
		}
	}

	return false
}

// validateConfigurationDependencies rejects interface values that conceal nil references.
func validateConfigurationDependencies(configuration Configuration) error {
	if typedNilInterface(configuration.TokenValidator) || typedNilInterface(configuration.Throttler) {
		return configurationError("caller-authentication dependency is typed nil")
	}

	if configuration.RequiresBasicThrottler() && configuration.Throttler == nil {
		return configurationError("Policy-Basic profiles require a generation-owned throttler")
	}

	return nil
}

// ProfileIDs returns detached deterministic generation credential-profile identities.
func (a *Authenticator) ProfileIDs() []string {
	if a == nil {
		return nil
	}

	return append([]string(nil), a.profileIDs...)
}

// Authenticate validates opaque evidence and constructs trusted caller context only on success.
func (a *Authenticator) Authenticate(ctx context.Context, input decision.AuthenticationInput) (decision.CallerContext, error) {
	if a == nil {
		return rejected()
	}

	if err := ctx.Err(); err != nil {
		return decision.CallerContext{}, err
	}

	switch input.Kind() {
	case policy.CallerAuthenticationKindBearer:
		return a.authenticateBearer(ctx, input)
	case policy.CallerAuthenticationKindBasic:
		return a.authenticateBasic(ctx, input)
	default:
		return a.authenticateInternal(input)
	}
}

// compileExternalProfiles validates and detaches every external credential rule.
func (a *Authenticator) compileExternalProfiles(profiles []ExternalProfile) (bool, bool, error) {
	hasBearer := false
	hasBasic := false

	for index := range profiles {
		profile := profiles[index]

		if !validCallerIdentity(profile.Principal) {
			return false, false, configurationError("external profile %d has an invalid principal", index)
		}

		if _, duplicate := a.external[profile.Principal]; duplicate {
			return false, false, configurationError("external profile %d duplicates a principal", index)
		}

		kinds, bearerEnabled, basicEnabled, err := compileExternalKinds(profile.AuthenticationKinds, index)
		if err != nil {
			return false, false, err
		}

		if basicEnabled != (profile.Basic != nil) {
			return false, false, configurationError("external profile %d has inconsistent Policy-Basic ownership", index)
		}

		rule := &externalRule{
			kinds:       kinds,
			principal:   profile.Principal,
			requireMTLS: profile.RequireMTLS,
		}

		if profile.Basic != nil {
			compiled, compileErr := compileBasicCredential(*profile.Basic, index)
			if compileErr != nil {
				return false, false, compileErr
			}

			if _, duplicate := a.basic[compiled.username]; duplicate {
				return false, false, configurationError("external profile %d duplicates a Policy-Basic username", index)
			}

			rule.basic = &compiled
			a.basic[compiled.username] = rule
		}

		a.external[rule.principal] = rule
		a.profileIDs = append(a.profileIDs, rule.principal)
		hasBearer = hasBearer || bearerEnabled
		hasBasic = hasBasic || basicEnabled
	}

	return hasBearer, hasBasic, nil
}

// compileExternalKinds validates one non-empty exact primary-kind set.
func compileExternalKinds(kinds []string, profileIndex int) (map[string]struct{}, bool, bool, error) {
	if len(kinds) == 0 {
		return nil, false, false, configurationError("external profile %d has no authentication kind", profileIndex)
	}

	result := make(map[string]struct{}, len(kinds))

	for _, kind := range kinds {
		if kind != policy.CallerAuthenticationKindBearer && kind != policy.CallerAuthenticationKindBasic {
			return nil, false, false, configurationError("external profile %d has an unsupported authentication kind", profileIndex)
		}

		if _, duplicate := result[kind]; duplicate {
			return nil, false, false, configurationError("external profile %d duplicates an authentication kind", profileIndex)
		}

		result[kind] = struct{}{}
	}

	_, bearerEnabled := result[policy.CallerAuthenticationKindBearer]
	_, basicEnabled := result[policy.CallerAuthenticationKindBasic]

	return result, bearerEnabled, basicEnabled, nil
}

// compileBasicCredential reduces secret material to one generation-owned fixed-size verifier.
func compileBasicCredential(input BasicCredential, profileIndex int) (compiledBasicCredential, error) {
	if !validCallerIdentity(input.Username) || strings.ContainsRune(input.Username, ':') || input.Password.IsZero() {
		return compiledBasicCredential{}, configurationError("external profile %d has invalid Policy-Basic material", profileIndex)
	}

	result := compiledBasicCredential{username: input.Username}

	input.Password.WithBytes(func(password []byte) {
		result.passwordDigest = sha256.Sum256(password)
	})

	return result, nil
}

// compileInternalCallers validates exact named capability and transport bindings.
func (a *Authenticator) compileInternalCallers(callers []InternalCaller) error {
	for index := range callers {
		rule, evidenceKind, err := a.compileInternalCaller(callers[index], index)
		if err != nil {
			return err
		}

		if a.hasInternalCapability(evidenceKind, rule.capabilityDigest) {
			return configurationError("internal caller %d duplicates an evidence capability", index)
		}

		a.internal[evidenceKind] = append(a.internal[evidenceKind], rule)
		a.profileIDs = append(a.profileIDs, rule.principal)
	}

	return nil
}

// compileInternalCaller validates and detaches one named internal capability rule.
func (a *Authenticator) compileInternalCaller(caller InternalCaller, index int) (internalRule, string, error) {
	if !validCallerIdentity(caller.Principal) || !validCallerIdentity(caller.EvidenceKind) || caller.Capability.IsZero() {
		return internalRule{}, "", configurationError("internal caller %d has invalid identity or capability material", index)
	}

	if reservedInternalEvidenceKind(caller.EvidenceKind) {
		return internalRule{}, "", configurationError("internal caller %d reuses an external authentication kind", index)
	}

	if a.profileIDExists(caller.Principal) {
		return internalRule{}, "", configurationError("internal caller %d duplicates a credential profile principal", index)
	}

	transports, err := compileTransportKinds(caller.TransportKinds, index)
	if err != nil {
		return internalRule{}, "", err
	}

	if caller.ExpectedMTLSIdentity != "" && !validCallerIdentity(caller.ExpectedMTLSIdentity) {
		return internalRule{}, "", configurationError("internal caller %d has an invalid mTLS identity", index)
	}

	rule := internalRule{
		transports:           transports,
		principal:            caller.Principal,
		expectedMTLSIdentity: caller.ExpectedMTLSIdentity,
		requireProtected:     caller.RequireProtected,
	}

	caller.Capability.WithBytes(func(capability []byte) {
		rule.capabilityDigest = sha256.Sum256(capability)
	})

	return rule, caller.EvidenceKind, nil
}

// profileIDExists reports whether an earlier compiled rule owns the exact principal.
func (a *Authenticator) profileIDExists(principal string) bool {
	for _, existing := range a.profileIDs {
		if existing == principal {
			return true
		}
	}

	return false
}

// hasInternalCapability compares one verifier against every same-kind rule in constant time.
func (a *Authenticator) hasInternalCapability(evidenceKind string, digest [32]byte) bool {
	for _, existing := range a.internal[evidenceKind] {
		if subtle.ConstantTimeCompare(existing.capabilityDigest[:], digest[:]) == 1 {
			return true
		}
	}

	return false
}

// reservedInternalEvidenceKind prevents named capabilities from shadowing primary authentication dispatch.
func reservedInternalEvidenceKind(kind string) bool {
	return kind == policy.CallerAuthenticationKindBearer || kind == policy.CallerAuthenticationKindBasic || kind == "mtls"
}

// compileTransportKinds validates one exact non-empty internal transport allowlist.
func compileTransportKinds(kinds []string, callerIndex int) (map[string]struct{}, error) {
	if len(kinds) == 0 {
		return nil, configurationError("internal caller %d has no transport kind", callerIndex)
	}

	result := make(map[string]struct{}, len(kinds))

	for _, kind := range kinds {
		if !validCallerIdentity(kind) {
			return nil, configurationError("internal caller %d has an invalid transport kind", callerIndex)
		}

		if _, duplicate := result[kind]; duplicate {
			return nil, configurationError("internal caller %d duplicates a transport kind", callerIndex)
		}

		result[kind] = struct{}{}
	}

	return result, nil
}

// authenticateBearer validates one exact Policy resource token and registered profile.
func (a *Authenticator) authenticateBearer(ctx context.Context, input decision.AuthenticationInput) (decision.CallerContext, error) {
	if a.tokenValidator == nil {
		return rejected()
	}

	credential := input.Credential()
	defer clear(credential)

	token, err := a.tokenValidator.ValidateAccessToken(ctx, credential)
	if err != nil {
		return rejected()
	}

	scopes, err := validatePolicyToken(token)
	if err != nil {
		return rejected()
	}

	profile, exists := a.external[token.ClientID]
	if !exists || !profile.permits(policy.CallerAuthenticationKindBearer) || !a.validExternalMTLS(profile, input) {
		return rejected()
	}

	return newTrustedCaller(decision.TrustedCallerInput{
		Principal:          token.ClientID,
		ClientID:           token.ClientID,
		Subject:            token.Subject,
		Issuer:             token.Issuer,
		Scopes:             scopes,
		AuthenticationKind: policy.CallerAuthenticationKindBearer,
	}, input)
}

// authenticateBasic verifies dedicated Policy-Basic material only after transport protection.
func (a *Authenticator) authenticateBasic(ctx context.Context, input decision.AuthenticationInput) (decision.CallerContext, error) {
	if !input.Protected() {
		return rejected()
	}

	credential := input.Credential()
	defer clear(credential)

	username, provided, key, valid := parseBasicPresentation(credential, input.Peer())
	if !valid {
		return rejected()
	}

	profile, verified := a.verifyBasicPresentation(ctx, username, provided, key)
	if !verified || !a.validExternalMTLS(profile, input) {
		return rejected()
	}

	caller, err := newTrustedCaller(decision.TrustedCallerInput{
		Principal:          profile.principal,
		AuthenticationKind: policy.CallerAuthenticationKindBasic,
	}, input)
	if err != nil {
		return decision.CallerContext{}, err
	}

	if !a.recordBasicSuccess(ctx, key) {
		return rejected()
	}

	return caller, nil
}

// parseBasicPresentation extracts a bounded username and fixed-size password verifier.
func parseBasicPresentation(credential []byte, peer string) (string, [32]byte, BasicThrottleKey, bool) {
	usernameBytes, password, found := bytes.Cut(credential, []byte{':'})
	if !found || len(usernameBytes) == 0 {
		return "", [32]byte{}, BasicThrottleKey{}, false
	}

	username := string(usernameBytes)
	if !validCallerIdentity(username) {
		return "", [32]byte{}, BasicThrottleKey{}, false
	}

	key := BasicThrottleKey{
		peer:           basicThrottlePeer(peer),
		identityDigest: sha256.Sum256(usernameBytes),
	}

	return username, sha256.Sum256(password), key, true
}

// verifyBasicPresentation applies throttling and one constant-time generation verifier comparison.
func (a *Authenticator) verifyBasicPresentation(
	ctx context.Context,
	username string,
	provided [32]byte,
	key BasicThrottleKey,
) (*externalRule, bool) {
	if !a.beforeBasicAttempt(ctx, key) {
		return nil, false
	}

	profile := a.basic[username]
	expected := dummyBasicPasswordDigest

	if profile != nil && profile.basic != nil {
		expected = profile.basic.passwordDigest
	}

	matched := subtle.ConstantTimeCompare(expected[:], provided[:]) == 1 && profile != nil

	if !matched {
		a.recordBasicFailure(ctx, key)

		return nil, false
	}

	return profile, true
}

// beforeBasicAttempt fails the generation closed after any throttle-state error.
func (a *Authenticator) beforeBasicAttempt(ctx context.Context, key BasicThrottleKey) bool {
	if a.basicThrottleUnavailable.Load() {
		return false
	}

	if err := a.throttler.BeforeAttempt(ctx, key); err != nil {
		if !errors.Is(err, ErrBasicThrottleLimit) {
			a.basicThrottleUnavailable.Store(true)
		}

		return false
	}

	return !a.basicThrottleUnavailable.Load()
}

// recordBasicFailure records one failed comparison and closes the generation on state loss.
func (a *Authenticator) recordBasicFailure(ctx context.Context, key BasicThrottleKey) {
	if err := a.throttler.RecordFailure(ctx, key); err != nil {
		a.basicThrottleUnavailable.Store(true)
	}
}

// recordBasicSuccess records one verified comparison and reports whether throttle state stayed healthy.
func (a *Authenticator) recordBasicSuccess(ctx context.Context, key BasicThrottleKey) bool {
	if a.basicThrottleUnavailable.Load() {
		return false
	}

	if err := a.throttler.RecordSuccess(ctx, key); err != nil {
		a.basicThrottleUnavailable.Store(true)

		return false
	}

	return !a.basicThrottleUnavailable.Load()
}

// basicThrottlePeer reduces trusted peer evidence to one stable source-IP bucket.
func basicThrottlePeer(peer string) string {
	address := sourceIP(peer)
	if !address.IsValid() {
		return ""
	}

	return address.String()
}

// authenticateInternal verifies one exact generation-owned named capability rule.
func (a *Authenticator) authenticateInternal(input decision.AuthenticationInput) (decision.CallerContext, error) {
	rules := a.internal[input.Kind()]
	if len(rules) == 0 {
		return rejected()
	}

	credential := input.Credential()
	defer clear(credential)

	presented := sha256.Sum256(credential)
	matched := matchingInternalRule(rules, presented)

	if matched == nil || !matched.acceptsTransport(input.TransportKind()) {
		return rejected()
	}

	if matched.requireProtected && !input.Protected() {
		return rejected()
	}

	if !matched.validMTLS(input) {
		return rejected()
	}

	return newTrustedCaller(decision.TrustedCallerInput{
		Principal:          matched.principal,
		AuthenticationKind: policy.CallerAuthenticationKindInternal,
		Internal:           true,
	}, input)
}

// matchingInternalRule compares every same-kind capability without early exit.
func matchingInternalRule(rules []internalRule, presented [32]byte) *internalRule {
	var matched *internalRule

	for index := range rules {
		if subtle.ConstantTimeCompare(rules[index].capabilityDigest[:], presented[:]) == 1 {
			matched = &rules[index]
		}
	}

	return matched
}

// validatePolicyToken enforces exact access-token, audience, principal, and scope semantics.
func validatePolicyToken(token ValidatedAccessToken) ([]string, error) {
	if token.TokenType != definitions.TokenTypeAccessToken || !validCallerIdentity(token.ClientID) {
		return nil, ErrAuthentication
	}

	audiences, valid := normalizedExactStrings(token.Audiences)
	if !valid || len(audiences) != 1 || audiences[0] != definitions.AudiencePolicyAPI {
		return nil, ErrAuthentication
	}

	scopes, valid := normalizedExactStrings(token.Scopes)
	if !valid {
		return nil, ErrAuthentication
	}

	hasEvaluate := false

	for _, scope := range scopes {
		if !definitions.IsOAuthScopeToken(scope) {
			return nil, ErrAuthentication
		}

		switch scope {
		case definitions.ScopePolicyEvaluate:
			hasEvaluate = true
		case definitions.ScopePolicyDiagnostics:
		default:
			return nil, ErrAuthentication
		}
	}

	if !hasEvaluate {
		return nil, ErrAuthentication
	}

	return scopes, nil
}

// normalizedExactStrings owns, deduplicates, and sorts exact non-empty values.
func normalizedExactStrings(values []string) ([]string, bool) {
	unique := make(map[string]struct{}, len(values))

	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
			return nil, false
		}

		unique[value] = struct{}{}
	}

	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}

	sort.Strings(result)

	return result, true
}

// validExternalMTLS applies global and profile-specific corroborating identity rules.
func (a *Authenticator) validExternalMTLS(profile *externalRule, input decision.AuthenticationInput) bool {
	identity := input.MTLSIdentity()
	required := profile.requireMTLS || (a.requireGRPCMTLS && input.TransportKind() == transportKindGRPC)

	if identity == "" {
		return !required
	}

	return input.Protected() && identity == profile.principal
}

// permits reports whether one external profile owns the requested primary kind.
func (r *externalRule) permits(kind string) bool {
	if r == nil {
		return false
	}

	_, allowed := r.kinds[kind]

	return allowed
}

// acceptsTransport reports whether one named internal rule admits the exact transport kind.
func (r *internalRule) acceptsTransport(kind string) bool {
	_, allowed := r.transports[kind]

	return allowed
}

// validMTLS validates explicitly configured internal mTLS corroboration without inference.
func (r *internalRule) validMTLS(input decision.AuthenticationInput) bool {
	identity := input.MTLSIdentity()
	if r.expectedMTLSIdentity == "" {
		return identity == ""
	}

	return input.Protected() && identity == r.expectedMTLSIdentity
}

// newTrustedCaller copies only authenticated identity plus host-created transport evidence.
func newTrustedCaller(trusted decision.TrustedCallerInput, input decision.AuthenticationInput) (decision.CallerContext, error) {
	trusted.SourceIP = sourceIP(input.Peer())
	trusted.MTLSIdentity = input.MTLSIdentity()
	trusted.TransportKind = input.TransportKind()
	trusted.Listener = input.Listener()
	trusted.HTTPRoute = input.HTTPRoute()
	trusted.GRPCMethod = input.GRPCMethod()

	caller, err := decision.NewCallerContext(trusted)
	if err != nil {
		return rejected()
	}

	return caller, nil
}

// sourceIP extracts one exact IP or IP:port peer without hostname inference.
func sourceIP(peer string) netip.Addr {
	if address, err := netip.ParseAddr(peer); err == nil {
		return address.Unmap()
	}

	if addressPort, err := netip.ParseAddrPort(peer); err == nil {
		return addressPort.Addr().Unmap()
	}

	return netip.Addr{}
}

// validCallerIdentity accepts exact bounded non-blank UTF-8 identity text.
func validCallerIdentity(value string) bool {
	return value != "" && len(value) <= maximumCallerIdentityBytes && strings.TrimSpace(value) == value && utf8.ValidString(value)
}

// configurationError creates a secret-free path-neutral generation failure.
func configurationError(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrConfiguration, fmt.Sprintf(format, arguments...))
}

// rejected returns the sole secret-free authentication failure shape.
func rejected() (decision.CallerContext, error) {
	return decision.CallerContext{}, ErrAuthentication
}
