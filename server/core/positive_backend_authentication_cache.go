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

package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"slices"
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/localcache"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/gin-gonic/gin"
)

const (
	backendAuthenticationCacheKeyVersion  = "nauthilus-positive-backend-authentication-v2"
	cachedBackendAuthenticationContextKey = "nauthilus_cached_backend_authentication"
	backendAuthenticationMaxValueDepth    = 64
	backendAuthenticationMaxValueNodes    = 16384
	backendAuthenticationSweepInterval    = time.Minute
)

type backendAuthenticationValueKind uint8

const (
	backendAuthenticationValueNil backendAuthenticationValueKind = iota
	backendAuthenticationValueScalar
	backendAuthenticationValueBytes
	backendAuthenticationValueStrings
	backendAuthenticationValueList
	backendAuthenticationValueObject
	backendAuthenticationValuePolicyFacts
)

type backendAuthenticationValue struct {
	scalar      any
	object      map[string]backendAuthenticationValue
	list        []backendAuthenticationValue
	policyFacts []backendAuthenticationPolicyFact
	strings     []string
	bytes       []byte
	kind        backendAuthenticationValueKind
}

type backendAuthenticationPolicyFact struct {
	value     backendAuthenticationValue
	attribute string
}

type backendAuthenticationValueEncoder struct {
	nodes int
}

// appliedBackendAuthentication is one request-owned materialized backend snapshot.
type appliedBackendAuthentication struct {
	attributes              bktype.AttributeMapping
	additionalAttributes    map[string]any
	groups                  []string
	groupDistinguishedNames []string
	backendRef              RemoteBackendRef
	backendName             string
	accountField            string
	account                 string
	totpSecretField         string
	totpRecoveryField       string
	uniqueUserIDField       string
	displayNameField        string
	backendAddress          string
	contextAccount          string
	backendPort             int
	sourceBackend           definitions.Backend
	userFound               bool
	authenticated           bool
}

// BackendAuthenticationCacheKey is an opaque credential-bound cache key.
type BackendAuthenticationCacheKey struct{ digest [sha256.Size]byte }

// CachedBackendAuthentication is an owned positive backend and identity snapshot.
type CachedBackendAuthentication struct {
	attributes              map[string][]backendAuthenticationValue
	additionalAttributes    map[string]backendAuthenticationValue
	groups                  []string
	groupDistinguishedNames []string
	backendRef              RemoteBackendRef
	backendName             string
	accountField            string
	account                 string
	totpSecretField         string
	totpRecoveryField       string
	uniqueUserIDField       string
	displayNameField        string
	backendAddress          string
	contextAccount          string
	backendPort             int
	sourceBackend           definitions.Backend
	userFound               bool
	authenticated           bool
}

type backendAuthenticationCacheEntry struct {
	authentication *CachedBackendAuthentication
	expiresAt      time.Time
}

type backendAuthenticationSweepRunner interface {
	Run(stop <-chan struct{}, sweep func())
}

type periodicBackendAuthenticationSweepRunner struct {
	interval time.Duration
}

// Run sweeps on a cache-owned ticker until the lifecycle is closed.
func (r periodicBackendAuthenticationSweepRunner) Run(stop <-chan struct{}, sweep func()) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sweep()
		case <-stop:
			return
		}
	}
}

type backendAuthenticationCacheLifecycle struct {
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// newBackendAuthenticationCacheLifecycle starts one runner owned by the cache instance.
func newBackendAuthenticationCacheLifecycle(cache *PositiveBackendAuthenticationCache, runner backendAuthenticationSweepRunner) *backendAuthenticationCacheLifecycle {
	if cache == nil || runner == nil {
		return nil
	}

	lifecycle := &backendAuthenticationCacheLifecycle{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}

	go func() {
		defer close(lifecycle.done)

		runner.Run(lifecycle.stop, func() { cache.SweepExpired() })
	}()

	return lifecycle
}

// close stops and joins the owned runner exactly once.
func (l *backendAuthenticationCacheLifecycle) close() {
	if l == nil {
		return
	}

	l.stopOnce.Do(func() { close(l.stop) })
	<-l.done
}

// PositiveBackendAuthenticationCache owns positive backend snapshots, expiry, and identity indexes.
type PositiveBackendAuthenticationCache struct {
	storage   *localcache.MemoryShardedCache
	clock     func() time.Time
	lifecycle *backendAuthenticationCacheLifecycle
	index     map[string]map[string]struct{}
	owners    map[string][]string
	mu        sync.Mutex
	closeOnce sync.Once
	closed    bool
}

var defaultPositiveBackendAuthenticationCache = newPositiveBackendAuthenticationCache(
	time.Now,
	periodicBackendAuthenticationSweepRunner{interval: backendAuthenticationSweepInterval},
)

// backendAuthenticationCache returns the request dependency or the process-wide default.
func (a *AuthState) backendAuthenticationCache() *PositiveBackendAuthenticationCache {
	if a != nil && a.deps.BackendAuthenticationCache != nil {
		return a.deps.BackendAuthenticationCache
	}

	return defaultPositiveBackendAuthenticationCache
}

// storePositiveBackendAuthentication captures one complete successful backend result.
func (a *AuthState) storePositiveBackendAuthentication(ctx *gin.Context, result *PassDBResult) bool {
	if a == nil || result == nil || a.Cfg() == nil {
		return false
	}

	return a.backendAuthenticationCache().StoreForRequest(
		ctx,
		a,
		result,
		a.Cfg().GetServer().GetLocalCacheAuthTTL(),
		a.Request.Username,
		a.GetAccount(),
	)
}

// NewPositiveBackendAuthenticationCache creates an isolated positive backend cache.
func NewPositiveBackendAuthenticationCache(clock func() time.Time) *PositiveBackendAuthenticationCache {
	return newPositiveBackendAuthenticationCache(clock, nil)
}

// newPositiveBackendAuthenticationCache creates a cache with an optional owned sweep runner.
func newPositiveBackendAuthenticationCache(clock func() time.Time, runner backendAuthenticationSweepRunner) *PositiveBackendAuthenticationCache {
	if clock == nil {
		clock = time.Now
	}

	cache := &PositiveBackendAuthenticationCache{
		storage: localcache.NewMemoryShardedCache(32, -1, 0),
		clock:   clock,
		index:   make(map[string]map[string]struct{}),
		owners:  make(map[string][]string),
	}
	cache.lifecycle = newBackendAuthenticationCacheLifecycle(cache, runner)

	return cache
}

// preparedCredentialDigest returns the canonical prepared credential digest.
func preparedCredentialDigest(auth *AuthState) string {
	if auth == nil {
		return ""
	}

	var digest string

	auth.Request.Password.WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		prepared := util.PreparePasswordBytes(value)
		defer clear(prepared)

		digest = util.GetHashBytes(prepared)
	})

	return digest
}

// requestPreparedCredentialDigest derives a binary digest from request configuration only.
func requestPreparedCredentialDigest(auth *AuthState) ([sha256.Size]byte, bool) {
	if auth == nil || auth.Cfg() == nil {
		return [sha256.Size]byte{}, false
	}

	var (
		digest [sha256.Size]byte
		valid  bool
	)

	auth.Request.Password.WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		prepared, ok := util.PreparePasswordBytesWithConfig(value, auth.Cfg())
		if !ok {
			return
		}

		defer clear(prepared)

		digest = sha256.Sum256(prepared)
		valid = true
	})

	return digest, valid
}

// buildBackendAuthenticationCacheKey derives an opaque key without materializing a password string.
func buildBackendAuthenticationCacheKey(auth *AuthState) (BackendAuthenticationCacheKey, bool) {
	credentialDigest, ok := requestPreparedCredentialDigest(auth)
	if !ok || auth.Request.Protocol == nil {
		return BackendAuthenticationCacheKey{}, false
	}

	clientIP := auth.Request.ClientIP
	if clientIP == "" {
		clientIP = defaultClientIPAny
	}

	parts := []string{backendAuthenticationCacheKeyVersion, auth.Request.Username, auth.Request.Service, auth.Request.Protocol.Get(), clientIP}
	hasher := sha256.New()
	length := make([]byte, binary.MaxVarintLen64)

	for _, part := range parts {
		n := binary.PutUvarint(length, uint64(len(part)))
		_, _ = hasher.Write(length[:n])
		_, _ = hasher.Write([]byte(part))
	}

	n := binary.PutUvarint(length, uint64(len(credentialDigest)))
	_, _ = hasher.Write(length[:n])
	_, _ = hasher.Write(credentialDigest[:])

	var key BackendAuthenticationCacheKey
	copy(key.digest[:], hasher.Sum(nil))

	return key, true
}

// storageKey returns a private opaque storage identifier.
func (k BackendAuthenticationCacheKey) storageKey() string {
	return base64.RawURLEncoding.EncodeToString(k.digest[:])
}

// transformSlice converts one slice while preserving nil and rejecting invalid elements.
func transformSlice[S any, D any](source []S, convert func(S) (D, bool)) ([]D, bool) {
	if source == nil {
		return nil, true
	}

	result := make([]D, len(source))

	for index, value := range source {
		converted, ok := convert(value)
		if !ok {
			return nil, false
		}

		result[index] = converted
	}

	return result, true
}

// transformStringMap converts one string-keyed map while preserving nil.
func transformStringMap[S any, D any](source map[string]S, convert func(S) (D, bool)) (map[string]D, bool) {
	if source == nil {
		return nil, true
	}

	result := make(map[string]D, len(source))

	for key, value := range source {
		converted, ok := convert(value)
		if !ok {
			return nil, false
		}

		result[key] = converted
	}

	return result, true
}

// encode converts one supported backend value to the immutable cache contract.
func (e *backendAuthenticationValueEncoder) encode(value any, depth int) (backendAuthenticationValue, bool) {
	if depth > backendAuthenticationMaxValueDepth || e.nodes >= backendAuthenticationMaxValueNodes {
		return backendAuthenticationValue{}, false
	}

	e.nodes++

	switch typed := value.(type) {
	case nil:
		return backendAuthenticationValue{kind: backendAuthenticationValueNil}, true
	case bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return backendAuthenticationValue{kind: backendAuthenticationValueScalar, scalar: typed}, true
	case []byte:
		return backendAuthenticationValue{kind: backendAuthenticationValueBytes, bytes: slices.Clone(typed)}, true
	case []string:
		return backendAuthenticationValue{kind: backendAuthenticationValueStrings, strings: slices.Clone(typed)}, true
	case []any:
		values, ok := transformSlice(typed, func(item any) (backendAuthenticationValue, bool) {
			return e.encode(item, depth+1)
		})

		return backendAuthenticationValue{kind: backendAuthenticationValueList, list: values}, ok
	case map[string]any:
		values, ok := transformStringMap(typed, func(item any) (backendAuthenticationValue, bool) {
			return e.encode(item, depth+1)
		})

		return backendAuthenticationValue{kind: backendAuthenticationValueObject, object: values}, ok
	case []pluginapi.PolicyFact:
		facts, ok := transformSlice(typed, func(fact pluginapi.PolicyFact) (backendAuthenticationPolicyFact, bool) {
			encoded, encodedOK := e.encode(fact.Value, depth+1)

			return backendAuthenticationPolicyFact{attribute: fact.Attribute, value: encoded}, encodedOK
		})

		return backendAuthenticationValue{kind: backendAuthenticationValuePolicyFacts, policyFacts: facts}, ok
	default:
		return backendAuthenticationValue{}, false
	}
}

// materialize creates one mutable request-owned value from the immutable contract.
func (v backendAuthenticationValue) materialize(depth int, nodes *int) (any, bool) {
	if depth > backendAuthenticationMaxValueDepth || *nodes >= backendAuthenticationMaxValueNodes {
		return nil, false
	}

	*nodes = *nodes + 1

	switch v.kind {
	case backendAuthenticationValueNil:
		return nil, true
	case backendAuthenticationValueScalar:
		return v.scalar, true
	case backendAuthenticationValueBytes:
		return slices.Clone(v.bytes), true
	case backendAuthenticationValueStrings:
		return slices.Clone(v.strings), true
	case backendAuthenticationValueList:
		return transformSlice(v.list, func(item backendAuthenticationValue) (any, bool) {
			return item.materialize(depth+1, nodes)
		})
	case backendAuthenticationValueObject:
		return transformStringMap(v.object, func(item backendAuthenticationValue) (any, bool) {
			return item.materialize(depth+1, nodes)
		})
	case backendAuthenticationValuePolicyFacts:
		return transformSlice(v.policyFacts, func(fact backendAuthenticationPolicyFact) (pluginapi.PolicyFact, bool) {
			value, ok := fact.value.materialize(depth+1, nodes)

			return pluginapi.PolicyFact{Attribute: fact.attribute, Value: value}, ok
		})
	default:
		return nil, false
	}
}

// encodeBackendAttributes converts backend attributes into immutable values.
func encodeBackendAttributes(source bktype.AttributeMapping, encoder *backendAuthenticationValueEncoder) (map[string][]backendAuthenticationValue, bool) {
	return transformStringMap(source, func(values []any) ([]backendAuthenticationValue, bool) {
		return transformSlice(values, func(value any) (backendAuthenticationValue, bool) {
			return encoder.encode(value, 1)
		})
	})
}

// materializeBackendAttributes creates one request-owned backend attribute map.
func materializeBackendAttributes(source map[string][]backendAuthenticationValue, nodes *int) (bktype.AttributeMapping, bool) {
	return transformStringMap(source, func(values []backendAuthenticationValue) ([]any, bool) {
		return transformSlice(values, func(value backendAuthenticationValue) (any, bool) {
			return value.materialize(1, nodes)
		})
	})
}

// captureCachedBackendAuthentication creates one immutable backend result snapshot.
func captureCachedBackendAuthentication(ctx *gin.Context, auth *AuthState, result *PassDBResult) (*CachedBackendAuthentication, bool) {
	if auth == nil || result == nil || !result.Authenticated || !result.UserFound {
		return nil, false
	}

	encoder := &backendAuthenticationValueEncoder{}

	attributes, ok := encodeBackendAttributes(result.Attributes, encoder)
	if !ok {
		return nil, false
	}

	additional, ok := transformStringMap(result.AdditionalAttributes, func(value any) (backendAuthenticationValue, bool) {
		return encoder.encode(value, 1)
	})
	if !ok {
		return nil, false
	}

	contextAccount := result.Account
	if ctx != nil && ctx.GetString(definitions.CtxAccountKey) != "" {
		contextAccount = ctx.GetString(definitions.CtxAccountKey)
	}

	return &CachedBackendAuthentication{
		attributes: attributes, additionalAttributes: additional,
		groups: slices.Clone(result.Groups), groupDistinguishedNames: slices.Clone(result.GroupDistinguishedNames),
		backendRef: result.BackendRef, backendName: result.BackendName,
		accountField: result.AccountField, account: result.Account, contextAccount: contextAccount,
		totpSecretField: result.TOTPSecretField, totpRecoveryField: result.TOTPRecoveryField,
		uniqueUserIDField: result.UniqueUserIDField, displayNameField: result.DisplayNameField,
		backendAddress: auth.Runtime.UsedBackendIP, backendPort: auth.Runtime.UsedBackendPort,
		sourceBackend: result.Backend, userFound: result.UserFound, authenticated: result.Authenticated,
	}, true
}

// isCompletePositive reports whether the snapshot satisfies the cache invariant.
func (d *CachedBackendAuthentication) isCompletePositive() bool {
	return d != nil && d.authenticated && d.userFound && d.sourceBackend != definitions.BackendUnknown
}

// materialize creates one complete request-owned backend snapshot.
func (d *CachedBackendAuthentication) materialize() (*appliedBackendAuthentication, bool) {
	if !d.isCompletePositive() {
		return nil, false
	}

	nodes := 0

	attributes, ok := materializeBackendAttributes(d.attributes, &nodes)
	if !ok {
		return nil, false
	}

	additional, ok := transformStringMap(d.additionalAttributes, func(value backendAuthenticationValue) (any, bool) {
		return value.materialize(1, &nodes)
	})
	if !ok {
		return nil, false
	}

	return &appliedBackendAuthentication{
		attributes: attributes, additionalAttributes: additional,
		groups: slices.Clone(d.groups), groupDistinguishedNames: slices.Clone(d.groupDistinguishedNames),
		backendRef: d.backendRef, backendName: d.backendName,
		accountField: d.accountField, account: d.account, contextAccount: d.contextAccount,
		totpSecretField: d.totpSecretField, totpRecoveryField: d.totpRecoveryField,
		uniqueUserIDField: d.uniqueUserIDField, displayNameField: d.displayNameField,
		backendAddress: d.backendAddress, backendPort: d.backendPort,
		sourceBackend: d.sourceBackend, userFound: d.userFound, authenticated: d.authenticated,
	}, true
}

// apply installs request-owned backend identity while preserving authority state.
func (d *appliedBackendAuthentication) apply(ctx *gin.Context, auth *AuthState) bool {
	if d == nil || ctx == nil || auth == nil {
		return false
	}

	auth.ReplaceAllAttributes(d.attributes)
	auth.SetResolvedGroups(d.groups, d.groupDistinguishedNames)
	auth.Runtime.AdditionalAttributes = d.additionalAttributes
	auth.Runtime.RemoteBackendRef = d.backendRef
	auth.Runtime.BackendName = d.backendName
	auth.Runtime.AccountField = d.accountField
	auth.Runtime.AccountName = d.account
	auth.Runtime.TOTPSecretField = d.totpSecretField
	auth.Runtime.TOTPRecoveryField = d.totpRecoveryField
	auth.Runtime.UniqueUserIDField = d.uniqueUserIDField
	auth.Runtime.DisplayNameField = d.displayNameField
	auth.Runtime.UsedBackendIP = d.backendAddress
	auth.Runtime.UsedBackendPort = d.backendPort
	auth.Runtime.SourcePassDBBackend = d.sourceBackend
	auth.Runtime.UsedPassDBBackend = definitions.BackendLocalCache
	auth.Runtime.UserFound = d.userFound
	auth.Runtime.Authenticated = d.authenticated
	ctx.Set(definitions.CtxAccountKey, d.contextAccount)

	if len(d.additionalAttributes) > 0 {
		ctx.Set(definitions.CtxAdditionalAttributesKey, d.additionalAttributes)
	}

	ctx.Set(cachedBackendAuthenticationContextKey, d)

	return true
}

// passDBResult projects request-owned data into one pooled result without cloning.
func (d *appliedBackendAuthentication) passDBResult() (*PassDBResult, bool) {
	if d == nil || !d.authenticated || !d.userFound {
		return nil, false
	}

	result := GetPassDBResultFromPool()
	result.Authenticated = d.authenticated
	result.UserFound = d.userFound
	result.Backend = d.sourceBackend
	result.BackendName = d.backendName
	result.BackendRef = d.backendRef
	result.AccountField = d.accountField
	result.Account = d.account
	result.TOTPSecretField = d.totpSecretField
	result.TOTPRecoveryField = d.totpRecoveryField
	result.UniqueUserIDField = d.uniqueUserIDField
	result.DisplayNameField = d.displayNameField
	result.Attributes = d.attributes
	result.Groups = d.groups
	result.GroupDistinguishedNames = d.groupDistinguishedNames
	result.AdditionalAttributes = d.additionalAttributes

	return result, true
}

// cachedBackendAuthenticationForRequest returns the owned warm snapshot.
func cachedBackendAuthenticationForRequest(ctx *gin.Context) (*appliedBackendAuthentication, bool) {
	if ctx == nil {
		return nil, false
	}

	value, found := ctx.Get(cachedBackendAuthenticationContextKey)
	if !found {
		return nil, false
	}

	authentication, ok := value.(*appliedBackendAuthentication)

	return authentication, ok && authentication != nil
}

// StoreForRequest records one request-eligible positive backend result.
func (c *PositiveBackendAuthenticationCache) StoreForRequest(
	ctx *gin.Context,
	auth *AuthState,
	result *PassDBResult,
	ttl time.Duration,
	identities ...string,
) bool {
	if c == nil || ttl <= 0 || !backendAuthenticationCacheRequestEligible(ctx, auth) {
		return false
	}

	key, ok := buildBackendAuthenticationCacheKey(auth)
	if !ok {
		return false
	}

	authentication, ok := captureCachedBackendAuthentication(ctx, auth, result)
	if !ok {
		return false
	}

	return c.storeOwned(key, authentication, ttl, identities...)
}

// storeOwned transfers one structurally validated immutable snapshot into cache ownership.
func (c *PositiveBackendAuthenticationCache) storeOwned(key BackendAuthenticationCacheKey, authentication *CachedBackendAuthentication, ttl time.Duration, identities ...string) bool {
	if c == nil || ttl <= 0 {
		return false
	}

	if !authentication.isCompletePositive() {
		return false
	}

	cacheKey := key.storageKey()
	identitySet := make(map[string]struct{})

	for _, identity := range identities {
		if identity != "" {
			identitySet[identity] = struct{}{}
		}
	}

	ownedIdentities := make([]string, 0, len(identitySet))
	for identity := range identitySet {
		ownedIdentities = append(ownedIdentities, identity)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return false
	}

	c.deleteLocked(cacheKey)
	entry := &backendAuthenticationCacheEntry{authentication: authentication, expiresAt: c.clock().Add(ttl)}
	c.owners[cacheKey] = ownedIdentities
	c.storage.Set(cacheKey, entry, -1)

	for _, identity := range ownedIdentities {
		if c.index[identity] == nil {
			c.index[identity] = make(map[string]struct{})
		}

		c.index[identity][cacheKey] = struct{}{}
	}

	return true
}

// backendAuthenticationCacheRequestEligible validates both request-context sources and cache gates.
func backendAuthenticationCacheRequestEligible(ctx *gin.Context, auth *AuthState) bool {
	if ctx == nil || auth == nil || auth.Request.NoAuth || auth.Request.Password.IsZero() || auth.HaveMonitoringFlag(definitions.MonInMemory) || auth.IsMasterUser() {
		return false
	}

	hasRequestContext := false

	if auth.Request.HTTPClientRequest != nil {
		hasRequestContext = true

		if auth.Request.HTTPClientRequest.Context().Err() != nil {
			return false
		}
	}

	if ctx.Request != nil {
		hasRequestContext = true

		if ctx.Request.Context().Err() != nil {
			return false
		}
	}

	return hasRequestContext
}

// ApplyForRequest loads and installs one request-eligible backend snapshot.
func (c *PositiveBackendAuthenticationCache) ApplyForRequest(ctx *gin.Context, auth *AuthState) bool {
	if c == nil || !backendAuthenticationCacheRequestEligible(ctx, auth) {
		return false
	}

	key, ok := buildBackendAuthenticationCacheKey(auth)
	if !ok {
		return false
	}

	snapshot, found := c.loadSnapshot(key)
	if !found {
		return false
	}

	authentication, ok := snapshot.materialize()
	if !ok {
		return false
	}

	return authentication.apply(ctx, auth)
}

// load returns one request-owned materialization without exposing cache memory.
func (c *PositiveBackendAuthenticationCache) load(key BackendAuthenticationCacheKey) (*appliedBackendAuthentication, bool) {
	snapshot, found := c.loadSnapshot(key)
	if !found {
		return nil, false
	}

	return snapshot.materialize()
}

// loadSnapshot returns one immutable unexpired cache-owned snapshot.
func (c *PositiveBackendAuthenticationCache) loadSnapshot(key BackendAuthenticationCacheKey) (*CachedBackendAuthentication, bool) {
	if c == nil {
		return nil, false
	}

	cacheKey := key.storageKey()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, false
	}

	value, found := c.storage.Get(cacheKey)
	if !found {
		return nil, false
	}

	entry, ok := value.(*backendAuthenticationCacheEntry)
	if !ok {
		c.deleteLocked(cacheKey)

		return nil, false
	}

	if !c.clock().Before(entry.expiresAt) {
		c.deleteLocked(cacheKey)
		return nil, false
	}

	if !entry.authentication.isCompletePositive() {
		c.deleteLocked(cacheKey)

		return nil, false
	}

	return entry.authentication, true
}

// InvalidateIdentities removes all variants owned by the supplied identities.
func (c *PositiveBackendAuthenticationCache) InvalidateIdentities(identities ...string) int {
	if c == nil {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0
	}

	keys := make(map[string]struct{})

	for _, identity := range identities {
		for key := range c.index[identity] {
			keys[key] = struct{}{}
		}
	}

	for key := range keys {
		c.deleteLocked(key)
	}

	return len(keys)
}

// Clear removes all cached backend snapshots and index ownership.
func (c *PositiveBackendAuthenticationCache) Clear() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.clearLocked()
}

// SweepExpired atomically removes idle expired values and all index ownership.
func (c *PositiveBackendAuthenticationCache) SweepExpired() int {
	if c == nil {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0
	}

	removed := 0
	now := c.clock()

	for key := range c.owners {
		value, found := c.storage.Get(key)
		entry, ok := value.(*backendAuthenticationCacheEntry)

		if !found || !ok || !now.Before(entry.expiresAt) {
			c.deleteLocked(key)

			removed++
		}
	}

	return removed
}

// Close clears the cache, stops its optional runner, and waits for completion.
func (c *PositiveBackendAuthenticationCache) Close() {
	if c == nil {
		return
	}

	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.clearLocked()
		lifecycle := c.lifecycle
		c.mu.Unlock()

		lifecycle.close()
	})
}

// clearLocked removes every value and ownership record while the cache lock is held.
func (c *PositiveBackendAuthenticationCache) clearLocked() {
	for key := range c.owners {
		c.storage.Delete(key)
	}

	c.owners = make(map[string][]string)
	c.index = make(map[string]map[string]struct{})
}

// deleteLocked removes one entry from storage and every identity index.
func (c *PositiveBackendAuthenticationCache) deleteLocked(key string) {
	identities := c.owners[key]

	for _, identity := range identities {
		delete(c.index[identity], key)

		if len(c.index[identity]) == 0 {
			delete(c.index, identity)
		}
	}

	delete(c.owners, key)
	c.storage.Delete(key)
}
