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

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"

	"github.com/redis/go-redis/v9"
)

const (
	redisKeyPrefix             = "HAVEIBEENPWND:"
	redisGateKeyPrefix         = "HAVEIBEENPWND:GATE:"
	cacheKeyPrefix             = "hibp:"
	headerAccept               = "Accept"
	headerUserAgent            = "User-Agent"
	headerValueAny             = "*/*"
	headerValueUserAgent       = "Nauthilus"
	postActionRuntimeParityGap = "native post-action runtime exchange is limited to later steps in the same plan"
	publicLogResultKey         = "haveibeenpwnd_result"
	publicLogResultLeaked      = "leaked"
	runtimeKeyHIBPHashInfo     = "haveibeenpwnd_hash_info"
	runtimeKeyLegacyRT         = "rt"
)

type checkOutcome struct {
	result   string
	hashInfo string
	count    int
	leaked   bool
	enqueued bool
}

// Enqueue validates request eligibility and runs the HIBP check with request-scoped credentials.
func (t postActionTarget) Enqueue(ctx context.Context, request pluginapi.PostActionRequest) (pluginapi.PostActionEnqueueResult, error) {
	return t.enqueueWithCredentials(ctx, request, request.Credentials)
}

// enqueueWithCredentials runs the HIBP check when a request-scoped credential provider is available.
func (t postActionTarget) enqueueWithCredentials(
	ctx context.Context,
	request pluginapi.PostActionRequest,
	credentials pluginapi.CredentialProvider,
) (pluginapi.PostActionEnqueueResult, error) {
	if t.plugin == nil {
		return pluginapi.PostActionEnqueueResult{}, fmt.Errorf("haveibeenpwnd post-action has no plugin")
	}

	state := t.plugin.snapshot()

	ctx, span := startHIBPSpan(ctx, state.tracer, operationCheck)
	defer span.End()

	if shouldSkipRequest(request.Snapshot) {
		recordSkipped(ctx, state, span)

		return pluginapi.PostActionEnqueueResult{Enqueued: false}, nil
	}

	hash, ok, err := sha1FromCredentials(ctx, credentials)
	if err != nil {
		span.RecordError(err)

		return pluginapi.PostActionEnqueueResult{}, err
	}

	if !ok {
		recordSkipped(ctx, state, span)

		return pluginapi.PostActionEnqueueResult{Enqueued: false}, nil
	}

	if state.cache == nil {
		return pluginapi.PostActionEnqueueResult{}, fmt.Errorf("haveibeenpwnd cache is unavailable")
	}

	outcome, err := checkPasswordHash(ctx, state, request.Snapshot, hash)
	if err != nil {
		span.RecordError(err)

		return pluginapi.PostActionEnqueueResult{}, err
	}

	state.metrics.recordCheckResult(ctx, outcome.result)
	span.SetAttributes(pluginapi.TraceAttribute{Key: traceAttrResult, Value: outcome.result})
	logOutcome(ctx, state, outcome)

	return enqueueResultFromOutcome(outcome), nil
}

// shouldSkipRequest preserves the Lua authenticated and no-auth gates.
func shouldSkipRequest(snapshot pluginapi.RequestSnapshot) bool {
	return snapshot.Runtime.NoAuth || !snapshot.Runtime.Authenticated
}

// sha1FromCredentials computes the lower-case SHA-1 hash inside the secret closure.
func sha1FromCredentials(ctx context.Context, credentials pluginapi.CredentialProvider) (string, bool, error) {
	if credentials == nil {
		return "", false, nil
	}

	secret, ok := credentials.Password(ctx)
	if !ok || secret == nil || secret.IsZero() {
		return "", false, nil
	}

	digest := sha1.New()
	wrote := false

	err := secret.WithBytes(func(value []byte) error {
		if len(value) == 0 {
			return nil
		}

		wrote = true
		_, writeErr := digest.Write(value)

		return writeErr
	})
	if err != nil {
		return "", false, err
	}

	if !wrote {
		return "", false, nil
	}

	return hex.EncodeToString(digest.Sum(nil)), true, nil
}

// checkPasswordHash evaluates local cache, Redis, gate, and HTTP paths for one SHA-1 hash.
func checkPasswordHash(ctx context.Context, state pluginState, snapshot pluginapi.RequestSnapshot, hash string) (checkOutcome, error) {
	prefix, suffix := hashParts(hash)
	cacheKey := localCacheKey(snapshot.Account, prefix)

	if cached, ok := state.cache.Get(ctx, cacheKey); ok {
		count, countOK := countFromAny(cached)
		if countOK {
			return countOutcome(resultCachePositive, resultCacheNegative, prefix, count, true), nil
		}
	}

	redisKey := redisHashKey(state.redis, snapshot.Account)

	count, found, err := redisHashCount(ctx, state.redis, redisKey, prefix)
	if err != nil {
		return checkOutcome{}, err
	}

	if found {
		cacheTTL := state.config.CacheNegativeTTL
		if count > 0 {
			cacheTTL = state.config.CachePositiveTTL
		}

		state.cache.Set(ctx, cacheKey, count, cacheTTL)

		return countOutcome(resultRedisPositive, resultRedisNegative, prefix, count, true), nil
	}

	gateKey := redisGateKey(state.redis, snapshot.Account, prefix)

	allowed, err := claimLookupGate(ctx, state.redis, gateKey, state.config.GateTTL)
	if err != nil {
		return checkOutcome{}, err
	}

	if !allowed {
		return checkOutcome{result: resultGateSkipped, enqueued: false}, nil
	}

	return lookupHTTPAndStore(ctx, state, snapshot, redisKey, cacheKey, prefix, suffix)
}

// lookupHTTPAndStore calls HIBP and stores the positive or negative result in Redis and cache.
func lookupHTTPAndStore(
	ctx context.Context,
	state pluginState,
	snapshot pluginapi.RequestSnapshot,
	redisKey string,
	cacheKey string,
	prefix string,
	suffix string,
) (checkOutcome, error) {
	count, found, err := lookupHIBPCount(ctx, state, prefix, suffix)
	if err != nil {
		return checkOutcome{}, err
	}

	if found {
		if err := writeRedisHashCount(ctx, state.redis, redisKey, prefix, count, state.config.RedisPositiveTTL); err != nil {
			return checkOutcome{}, err
		}

		state.cache.Set(ctx, cacheKey, count, state.config.CachePositiveTTL)

		if _, err := notifyPositiveMail(ctx, state, snapshot, redisKey, prefix, count); err != nil {
			return checkOutcome{}, err
		}

		return countOutcome(resultHTTPPositive, resultHTTPNegative, prefix, count, true), nil
	}

	if err := writeRedisHashCount(ctx, state.redis, redisKey, prefix, 0, state.config.RedisNegativeTTL); err != nil {
		return checkOutcome{}, err
	}

	state.cache.Set(ctx, cacheKey, 0, state.config.CacheNegativeTTL)

	return countOutcome(resultHTTPPositive, resultHTTPNegative, prefix, 0, true), nil
}

// lookupHIBPCount performs the k-anonymity HTTP lookup and parses the suffix count.
func lookupHIBPCount(ctx context.Context, state pluginState, prefix string, suffix string) (int, bool, error) {
	if state.http == nil {
		return 0, false, fmt.Errorf("haveibeenpwnd HTTP facade unavailable")
	}

	ctx, span := startHIBPSpan(ctx, state.tracer, operationHTTP)
	defer span.End()

	start := time.Now()
	response, err := state.http.Do(ctx, pluginapi.HTTPRequest{
		Method:           http.MethodGet,
		URL:              state.config.APIBaseURL + prefix,
		Service:          pluginName,
		Headers:          hibpHeaders(),
		Timeout:          state.config.HTTPTimeout,
		MaxResponseBytes: state.config.HTTPMaxResponseBytes,
	})
	duration := time.Since(start)

	if err != nil {
		span.RecordError(err)
		state.metrics.recordHTTPResult(ctx, resultHTTPError, duration)

		return 0, false, err
	}

	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("haveibeenpwnd lookup failed with status %d", response.StatusCode)
		span.RecordError(err)
		state.metrics.recordHTTPResult(ctx, resultStatusError, duration)

		return 0, false, err
	}

	count, found := parseHIBPCount(response.Body, suffix)
	if found {
		span.SetAttributes(pluginapi.TraceAttribute{Key: traceAttrResult, Value: resultHTTPPositive})
		state.metrics.recordHTTPResult(ctx, resultHTTPPositive, duration)

		return count, true, nil
	}

	span.SetAttributes(pluginapi.TraceAttribute{Key: traceAttrResult, Value: resultHTTPNegative})
	state.metrics.recordHTTPResult(ctx, resultHTTPNegative, duration)

	return 0, false, nil
}

// hibpHeaders returns the Lua-compatible HIBP request headers.
func hibpHeaders() map[string][]string {
	return map[string][]string{
		headerAccept:    {headerValueAny},
		headerUserAgent: {headerValueUserAgent},
	}
}

// parseHIBPCount finds a case-insensitive suffix match in an HIBP range response.
func parseHIBPCount(body []byte, suffix string) (int, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		responseSuffix, countText, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(responseSuffix), suffix) {
			continue
		}

		count, err := strconv.Atoi(strings.TrimSpace(countText))
		if err != nil || count <= 0 {
			return 0, false
		}

		return count, true
	}

	return 0, false
}

// redisHashCount reads the Lua-compatible Redis hash count for one prefix.
func redisHashCount(ctx context.Context, redisFacade pluginapi.Redis, redisKey string, prefix string) (int, bool, error) {
	if redisFacade == nil || redisFacade.Read() == nil {
		return 0, false, fmt.Errorf("haveibeenpwnd Redis facade unavailable")
	}

	value, err := redisFacade.Read().HGet(ctx, redisKey, prefix).Result()
	if err == redis.Nil {
		return 0, false, nil
	}

	if err != nil {
		return 0, false, err
	}

	count, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, false, nil
	}

	return count, true, nil
}

// writeRedisHashCount writes and expires the Lua-compatible Redis hash count.
func writeRedisHashCount(
	ctx context.Context,
	redisFacade pluginapi.Redis,
	redisKey string,
	prefix string,
	count int,
	ttl time.Duration,
) error {
	if redisFacade == nil || redisFacade.Write() == nil {
		return fmt.Errorf("haveibeenpwnd Redis facade unavailable")
	}

	if err := redisFacade.Write().HSet(ctx, redisKey, prefix, count).Err(); err != nil {
		return err
	}

	if err := redisFacade.Write().Expire(ctx, redisKey, ttl).Err(); err != nil {
		return err
	}

	return nil
}

// claimLookupGate acquires the Redis SET NX EX gate before an external lookup.
func claimLookupGate(ctx context.Context, redisFacade pluginapi.Redis, gateKey string, ttl time.Duration) (bool, error) {
	if redisFacade == nil || redisFacade.Write() == nil {
		return false, fmt.Errorf("haveibeenpwnd Redis facade unavailable")
	}

	return redisFacade.Write().SetNX(ctx, gateKey, "1", ttl).Result()
}

// countOutcome maps positive and negative count values into a bounded outcome.
func countOutcome(positiveResult string, negativeResult string, prefix string, count int, enqueued bool) checkOutcome {
	if count > 0 {
		return checkOutcome{
			result:   positiveResult,
			hashInfo: prefix + strconv.Itoa(count),
			count:    count,
			leaked:   true,
			enqueued: enqueued,
		}
	}

	return checkOutcome{
		result:   negativeResult,
		enqueued: enqueued,
	}
}

// enqueueResultFromOutcome maps an internal outcome into public post-action diagnostics.
func enqueueResultFromOutcome(outcome checkOutcome) pluginapi.PostActionEnqueueResult {
	result := pluginapi.PostActionEnqueueResult{
		Enqueued: outcome.enqueued,
		Logs: []pluginapi.LogField{
			{Key: logFieldResult, Value: outcome.result},
		},
	}

	if outcome.leaked {
		result.Logs = append(result.Logs, pluginapi.LogField{Key: publicLogResultKey, Value: publicLogResultLeaked})
	}

	if outcome.hashInfo != "" {
		result.RuntimeDelta = pluginapi.RuntimeDelta{
			Set: map[string]any{
				runtimeKeyHIBPHashInfo: outcome.hashInfo,
			},
		}
	}

	return result
}

// logOutcome writes a secret-free bounded result log.
func logOutcome(ctx context.Context, state pluginState, outcome checkOutcome) {
	if state.logger == nil {
		return
	}

	state.logger.Debug(ctx, "haveibeenpwnd check completed", pluginapi.LogField{Key: logFieldResult, Value: outcome.result})
}

// recordSkipped records a bounded skipped result.
func recordSkipped(ctx context.Context, state pluginState, span pluginapi.Span) {
	state.metrics.recordCheckResult(ctx, resultSkipped)
	span.SetAttributes(pluginapi.TraceAttribute{Key: traceAttrResult, Value: resultSkipped})
}

// hashParts splits a SHA-1 hash into HIBP k-anonymity prefix and suffix.
func hashParts(hash string) (string, string) {
	if len(hash) <= 5 {
		return strings.ToLower(hash), ""
	}

	return strings.ToLower(hash[:5]), strings.ToLower(hash[5:])
}

// redisHashKey returns the Lua-compatible HIBP Redis hash key.
func redisHashKey(redisFacade pluginapi.Redis, account string) string {
	key := redisKeyPrefix + md5Hex(account)
	if redisFacade == nil || redisFacade.Keys() == nil {
		return key
	}

	return redisFacade.Keys().Key(key)
}

// redisGateKey returns the Lua-compatible HIBP Redis gate key.
func redisGateKey(redisFacade pluginapi.Redis, account string, prefix string) string {
	key := redisGateKeyPrefix + md5Hex(account) + ":" + prefix
	if redisFacade == nil || redisFacade.Keys() == nil {
		return key
	}

	return redisFacade.Keys().Key(key)
}

// localCacheKey returns the Lua-compatible process-local HIBP cache key.
func localCacheKey(account string, prefix string) string {
	return cacheKeyPrefix + account + ":" + prefix
}

// md5Hex returns the lower-case MD5 hex digest used by the Lua Redis key layout.
func md5Hex(value string) string {
	sum := md5.Sum([]byte(value))

	return hex.EncodeToString(sum[:])
}

// countFromAny accepts cache values written by this plugin and defensive test fixtures.
func countFromAny(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), typed == float64(int(typed))
	case string:
		count, err := strconv.Atoi(strings.TrimSpace(typed))

		return count, err == nil
	default:
		return 0, false
	}
}
