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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	dedupKeyPrefix       = "clickhouse:authdedup:"
	headerAccept         = "Accept"
	headerAuthorization  = "Authorization"
	headerContentType    = "Content-Type"
	headerUserAgent      = "User-Agent"
	headerClickHouseUser = "X-ClickHouse-User"
	headerClickHouseKey  = "X-ClickHouse-Key"
	headerValueAny       = "*/*"
	headerValueJSON      = "application/json"
	headerValueUserAgent = "Nauthilus"
	authMethodBasic      = "basic"
	authMethodNone       = "none"
	authMethodXHeaders   = "x_headers"
	statusOK             = http.StatusOK
	statusNoContent      = http.StatusNoContent
)

// Enqueue builds, batches, and flushes one ClickHouse post-action row.
//
//nolint:funlen // The enqueue path stays linear to preserve Lua action ordering.
func (t postActionTarget) Enqueue(ctx context.Context, request pluginapi.PostActionRequest) (pluginapi.PostActionEnqueueResult, error) {
	if t.plugin == nil {
		return pluginapi.PostActionEnqueueResult{}, fmt.Errorf("clickhouse post-action has no plugin")
	}

	state := t.plugin.snapshot()
	if state.cache == nil {
		return pluginapi.PostActionEnqueueResult{}, fmt.Errorf("clickhouse cache is unavailable")
	}

	ctx, span := startPostActionSpan(ctx, state.tracer, operationEnqueue, 0)
	defer span.End()

	if shouldSkipNoAuth(request.Snapshot) {
		state.metrics.recordQueueResult(ctx, resultSkipped)

		return pluginapi.PostActionEnqueueResult{Enqueued: false}, nil
	}

	allowed, err := allowAuthenticatedWrite(ctx, state, request.Snapshot)
	if err != nil {
		recordDedupFailOpen(ctx, state, span, err)
	}

	if !allowed {
		state.metrics.recordQueueResult(ctx, resultDedupSkipped)
		span.SetAttributes(pluginapi.TraceAttribute{Key: traceAttrResult, Value: resultDedupSkipped})

		return pluginapi.PostActionEnqueueResult{Enqueued: false}, nil
	}

	rowJSON, err := encodeRequestRow(request)
	if err != nil {
		span.RecordError(err)
		state.metrics.recordQueueResult(ctx, resultEncodeError)

		if state.logger != nil {
			state.logger.Error(ctx, "clickhouse row encoding failed", pluginapi.LogField{Key: logFieldResult, Value: resultEncodeError})
		}

		return pluginapi.PostActionEnqueueResult{}, err
	}

	length := state.cache.Push(ctx, state.config.CacheKey, string(rowJSON))
	state.metrics.recordQueueResult(ctx, resultQueued)
	span.SetAttributes(
		pluginapi.TraceAttribute{Key: traceAttrResult, Value: resultQueued},
		pluginapi.TraceAttribute{Key: traceAttrBatchSize, Value: length},
	)

	if state.logger != nil {
		state.logger.Debug(
			ctx,
			"clickhouse row queued",
			pluginapi.LogField{Key: logFieldRows, Value: length},
			pluginapi.LogField{Key: logFieldThreshold, Value: state.config.BatchSize},
		)
	}

	if length < state.config.BatchSize {
		return pluginapi.PostActionEnqueueResult{QueuedID: state.config.CacheKey, Enqueued: true}, nil
	}

	return pluginapi.PostActionEnqueueResult{QueuedID: state.config.CacheKey, Enqueued: true}, flushBatch(ctx, state)
}

// encodeRequestRow builds and encodes a ClickHouse row for module-cache storage.
func encodeRequestRow(request pluginapi.PostActionRequest) ([]byte, error) {
	row, err := buildRow(request)
	if err != nil {
		return nil, err
	}

	return json.Marshal(row)
}

// startPostActionSpan starts a bounded ClickHouse child span.
func startPostActionSpan(ctx context.Context, tracer pluginapi.Tracer, operation string, batchSize int) (context.Context, pluginapi.Span) {
	if ctx == nil {
		ctx = context.Background()
	}

	if tracer == nil {
		return ctx, noopSpan{}
	}

	return tracer.Start(
		ctx,
		"clickhouse.post_action."+operation,
		pluginapi.TraceAttribute{Key: traceAttrModule, Value: pluginName},
		pluginapi.TraceAttribute{Key: traceAttrComponent, Value: componentPostAction},
		pluginapi.TraceAttribute{Key: traceAttrOperation, Value: operation},
		pluginapi.TraceAttribute{Key: traceAttrBatchSize, Value: batchSize},
	)
}

// shouldSkipNoAuth preserves the Lua no-auth skip except OIDC token post-actions.
func shouldSkipNoAuth(snapshot pluginapi.RequestSnapshot) bool {
	if !snapshot.Runtime.NoAuth {
		return false
	}

	return snapshot.Protocol != "oidc" ||
		snapshot.Service != "idp" ||
		strings.TrimSpace(snapshot.IDP.GrantType) == ""
}

// allowAuthenticatedWrite applies Redis SET NX EX deduplication for authenticated requests.
func allowAuthenticatedWrite(ctx context.Context, state pluginState, snapshot pluginapi.RequestSnapshot) (bool, error) {
	if !snapshot.Runtime.Authenticated {
		return true, nil
	}

	identity := strings.TrimSpace(snapshot.Username)
	clientIP := strings.TrimSpace(snapshot.ClientIP)

	if identity == "" || clientIP == "" {
		return true, nil
	}

	if state.redis == nil || state.redis.Write() == nil {
		return true, fmt.Errorf("redis facade unavailable")
	}

	key := dedupKeyPrefix + identity + ":" + clientIP
	if keys := state.redis.Keys(); keys != nil {
		key = keys.Key(key)
	}

	ok, err := state.redis.Write().SetNX(ctx, key, "1", state.config.AuthDedupTTL).Result()
	if err != nil {
		return true, err
	}

	return ok, nil
}

// recordDedupFailOpen logs and traces a Redis dedup failure without exposing keys or identities.
func recordDedupFailOpen(ctx context.Context, state pluginState, span pluginapi.Span, err error) {
	if span != nil {
		span.RecordError(err)
	}

	if state.logger != nil {
		state.logger.Error(ctx, "clickhouse redis dedup failed open", pluginapi.LogField{Key: logFieldResult, Value: "dedup_fail_open"})
	}
}

// flushBatch posts all queued rows and requeues them on failure.
func flushBatch(ctx context.Context, state pluginState) error {
	rows := state.cache.PopAll(ctx, state.config.CacheKey)
	if len(rows) == 0 {
		return nil
	}

	ctx, span := startPostActionSpan(ctx, state.tracer, operationFlush, len(rows))
	defer span.End()

	if state.config.InsertURL == "" {
		requeueRows(ctx, state, rows)
		recordFlush(ctx, state, span, resultNoURL, 0)

		if state.logger != nil {
			state.logger.Info(ctx, "clickhouse insert URL missing; batch kept in cache", pluginapi.LogField{Key: logFieldRows, Value: len(rows)})
		}

		return nil
	}

	start := time.Now()
	response, err := postRows(ctx, state, rows)
	duration := time.Since(start)

	if err != nil {
		requeueRows(ctx, state, rows)
		span.RecordError(err)
		recordFlush(ctx, state, span, resultHTTPError, duration)

		return err
	}

	if response.StatusCode != statusOK && response.StatusCode != statusNoContent {
		requeueRows(ctx, state, rows)

		err := fmt.Errorf("clickhouse insert failed with status %d", response.StatusCode)
		span.RecordError(err)
		recordFlush(ctx, state, span, resultStatusError, duration)

		return err
	}

	recordFlush(ctx, state, span, resultSuccess, duration)

	if state.logger != nil {
		state.logger.Info(ctx, "clickhouse batch inserted", pluginapi.LogField{Key: logFieldRows, Value: len(rows)})
	}

	return nil
}

// postRows sends one newline-delimited JSONEachRow body through the host HTTP facade.
func postRows(ctx context.Context, state pluginState, rows []any) (pluginapi.HTTPResponse, error) {
	if state.http == nil {
		return pluginapi.HTTPResponse{}, fmt.Errorf("clickhouse HTTP facade unavailable")
	}

	body := ndjsonBody(rows)
	headers, authMethod := buildHeaders(state.config)

	if state.logger != nil {
		state.logger.Debug(
			ctx,
			"clickhouse batch posting",
			pluginapi.LogField{Key: logFieldRows, Value: len(rows)},
			pluginapi.LogField{Key: logFieldAuthMethod, Value: authMethod},
			pluginapi.LogField{Key: logFieldURLConfigured, Value: true},
		)
	}

	return state.http.Do(ctx, pluginapi.HTTPRequest{
		Method:           http.MethodPost,
		URL:              state.config.InsertURL,
		Service:          pluginName,
		Headers:          headers,
		Body:             body,
		Timeout:          state.config.Timeout,
		MaxResponseBytes: state.config.MaxResponseBytes,
	})
}

// buildHeaders prepares secret-safe ClickHouse HTTP headers.
func buildHeaders(config moduleConfig) (map[string][]string, string) {
	headers := map[string][]string{
		headerAccept:      {headerValueAny},
		headerUserAgent:   {headerValueUserAgent},
		headerContentType: {headerValueJSON},
	}

	user := strings.TrimSpace(config.User)
	password := config.Password

	switch {
	case user != "" && password != "":
		encoded := base64.RawStdEncoding.EncodeToString([]byte(user + ":" + password))
		headers[headerAuthorization] = []string{"Basic " + encoded}

		return headers, authMethodBasic
	case user != "" || password != "":
		if user != "" {
			headers[headerClickHouseUser] = []string{user}
		}

		if password != "" {
			headers[headerClickHouseKey] = []string{password}
		}

		return headers, authMethodXHeaders
	default:
		return headers, authMethodNone
	}
}

// ndjsonBody joins cached row JSON strings into one JSONEachRow request body.
func ndjsonBody(rows []any) []byte {
	lines := make([][]byte, 0, len(rows))
	for _, row := range rows {
		switch typed := row.(type) {
		case string:
			lines = append(lines, []byte(typed))
		case []byte:
			lines = append(lines, typed)
		default:
			encoded, err := json.Marshal(typed)
			if err == nil {
				lines = append(lines, encoded)
			}
		}
	}

	return bytes.Join(lines, []byte("\n"))
}

// requeueRows restores a flushed batch to the cache after insert failure.
func requeueRows(ctx context.Context, state pluginState, rows []any) {
	for _, row := range rows {
		state.cache.Push(ctx, state.config.CacheKey, row)
	}

	state.metrics.recordFlushResult(ctx, resultRequeued, 0)

	if state.logger != nil {
		state.logger.Warn(ctx, "clickhouse batch requeued", pluginapi.LogField{Key: logFieldRows, Value: len(rows)})
	}
}

// recordFlush records a bounded flush result in metrics, traces, and logs.
func recordFlush(ctx context.Context, state pluginState, span pluginapi.Span, result string, duration time.Duration) {
	state.metrics.recordFlushResult(ctx, result, duration)

	if span != nil {
		span.SetAttributes(pluginapi.TraceAttribute{Key: traceAttrResult, Value: result})
	}
}
