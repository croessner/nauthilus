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


package rediscli

import (
	"context"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/testing/oteltest"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestRedisTracingOmitsCommandArguments(t *testing.T) {
	recorder := &oteltest.Collector{}
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(recorder))
	previous := otel.GetTracerProvider()

	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)

		_ = provider.Shutdown(context.Background())
	})

	client := redis.NewClient(&redis.Options{Addr: "unused:6379"})
	mocked, expectations := redismock.NewClientMock()

	instrumentRedisIfEnabled(redisReadOnlyTraceConfig(), client)
	client.AddHook(redisTraceMockTransport{client: mocked})
	t.Cleanup(func() {
		_ = client.Close()
		_ = mocked.Close()
	})

	const key = "denylist:synthetic-bearer-token"

	expectations.ExpectGet(key).RedisNil()
	expectations.ExpectGet(key).RedisNil()
	_ = client.Get(t.Context(), key).Err()
	_, _ = client.Pipelined(t.Context(), func(pipe redis.Pipeliner) error {
		pipe.Get(t.Context(), key)

		return nil
	})

	if err := expectations.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}

	spans := recorder.Spans()
	if len(spans) != 2 {
		t.Fatalf("recorded %d spans, want command and pipeline spans", len(spans))
	}

	for _, span := range spans {
		for _, attr := range span.Attributes() {
			if attr.Key == "db.statement" || strings.Contains(attr.Value.String(), key) {
				t.Errorf("span %q exposes Redis command arguments through %q", span.Name(), attr.Key)
			}
		}
	}
}

type redisTraceMockTransport struct {
	client *redis.Client
}

// DialHook preserves the unused transport; command hooks terminate in redismock.
func (h redisTraceMockTransport) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

// ProcessHook routes commands through redismock after the production tracing hook.
func (h redisTraceMockTransport) ProcessHook(_ redis.ProcessHook) redis.ProcessHook {
	return h.client.Process
}

// ProcessPipelineHook resolves each pipeline command without opening a connection.
func (h redisTraceMockTransport) ProcessPipelineHook(_ redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, commands []redis.Cmder) error {
		for _, command := range commands {
			if err := h.client.Process(ctx, command); err != nil {
				return err
			}
		}

		return nil
	}
}
