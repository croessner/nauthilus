// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"bytes"
	"errors"
	"time"

	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
)

const canonicalBrowserEnvelopeKeyEpoch uint16 = 1

type canonicalSystemClock struct{}

func (canonicalSystemClock) Now() time.Time { return time.Now().UTC() }

// NewCanonicalBrowserRuntime composes the sole v1 browser envelope and typed Redis stores.
func NewCanonicalBrowserRuntime(handlerDeps *deps.Deps) (*cookie.CanonicalRuntime, error) {
	if handlerDeps == nil || handlerDeps.Cfg == nil || handlerDeps.Env == nil || handlerDeps.Redis == nil ||
		handlerDeps.Redis.GetWriteHandle() == nil {
		return nil, errors.New("canonical browser runtime: missing required dependency")
	}

	server := handlerDeps.Cfg.GetServer()
	if server == nil {
		return nil, errors.New("canonical browser runtime: missing server configuration")
	}

	var frontendSecret []byte

	server.GetFrontend().GetEncryptionSecret().WithBytes(func(value []byte) {
		frontendSecret = bytes.Clone(value)
	})

	defer clear(frontendSecret)

	if len(frontendSecret) == 0 {
		return nil, errors.New("canonical browser runtime: missing frontend encryption secret")
	}

	return cookie.NewCanonicalRuntime(
		frontendSecret,
		canonicalBrowserEnvelopeKeyEpoch,
		handlerDeps.Redis.GetWriteHandle(),
		server.GetRedis().GetPrefix(),
		canonicalSystemClock{},
		sessionstate.NewRandomHandleGenerator(nil),
		!handlerDeps.Env.GetDevMode(),
	)
}
