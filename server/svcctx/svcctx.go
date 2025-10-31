// Copyright (C) 2024 Christian Rößner
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

// Package svcctx is a small package that provides a long-lived service/root context for the
// application. It can be initialized once at program startup and used as a
// safe fallback context in places that are not tied to an active HTTP request
// (e.g., background tasks, singleflight leaders, queues).
package svcctx

import (
	"context"
	"sync"
)

var (
	once   sync.Once
	root   context.Context
	cancel context.CancelFunc
)

// InitSvcCtx initializes the service/root context exactly once. If ctx is nil,
// context.Background() is used. The returned context can be cancelled by
// calling Cancel().
func initSvcCtx() {
	once.Do(func() {
		ctx := context.Background()
		root, cancel = context.WithCancel(ctx)
	})
}

// Get returns the initialized root context if available, otherwise
// context.Background(). This ensures callers always receive a non-nil context.
func Get() context.Context {
	if root == nil {
		return context.Background()
	}

	return root
}

// GetCtxWithCancel returns a root context and its associated cancel function, initializing them if not already set.
func GetCtxWithCancel() (context.Context, context.CancelFunc) {
	if root != nil && cancel != nil {
		return root, cancel
	}

	initSvcCtx()

	return GetCtxWithCancel()
}
