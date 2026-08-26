// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package runtime

import "context"

// contextWithHost binds one non-nil request-local host under its private key.
func contextWithHost[Host any](ctx context.Context, key any, host Host) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	if nilInterface(host) {
		return ctx
	}

	return context.WithValue(ctx, key, host)
}

// hostFromContext resolves one non-nil request-local host under its private key.
func hostFromContext[Host any](ctx context.Context, key any) (Host, bool) {
	var empty Host

	if ctx == nil {
		return empty, false
	}

	host, ok := ctx.Value(key).(Host)

	return host, ok && !nilInterface(host)
}
