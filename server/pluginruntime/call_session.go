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

package pluginruntime

import "context"

// pluginCallSessionKey carries the request session from the point where a request snapshot is built to the shared
// plugin call boundary.
type pluginCallSessionKey struct{}

// withPluginCallSession attaches a request session to ctx so plugin call observations can name the request. An empty
// session leaves ctx unchanged.
func withPluginCallSession(ctx context.Context, session string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}

	if session == "" {
		return ctx
	}

	return context.WithValue(ctx, pluginCallSessionKey{}, session)
}

// pluginCallSession returns the request session attached by withPluginCallSession, or an empty string.
func pluginCallSession(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	session, _ := ctx.Value(pluginCallSessionKey{}).(string)

	return session
}
