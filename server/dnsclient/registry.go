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

package dnsclient

import (
	"sync"

	"github.com/croessner/nauthilus/v4/server/config"
)

// Registry hands out one long-lived Client per distinct Settings value, so all
// callers with the same configuration share retries state and pooled sockets.
type Registry struct {
	observer Observer
	clients  map[Settings]*Client
	mu       sync.Mutex
}

// NewRegistry creates an empty registry whose clients report to observer.
func NewRegistry(observer Observer) *Registry {
	return &Registry{observer: observer, clients: make(map[Settings]*Client)}
}

// Client returns the shared client for the given settings, creating it on first use.
func (r *Registry) Client(settings Settings) *Client {
	settings = settings.normalized()

	r.mu.Lock()
	defer r.mu.Unlock()

	client, ok := r.clients[settings]
	if !ok {
		client = New(settings, r.observer)
		r.clients[settings] = client
	}

	return client
}

// defaultRegistry serves the process-wide clients that publish Prometheus metrics.
var defaultRegistry = NewRegistry(prometheusObserver{})

// For returns the shared process-wide client for the DNS settings of cfg.
func For(cfg config.File) *Client {
	return defaultRegistry.Client(SettingsFromConfig(cfg))
}
