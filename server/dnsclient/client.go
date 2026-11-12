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
	"context"
	"net"
	"strings"
)

const networkUDP = "udp"

// Client is a long-lived DNS client. It bounds every lookup by the configured
// budget, sends overlapping retries, and optionally reuses pooled UDP sockets.
type Client struct {
	observer Observer
	pool     *socketPool
	dialer   *net.Dialer

	// resolvers holds one standard resolver per attempt. Separate instances keep
	// the standard library from merging a retry into the attempt it is meant to replace.
	resolvers []*net.Resolver
	settings  Settings
}

// New creates a client for the given settings. A nil observer discards all events.
func New(settings Settings, observer Observer) *Client {
	settings = settings.normalized()

	if observer == nil {
		observer = discardObserver{}
	}

	client := &Client{
		observer: observer,
		dialer:   &net.Dialer{Timeout: settings.Timeout},
		settings: settings,
	}

	if settings.PoolSize > 0 {
		client.pool = newSocketPool(client.dialer, observer, settings.PoolSize, settings.PoolMaxUses)
	}

	client.resolvers = make([]*net.Resolver, settings.Attempts)
	for index := range client.resolvers {
		client.resolvers[index] = client.newResolver()
	}

	return client
}

// newResolver builds a pure Go resolver that dials through this client when a
// custom resolver address or the socket pool is configured.
func (c *Client) newResolver() *net.Resolver {
	resolver := &net.Resolver{PreferGo: true}

	if c.settings.Resolver != "" || c.pool != nil {
		resolver.Dial = c.dial
	}

	return resolver
}

// dial connects to the configured resolver, leasing pooled sockets for UDP.
func (c *Client) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if c.settings.Resolver != "" {
		address = c.settings.Resolver
	}

	if c.pool != nil && strings.HasPrefix(network, networkUDP) {
		return c.pool.lease(ctx, network, address)
	}

	return c.dialer.DialContext(ctx, network, address)
}

// Settings returns the effective settings of the client.
func (c *Client) Settings() Settings {
	return c.settings
}

// Close releases all idle pooled sockets. Lookups in flight finish normally.
func (c *Client) Close() {
	if c.pool != nil {
		c.pool.close()
	}
}

// LookupIP resolves host to IP addresses of the given network ("ip", "ip4" or "ip6").
func (c *Client) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return runLookup(ctx, c, host, func(ctx context.Context, resolver *net.Resolver) ([]net.IP, error) {
		return resolver.LookupIP(ctx, network, host)
	})
}

// LookupHost resolves host to its addresses in string form.
func (c *Client) LookupHost(ctx context.Context, host string) ([]string, error) {
	return runLookup(ctx, c, host, func(ctx context.Context, resolver *net.Resolver) ([]string, error) {
		return resolver.LookupHost(ctx, host)
	})
}

// LookupAddr performs a reverse lookup for the given address.
func (c *Client) LookupAddr(ctx context.Context, address string) ([]string, error) {
	return runLookup(ctx, c, address, func(ctx context.Context, resolver *net.Resolver) ([]string, error) {
		return resolver.LookupAddr(ctx, address)
	})
}

// LookupTXT returns the TXT records of the given name.
func (c *Client) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return runLookup(ctx, c, name, func(ctx context.Context, resolver *net.Resolver) ([]string, error) {
		return resolver.LookupTXT(ctx, name)
	})
}

// LookupCNAME returns the canonical name of the given host.
func (c *Client) LookupCNAME(ctx context.Context, host string) (string, error) {
	return runLookup(ctx, c, host, func(ctx context.Context, resolver *net.Resolver) (string, error) {
		return resolver.LookupCNAME(ctx, host)
	})
}

// LookupMX returns the MX records of the given name.
func (c *Client) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return runLookup(ctx, c, name, func(ctx context.Context, resolver *net.Resolver) ([]*net.MX, error) {
		return resolver.LookupMX(ctx, name)
	})
}

// LookupNS returns the NS records of the given name.
func (c *Client) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	return runLookup(ctx, c, name, func(ctx context.Context, resolver *net.Resolver) ([]*net.NS, error) {
		return resolver.LookupNS(ctx, name)
	})
}

// runLookup executes one lookup as a race of overlapping attempts inside the
// client budget and reports the outcome to the observer.
func runLookup[T any](ctx context.Context, c *Client, name string, lookup lookupFunc[T]) (T, error) {
	ctx, cancel := c.boundContext(ctx)
	defer cancel()

	race := newLookupRace(ctx, name, c.resolvers, lookup)
	value, err := race.run(c.settings.RetryInterval)

	c.observer.LookupDone(classifyResult(err), race.started)

	return value, err
}

// boundContext applies the lookup budget unless the caller already set a
// deadline. Cancelling the result stops attempts that lost the race.
func (c *Client) boundContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}

	return context.WithTimeout(ctx, c.settings.Timeout)
}
