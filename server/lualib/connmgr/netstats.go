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

package connmgr

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/util"

	psnet "github.com/shirou/gopsutil/v4/net"
	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
)

// GenericConnectionChan is a channel that carries GenericConnection updates reflecting the state of network connections.
var GenericConnectionChan = make(chan GenericConnection)

// GenericConnection represents a connection target along with its connection count.
type GenericConnection struct {
	// Target represents the endpoint address for a connection in the format host:port.
	Target string

	*TargetInfo
}

// ConnectionManager manages network connections, keeps track of targets and their connection counts, and handles synchronization.
type ConnectionManager struct {
	// targets stores a map of target addresses to their corresponding connection information.
	targets map[string]TargetInfo

	// ipTargets stores a map of DNS targets to their corresponding IP addresses.
	ipTargets map[string][]string

	ticker *time.Ticker

	// mu is a mutex used to synchronize access to targets map in ConnectionManager.
	mu sync.Mutex
}

// TargetInfo represents information about a target connection including its count and direction.
type TargetInfo struct {
	// Description provides a textual explanation of the target's purpose or other contextual information.
	Description string

	// Count represents the number of active connections to the target.
	Count int

	// Direction specifies the direction of the connection, indicating whether it is incoming or outgoing.
	Direction string
}

// manager is a global instance of ConnectionManager that handles network connections and synchronization.
var manager *ConnectionManager

func init() {
	manager = NewConnectionManager()
}

// logError logs an error message along with the provided error if err is not nil.
func logError(message string, err error) {
	if err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, message,
			definitions.LogKeyError, err,
		)
	}
}

// StartMonitoring begins monitoring IP updates at regular intervals using a ticker and a goroutine.
func (m *ConnectionManager) StartMonitoring(ctx context.Context, cfg config.File) {
	m.ticker = time.NewTicker(time.Minute)

	go func() {
		for {
			select {
			case <-m.ticker.C:
				m.checkForIPUpdates(ctx, cfg)
			case <-ctx.Done():
				m.ticker.Stop()

				return
			}
		}
	}()
}

// equalIPs compares two slices of IP address strings and returns true if they are equal, otherwise returns false.
func equalIPs(ipListA, ipListB []string) bool {
	if len(ipListA) != len(ipListB) {
		return false
	}

	sort.Strings(ipListA)
	sort.Strings(ipListB)

	for i, v := range ipListA {
		if ipListB[i] != v {
			return false
		}
	}

	return true
}

// createDeadlineContext sets a deadline for the provided context based on the server DNS timeout configuration.
func createDeadlineContext(ctx context.Context, cfg config.File) (context.Context, context.CancelFunc) {
	return context.WithDeadline(ctx, time.Now().Add(cfg.GetServer().GetDNS().GetTimeout()*time.Second))
}

// NewConnectionManager returns a new instance of ConnectionManager with an initialized targets map.
func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		targets:   make(map[string]TargetInfo),
		ipTargets: make(map[string][]string),
	}
}

// GetConnectionManager returns the global instance of ConnectionManager, facilitating access to network connection management.
func GetConnectionManager() *ConnectionManager {
	return manager
}

// checkForIPUpdates updates the IP addresses for each target in the ConnectionManager.
func (m *ConnectionManager) checkForIPUpdates(ctx context.Context, cfg config.File) {
	m.mu.Lock()

	defer m.mu.Unlock()

	for target := range m.targets {
		host, _, err := net.SplitHostPort(target)
		if err != nil {
			continue
		}

		ctxTimeout, cancel := createDeadlineContext(ctx, cfg)
		resolver := util.NewDNSResolver()

		tr := monittrace.New("nauthilus/dns")
		tctx, tsp := tr.StartClient(ctxTimeout, "dns.lookup",
			attribute.String("rpc.system", "dns"),
			attribute.String("peer.service", "dns"),
			attribute.String("dns.question.name", host),
			attribute.String("dns.question.type", "A|AAAA"),
		)

		hostPeer, port, ok := util.DNSResolverPeer(cfg)
		if ok {
			tsp.SetAttributes(
				attribute.String("peer.hostname", hostPeer),
				attribute.Int("peer.port", port),
			)
		}

		ips, err := resolver.LookupHost(tctx, host)
		if err != nil {
			tsp.RecordError(err)
			cancel()
			tsp.End()

			continue
		}

		if !equalIPs(m.ipTargets[target], ips) {
			m.ipTargets[target] = ips

			level.Debug(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Updated IPs for target '%s': %v\n", target, ips))
		}

		tsp.SetAttributes(attribute.Int("dns.answer.count", len(ips)))
		tsp.End()

		cancel()
	}
}

// Register adds a new target with the specified description and  direction to the ConnectionManager if it does not already exist.
func (m *ConnectionManager) Register(ctx context.Context, cfg config.File, target, direction string, description string) {
	m.mu.Lock()

	defer m.mu.Unlock()

	// Check if target is already registered with the same direction
	if knownTarget, exists := m.targets[target]; exists && knownTarget.Direction == direction {
		return
	}

	// Resolve DNS name to IP addresses
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		logError("Error while proccessing the target", err)

		return
	}

	ctxTimeut, cancel := createDeadlineContext(ctx, cfg)

	defer cancel()

	resolver := util.NewDNSResolver()

	tr := monittrace.New("nauthilus/dns")
	tctx, tsp := tr.StartClient(ctxTimeut, "dns.lookup",
		attribute.String("rpc.system", "dns"),
		attribute.String("peer.service", "dns"),
		attribute.String("dns.question.name", host),
		attribute.String("dns.question.type", "A|AAAA"),
	)

	hostPeer, port, ok := util.DNSResolverPeer(cfg)
	if ok {
		tsp.SetAttributes(
			attribute.String("peer.hostname", hostPeer),
			attribute.Int("peer.port", port),
		)
	}

	ips, err := resolver.LookupHost(tctx, host)
	if err != nil {
		tsp.RecordError(err)
		logError(fmt.Sprintf("Unable to resolve DNS name '%s'", host), err)
		tsp.End()

		return
	}

	// Store IP addresses for the DNS name
	m.ipTargets[target] = ips
	tsp.SetAttributes(attribute.Int("dns.answer.count", len(ips)))
	tsp.End()

	m.targets[target] = TargetInfo{
		Description: description,
		Direction:   direction,
	}
}

// GetCount retrieves the connection count for the specified target.
// Returns the count of connections and a boolean indicating if the target was found.
func (m *ConnectionManager) GetCount(target string) (int, bool) {
	m.mu.Lock()

	defer m.mu.Unlock()

	info, ok := m.targets[target]

	return info.Count, ok
}

// UpdateCounts refreshes the connection counts for all registered targets based on the current network connections.
func (m *ConnectionManager) UpdateCounts() {
	connections, err := psnet.Connections("tcp")
	if err != nil {
		logError("Error when retrieving the connections", err)

		return
	}

	m.mu.Lock()

	defer m.mu.Unlock()

	for target, info := range m.targets {
		_, portStr, err := net.SplitHostPort(target)
		if err != nil {
			logError(fmt.Sprintf("Error when processing the target '%s'", target), err)

			continue
		}

		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			logError(fmt.Sprintf("Invalid port number for destination '%s'", target), err)

			continue
		}

		count := 0
		for _, conn := range connections {
			var addr psnet.Addr

			if conn.Status != "ESTABLISHED" {
				continue
			}

			if info.Direction == "local" {
				addr = conn.Laddr
			} else {
				addr = conn.Raddr
			}

			for _, ip := range m.ipTargets[target] {
				if ip == "0.0.0.0" || ip == "::" || ip == addr.IP {
					if addr.Port == uint32(port) {
						count++
					}
				}
			}
		}

		info.Count = count
		m.targets[target] = info

		GenericConnectionChan <- GenericConnection{Target: target, TargetInfo: &info}
	}
}

// StartTicker launches a ticker that triggers the update of connection counts at the specified interval.
func (m *ConnectionManager) StartTicker(interval time.Duration) {
	ticker := time.NewTicker(interval)

	defer ticker.Stop()

	for range ticker.C {
		m.UpdateCounts()
	}
}

// StartTickerWithContext launches a ticker that triggers the update of connection counts at the specified interval.
// The ticker is stopped and the function returns when ctx is canceled.
func (m *ConnectionManager) StartTickerWithContext(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.UpdateCounts()
		}
	}
}

// luaCountOpenConnections returns the number of open connections for a given target. If the target is not registered,
// it returns nil and an error message.
func (m *ConnectionManager) luaCountOpenConnections(L *lua.LState) int {
	target := L.ToString(1)

	count, ok := m.GetCount(target)
	if !ok {
		L.Push(lua.LNil)
		L.Push(lua.LString("Target not registered"))

		return 2
	}

	L.Push(lua.LNumber(count))

	return 1
}

// luaRegisterTarget registers a new target and its direction from Lua state into the ConnectionManager.
func (m *ConnectionManager) luaRegisterTarget(ctx context.Context, cfg config.File) lua.LGFunction {
	return func(L *lua.LState) int {
		target := L.ToString(1)
		direction := L.ToString(2)
		description := L.ToString(3)

		m.Register(ctx, cfg, target, direction, description)

		return 0
	}
}

// LoaderModPsnet is a function that registers the "psnet" module in the given Lua state.
// It creates a new Lua table, assigns functions from exportsModPsnet to it,
// and pushes it onto the Lua stack. It returns 1 to indicate that one value
// has been pushed onto the stack.
func LoaderModPsnet(ctx context.Context, cfg config.File) lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnRegisterConnectionTarget: manager.luaRegisterTarget(ctx, cfg),
			definitions.LuaFnGetConnectionTarget:      manager.luaCountOpenConnections,
		})

		L.Push(mod)

		return 1
	}
}

// LoaderPsnetStateless returns an empty, stateless module placeholder for nauthilus_psnet.
// It allows require("nauthilus_psnet") to succeed before per-request binding replaces it
// with a context-aware version via BindModuleIntoReq.
func LoaderPsnetStateless() lua.LGFunction {
	return func(L *lua.LState) int {
		L.Push(L.NewTable())

		return 1
	}
}
