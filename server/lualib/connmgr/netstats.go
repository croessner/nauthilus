package connmgr

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/log"

	"github.com/go-kit/log/level"
	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/yuin/gopher-lua"
)

// ConnectionManager manages network connections, keeps track of targets and their connection counts, and handles synchronization.
type ConnectionManager struct {
	// targets stores a map of target addresses to their corresponding connection information.
	targets map[string]TargetInfo

	// mu is a mutex used to synchronize access to targets map in ConnectionManager.
	mu sync.Mutex
}

// TargetInfo represents information about a target connection including its count and direction.
type TargetInfo struct {
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
		level.Error(log.Logger).Log(global.LogKeyError, fmt.Sprintf("%s: %v\n", message, err))
	}
}

// NewConnectionManager returns a new instance of ConnectionManager with an initialized targets map.
func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		targets: make(map[string]TargetInfo),
	}
}

// GetConnectionManager returns the global instance of ConnectionManager, facilitating access to network connection management.
func GetConnectionManager() *ConnectionManager {
	return manager
}

// Register adds a new target with the specified direction to the ConnectionManager if it does not already exist.
func (m *ConnectionManager) Register(target, direction string) {
	m.mu.Lock()

	defer m.mu.Unlock()

	if _, exists := m.targets[target]; exists {
		return
	}

	m.targets[target] = TargetInfo{Direction: direction}
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
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			logError(fmt.Sprintf("Error when processing the target '%s'", target), err)

			continue
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			logError(fmt.Sprintf("Invalid port number for destination '%s'", target), err)

			continue
		}

		count := 0
		for _, conn := range connections {
			var addr psnet.Addr

			if info.Direction == "local" {
				addr = conn.Laddr
			} else {
				addr = conn.Raddr
			}

			if host == "" || host == "0.0.0.0" || host == "::" || addr.IP == host {
				if addr.Port == uint32(port) {
					count++
				}
			}
		}

		info.Count = count
		m.targets[target] = info
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
func (m *ConnectionManager) luaRegisterTarget(L *lua.LState) int {
	target := L.ToString(1)
	direction := L.ToString(2)

	m.Register(target, direction)

	return 0
}

// exportsModPsnet contains mappings of Lua function names to their corresponding Go function implementations.
var exportsModPsnet = map[string]lua.LGFunction{
	global.LuaFnRegisterConnectionTarget: manager.luaRegisterTarget,
	global.LuaFnGetConnectionTarget:      manager.luaCountOpenConnections,
}

// LoaderModPsnet is a function that registers the "psnet" module in the given Lua state.
// It creates a new Lua table, assigns functions from exportsModPsnet to it,
// and pushes it onto the Lua stack. It returns 1 to indicate that one value
// has been pushed onto the stack.
func LoaderModPsnet(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exportsModPsnet)

	L.Push(mod)

	return 1
}
