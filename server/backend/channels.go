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

package backend

import (
	"fmt"
	"sync"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
)

func TrySignalDone(ch chan bktype.Done) {
	if ch == nil {
		return
	}

	select {
	case ch <- bktype.Done{}:
	default:
	}
}

// Channel is an interface comprising methods to retrieve LDAPChannel and LuaChannel instances.
type Channel interface {
	// GetLdapChannel retrieves and returns the LDAPChannel instance associated with the implementation of the Channel interface.
	GetLdapChannel() LDAPChannel

	// GetLuaChannel retrieves and returns the LuaChannel instance associated with the Channel interface implementation.
	GetLuaChannel() LuaChannel
}

type channelImpl struct {
	ldapChannel LDAPChannel
	luaChannel  LuaChannel
	ldapOnce    sync.Once
	luaOnce     sync.Once
}

// GetLdapChannel retrieves and returns the LDAPChannel instance associated with the channelImpl instance.
func (c *channelImpl) GetLdapChannel() LDAPChannel {
	if c == nil {
		return nil
	}

	return c.ldapChannel
}

func (c *channelImpl) GetLuaChannel() LuaChannel {
	if c == nil {
		return nil
	}

	return c.luaChannel
}

var _ Channel = &channelImpl{}

// NewChannel initializes and returns a new instance of the Channel interface implementation.
func NewChannel(cfg config.File) Channel {
	c := &channelImpl{}

	if cfg != nil && cfg.HaveLDAPBackend() {
		c.ldapChannel = NewLDAPChannel(definitions.DefaultBackendName)
	}

	if cfg != nil && cfg.HaveLuaBackend() {
		c.luaChannel = NewLuaChannel(definitions.DefaultBackendName)
	}

	return c
}

// LDAPChannel defines an interface for managing LDAP-related channels for communication and operation handling.
type LDAPChannel interface {
	// GetLookupEndChan returns a channel that signals the completion of lookup operations.
	GetLookupEndChan(poolName string) chan bktype.Done

	// GetAuthEndChan returns the channel used to signal the completion of authentication operations.
	GetAuthEndChan(poolName string) chan bktype.Done

	// GetPoolNames retrieves and returns a list of names for all configured LDAP connection pools.
	GetPoolNames() []string

	// AddChannel creates and initializes all necessary channels for the specified LDAP connection pool by poolName.
	AddChannel(poolName string) error
}

type ldapChannelImpl struct {
	lookupEndChan map[string]chan bktype.Done
	authEndChan   map[string]chan bktype.Done
}

// GetLookupEndChan returns the channel used to signal the completion of lookup operations.
func (c *ldapChannelImpl) GetLookupEndChan(poolName string) chan bktype.Done {
	if _, okay := c.lookupEndChan[poolName]; !okay {
		panic(fmt.Sprintf("pool name not found: %s", poolName))
	}

	return c.lookupEndChan[poolName]
}

// GetAuthEndChan returns the channel used to signal the completion of authentication operations.
func (c *ldapChannelImpl) GetAuthEndChan(poolName string) chan bktype.Done {
	if _, okay := c.authEndChan[poolName]; !okay {
		panic(fmt.Sprintf("pool name not found: %s", poolName))
	}

	return c.authEndChan[poolName]
}

// GetPoolNames retrieves all pool names as a slice of strings from the `lookupEndChan` map in the `ldapChannelImpl` struct.
func (c *ldapChannelImpl) GetPoolNames() []string {
	poolNames := make([]string, 0, len(c.lookupEndChan))

	for poolName := range c.lookupEndChan {
		poolNames = append(poolNames, poolName)
	}

	return poolNames
}

// AddChannel creates and initializes the necessary channels for a specific pool name in the `ldapChannelImpl` instance.
// Returns an error if the provided pool name matches the reserved `DefaultBackendName`.
func (c *ldapChannelImpl) AddChannel(poolName string) error {
	if poolName == definitions.DefaultBackendName {
		return fmt.Errorf("pool name cannot be %s", definitions.DefaultBackendName)
	}

	c.lookupEndChan[poolName] = make(chan bktype.Done, 1)
	c.authEndChan[poolName] = make(chan bktype.Done, 1)

	return nil
}

var _ LDAPChannel = &ldapChannelImpl{}

func NewLDAPChannel(poolName string) LDAPChannel {
	lookupEndChan := make(map[string]chan bktype.Done)
	authEndChan := make(map[string]chan bktype.Done)

	lookupEndChan[poolName] = make(chan bktype.Done, 1)
	authEndChan[poolName] = make(chan bktype.Done, 1)

	return &ldapChannelImpl{
		lookupEndChan: lookupEndChan,
		authEndChan:   authEndChan,
	}
}

// LuaChannel defines an interface for managing Lua-related channels used for communication and request handling.
type LuaChannel interface {
	// GetLookupEndChan returns a channel used to signal the completion of lookup operations.
	GetLookupEndChan(backendName string) chan bktype.Done

	// GetBackendNames returns a list of all available backend names configured in the LuaChannel implementation.
	GetBackendNames() []string

	// AddChannel adds a new channel for the specified backend identified by the backendName.
	// Returns an error if the backendName is invalid or the channel could not be created.
	AddChannel(backendName string) error
}

type LuaChannelImpl struct {
	lookupEndChan map[string]chan bktype.Done
}

// GetLookupEndChan returns a channel of type Done that signals the end of a lookup operation.
func (c *LuaChannelImpl) GetLookupEndChan(backendName string) chan bktype.Done {
	if _, okay := c.lookupEndChan[backendName]; !okay {
		panic(fmt.Sprintf("backend name not found: %s", backendName))
	}

	return c.lookupEndChan[backendName]
}

// GetBackendNames retrieves a list of backend names from the LuaChannelImpl's lookupEndChan map.
func (c *LuaChannelImpl) GetBackendNames() []string {
	backendNames := make([]string, 0, len(c.lookupEndChan))

	for backendName := range c.lookupEndChan {
		backendNames = append(backendNames, backendName)
	}

	return backendNames
}

// AddChannel initializes channels for request and completion handling for a specified backend name. Returns an error if the backend name is invalid.
func (c *LuaChannelImpl) AddChannel(backendName string) error {
	if backendName == definitions.DefaultBackendName {
		return fmt.Errorf("backend name cannot be %s", definitions.DefaultBackendName)
	}

	c.lookupEndChan[backendName] = make(chan bktype.Done, 1)

	return nil
}

var _ LuaChannel = &LuaChannelImpl{}

// NewLuaChannel creates and returns a new instance of LuaChannel, initialized as a LuaChannelImpl.
func NewLuaChannel(backendName string) LuaChannel {
	lookupEndChan := make(map[string]chan bktype.Done)

	lookupEndChan[backendName] = make(chan bktype.Done, 1)

	return &LuaChannelImpl{
		lookupEndChan: lookupEndChan,
	}
}
