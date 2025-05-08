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

var (
	channel     Channel
	initChannel sync.Once
)

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
	c.ldapOnce.Do(func() {
		if c.ldapChannel == nil {
			c.ldapChannel = NewLDAPChannel(definitions.DefaultBackendName)
		}
	})

	return c.ldapChannel
}

// GetLuaChannel retrieves and returns the LuaChannel instance associated with the channelImpl.
func (c *channelImpl) GetLuaChannel() LuaChannel {
	c.luaOnce.Do(func() {
		if c.luaChannel == nil {
			c.luaChannel = NewLuaChannel(definitions.DefaultBackendName)
		}
	})

	return c.luaChannel
}

var _ Channel = &channelImpl{}

// GetChannel returns a singleton instance of the Channel interface, initializing it if not already created.
func GetChannel() Channel {
	initChannel.Do(func() {
		if channel == nil {
			channel = NewChannel()
		}
	})

	return channel
}

// NewChannel initializes and returns a new instance of the Channel interface implementation.
func NewChannel() Channel {
	var ldapChannel LDAPChannel
	var luaChannel LuaChannel

	if config.GetFile().HaveLDAPBackend() {
		ldapChannel = NewLDAPChannel(definitions.DefaultBackendName)
	}

	if config.GetFile().HaveLuaBackend() {
		luaChannel = NewLuaChannel(definitions.DefaultBackendName)
	}

	return &channelImpl{
		ldapChannel: ldapChannel,
		luaChannel:  luaChannel,
	}
}

// LDAPChannel defines an interface for managing LDAP-related channels for communication and operation handling.
type LDAPChannel interface {
	// GetLookupEndChan returns a channel that signals the completion of lookup operations.
	GetLookupEndChan(poolName string) chan bktype.Done

	// GetAuthEndChan returns the channel used to signal the completion of authentication operations.
	GetAuthEndChan(poolName string) chan bktype.Done

	// GetLookupRequestChan retrieves the LDAPRequest channel associated with lookup operations.
	GetLookupRequestChan(poolName string) chan *bktype.LDAPRequest

	// GetAuthRequestChan retrieves the LDAPAuthRequest channel for handling authentication requests.
	GetAuthRequestChan(poolName string) chan *bktype.LDAPAuthRequest

	// GetPoolNames retrieves and returns a list of names for all configured LDAP connection pools.
	GetPoolNames() []string

	// AddChannel creates and initializes all necessary channels for the specified LDAP connection pool by poolName.
	AddChannel(poolName string) error
}

type ldapChannelImpl struct {
	lookupEndChan map[string]chan bktype.Done
	authEndChan   map[string]chan bktype.Done
	lookupReqChan map[string]chan *bktype.LDAPRequest
	authReqChan   map[string]chan *bktype.LDAPAuthRequest
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

// GetLookupRequestChan returns the LDAP request channel associated with lookup operations.
func (c *ldapChannelImpl) GetLookupRequestChan(poolName string) chan *bktype.LDAPRequest {
	if _, okay := c.lookupReqChan[poolName]; !okay {
		panic(fmt.Sprintf("pool name not found: %s", poolName))
	}

	return c.lookupReqChan[poolName]
}

// GetAuthRequestChan retrieves the LDAP authentication request channel stored in the struct.
func (c *ldapChannelImpl) GetAuthRequestChan(poolName string) chan *bktype.LDAPAuthRequest {
	if _, okay := c.authReqChan[poolName]; !okay {
		panic(fmt.Sprintf("pool name not found: %s", poolName))
	}

	return c.authReqChan[poolName]
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
	c.lookupReqChan[poolName] = make(chan *bktype.LDAPRequest, definitions.MaxChannelSize)
	c.authReqChan[poolName] = make(chan *bktype.LDAPAuthRequest, definitions.MaxChannelSize)

	return nil
}

var _ LDAPChannel = &ldapChannelImpl{}

func NewLDAPChannel(poolName string) LDAPChannel {
	lookupEndChan := make(map[string]chan bktype.Done)
	authEndChan := make(map[string]chan bktype.Done)
	lookupReqChan := make(map[string]chan *bktype.LDAPRequest)
	authReqChan := make(map[string]chan *bktype.LDAPAuthRequest)

	lookupEndChan[poolName] = make(chan bktype.Done, 1)
	authEndChan[poolName] = make(chan bktype.Done, 1)
	lookupReqChan[poolName] = make(chan *bktype.LDAPRequest, definitions.MaxChannelSize)
	authReqChan[poolName] = make(chan *bktype.LDAPAuthRequest, definitions.MaxChannelSize)

	return &ldapChannelImpl{
		lookupEndChan: lookupEndChan,
		authEndChan:   authEndChan,
		lookupReqChan: lookupReqChan,
		authReqChan:   authReqChan,
	}
}

// LuaChannel defines an interface for managing Lua-related channels used for communication and request handling.
type LuaChannel interface {
	// GetLookupEndChan returns a channel used to signal the completion of lookup operations.
	GetLookupEndChan(backendName string) chan bktype.Done

	// GetLookupRequestChan retrieves the LuaRequest channel used for managing Lua-related request operations.
	GetLookupRequestChan(backendName string) chan *bktype.LuaRequest

	// GetBackendNames returns a list of all available backend names configured in the LuaChannel implementation.
	GetBackendNames() []string

	// AddChannel adds a new channel for the specified backend identified by the backendName.
	// Returns an error if the backendName is invalid or the channel could not be created.
	AddChannel(backendName string) error
}

type LuaChannelImpl struct {
	lookupEndChan map[string]chan bktype.Done
	lookupReqChan map[string]chan *bktype.LuaRequest
}

// GetLookupEndChan returns a channel of type Done that signals the end of a lookup operation.
func (c *LuaChannelImpl) GetLookupEndChan(backendName string) chan bktype.Done {
	if _, okay := c.lookupEndChan[backendName]; !okay {
		panic(fmt.Sprintf("backend name not found: %s", backendName))
	}

	return c.lookupEndChan[backendName]
}

// GetLookupRequestChan returns the pointer to a LuaRequest used for handling Lua requests in the channel.
func (c *LuaChannelImpl) GetLookupRequestChan(backendName string) chan *bktype.LuaRequest {
	if _, okay := c.lookupReqChan[backendName]; !okay {
		panic(fmt.Sprintf("backend name not found: %s", backendName))
	}

	return c.lookupReqChan[backendName]
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
	c.lookupReqChan[backendName] = make(chan *bktype.LuaRequest, definitions.MaxChannelSize)

	return nil
}

var _ LuaChannel = &LuaChannelImpl{}

// NewLuaChannel creates and returns a new instance of LuaChannel, initialized as a LuaChannelImpl.
func NewLuaChannel(backendName string) LuaChannel {
	lookupEndChan := make(map[string]chan bktype.Done)
	lookupReqChan := make(map[string]chan *bktype.LuaRequest)

	lookupEndChan[backendName] = make(chan bktype.Done, 1)
	lookupReqChan[backendName] = make(chan *bktype.LuaRequest, definitions.MaxChannelSize)

	return &LuaChannelImpl{
		lookupEndChan: lookupEndChan,
		lookupReqChan: lookupReqChan,
	}
}
