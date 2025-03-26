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
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
)

var channel Channel

// Channel is an interface comprising methods to retrieve LDAPChannel and LuaChannel instances.
type Channel interface {
	// GetLdapChannel retrieves and returns the LDAPChannel instance associated with the implementation of the Channel interface.
	GetLdapChannel() LDAPChannel

	// GetLuaChannel retrieves and returns the LuaChannel instance associated with the Channel interface implementation.
	GetLuaChannel() LuaChannel

	// DestroyLdapChannel releases the LDAPChannel instance by setting it to nil, freeing associated resources.
	DestroyLdapChannel()

	// DestroyLuaChannel releases the LuaChannel instance associated with the Channel implementation by setting it to nil.
	DestroyLuaChannel()
}

type channelImpl struct {
	ldapChannel LDAPChannel
	luaChannel  LuaChannel
}

// GetLdapChannel retrieves and returns the LDAPChannel instance associated with the channelImpl instance.
func (c *channelImpl) GetLdapChannel() LDAPChannel {
	if c.ldapChannel == nil {
		c.ldapChannel = NewLDAPChannel()
	}

	return c.ldapChannel
}

// GetLuaChannel retrieves and returns the LuaChannel instance associated with the channelImpl.
func (c *channelImpl) GetLuaChannel() LuaChannel {
	if c.luaChannel == nil {
		c.luaChannel = NewLuaChannel()
	}

	return c.luaChannel
}

func (c *channelImpl) DestroyLdapChannel() {
	c.ldapChannel = nil
}

func (c *channelImpl) DestroyLuaChannel() {
	c.luaChannel = nil
}

var _ Channel = &channelImpl{}

// GetChannel returns a singleton instance of the Channel interface, initializing it if not already created.
func GetChannel() Channel {
	if channel == nil {
		channel = NewChannel()
	}

	return channel
}

// NewChannel initializes and returns a new instance of the Channel interface implementation.
func NewChannel() Channel {
	return &channelImpl{
		ldapChannel: NewLDAPChannel(),
		luaChannel:  NewLuaChannel(),
	}
}

// LDAPChannel defines an interface for managing LDAP-related channels for communication and operation handling.
type LDAPChannel interface {
	// GetLookupEndChan returns a channel that signals the completion of lookup operations.
	GetLookupEndChan() chan Done

	// GetAuthEndChan returns the channel used to signal the completion of authentication operations.
	GetAuthEndChan() chan Done

	// GetLookupRequestChan retrieves the LDAPRequest channel associated with lookup operations.
	GetLookupRequestChan() chan *LDAPRequest

	// GetAuthRequestChan retrieves the LDAPAuthRequest channel for handling authentication requests.
	GetAuthRequestChan() chan *LDAPAuthRequest

	// CloseLookup closes the channel used to signal the completion of lookup operations in the LDAP channel.
	CloseLookup()

	// CloseAuth closes the channel used to signal the completion of authentication operations in the LDAP channel.
	CloseAuth()
}

type ldapChannelImpl struct {
	lookupEndChan chan Done
	authEndChan   chan Done
	lookupReqChan chan *LDAPRequest
	authReqChan   chan *LDAPAuthRequest
}

// GetLookupEndChan returns the channel used to signal the completion of lookup operations.
func (c *ldapChannelImpl) GetLookupEndChan() chan Done {
	return c.lookupEndChan
}

// GetAuthEndChan returns the channel used to signal the completion of authentication operations.
func (c *ldapChannelImpl) GetAuthEndChan() chan Done {
	return c.authEndChan
}

// GetLookupRequestChan returns the LDAP request channel associated with lookup operations.
func (c *ldapChannelImpl) GetLookupRequestChan() chan *LDAPRequest {
	return c.lookupReqChan
}

// GetAuthRequestChan retrieves the LDAP authentication request channel stored in the struct.
func (c *ldapChannelImpl) GetAuthRequestChan() chan *LDAPAuthRequest {
	return c.authReqChan
}

// CloseLookup closes all the channels associated with LDAP lookup and authentication operations in ldapChannelImpl.
func (c *ldapChannelImpl) CloseLookup() {
	close(c.lookupEndChan)
	close(c.lookupReqChan)

	c.lookupEndChan = nil
	c.lookupReqChan = nil
}

// CloseAuth closes the channels associated with authentication operations in ldapChannelImpl.
func (c *ldapChannelImpl) CloseAuth() {
	close(c.authEndChan)
	close(c.authReqChan)

	c.authEndChan = nil
	c.authReqChan = nil
}

var _ LDAPChannel = &ldapChannelImpl{}

func NewLDAPChannel() LDAPChannel {
	return &ldapChannelImpl{
		lookupEndChan: make(chan Done),
		authEndChan:   make(chan Done),
		lookupReqChan: make(chan *LDAPRequest, config.GetFile().GetLDAP().Config.LookupPoolSize),
		authReqChan:   make(chan *LDAPAuthRequest, config.GetFile().GetLDAP().Config.AuthPoolSize),
	}
}

// LuaChannel defines an interface for managing Lua-related channels used for communication and request handling.
type LuaChannel interface {
	// GetLookupEndChan returns a channel used to signal the completion of lookup operations.
	GetLookupEndChan() chan Done

	// GetLookupRequestChan retrieves the LuaRequest channel used for managing Lua-related request operations.
	GetLookupRequestChan() chan *LuaRequest

	// Close terminates any active channels or ongoing operations associated with the LuaChannel.
	Close()
}

type LuaChannelImpl struct {
	lookupEndChan chan Done
	lookupReqChan chan *LuaRequest
}

// GetLookupEndChan returns a channel of type Done that signals the end of a lookup operation.
func (c *LuaChannelImpl) GetLookupEndChan() chan Done {
	return c.lookupEndChan
}

// GetLookupRequestChan returns the pointer to a LuaRequest used for handling Lua requests in the channel.
func (c *LuaChannelImpl) GetLookupRequestChan() chan *LuaRequest {
	return c.lookupReqChan
}

// Close shuts down both lookupEndChan and lookupReqChan channels to release resources and stop channel operations.
func (c *LuaChannelImpl) Close() {
	close(c.lookupEndChan)
	close(c.lookupReqChan)

	c.lookupEndChan = nil
	c.lookupReqChan = nil
}

var _ LuaChannel = &LuaChannelImpl{}

// NewLuaChannel creates and returns a new instance of LuaChannel, initialized as a LuaChannelImpl.
func NewLuaChannel() LuaChannel {
	return &LuaChannelImpl{
		lookupEndChan: make(chan Done),
		lookupReqChan: make(chan *LuaRequest, definitions.MaxChannelSize),
	}
}
