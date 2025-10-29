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

package bktype

import (
	"context"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-ldap/ldap/v3"
)

// PoolRequest represents a generic interface for handling LDAP requests and responses.
// It provides a method to retrieve a channel for receiving LDAP replies.
type PoolRequest[T any] interface {
	GetLDAPReplyChan() chan *LDAPReply
}

// LDAPModifyAttributes represents a map of attribute names to their corresponding values for LDAP modify operations.
type LDAPModifyAttributes map[string][]string

// LDAPRequest represents an LDAP request.
type LDAPRequest struct {
	// GUID is the globally unique identifier for this LDAP request, optional.
	GUID string

	// RequestID represents the globally unique identifier for an LDAP request. It is a pointer to a string.
	RequestID string

	// PoolName is the target LDAP pool name this request must be processed by (e.g., "default" or "mail").
	PoolName string

	// Filter is the criteria that the LDAP request uses to filter during the search.
	Filter string

	// BaseDN is the base distinguished name used as the search base.
	BaseDN string

	// SearchAttributes are the attributes for which values are to be returned in the search results.
	SearchAttributes []string

	// MacroSource is the source of macros to be used, optional.
	MacroSource *util.MacroSource

	// Scope defines the scope for LDAP search (base, one, or sub).
	Scope config.LDAPScope

	// Command represents the LDAP command to be executed (add, modify, delete, or search).
	Command definitions.LDAPCommand

	SubCommand definitions.LDAPSubCommand

	// ModifyDN specifies the distinguished name (DN) to be modified during an LDAP modify operation.
	ModifyDN string

	// ModifyAttributes contains attributes information used in modify command.
	ModifyAttributes LDAPModifyAttributes

	// LDAPReplyChan is the channel where reply from LDAP server is sent.
	LDAPReplyChan chan *LDAPReply

	// HTTPClientContext is the context for managing HTTP requests and responses.
	HTTPClientContext context.Context
}

// GetLDAPReplyChan returns the channel where replies from the LDAP server are sent.
// It retrieves and returns the value of the `LDAPReplyChan` field of the `LDAPRequest` struct.
func (l *LDAPRequest) GetLDAPReplyChan() chan *LDAPReply {
	return l.LDAPReplyChan
}

var _ PoolRequest[LDAPRequest] = (*LDAPRequest)(nil)

// LDAPAuthRequest represents a request to authenticate with an LDAP server.
type LDAPAuthRequest struct {
	// GUID is the unique identifier for the LDAP auth request.
	GUID string

	// PoolName is the target LDAP pool name this auth request must be processed by.
	PoolName string

	// BindDN is the Distinguished Name for binding to the LDAP server.
	BindDN string

	// BindPW is the password for binding to the LDAP server.
	BindPW string

	// LDAPReplyChan is a channel where the LDAP responses will be sent.
	LDAPReplyChan chan *LDAPReply

	// HTTPClientContext is the context for the HTTP client
	// carrying the LDAP auth request.
	HTTPClientContext context.Context
}

// GetLDAPReplyChan returns the channel where LDAP responses are sent.
func (l *LDAPAuthRequest) GetLDAPReplyChan() chan *LDAPReply {
	return l.LDAPReplyChan
}

var _ PoolRequest[LDAPAuthRequest] = (*LDAPAuthRequest)(nil)

// LDAPReply represents the structure for handling responses from an LDAP operation.
// It contains the result of the operation, raw entries, and any possible error encountered.
type LDAPReply struct {
	// Result holds the outcome of a database query or LDAP operation, mapping field names or attributes to their values.
	Result AttributeMapping

	// RawResult contains a slice of raw LDAP entries retrieved from an LDAP operation. It is used for processing raw data.
	RawResult []*ldap.Entry

	// Err captures any error encountered during the LDAP operation or response parsing.
	Err error
}
