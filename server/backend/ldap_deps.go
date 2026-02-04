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
	"context"
	"log/slog"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/ldappool"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
)

// LDAPQueue abstracts the shared lookup request queue for LDAP workers.
type LDAPQueue interface {
	AddPoolName(poolName string)
	SetMaxQueueLength(poolName string, length int)
	PopWithContext(ctx context.Context, poolName string) *bktype.LDAPRequest
}

// LDAPRequestEnqueuer enqueues LDAP lookup requests with a priority.
type LDAPRequestEnqueuer interface {
	Push(request *bktype.LDAPRequest, priority int)
}

// LDAPAuthQueue abstracts the authentication request queue for LDAP workers.
type LDAPAuthQueue interface {
	AddPoolName(poolName string)
	SetMaxQueueLength(poolName string, length int)
	PopWithContext(ctx context.Context, poolName string) *bktype.LDAPAuthRequest
}

// LDAPPoolFactory creates LDAP pools for lookup or authentication workers.
type LDAPPoolFactory interface {
	NewPool(ctx context.Context, cfg config.File, logger *slog.Logger, poolType int, poolName string) ldappool.LDAPPool
}

// LDAPWorkerDeps provides injectable dependencies for LDAP worker startup.
type LDAPWorkerDeps struct {
	Queue       LDAPQueue
	AuthQueue   LDAPAuthQueue
	PoolFactory LDAPPoolFactory
}

func (d LDAPWorkerDeps) ldapQueue() LDAPQueue {
	if d.Queue != nil {
		return d.Queue
	}

	return defaultLDAPQueue{}
}

func (d LDAPWorkerDeps) ldapAuthQueue() LDAPAuthQueue {
	if d.AuthQueue != nil {
		return d.AuthQueue
	}

	return defaultLDAPAuthQueue{}
}

func (d LDAPWorkerDeps) poolFactory() LDAPPoolFactory {
	if d.PoolFactory != nil {
		return d.PoolFactory
	}

	return defaultLDAPPoolFactory{}
}

type defaultLDAPQueue struct{}

func (defaultLDAPQueue) AddPoolName(poolName string) {
	priorityqueue.LDAPQueue.AddPoolName(poolName)
}

func (defaultLDAPQueue) SetMaxQueueLength(poolName string, length int) {
	priorityqueue.LDAPQueue.SetMaxQueueLength(poolName, length)
}

func (defaultLDAPQueue) PopWithContext(ctx context.Context, poolName string) *bktype.LDAPRequest {
	return priorityqueue.LDAPQueue.PopWithContext(ctx, poolName)
}

// luaLDAPQueue is used by the Lua LDAP helpers to enqueue lookup requests.
var luaLDAPQueue LDAPRequestEnqueuer = defaultLDAPRequestEnqueuer{}

// SetLuaLDAPQueue replaces the Lua LDAP queue enqueuer (nil restores defaults).
func SetLuaLDAPQueue(enqueuer LDAPRequestEnqueuer) {
	if enqueuer == nil {
		luaLDAPQueue = defaultLDAPRequestEnqueuer{}
		return
	}

	luaLDAPQueue = enqueuer
}

type defaultLDAPRequestEnqueuer struct{}

func (defaultLDAPRequestEnqueuer) Push(request *bktype.LDAPRequest, priority int) {
	priorityqueue.LDAPQueue.Push(request, priority)
}

type defaultLDAPAuthQueue struct{}

func (defaultLDAPAuthQueue) AddPoolName(poolName string) {
	priorityqueue.LDAPAuthQueue.AddPoolName(poolName)
}

func (defaultLDAPAuthQueue) SetMaxQueueLength(poolName string, length int) {
	priorityqueue.LDAPAuthQueue.SetMaxQueueLength(poolName, length)
}

func (defaultLDAPAuthQueue) PopWithContext(ctx context.Context, poolName string) *bktype.LDAPAuthRequest {
	return priorityqueue.LDAPAuthQueue.PopWithContext(ctx, poolName)
}

type defaultLDAPPoolFactory struct{}

func (defaultLDAPPoolFactory) NewPool(ctx context.Context, cfg config.File, logger *slog.Logger, poolType int, poolName string) ldappool.LDAPPool {
	return ldappool.NewPool(ctx, cfg, logger, poolType, poolName)
}
