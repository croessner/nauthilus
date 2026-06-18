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

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/lualib/connmgr"
)

const maxConnectionTargetLabelValueLength = 64

var allowedConnectionTargetLabels = map[string]struct{}{
	"component":      {},
	"protocol":       {},
	"role":           {},
	httpLabelService: {},
}

var _ pluginapi.ConnectionTargets = (*ConnectionTargetFacade)(nil)

// ConnectionTargetRegistrar records validated connection target registrations.
type ConnectionTargetRegistrar interface {
	Register(context.Context, string, string, string)
	Count(string) (int, bool)
}

// ConnectionTargetFacade registers plugin-owned network targets with host observability.
type ConnectionTargetFacade struct {
	registrar ConnectionTargetRegistrar
	byAddress map[string]string
	byName    map[string]pluginapi.ConnectionTarget
	mu        sync.Mutex
}

// NewConnectionTargetFacade returns a duplicate-safe connection target facade.
func NewConnectionTargetFacade(registrar ConnectionTargetRegistrar) *ConnectionTargetFacade {
	if registrar == nil {
		registrar = noopConnectionTargetRegistrar{}
	}

	return &ConnectionTargetFacade{
		registrar: registrar,
		byAddress: make(map[string]string),
		byName:    make(map[string]pluginapi.ConnectionTarget),
	}
}

// NewConnectionTargetFacadeForConfig returns a facade backed by the Lua-compatible connection manager.
func NewConnectionTargetFacadeForConfig(cfg config.File) *ConnectionTargetFacade {
	return NewConnectionTargetFacade(connmgrConnectionTargetRegistrar{
		cfg:     cfg,
		manager: connmgr.GetConnectionManager(),
	})
}

// Register validates and records one connection target.
func (f *ConnectionTargetFacade) Register(ctx context.Context, target pluginapi.ConnectionTarget) error {
	if ctx == nil {
		ctx = context.Background()
	}

	normalized, err := validateConnectionTarget(target)
	if err != nil {
		return err
	}

	if f == nil {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	addressKey := connectionTargetAddressKey(normalized)

	registered, err := f.checkDuplicateLocked(addressKey, normalized)
	if err != nil {
		return err
	}

	if registered {
		return nil
	}

	f.registrar.Register(ctx, normalized.Address, string(normalized.Direction), normalized.Description)
	f.byName[normalized.Name] = cloneConnectionTarget(normalized)
	f.byAddress[addressKey] = normalized.Name

	return nil
}

// Count returns the current observed count for a named target when available.
func (f *ConnectionTargetFacade) Count(_ context.Context, name string) (int, bool) {
	if f == nil {
		return 0, false
	}

	f.mu.Lock()
	target, ok := f.byName[name]
	f.mu.Unlock()

	if !ok {
		return 0, false
	}

	return f.registrar.Count(target.Address)
}

// checkDuplicateLocked enforces deterministic duplicate registration behavior.
func (f *ConnectionTargetFacade) checkDuplicateLocked(addressKey string, target pluginapi.ConnectionTarget) (bool, error) {
	if existing, ok := f.byName[target.Name]; ok {
		if sameConnectionTargetIdentity(existing, target) {
			return true, nil
		}

		return false, fmt.Errorf("%w: target name %q already registered", pluginapi.ErrConnectionTargetConflict, target.Name)
	}

	if existingName, ok := f.byAddress[addressKey]; ok {
		return false, fmt.Errorf("%w: address %q already registered as %q", pluginapi.ErrConnectionTargetConflict, target.Address, existingName)
	}

	return false, nil
}

// validateConnectionTarget returns a normalized connection target or a public validation error.
func validateConnectionTarget(target pluginapi.ConnectionTarget) (pluginapi.ConnectionTarget, error) {
	if err := pluginapi.ValidateComponentName(target.Name); err != nil {
		return pluginapi.ConnectionTarget{}, err
	}

	address, err := validateConnectionTargetAddress(target.Address)
	if err != nil {
		return pluginapi.ConnectionTarget{}, err
	}

	if target.Direction != pluginapi.ConnectionTargetDirectionLocal &&
		target.Direction != pluginapi.ConnectionTargetDirectionRemote {
		return pluginapi.ConnectionTarget{}, fmt.Errorf("%w: invalid direction %q", pluginapi.ErrInvalidConnectionTarget, target.Direction)
	}

	labels, err := validateConnectionTargetLabels(target.Labels)
	if err != nil {
		return pluginapi.ConnectionTarget{}, err
	}

	description := strings.TrimSpace(target.Description)
	if description == "" {
		description = target.Name
	}

	return pluginapi.ConnectionTarget{
		Name:        target.Name,
		Address:     address,
		Direction:   target.Direction,
		Description: description,
		Labels:      labels,
	}, nil
}

// validateConnectionTargetAddress accepts only host:port targets without URL paths or secrets.
func validateConnectionTargetAddress(address string) (string, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", fmt.Errorf("%w: address must be host:port", pluginapi.ErrInvalidConnectionTarget)
	}

	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("%w: address host is empty", pluginapi.ErrInvalidConnectionTarget)
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("%w: address port is invalid", pluginapi.ErrInvalidConnectionTarget)
	}

	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// validateConnectionTargetLabels copies bounded labels and rejects high-cardinality keys.
func validateConnectionTargetLabels(labels map[string]string) (map[string]string, error) {
	if len(labels) == 0 {
		return nil, nil
	}

	cloned := make(map[string]string, len(labels))
	for name, value := range labels {
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)

		if _, allowed := allowedConnectionTargetLabels[name]; !allowed {
			return nil, fmt.Errorf("%w: label %q is not allowed", pluginapi.ErrInvalidConnectionTarget, name)
		}

		if err := pluginapi.ValidateComponentName(value); err != nil {
			return nil, fmt.Errorf("%w: label %q value is invalid", pluginapi.ErrInvalidConnectionTarget, name)
		}

		if len(value) > maxConnectionTargetLabelValueLength {
			return nil, fmt.Errorf("%w: label %q value is too long", pluginapi.ErrInvalidConnectionTarget, name)
		}

		cloned[name] = value
	}

	return cloned, nil
}

// cloneConnectionTarget copies mutable connection target fields.
func cloneConnectionTarget(target pluginapi.ConnectionTarget) pluginapi.ConnectionTarget {
	if len(target.Labels) == 0 {
		return target
	}

	target.Labels = map[string]string{}
	for name, value := range target.Labels {
		target.Labels[name] = value
	}

	return target
}

// sameConnectionTargetIdentity compares stable target identity fields for idempotent registration.
func sameConnectionTargetIdentity(left pluginapi.ConnectionTarget, right pluginapi.ConnectionTarget) bool {
	return left.Name == right.Name &&
		left.Address == right.Address &&
		left.Direction == right.Direction
}

// connectionTargetAddressKey builds the uniqueness key used by the facade.
func connectionTargetAddressKey(target pluginapi.ConnectionTarget) string {
	return string(target.Direction) + "|" + target.Address
}

type connmgrConnectionTargetRegistrar struct {
	cfg     config.File
	manager *connmgr.ConnectionManager
}

// Register delegates to the Lua-compatible connection manager.
func (r connmgrConnectionTargetRegistrar) Register(ctx context.Context, address string, direction string, description string) {
	if r.manager == nil || r.cfg == nil {
		return
	}

	r.manager.Register(ctx, r.cfg, address, direction, description)
}

// Count delegates to the Lua-compatible connection manager.
func (r connmgrConnectionTargetRegistrar) Count(address string) (int, bool) {
	if r.manager == nil {
		return 0, false
	}

	return r.manager.GetCount(address)
}

type noopConnectionTargetRegistrar struct{}

// Register records no target for the no-op registrar.
func (noopConnectionTargetRegistrar) Register(context.Context, string, string, string) {}

// Count returns no target for the no-op registrar.
func (noopConnectionTargetRegistrar) Count(string) (int, bool) {
	return 0, false
}
