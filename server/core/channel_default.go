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

package core

import (
	stdlog "log"
	"sync"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/backend"
)

// Channel injection seam for core subtrees.
//
// Runtime must configure a default channel at the boundary.

type channelHolder struct {
	ch backend.Channel
}

var defaultChannel atomic.Value
var warnMissingChannelOnce sync.Once

func init() {
	defaultChannel.Store(channelHolder{ch: nil})
}

// SetDefaultChannel sets the process-wide default channel for core.
func SetDefaultChannel(ch backend.Channel) {
	defaultChannel.Store(channelHolder{ch: ch})
}

func getDefaultChannel() backend.Channel {
	if v := defaultChannel.Load(); v != nil {
		if h, ok := v.(channelHolder); ok {
			if h.ch != nil {
				return h.ch
			}
		}
	}

	warnMissingChannelOnce.Do(func() {
		stdlog.Printf("ERROR: core default channel is not configured. Ensure the boundary calls core.SetDefaultChannel(...)\n")
	})

	panic("core: default channel not configured")
}
