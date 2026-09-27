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

package main

import (
	"context"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// goStoppableWorker starts one host-supervised loop that ends when either the
// returned cancel function is called or the host stops its workers.
//
// Host.Go detaches the context it is given from cancellation and hands the
// loop a host-owned context instead, so cancelling the start context alone
// never reaches the loop. The loop therefore runs on its own cancellable
// context, and the host lifetime is bridged into it.
func goStoppableWorker(host pluginapi.Host, name string, loop func(context.Context) error) context.CancelFunc {
	parent := host.ServiceContext()
	if parent == nil {
		parent = context.Background()
	}

	workerCtx, cancel := context.WithCancel(parent)

	host.Go(workerCtx, name, func(hostCtx context.Context) error {
		release := context.AfterFunc(hostCtx, cancel)
		defer release()

		return loop(workerCtx)
	})

	return cancel
}
