// Copyright (C) 2025 Christian Rößner
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

package signalsfx

import (
	"os"
	"os/signal"
)

// Notifier abstracts OS signal subscription so unit tests don't rely on real OS signals.
type Notifier interface {
	Notify(ch chan<- os.Signal, sig ...os.Signal)
	Stop(ch chan<- os.Signal)
}

type osSignalNotifier struct{}

// NewNotifier constructs the production Notifier implementation backed by os/signal.
func NewNotifier() Notifier {
	return &osSignalNotifier{}
}

func (n *osSignalNotifier) Notify(ch chan<- os.Signal, sig ...os.Signal) {
	signal.Notify(ch, sig...)
}

func (n *osSignalNotifier) Stop(ch chan<- os.Signal) {
	signal.Stop(ch)
}
