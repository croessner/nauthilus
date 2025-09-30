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

package admin

// FlushUserCmdStatus represents an user's command status.
type FlushUserCmdStatus struct {
	// User holds the identifier of a user.
	User string `json:"user"`

	// RemovedKeys contains a list of keys that have been removed during the user's command execution.
	RemovedKeys []string `json:"removed_keys"`

	// Status represents the status of the user's command.
	Status string `json:"status"`
}

// FlushUserCmd is a data structure used to handle user commands for flushing data.
type FlushUserCmd struct {
	// User is the field representing the name of the user to be flushed.
	User string `json:"user" binding:"required"`
}
