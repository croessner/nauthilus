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

// Package mfa_backchannel provides mfa backchannel functionality.
package mfa_backchannel

const (
	mfaBackchannelCredentialJSONRequired     = "credential must be valid JSON"
	mfaBackchannelInvalidJSON                = "Invalid JSON payload"
	mfaBackchannelResponseKeyError           = "error"
	mfaBackchannelResponseKeyStatus          = "status"
	mfaBackchannelStatusOK                   = "ok"
	mfaBackchannelUsernameCredentialRequired = "username and credential are required"
	mfaBackchannelUsernameRequired           = "username is required"
)
