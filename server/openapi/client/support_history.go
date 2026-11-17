// Copyright (C) 2026 Christian Rößner
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

package client

import (
	"context"

	management "github.com/croessner/nauthilus/v4/server/openapi/generated/management"
)

// SearchAuthenticationAttempts searches recorded attempts of one subject; the bearer token needs
// nauthilus:history_read.
func (client *ManagementClient) SearchAuthenticationAttempts(ctx context.Context, body management.SearchAuthenticationAttemptsJSONRequestBody, editors ...management.RequestEditorFn) (*management.SearchAuthenticationAttemptsResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.SearchAuthenticationAttemptsWithResponse(ctx, body, editors...)
}

// GetAuthenticationAttempt returns every recorded event of one diagnostic attempt id.
func (client *ManagementClient) GetAuthenticationAttempt(ctx context.Context, body management.GetAuthenticationAttemptJSONRequestBody, editors ...management.RequestEditorFn) (*management.GetAuthenticationAttemptResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.GetAuthenticationAttemptWithResponse(ctx, body, editors...)
}

// SearchBruteForceBans explains recorded brute-force bans of one IP or network.
func (client *ManagementClient) SearchBruteForceBans(ctx context.Context, body management.SearchBruteForceBansJSONRequestBody, editors ...management.RequestEditorFn) (*management.SearchBruteForceBansResponse, error) {
	generated, err := client.generatedClient()
	if err != nil {
		return nil, err
	}

	return generated.SearchBruteForceBansWithResponse(ctx, body, editors...)
}
