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
	"io"
	"log/slog"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/go-redis/redismock/v9"
)

// setupAuthDeps returns hermetic auth dependencies with a mocked Redis client and a discarding logger.
func setupAuthDeps() AuthDeps {
	db, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	return AuthDeps{
		Cfg:          config.GetFile(),
		Env:          config.NewTestEnvironmentConfig(),
		Logger:       logger,
		Redis:        redisClient,
		AccountCache: nil,
		Channel:      nil,
	}
}
