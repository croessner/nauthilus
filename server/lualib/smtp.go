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

package lualib

import (
	"context"
	"log/slog"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/croessner/nauthilus/server/lualib/smtp"

	lua "github.com/yuin/gopher-lua"
)

// MailManager provides functionalities for sending emails using an SMTP client.
type MailManager struct {
	*BaseManager
	smtpClient smtp.Client
}

// NewMailManager creates a new MailManager instance with the provided smtp.Client.
func NewMailManager(ctx context.Context, cfg config.File, logger *slog.Logger, smtpClient smtp.Client) *MailManager {
	return &MailManager{
		BaseManager: NewBaseManager(ctx, cfg, logger),
		smtpClient:  smtpClient,
	}
}

// SendMail sends an email using the provided smtp.Client and Lua table parameters for configuration and recipient data.
// It extracts settings like server, port, credentials, and email content from the Lua table and invokes the SMTP client.
func (m *MailManager) SendMail(L *lua.LState) int {
	stack := luastack.NewManager(L)
	tbl := stack.CheckTable(1)

	username := getStringFromTable(tbl, "username")
	password := getStringFromTable(tbl, "password")
	from := getStringFromTable(tbl, "from")
	server := getStringFromTable(tbl, "server")
	heloName := getStringFromTable(tbl, "helo_name")
	subject := getStringFromTable(tbl, "subject")
	body := getStringFromTable(tbl, "body")
	tls := getBoolFromTable(tbl, "tls")
	startTLS := getBoolFromTable(tbl, "starttls")
	lmtp := getBoolFromTable(tbl, "lmtp")

	portVal := tbl.RawGetString("port")
	port, ok := portVal.(lua.LNumber)
	if !ok {
		return stack.PushResult(lua.LString("'port' must be a number"))
	}

	tableVal := tbl.RawGet(lua.LString("to"))
	recipientTable, ok := tableVal.(*lua.LTable)
	if !ok {
		return stack.PushResult(lua.LString("'to' must be a table"))
	}

	to := make([]string, 0)
	recipientTable.ForEach(func(_ lua.LValue, v lua.LValue) {
		to = append(to, v.String())
	})

	err := m.smtpClient.SendMail(smtp.NewMailOptions(server, int(port), heloName, username, password, from, to, subject, body, tls, startTLS, lmtp))

	if err != nil {
		return stack.PushResult(lua.LString(err.Error()))
	}

	return stack.PushResult(lua.LNil)
}

// LoaderModMail is a stateless module loader for nauthilus_mail.
// It pre-binds a real SMTP client implementation and exposes send_mail()
// to Lua. This module does not require request context and can be preloaded
// once per VM.
func LoaderModMail(ctx context.Context, cfg config.File, logger *slog.Logger) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewMailManager(ctx, cfg, logger, &smtp.EmailClient{})

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnSendMail: manager.SendMail,
		})

		return stack.PushResult(mod)
	}
}
