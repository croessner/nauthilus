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
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/smtp"

	lua "github.com/yuin/gopher-lua"
)

// MailModule provides functionalities for sending emails using an SMTP client.
type MailModule struct {
	// smtpClient is an implementation of the smtp.Client interface used for sending emails.
	smtpClient smtp.Client
}

// NewMailModule creates a new MailModule instance with the provided smtp.Client.
func NewMailModule(smtpClient smtp.Client) *MailModule {
	return &MailModule{smtpClient: smtpClient}
}

// Loader initializes the MailModule's Lua library by registering its functions and returning the module table.
// This method pushes the initialized module onto the Lua stack and returns 1 to indicate one value is returned.
func (m *MailModule) Loader(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		definitions.LuaFnSendMail: SendMail(m.smtpClient),
	})

	L.Push(mod)

	return 1
}

// LoaderModMail is a stateless module loader for nauthilus_mail.
// It pre-binds a real SMTP client implementation and exposes send_mail()
// to Lua. This module does not require request context and can be preloaded
// once per VM.
func LoaderModMail(L *lua.LState) int {
	mail := NewMailModule(&smtp.EmailClient{})

	return mail.Loader(L)
}

// getStringFromTable retrieves a string value from a Lua table by its key. Returns an empty string if the key is not found.
func getStringFromTable(table *lua.LTable, key string) string {
	value := table.RawGetString(key)
	if value == lua.LNil {
		return ""
	}

	return value.String()
}

// getBoolFromTable retrieves a boolean value from a Lua table by its key. Returns false if the key does not exist or is invalid.
func getBoolFromTable(table *lua.LTable, key string) bool {
	value := table.RawGetString(key)
	if value == lua.LNil {
		return false
	}

	if boolVal, ok := value.(lua.LBool); ok {
		return bool(boolVal)
	}

	return false
}

// SendMail sends an email using the provided smtp.Client and Lua table parameters for configuration and recipient data.
// It extracts settings like server, port, credentials, and email content from the Lua table and invokes the SMTP client.
func SendMail(smtpClient smtp.Client) lua.LGFunction {
	return func(L *lua.LState) int {
		tbl := L.CheckTable(1)

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
			L.Push(lua.LString("'port' must be a number"))

			return 1
		}

		tableVal := tbl.RawGet(lua.LString("to"))
		recipientTable, ok := tableVal.(*lua.LTable)
		if !ok {
			L.Push(lua.LString("'to' must be a table"))

			return 1
		}

		to := make([]string, 0)
		recipientTable.ForEach(func(k lua.LValue, v lua.LValue) {
			to = append(to, v.String())
		})

		err := smtpClient.SendMail(smtp.NewMailOptions(server, int(port), heloName, username, password, from, to, subject, body, tls, startTLS, lmtp))

		if err != nil {
			L.Push(lua.LString(err.Error()))
		} else {
			L.Push(lua.LNil)
		}

		return 1
	}
}
