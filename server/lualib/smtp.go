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
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/lualib/smtp"

	"github.com/yuin/gopher-lua"
)

// SmtpClient represents an instance of the EmailClient struct, which is a real SMTP client used for sending emails. SmtpClient is a variable of type *smtp.EmailClient.
// The EmailClient struct has a SendMail method that sends an email using the provided MailOptions configuration. If the options parameter is nil, it returns an error; otherwise, it passes the non-nil options to the smtp.SendMail method and returns its result.
// The SendMail method of the EmailClient struct is used to send emails with the EmailClient instance and the SendMail method from the smtp package.
var SmtpClient *smtp.EmailClient

// A mapping of Lua function names to the corresponding Go LGFunctions.
// The "send_mail" function is mapped to the SendMail function.
var exportsModMail = map[string]lua.LGFunction{
	global.LuaFnSendMail: SendMail(SmtpClient),
}

// LoaderModMail initializes a new module for the "nauthilus_mail" module in Lua.
// It sets the functions from the "exportsModMail" map into a new lua.LTable.
// The module table is then pushed onto the top of the stack.
// Finally, it returns 1 to indicate that one value has been returned to Lua.
func LoaderModMail(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exportsModMail)

	L.Push(mod)

	return 1
}

// getStringFromTable retrieves a string value from a Lua table by its key.
// If the value is not present or is nil, an empty string is returned.
//
// Parameters:
// - table: The Lua table to retrieve the value from.
// - key: The key of the value to retrieve.
//
// Returns:
// - The string value corresponding to the provided key. If the value is not present or is nil, an empty string is returned.
//
// Example usage:
// ```
// value := getStringFromTable(tbl, "key")
// ```
func getStringFromTable(table *lua.LTable, key string) string {
	value := table.RawGetString(key)
	if value == lua.LNil {
		return ""
	}

	return value.String()
}

// getBoolFromTable retrieves a boolean value from a Lua table by its key.
// If the value is not present or is not of type boolean, false is returned.
//
// Parameters:
// - table: The Lua table to retrieve the value from.
// - key: The key of the value to retrieve.
//
// Returns:
// - The boolean value corresponding to the provided key. If the value is not present or is not of type boolean, false is returned.
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

// SendMail sends an email using the provided Client implementation.
//
// Parameters:
// - smtpClient: An implementation of the Client interface for sending emails.
//
// Returns:
// - Returns a Lua LGFunction that accepts a Lua state and sends the email using the provided parameters.
// - If an error occurs during sending the email, a LuaString with the error message is pushed onto the Lua stack.
// - If the email is sent successfully, a LuaNil is pushed onto the Lua stack.
//
// Example usage:
// ```
// // Create a real SMTP client instance
// smtpClient := &lualib.EmailClient{}
//
// // Create a Lua state
// L := lua.NewState()
//
// // Register the SendMail function with the Lua state
// L.SetGlobal("SendMail", lualib.SendMail(smtpClient))
// ```
//
// Note: The Client interface is defined as follows:
// ```
//
//	type Client interface {
//		SendMail(options *MailOptions) error
//	}
//
// ```
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
