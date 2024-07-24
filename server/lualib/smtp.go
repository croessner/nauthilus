package lualib

import (
	"github.com/croessner/nauthilus/server/lualib/smtp"

	"github.com/yuin/gopher-lua"
)

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
