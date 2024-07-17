package lualib

import (
	"github.com/croessner/nauthilus/server/lualib/smtp"

	"github.com/yuin/gopher-lua"
)

// SMTPClient is an interface for sending email using SMTP protocol.
type SMTPClient interface {
	// SendMail sends an email using the provided SMTPClient implementation.
	//
	// Parameters:
	// - server: The address of the SMTP server.
	// - port: The port number of the SMTP server.
	// - username: The username to authenticate with the SMTP server.
	// - password: The password to authenticate with the SMTP server.
	// - from: The email address of the sender.
	// - to: A list of email addresses of the recipients.
	// - subject: The subject of the email.
	// - body: The body of the email.
	// - tls: Specifies whether to use TLS for the SMTP connection.
	// - startTLS: Specifies whether to use STARTTLS for the SMTP connection.
	//
	// Returns:
	// - An error if sending the email fails, otherwise nil.
	//
	// Example usage:
	// ```
	// smtpClient := &lualib.RealSMTP{}
	// err := SendMail(smtpClient, "smtp.example.com", 587, "user@example.com", "password",
	//     "sender@example.com", []string{"recipient@example.com"}, "Hello, World!",
	//     "This is the body of the email.", true, true)
	// if err != nil {
	//     fmt.Println("Failed to send email:", err)
	// }
	// ```
	SendMail(server string, port int, username string, password string,
		from string, to []string, subject string, body string, tls bool, startTLS bool) error
}

// RealSMTP is a struct representing a real SMTP server.
type RealSMTP struct{}

// SendMail sends an email using the SMTPClient implementation RealSMTP.
//
// Parameters:
// - server: The SMTP server address.
// - port: The SMTP server port number.
// - username: The username for authentication.
// - password: The password for authentication.
// - from: The email address of the sender.
// - to: An array of email addresses of the recipients.
// - subject: The subject of the email.
// - body: The body or content of the email.
// - tls: A boolean indicating whether to use TLS encryption.
// - startTLS: A boolean indicating whether to start a TLS connection.
//
// Returns:
// - An error if any occurs during sending the email.
//
// Note: This method internally calls smtp.SendMail to send the email.
func (s *RealSMTP) SendMail(server string, port int, username string, password string,
	from string, to []string, subject string, body string, tls bool, startTLS bool) error {
	return smtp.SendMail(server, port, username, password, from, to, subject, body, tls, startTLS)
}

// SendMail sends an email using the provided SMTPClient implementation.
//
// Parameters:
// - smtpClient: An implementation of the SMTPClient interface for sending emails.
//
// Returns:
// - Returns a Lua LGFunction that accepts a Lua state and sends the email using the provided parameters.
// - If an error occurs during sending the email, a LuaString with the error message is pushed onto the Lua stack.
// - If the email is sent successfully, a LuaNil is pushed onto the Lua stack.
//
// Example usage:
// ```
// // Create a real SMTP client instance
// smtpClient := &lualib.RealSMTP{}
//
// // Create a Lua state
// L := lua.NewState()
//
// // Register the SendMail function with the Lua state
// L.SetGlobal("SendMail", lualib.SendMail(smtpClient))
// ```
//
// Note: The SMTPClient interface is defined as follows:
// ```
//
//	type SMTPClient interface {
//		SendMail(server string, port int, username string, password string,
//			from string, to []string, subject string, body string, tls bool, startTLS bool) error
//	}
//
// ```
func SendMail(smtpClient SMTPClient) lua.LGFunction {
	return func(L *lua.LState) int {
		tbl := L.CheckTable(1)

		username := tbl.RawGetString("username").String()
		password := tbl.RawGetString("password").String()
		from := tbl.RawGetString("from").String()
		server := tbl.RawGetString("server").String()
		subject := tbl.RawGetString("subject").String()
		body := tbl.RawGetString("body").String()

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

		to := make([]string, recipientTable.Len())

		recipientTable.ForEach(func(k lua.LValue, v lua.LValue) {
			to = append(to, v.String())
		})

		tlsVal := tbl.RawGetString("tls")
		tls, ok := tlsVal.(lua.LBool)
		if !ok {
			L.Push(lua.LString("tls must be a boolean"))

			return 1
		}

		startTLSVal := tbl.RawGetString("starttls")
		startTLS, ok := startTLSVal.(lua.LBool)
		if !ok {
			L.Push(lua.LString("starttls must be a boolean"))

			return 1
		}

		err := smtpClient.SendMail(server, int(port), username, password, from, to, subject, body, bool(tls), bool(startTLS))

		if err != nil {
			L.Push(lua.LString(err.Error()))
		} else {
			L.Push(lua.LNil)
		}

		return 1
	}
}
