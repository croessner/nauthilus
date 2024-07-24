package smtp

import "io"

// sendEmailContent is a function that sends an email content using a generic SMTP or LMTP client.
// It takes a GenericClient interface, the sender's email address, a slice of recipients' email addresses,
// and the email content as a byte array. It performs the necessary operations to establish a connection,
// set the sender and recipients, write the email content, and close the connection.
// It returns an error if any occurs during the email sending process, or nil if the email is sent successfully.
func sendEmailContent(genericClient GenericClient, from string, to []string, msg []byte) error {
	var (
		wc  io.WriteCloser
		err error
	)

	if err = genericClient.Mail(from); err != nil {
		return err
	}

	for _, addr := range to {
		if err = genericClient.Rcpt(addr); err != nil {
			return err
		}
	}

	wc, err = genericClient.Data()
	if err != nil {
		return err
	}

	_, err = wc.Write(msg)
	if err != nil {
		return err
	}

	err = wc.Close()
	if err != nil {
		return err
	}

	err = genericClient.Quit()
	if err != nil {
		return err
	}

	return nil
}
