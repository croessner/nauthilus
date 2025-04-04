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

package smtp

import "io"

// sendEmailContent sends an email using the provided GenericClient, sender address, recipient list, and message content.
// It handles connection setup, message transmission, and cleanup, returning an error if any step fails.
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
