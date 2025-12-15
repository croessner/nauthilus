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

package config

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

// ToTLSConfig builds a *tls.Config from the TLS settings.
// It returns nil when TLS is not enabled. The configuration includes:
// - Root CAs from CAFile (if provided)
// - Client certificate (if Cert and Key are provided)
// - InsecureSkipVerify according to SkipVerify
// Note: MinTLSVersion and CipherSuites are not mapped here yet; extend as needed.
func (t *TLS) ToTLSConfig() *tls.Config {
	if t == nil || !t.IsEnabled() {
		return nil
	}

	var certs []tls.Certificate
	var caPool *x509.CertPool

	if t.GetCAFile() != "" {
		if pem, err := os.ReadFile(t.GetCAFile()); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				caPool = pool
			}
		}
	}

	if t.GetCert() != "" && t.GetKey() != "" {
		if cert, err := tls.LoadX509KeyPair(t.GetCert(), t.GetKey()); err == nil {
			certs = append(certs, cert)
		}
	}

	return &tls.Config{
		Certificates:       certs,
		RootCAs:            caPool,
		InsecureSkipVerify: t.GetSkipVerify(),
	}
}
