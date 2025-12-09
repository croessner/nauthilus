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
