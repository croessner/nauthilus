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
	"fmt"
	"os"
)

type tlsClientConfigProvider interface {
	GetCAFile() string
	GetCert() string
	GetKey() string
	GetSkipVerify() bool
	GetMinTLSVersion() string
	GetCipherSuites() []string
}

// ToTLSConfig builds a *tls.Config from the TLS settings.
// It returns nil when TLS is not enabled. The configuration includes:
// - Root CAs from CAFile (if provided)
// - Client certificate (if Cert and Key are provided)
// - InsecureSkipVerify according to SkipVerify
func (t *TLS) ToTLSConfig() *tls.Config {
	if t == nil || !t.IsEnabled() {
		return nil
	}

	config, err := buildClientTLSConfig(t)
	if err != nil {
		return nil
	}

	return config
}

// ToTLSConfig builds a *tls.Config from outbound HTTP client TLS settings.
// It returns nil when no custom TLS settings are configured.
func (t *HTTPClientTLS) ToTLSConfig() *tls.Config {
	if t == nil || !t.hasCustomSettings() {
		return nil
	}

	config, err := buildClientTLSConfig(t)
	if err != nil {
		return nil
	}

	return config
}

func (t *HTTPClientTLS) hasCustomSettings() bool {
	if t == nil {
		return false
	}

	return t.SkipVerify ||
		t.MinTLSVersion != "" ||
		t.Cert != "" ||
		t.Key != "" ||
		t.CAFile != "" ||
		len(t.CipherSuites) > 0
}

func buildClientTLSConfig(provider tlsClientConfigProvider) (*tls.Config, error) {
	if provider == nil {
		return nil, nil
	}

	var certs []tls.Certificate
	var caPool *x509.CertPool

	if provider.GetCAFile() != "" {
		pem, err := os.ReadFile(provider.GetCAFile())
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse CA file: invalid PEM data")
		}

		caPool = pool
	}

	if provider.GetCert() != "" && provider.GetKey() != "" {
		cert, err := tls.LoadX509KeyPair(provider.GetCert(), provider.GetKey())
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	return &tls.Config{
		Certificates:       certs,
		RootCAs:            caPool,
		MinVersion:         TLSMinVersionValue(provider.GetMinTLSVersion()),
		CipherSuites:       TLSCipherSuiteValues(provider.GetCipherSuites()),
		InsecureSkipVerify: provider.GetSkipVerify(),
	}, nil
}

// TLSMinVersionValue converts a configured TLS version label into the tls package constant.
func TLSMinVersionValue(version string) uint16 {
	switch version {
	case "TLS1.3":
		return tls.VersionTLS13
	case "TLS1.2":
		return tls.VersionTLS12
	default:
		return tls.VersionTLS12
	}
}

// TLSCipherSuiteValues converts configured cipher suite names into tls package constants.
func TLSCipherSuiteValues(suites []string) []uint16 {
	if len(suites) == 0 {
		return nil
	}

	translated := make([]uint16, 0, len(suites))
	for _, suite := range suites {
		if mapped, ok := TLSCipherSuiteValue(suite); ok {
			translated = append(translated, mapped)
		}
	}

	return translated
}

// TLSCipherSuiteValue converts one configured cipher suite name into the tls package constant.
func TLSCipherSuiteValue(suite string) (uint16, bool) {
	cipherMap := map[string]uint16{
		"TLS_AES_128_GCM_SHA256":                  tls.TLS_AES_128_GCM_SHA256,
		"TLS_AES_256_GCM_SHA384":                  tls.TLS_AES_256_GCM_SHA384,
		"TLS_CHACHA20_POLY1305_SHA256":            tls.TLS_CHACHA20_POLY1305_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	mapped, ok := cipherMap[suite]

	return mapped, ok
}
