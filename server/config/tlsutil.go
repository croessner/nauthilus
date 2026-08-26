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
	"strings"
)

var tls12CipherSuites = map[string]uint16{
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

var tls13CipherSuites = map[string]struct{}{
	"TLS_AES_128_GCM_SHA256":       {},
	"TLS_AES_256_GCM_SHA384":       {},
	"TLS_CHACHA20_POLY1305_SHA256": {},
}

// TLSClientConfigProvider exposes file-backed outbound TLS settings.
type TLSClientConfigProvider interface {
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

	config, err := buildClientTLSConfig(nil, t)
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

	config, err := buildClientTLSConfig(nil, t)
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

// BuildClientTLSConfig constructs outbound TLS exclusively from one candidate's sealed artifacts.
func BuildClientTLSConfig(configured File, provider TLSClientConfigProvider) (*tls.Config, error) {
	return buildClientTLSConfig(configured, provider)
}

// buildClientTLSConfig parses trust and identity bytes owned by one immutable config snapshot.
func buildClientTLSConfig(configured File, provider TLSClientConfigProvider) (*tls.Config, error) {
	if !clientTLSProviderEnabled(provider) {
		return nil, nil
	}

	caPool, err := loadClientRootCAs(configured, provider.GetCAFile())
	if err != nil {
		return nil, err
	}

	certificates, err := loadClientCertificates(configured, provider.GetCert(), provider.GetKey())
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates:       certificates,
		RootCAs:            caPool,
		MinVersion:         TLSMinVersionValue(provider.GetMinTLSVersion()),
		CipherSuites:       TLSCipherSuiteValues(provider.GetCipherSuites()),
		InsecureSkipVerify: provider.GetSkipVerify(),
	}, nil
}

// clientTLSProviderEnabled reports whether one supported provider requests custom TLS.
func clientTLSProviderEnabled(provider TLSClientConfigProvider) bool {
	if provider == nil {
		return false
	}

	switch typed := provider.(type) {
	case *TLS:
		return typed.IsEnabled()
	case *HTTPClientTLS:
		return typed.hasCustomSettings()
	default:
		return true
	}
}

// loadClientRootCAs parses one optional candidate-bound trust bundle.
func loadClientRootCAs(configured File, path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}

	pemBytes, err := readSealedArtifact(configured, path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	defer clear(pemBytes)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("parse CA file: invalid PEM data")
	}

	return pool, nil
}

// loadClientCertificates parses one optional candidate-bound certificate and key pair.
func loadClientCertificates(configured File, certPath string, keyPath string) ([]tls.Certificate, error) {
	if (certPath == "") != (keyPath == "") {
		return nil, fmt.Errorf("client certificate and key must be configured together")
	}

	if certPath == "" {
		return nil, nil
	}

	certificatePEM, err := readSealedArtifact(configured, certPath)
	if err != nil {
		return nil, fmt.Errorf("read client certificate: %w", err)
	}
	defer clear(certificatePEM)

	keyPEM, err := readSealedArtifact(configured, keyPath)
	if err != nil {
		return nil, fmt.Errorf("read client key: %w", err)
	}
	defer clear(keyPEM)

	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}

	return []tls.Certificate{certificate}, nil
}

// readSealedArtifact returns one defensive copy from the candidate-bound snapshot.
func readSealedArtifact(configured File, path string) ([]byte, error) {
	snapshot, err := ArtifactSnapshotFor(configured)
	if err != nil {
		return nil, err
	}

	return snapshot.ReadFile(path)
}

// TLSMinVersionValue converts a configured TLS version label into the tls package constant.
func TLSMinVersionValue(version string) uint16 {
	switch version {
	case TLSVersion13:
		return tls.VersionTLS13
	case defaultTLSMinVersion:
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
	mapped, ok := tls12CipherSuites[suite]

	return mapped, ok
}

// ValidateTLSCipherSuites checks that configured cipher suites only contain values
// that Go can actually apply through tls.Config.CipherSuites.
func ValidateTLSCipherSuites(path, minTLSVersion string, suites []string) error {
	if len(suites) == 0 {
		return nil
	}

	if minTLSVersion == TLSVersion13 {
		return fmt.Errorf("%s must be empty when %s is TLS1.3; cipher_suites only applies to TLS 1.2", path, joinConfigPath(strings.TrimSuffix(path, ".cipher_suites"), "min_tls_version"))
	}

	for index, suite := range suites {
		if IsTLS13CipherSuite(suite) {
			return fmt.Errorf("%s[%d]: %q is a TLS 1.3 cipher suite; TLS 1.3 cipher suites are not configurable through tls.Config.cipher_suites", path, index, suite)
		}

		if _, ok := TLSCipherSuiteValue(suite); !ok {
			return fmt.Errorf("%s[%d]: unsupported TLS cipher suite %q", path, index, suite)
		}
	}

	return nil
}

// IsTLS13CipherSuite reports whether the name is a TLS 1.3 cipher suite.
func IsTLS13CipherSuite(suite string) bool {
	_, ok := tls13CipherSuites[suite]

	return ok
}
