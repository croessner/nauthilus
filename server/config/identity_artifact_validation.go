// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sort"
	"strings"

	"github.com/croessner/nauthilus/v3/server/idp/signing"
)

type sealedCredentialValidator struct {
	configured *FileSettings     `mapstructure:"-"`
	artifacts  *ArtifactSnapshot `mapstructure:"-"`
}

// validateSealedIdentityAuthorityArtifacts parses every lazy identity and remote credential from one exact snapshot.
func validateSealedIdentityAuthorityArtifacts(
	configured *FileSettings,
	artifacts *ArtifactSnapshot,
) error {
	validator := sealedCredentialValidator{configured: configured, artifacts: artifacts}

	if err := validator.validateIdentity(); err != nil {
		return err
	}

	return validator.validateRemoteAuthorities()
}

// validateIdentity parses OIDC and SAML keys and certificates used after startup.
func (v sealedCredentialValidator) validateIdentity() error {
	if v.configured == nil || v.configured.GetIDP() == nil {
		return nil
	}

	identity := v.configured.GetIDP()
	if err := v.validateOIDC(identity.OIDC); err != nil {
		return err
	}

	return v.validateSAML(identity.SAML2)
}

// validateOIDC parses every static signing and private_key_jwt verification key.
func (v sealedCredentialValidator) validateOIDC(oidc OIDCConfig) error {
	for index, key := range oidc.SigningKeys {
		content, err := v.content(key.Key, key.KeyFile, "OIDC signing key")
		if err != nil {
			return fmt.Errorf("identity.oidc.signing_keys[%d]: %w", index, err)
		}

		if content == "" {
			continue
		}

		if err = validateOIDCPrivateKey(content, key.GetAlgorithm()); err != nil {
			return fmt.Errorf("identity.oidc.signing_keys[%d]: invalid OIDC signing key: %w", index, err)
		}
	}

	for index, client := range oidc.Clients {
		content, err := v.content(client.ClientPublicKey, client.ClientPublicKeyFile, "OIDC client public key")
		if err != nil {
			return fmt.Errorf("identity.oidc.clients[%d]: %w", index, err)
		}

		if content == "" {
			continue
		}

		if err = validateOIDCPublicKey(content, client.GetClientPublicKeyAlgorithm()); err != nil {
			return fmt.Errorf("identity.oidc.clients[%d]: invalid OIDC client public key: %w", index, err)
		}
	}

	return nil
}

// validateSAML parses the IdP pair and every configured service-provider certificate.
func (v sealedCredentialValidator) validateSAML(saml SAML2Config) error {
	if !saml.Enabled {
		return nil
	}

	certificate, err := v.content(saml.Cert, saml.CertFile, "SAML IdP certificate")
	if err != nil {
		return err
	}

	if _, err = parseFirstPEMCertificate(certificate); err != nil {
		return fmt.Errorf("invalid SAML IdP certificate: %w", err)
	}

	privateKey, err := v.content(saml.Key, saml.KeyFile, "SAML IdP private key")
	if err != nil {
		return err
	}

	if _, err = signing.ParseRSAPrivateKeyPEM(privateKey); err != nil {
		return fmt.Errorf("invalid SAML IdP private key: %w", err)
	}

	if _, err = tls.X509KeyPair([]byte(certificate), []byte(privateKey)); err != nil {
		return fmt.Errorf("invalid SAML IdP certificate/key pair: %w", err)
	}

	for index, provider := range saml.ServiceProviders {
		content, readErr := v.content(provider.Cert, provider.CertFile, "SAML SP certificate")
		if readErr != nil {
			return fmt.Errorf("identity.saml.service_providers[%d]: %w", index, readErr)
		}

		if content == "" {
			continue
		}

		if _, parseErr := parseFirstPEMCertificate(content); parseErr != nil {
			return fmt.Errorf("identity.saml.service_providers[%d]: invalid SAML SP certificate: %w", index, parseErr)
		}
	}

	return nil
}

// validateRemoteAuthorities parses remote trust, mTLS identity, and caller credentials deterministically.
func (v sealedCredentialValidator) validateRemoteAuthorities() error {
	if v.configured == nil {
		return nil
	}

	authorities := v.configured.GetNauthilusAuthorityClients()

	names := make([]string, 0, len(authorities))
	for name := range authorities {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		if err := v.validateRemoteAuthority(name, authorities[name]); err != nil {
			return err
		}
	}

	return nil
}

// validateRemoteAuthority parses one outbound authority's exact TLS and bearer material.
func (v sealedCredentialValidator) validateRemoteAuthority(
	name string,
	authority *NauthilusAuthorityClientSection,
) error {
	if authority == nil {
		return nil
	}

	path := "runtime.clients.grpc.nauthilus_authorities." + name
	if err := v.validateAuthorityTLS(path, authority.GetTLS()); err != nil {
		return err
	}

	return v.validateAuthorityBearer(path, authority)
}

// validateAuthorityTLS parses one remote CA and matching client certificate pair.
func (v sealedCredentialValidator) validateAuthorityTLS(path string, configured *AuthorityTLSSection) error {
	if configured == nil || !configured.IsEnabled() {
		return nil
	}

	if configured.CA != "" {
		ca, err := v.read(configured.CA, "authority CA")
		if err != nil {
			return fmt.Errorf("%s.tls.ca: %w", path, err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			clear(ca)

			return fmt.Errorf("%s.tls.ca: authority CA file contains no certificates", path)
		}

		clear(ca)
	}

	if configured.Cert == "" && configured.Key == "" {
		return nil
	}

	certificate, err := v.read(configured.Cert, "authority client certificate")
	if err != nil {
		return fmt.Errorf("%s.tls.cert: %w", path, err)
	}
	defer clear(certificate)

	privateKey, err := v.read(configured.Key, "authority client key")
	if err != nil {
		return fmt.Errorf("%s.tls.key: %w", path, err)
	}
	defer clear(privateKey)

	if _, err = tls.X509KeyPair(certificate, privateKey); err != nil {
		return fmt.Errorf("%s.tls: invalid authority client certificate/key pair: %w", path, err)
	}

	return nil
}

// validateAuthorityBearer parses static-token and private_key_jwt caller credentials.
func (v sealedCredentialValidator) validateAuthorityBearer(
	path string,
	authority *NauthilusAuthorityClientSection,
) error {
	configured := &authority.GetCallerAuth().OIDCBearer
	if tokenPath := configured.GetStaticTokenFile(); tokenPath != "" {
		raw, err := v.read(tokenPath, "authority static token file")
		if err != nil {
			return fmt.Errorf("%s.caller_auth.oidc_bearer.static_token_file: %w", path, err)
		}

		token := strings.TrimSpace(string(raw))
		clear(raw)

		if token == "" {
			return fmt.Errorf("%s.caller_auth.oidc_bearer.static_token_file: authority static token file is empty", path)
		}

		if authority.IsSplitStrictMode() && strings.Count(token, ".") == 2 {
			return fmt.Errorf("%s.caller_auth.oidc_bearer.static_token_file: strict split mode rejects JWT caller tokens", path)
		}
	}

	if !configured.IsEnabled() || configured.GetTokenEndpointAuthMethod() != AuthorityPrivateKeyJWTAuth {
		return nil
	}

	privateKey, err := v.read(configured.ClientPrivateKeyFile, "private_key_jwt key")
	if err != nil {
		return fmt.Errorf("%s.caller_auth.oidc_bearer.client_private_key_file: %w", path, err)
	}
	defer clear(privateKey)

	if err = validateOIDCPrivateKey(string(privateKey), configured.ClientAssertionAlg); err != nil {
		return fmt.Errorf("%s.caller_auth.oidc_bearer.client_private_key_file: invalid private_key_jwt key: %w", path, err)
	}

	return nil
}

// content resolves inline credential material or reads one candidate-captured file.
func (v sealedCredentialValidator) content(raw any, path string, label string) (string, error) {
	content, err := GetContent(raw, "")
	if err != nil || content != "" || path == "" {
		return content, err
	}

	contentBytes, err := v.read(path, label)
	if err != nil {
		return "", err
	}

	content = string(contentBytes)
	clear(contentBytes)

	return content, nil
}

// read returns one detached exact byte stream from the candidate snapshot.
func (v sealedCredentialValidator) read(path string, label string) ([]byte, error) {
	if v.artifacts == nil {
		return nil, fmt.Errorf("read %s: %w", label, ErrArtifactNotCaptured)
	}

	content, err := v.artifacts.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}

	return content, nil
}

// validateOIDCPrivateKey type-checks one supported signing key algorithm.
func validateOIDCPrivateKey(content string, algorithm string) error {
	switch strings.ToUpper(algorithm) {
	case "", signing.AlgorithmRS256:
		_, err := signing.ParseRSAPrivateKeyPEM(content)

		return err
	case strings.ToUpper(signing.AlgorithmEdDSA):
		_, err := signing.ParseEd25519PrivateKeyPEM(content)

		return err
	default:
		return fmt.Errorf("unsupported signing algorithm %q", algorithm)
	}
}

// validateOIDCPublicKey type-checks one supported client assertion key algorithm.
func validateOIDCPublicKey(content string, algorithm string) error {
	switch strings.ToUpper(algorithm) {
	case "", signing.AlgorithmRS256:
		_, err := signing.ParseRSAPublicKeyPEM(content)

		return err
	case strings.ToUpper(signing.AlgorithmEdDSA):
		_, err := signing.ParseEd25519PublicKeyPEM(content)

		return err
	default:
		return fmt.Errorf("unsupported public-key algorithm %q", algorithm)
	}
}
