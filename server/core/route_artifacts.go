// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"html/template"
	"path/filepath"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v4/server/config"
)

const grpcHTTP2NextProtocol = "h2"

var frontendAssetDirectories = [...]string{"css", "js", "img", "fonts"}

// FrontendAsset is one detached immutable public file under the frontend asset root.
type FrontendAsset struct {
	RelativePath string
	Content      []byte
}

// RouteArtifacts owns every parsed or copied file dependency used by inbound routes.
type RouteArtifacts struct {
	frontendTemplates *template.Template
	httpClientCAs     *x509.CertPool
	grpcClientCAs     *x509.CertPool
	httpCertificate   *tls.Certificate
	grpcCertificate   *tls.Certificate
	staticFiles       map[string][]byte
	frontendAssets    []FrontendAsset
}

// PrepareRouteArtifacts parses all listener identities, trust roots, templates, and public files from one sealed source.
func PrepareRouteArtifacts(configured config.File, snapshot *config.ArtifactSnapshot) (*RouteArtifacts, error) {
	if configured == nil || snapshot == nil {
		return nil, fmt.Errorf("prepare route artifacts: config and sealed snapshot are required")
	}

	result := &RouteArtifacts{staticFiles: make(map[string][]byte)}
	if err := result.prepareHTTP(configured.GetServer().GetTLS(), snapshot); err != nil {
		return nil, err
	}

	if err := result.prepareGRPC(configured, snapshot); err != nil {
		return nil, err
	}

	if err := result.prepareFrontend(configured.GetServer().GetFrontend(), snapshot); err != nil {
		return nil, err
	}

	if err := result.prepareSecurityTxt(configured.GetServer().GetSecurityTxt(), snapshot); err != nil {
		return nil, err
	}

	return result, nil
}

// prepareHTTP parses the inbound HTTP identity and optional client trust pool.
func (a *RouteArtifacts) prepareHTTP(section *config.TLS, snapshot *config.ArtifactSnapshot) error {
	if section == nil || !section.IsEnabled() {
		return nil
	}

	certificate, err := readSealedKeyPair(snapshot, section.GetCert(), section.GetKey())
	if err != nil {
		return fmt.Errorf("prepare runtime.servers.http.tls certificate: %w", err)
	}

	a.httpCertificate = &certificate

	if section.GetCAFile() == "" {
		return nil
	}

	a.httpClientCAs, err = readSealedCertPool(snapshot, section.GetCAFile())
	if err != nil {
		return fmt.Errorf("prepare runtime.servers.http.tls.ca_file: %w", err)
	}

	return nil
}

// prepareGRPC parses the inbound gRPC identity and optional client trust pool.
func (a *RouteArtifacts) prepareGRPC(configured config.File, snapshot *config.ArtifactSnapshot) error {
	provider, ok := configured.(config.RuntimeGRPCAuthServerProvider)
	if !ok {
		return nil
	}

	section := provider.GetRuntimeGRPCAuthServer().GetTLS()
	if !section.IsEnabled() {
		return nil
	}

	certificate, err := readSealedKeyPair(snapshot, section.GetCert(), section.GetKey())
	if err != nil {
		return fmt.Errorf("prepare runtime.servers.grpc.authority.tls certificate: %w", err)
	}

	a.grpcCertificate = &certificate

	if section.GetClientCA() == "" {
		return nil
	}

	a.grpcClientCAs, err = readSealedCertPool(snapshot, section.GetClientCA())
	if err != nil {
		return fmt.Errorf("prepare runtime.servers.grpc.authority.tls.client_ca: %w", err)
	}

	return nil
}

// prepareFrontend parses templates and copies every configured public asset tree.
func (a *RouteArtifacts) prepareFrontend(frontend *config.Frontend, snapshot *config.ArtifactSnapshot) error {
	if frontend == nil || strings.TrimSpace(frontend.GetHTMLStaticContentPath()) == "" {
		return nil
	}

	templateDirectory := filepath.Clean(frontend.GetHTMLStaticContentPath())
	if err := a.prepareFrontendTemplates(frontend.Enabled, templateDirectory, snapshot); err != nil {
		return err
	}

	assetBase := frontendAssetBasePath(templateDirectory)
	if err := a.prepareFrontendAssets(assetBase, snapshot); err != nil {
		return err
	}

	slices.SortFunc(a.frontendAssets, func(left FrontendAsset, right FrontendAsset) int {
		return strings.Compare(left.RelativePath, right.RelativePath)
	})

	return nil
}

// prepareFrontendTemplates parses every captured HTML template without reopening its carrier.
func (a *RouteArtifacts) prepareFrontendTemplates(
	enabled bool,
	templateDirectory string,
	snapshot *config.ArtifactSnapshot,
) error {
	templatePattern := filepath.Join(templateDirectory, "*.html")

	files, err := snapshot.FilesMatching(templatePattern)
	if err != nil {
		return fmt.Errorf("prepare frontend templates: %w", err)
	}

	if len(files) == 0 {
		if enabled {
			return fmt.Errorf("prepare frontend templates: no files matched %q", templatePattern)
		}

		return nil
	}

	a.frontendTemplates, err = parseSealedTemplates(files)
	if err != nil {
		return fmt.Errorf("prepare frontend templates: %w", err)
	}

	return nil
}

// prepareFrontendAssets copies every captured public asset under its normalized relative path.
func (a *RouteArtifacts) prepareFrontendAssets(assetBase string, snapshot *config.ArtifactSnapshot) error {
	for _, directory := range frontendAssetDirectories {
		assets, err := snapshot.FilesUnder(filepath.Join(assetBase, directory))
		if err != nil {
			return fmt.Errorf("prepare frontend %s assets: %w", directory, err)
		}

		for _, asset := range assets {
			if err = a.appendFrontendAsset(assetBase, asset); err != nil {
				return err
			}
		}
	}

	return nil
}

// appendFrontendAsset validates and retains one asset beneath the captured public root.
func (a *RouteArtifacts) appendFrontendAsset(assetBase string, asset config.ArtifactFile) error {
	relative, err := filepath.Rel(assetBase, asset.Path)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		clear(asset.Content)

		return fmt.Errorf("prepare frontend asset %q: path escapes asset root", asset.Path)
	}

	a.frontendAssets = append(a.frontendAssets, FrontendAsset{
		RelativePath: filepath.ToSlash(relative), Content: asset.Content,
	})

	return nil
}

// prepareSecurityTxt copies optional route-served RFC 9116 companion files.
func (a *RouteArtifacts) prepareSecurityTxt(section *config.SecurityTxt, snapshot *config.ArtifactSnapshot) error {
	if section == nil || !section.IsEnabled() {
		return nil
	}

	for _, path := range []string{section.GetEncryptionFile(), section.GetPolicyFile()} {
		if strings.TrimSpace(path) == "" {
			continue
		}

		content, err := snapshot.ReadFile(path)
		if err != nil {
			return fmt.Errorf("prepare security.txt route artifact %q: %w", path, err)
		}

		a.staticFiles[filepath.Clean(path)] = content
	}

	return nil
}

// FrontendTemplates returns a detached parsed template set for one router.
func (a *RouteArtifacts) FrontendTemplates() (*template.Template, error) {
	if a == nil || a.frontendTemplates == nil {
		return nil, fmt.Errorf("prepared frontend templates are unavailable")
	}

	return a.frontendTemplates.Clone()
}

// FrontendAssets returns defensive copies of every captured public asset.
func (a *RouteArtifacts) FrontendAssets() []FrontendAsset {
	if a == nil {
		return nil
	}

	result := make([]FrontendAsset, 0, len(a.frontendAssets))
	for _, asset := range a.frontendAssets {
		result = append(result, FrontendAsset{
			RelativePath: asset.RelativePath,
			Content:      bytes.Clone(asset.Content),
		})
	}

	return result
}

// ReadFile returns a defensive copy of one sealed route-served file.
func (a *RouteArtifacts) ReadFile(path string) ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("prepared route artifacts are unavailable")
	}

	content, ok := a.staticFiles[filepath.Clean(path)]
	if !ok {
		return nil, fmt.Errorf("route artifact %q was not prepared", path)
	}

	return bytes.Clone(content), nil
}

// HTTPServerCertificate returns a detached listener identity.
func (a *RouteArtifacts) HTTPServerCertificate() (tls.Certificate, error) {
	if a == nil || a.httpCertificate == nil {
		return tls.Certificate{}, fmt.Errorf("prepared HTTP TLS identity is unavailable")
	}

	return cloneTLSCertificate(*a.httpCertificate), nil
}

// HTTPClientCAs returns a detached inbound HTTP trust pool.
func (a *RouteArtifacts) HTTPClientCAs() *x509.CertPool {
	if a == nil || a.httpClientCAs == nil {
		return nil
	}

	return a.httpClientCAs.Clone()
}

// GRPCServerTLSConfig builds one detached gRPC listener configuration from sealed material.
func (a *RouteArtifacts) GRPCServerTLSConfig(section *config.RuntimeGRPCTLSSection) (*tls.Config, error) {
	if section == nil || !section.IsEnabled() {
		return nil, nil
	}

	if a == nil || a.grpcCertificate == nil {
		return nil, fmt.Errorf("prepared gRPC TLS identity is unavailable")
	}

	clientCAs := a.grpcClientCAs
	clientAuth := tls.NoClientCert

	if section.RequiresClientCert() {
		if clientCAs == nil {
			return nil, fmt.Errorf("prepared gRPC client CA is unavailable")
		}

		clientAuth = tls.RequireAndVerifyClientCert
	} else if clientCAs != nil {
		clientAuth = tls.VerifyClientCertIfGiven
	}

	var detachedClientCAs *x509.CertPool
	if clientCAs != nil {
		detachedClientCAs = clientCAs.Clone()
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cloneTLSCertificate(*a.grpcCertificate)},
		ClientAuth:   clientAuth,
		ClientCAs:    detachedClientCAs,
		MinVersion:   config.TLSMinVersionValue(section.GetMinTLSVersion()),
		NextProtos:   []string{grpcHTTP2NextProtocol},
	}, nil
}

// readSealedKeyPair parses one certificate identity without reopening its paths.
func readSealedKeyPair(snapshot *config.ArtifactSnapshot, certPath string, keyPath string) (tls.Certificate, error) {
	certificatePEM, err := snapshot.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clear(certificatePEM)

	keyPEM, err := snapshot.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clear(keyPEM)

	return tls.X509KeyPair(certificatePEM, keyPEM)
}

// readSealedCertPool parses one trust bundle without reopening its path.
func readSealedCertPool(snapshot *config.ArtifactSnapshot, path string) (*x509.CertPool, error) {
	content, err := snapshot.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(content)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(content) {
		return nil, fmt.Errorf("invalid PEM data")
	}

	return pool, nil
}

// parseSealedTemplates reproduces ParseFiles naming while consuming captured bytes.
func parseSealedTemplates(files []config.ArtifactFile) (*template.Template, error) {
	defer func() {
		for index := range files {
			clear(files[index].Content)
		}
	}()

	var parsed *template.Template

	for _, file := range files {
		name := filepath.Base(file.Path)
		if parsed == nil {
			parsed = template.New(name).Funcs(defaultTemplateFuncMap())
		}

		current := parsed
		if name != parsed.Name() {
			current = parsed.New(name)
		}

		_, err := current.Parse(string(file.Content))
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", file.Path, err)
		}
	}

	return parsed, nil
}

// frontendAssetBasePath resolves the public asset root beside a templates directory.
func frontendAssetBasePath(templateDirectory string) string {
	if filepath.Base(templateDirectory) == "templates" {
		return filepath.Dir(templateDirectory)
	}

	return templateDirectory
}

// cloneTLSCertificate detaches the mutable byte slices of one parsed identity.
func cloneTLSCertificate(source tls.Certificate) tls.Certificate {
	result := source

	result.Certificate = make([][]byte, len(source.Certificate))
	for index := range source.Certificate {
		result.Certificate[index] = bytes.Clone(source.Certificate[index])
	}

	result.OCSPStaple = bytes.Clone(source.OCSPStaple)

	result.SignedCertificateTimestamps = make([][]byte, len(source.SignedCertificateTimestamps))
	for index := range source.SignedCertificateTimestamps {
		result.SignedCertificateTimestamps[index] = bytes.Clone(source.SignedCertificateTimestamps[index])
	}

	return result
}
