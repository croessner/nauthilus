// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package idp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/gin-gonic/gin"
)

func TestFrontendStaticAssetsServeSealedBytesAfterLiveMutation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	artifacts := prepareSealedFrontendRouteArtifacts(t)
	router := gin.New()
	registerFrontendStaticAssets(router, artifacts)

	for _, testCase := range []struct {
		path string
		want string
	}{
		{path: "/static/css/theme.css", want: "captured-css"},
		{path: "/favicon.ico", want: "captured-favicon"},
		{path: "/static/img/icons/logo.svg", want: "captured-nested-image"},
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, testCase.path, nil))

		if response.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want %d", testCase.path, response.Code, http.StatusOK)
		}

		if got := response.Body.String(); got != testCase.want {
			t.Fatalf("GET %s body = %q, want sealed bytes %q", testCase.path, got, testCase.want)
		}
	}

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/static/css/late.css", nil))

	if response.Code != http.StatusNotFound {
		t.Fatalf("GET late static CSS status = %d, want sealed-membership 404", response.Code)
	}
}

// prepareSealedFrontendRouteArtifacts captures the fixture before mutating its live files.
func prepareSealedFrontendRouteArtifacts(t *testing.T) *core.RouteArtifacts {
	t.Helper()

	assetBase := t.TempDir()
	templateDirectory := filepath.Join(assetBase, "templates")
	cssDirectory := filepath.Join(assetBase, "css")
	imageDirectory := filepath.Join(assetBase, "img", "icons")

	if err := os.MkdirAll(templateDirectory, 0o700); err != nil {
		t.Fatalf("create template directory: %v", err)
	}

	if err := os.MkdirAll(cssDirectory, 0o700); err != nil {
		t.Fatalf("create CSS directory: %v", err)
	}

	if err := os.MkdirAll(imageDirectory, 0o700); err != nil {
		t.Fatalf("create image directory: %v", err)
	}

	templatePath := filepath.Join(templateDirectory, "base.html")
	cssPath := filepath.Join(cssDirectory, "theme.css")
	faviconPath := filepath.Join(assetBase, "img", "favicon.ico")
	nestedImagePath := filepath.Join(imageDirectory, "logo.svg")

	writeFrontendRouteArtifact(t, templatePath, []byte(`{{ define "base.html" }}base{{ end }}`))
	writeFrontendRouteArtifact(t, cssPath, []byte("captured-css"))
	writeFrontendRouteArtifact(t, faviconPath, []byte("captured-favicon"))
	writeFrontendRouteArtifact(t, nestedImagePath, []byte("captured-nested-image"))

	cfg := &config.FileSettings{Server: &config.ServerSection{Frontend: config.Frontend{
		Enabled: true, HTMLStaticContentPath: templateDirectory,
	}}}

	snapshot, err := config.CaptureArtifactSnapshot(config.ProductionArtifactSnapshotSpec(cfg))
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	artifacts, err := core.PrepareRouteArtifacts(cfg, snapshot)
	if err != nil {
		t.Fatalf("PrepareRouteArtifacts() error = %v", err)
	}

	mutateFrontendRouteArtifacts(t, cssDirectory, cssPath, faviconPath, nestedImagePath)

	return artifacts
}

// mutateFrontendRouteArtifacts changes captured files and adds one late member after preparation.
func mutateFrontendRouteArtifacts(t *testing.T, cssDirectory string, paths ...string) {
	t.Helper()

	contents := [][]byte{
		[]byte("mutated-css"),
		[]byte("mutated-favicon"),
		[]byte("mutated-nested-image"),
	}
	for index, path := range paths {
		writeFrontendRouteArtifact(t, path, contents[index])
	}

	writeFrontendRouteArtifact(t, filepath.Join(cssDirectory, "late.css"), []byte("late-css"))
}

// writeFrontendRouteArtifact replaces one test-owned frontend file.
func writeFrontendRouteArtifact(t *testing.T, path string, content []byte) {
	t.Helper()

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write frontend artifact %q: %v", path, err)
	}
}
