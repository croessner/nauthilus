//go:build auth_basic_endpoint

// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/gin-gonic/gin"
)

func TestBasicEndpointUsesInjectedAuthApplicationAndRemovesPresentation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &recordingAuthApplicationService{}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/basic", http.NoBody)
	request.SetBasicAuth(applicationBoundaryUsername, applicationBoundaryPassword)
	attachApplicationBoundaryTransport(t, request)

	response := httptest.NewRecorder()
	applicationBoundaryRouter(applicationBoundaryDeps(), service).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200; body=%q", response.Code, response.Body.String())
	}

	call := service.onlyCall(t)
	if call.operation != core.AuthModeAuthenticate || call.input.Service != definitions.ServBasic {
		t.Fatalf("operation/service = %q/%q, want authenticate/basic", call.operation, call.input.Service)
	}

	if call.input.EntryPoint != core.AuthnEntryBackchannel {
		t.Fatalf("entry point = %q, want backchannel", call.input.EntryPoint)
	}

	if call.input.Credentials.Username != applicationBoundaryUsername {
		t.Fatalf("username = %q, want %q", call.input.Credentials.Username, applicationBoundaryUsername)
	}

	call.input.Credentials.Password.WithString(func(password string) {
		if password != applicationBoundaryPassword {
			t.Fatalf("password = %q, want test password", password)
		}
	})

	if request.Header.Get("Authorization") != "" {
		t.Fatal("Authorization presentation remains on the request after conversion")
	}

	if values := call.input.Context.RequestMetadata["authorization"]; len(values) != 0 {
		t.Fatalf("Authorization presentation reached request metadata: %#v", values)
	}
}
