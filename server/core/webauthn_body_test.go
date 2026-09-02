// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/gin-gonic/gin"
)

func TestParseRegistrationFinishResponseRejectsOversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, contentLength := range []int64{util.DefaultHTTPRequestBodyLimit + 1, -1} {
		response := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(response)
		body := bytes.Repeat([]byte("a"), int(util.DefaultHTTPRequestBodyLimit+1))
		ctx.Request = httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", bytes.NewReader(body))
		ctx.Request.ContentLength = contentLength

		_, parsed, ok := parseRegistrationFinishResponse(ctx)
		if ok || parsed != nil {
			t.Fatal("oversized WebAuthn registration response was accepted")
		}

		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("response status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
		}
	}
}
