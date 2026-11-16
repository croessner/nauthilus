// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/definitions"

	"github.com/gin-gonic/gin"
)

// TestPostActionOutcomeBindingWithoutSealIsUnknown pins that an unsealed run never inherits capture-time status values.
func TestPostActionOutcomeBindingWithoutSealIsUnknown(t *testing.T) {
	request := pluginapi.PostActionRequest{}
	request.Snapshot.Diagnostics.HTTPStatus = http.StatusForbidden
	request.Snapshot.Diagnostics.StatusMessage = definitions.PasswordFail

	postActionOutcomeBinding{cell: &authnTerminalOutcomeCell{}}.bind(&request)

	if request.Outcome.Known || request.Outcome.Decision != pluginapi.AuthOutcomeUnknown {
		t.Fatalf("outcome = %+v, want unknown", request.Outcome)
	}

	if request.Snapshot.Diagnostics.HTTPStatus != 0 || request.Snapshot.Diagnostics.StatusMessage != "" {
		t.Fatalf("diagnostics = %d/%q, want cleared capture-time status",
			request.Snapshot.Diagnostics.HTTPStatus, request.Snapshot.Diagnostics.StatusMessage)
	}
}

// TestAuthnTerminalOutcomeCellSealsOnce pins that a run keeps its first terminal outcome.
func TestAuthnTerminalOutcomeCellSealsOnce(t *testing.T) {
	cell := &authnTerminalOutcomeCell{}
	cell.seal(pluginapi.AuthOutcome{Decision: pluginapi.AuthOutcomeTempFail, HTTPStatus: http.StatusInternalServerError})
	cell.seal(pluginapi.AuthOutcome{Decision: pluginapi.AuthOutcomeOK, HTTPStatus: http.StatusOK})

	got := cell.load()
	if !got.Known || got.Decision != pluginapi.AuthOutcomeTempFail || got.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("sealed outcome = %+v, want first tempfail", got)
	}
}

// TestPostActionCompletionMiddlewareRecordsCommittedStatus pins that the HTTP boundary records the committed status
// before it opens the gate, so detached work sees what the client received.
func TestPostActionCompletionMiddlewareRecordsCommittedStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var recorder *PostActionTransportRecorder

	engine := gin.New()
	engine.Use(postActionResponseCompletionMiddleware())
	engine.GET("/auth", func(ctx *gin.Context) {
		recorder = PostActionTransportRecorderFromContext(ctx.Request.Context())
		ctx.Status(http.StatusOK)
	})

	engine.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth", nil))

	if recorder == nil {
		t.Fatal("completion middleware installed no transport recorder")
	}

	request := pluginapi.PostActionRequest{}
	cell := &authnTerminalOutcomeCell{}
	cell.seal(pluginapi.AuthOutcome{Decision: pluginapi.AuthOutcomeFail, HTTPStatus: http.StatusOK})

	postActionOutcomeBinding{cell: cell, transport: recorder}.bind(&request)

	if request.Outcome.Transport != pluginapi.AuthTransportHTTP || request.Outcome.TransportStatus != http.StatusOK {
		t.Fatalf("outcome transport = %q/%d, want http/200", request.Outcome.Transport, request.Outcome.TransportStatus)
	}
}
