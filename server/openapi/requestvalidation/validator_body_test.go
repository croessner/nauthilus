// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package requestvalidation

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/util"
)

func TestReadAndRestoreBodyEnforcesLimitAndRestoresAcceptedBody(t *testing.T) {
	accepted := bytes.Repeat([]byte("a"), int(util.DefaultHTTPRequestBodyLimit))
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(accepted))

	body, err := readAndRestoreBody(request)
	if err != nil {
		t.Fatalf("read accepted body: %v", err)
	}

	restored, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}

	if !bytes.Equal(body, accepted) || !bytes.Equal(restored, accepted) {
		t.Fatal("accepted request body was not restored exactly")
	}

	for _, contentLength := range []int64{util.DefaultHTTPRequestBodyLimit + 1, -1} {
		oversized := bytes.Repeat([]byte("b"), int(util.DefaultHTTPRequestBodyLimit+1))
		request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(oversized))
		request.ContentLength = contentLength

		_, err = readAndRestoreBody(request)
		if !errors.Is(err, util.ErrRequestBodyTooLarge) {
			t.Fatalf("oversized body error = %v, want ErrRequestBodyTooLarge", err)
		}
	}
}
