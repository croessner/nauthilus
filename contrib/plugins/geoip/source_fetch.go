// Copyright (C) 2026 Christian Roessner
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

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type sourceBytesFetcher interface {
	Fetch(context.Context, string) ([]byte, error)
}

type sourceFetchFunc func(context.Context, sourceBytesFetcher, string, time.Duration) ([]byte, error)

// fetchHTTPSource downloads one HTTP(S) source with bounded response size.
func fetchHTTPSource(ctx context.Context, client *http.Client, sourceURL string, maxBytes int, subject string) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create %s request: %w", subject, err)
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch %s data: %w", subject, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch %s data: unexpected HTTP status %d", subject, response.StatusCode)
	}

	limited := io.LimitReader(response.Body, int64(maxBytes)+1)

	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read %s data: %w", subject, err)
	}

	if len(raw) > maxBytes {
		return nil, fmt.Errorf("%s data exceeds %d bytes", subject, maxBytes)
	}

	return raw, nil
}

// fetchSourceContents downloads all configured sources through a source-specific fetch function.
func fetchSourceContents(
	ctx context.Context,
	fetcher sourceBytesFetcher,
	sourceURLs []string,
	timeout time.Duration,
	nilFetcherMessage string,
	fetchSource sourceFetchFunc,
) ([][]byte, error) {
	if fetcher == nil {
		return nil, errors.New(nilFetcherMessage)
	}

	contents := make([][]byte, 0, len(sourceURLs))
	for _, sourceURL := range sourceURLs {
		raw, err := fetchSource(ctx, fetcher, sourceURL, timeout)
		if err != nil {
			return nil, err
		}

		contents = append(contents, raw)
	}

	return contents, nil
}

// fetchSourceWithTimeout applies a per-source timeout to one fetcher call.
func fetchSourceWithTimeout(
	ctx context.Context,
	fetcher sourceBytesFetcher,
	sourceURL string,
	timeout time.Duration,
) ([]byte, error) {
	sourceCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return fetcher.Fetch(sourceCtx, sourceURL)
}
