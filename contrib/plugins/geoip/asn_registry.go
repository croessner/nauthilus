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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxASNRegistryResponseBytes = 32 << 20

type asnRegistryFetcher interface {
	Fetch(context.Context, string) ([]byte, error)
}

type httpASNRegistryFetcher struct {
	client *http.Client
}

type asnRegistrySnapshot struct {
	ranges   []asnRegistryRange
	loadedAt time.Time
}

type asnRegistryRange struct {
	record asnRegistryRecord
	start  int
	end    int
}

type asnRegistryRecord struct {
	Registry   string
	CountryISO string
	Allocated  string
	Status     string
	ASN        int
}

// Fetch downloads one delegated registry stats document.
func (f httpASNRegistryFetcher) Fetch(ctx context.Context, sourceURL string) ([]byte, error) {
	client := f.client
	if client == nil {
		client = http.DefaultClient
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create ASN registry request: %w", err)
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch ASN registry data: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch ASN registry data: unexpected HTTP status %d", response.StatusCode)
	}

	limited := io.LimitReader(response.Body, maxASNRegistryResponseBytes+1)

	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read ASN registry data: %w", err)
	}

	if len(raw) > maxASNRegistryResponseBytes {
		return nil, fmt.Errorf("ASN registry data exceeds %d bytes", maxASNRegistryResponseBytes)
	}

	return raw, nil
}

// fetchASNRegistrySnapshot downloads, parses, and merges all configured registry feeds.
func fetchASNRegistrySnapshot(
	ctx context.Context,
	fetcher asnRegistryFetcher,
	sourceURLs []string,
	timeout time.Duration,
) (*asnRegistrySnapshot, error) {
	if fetcher == nil {
		return nil, fmt.Errorf("ASN registry fetcher is nil")
	}

	contents := make([][]byte, 0, len(sourceURLs))
	for _, sourceURL := range sourceURLs {
		raw, err := fetchASNRegistrySource(ctx, fetcher, sourceURL, timeout)
		if err != nil {
			return nil, err
		}

		contents = append(contents, raw)
	}

	return buildASNRegistrySnapshot(contents)
}

// fetchASNRegistrySource applies a per-source timeout to one registry fetch.
func fetchASNRegistrySource(
	ctx context.Context,
	fetcher asnRegistryFetcher,
	sourceURL string,
	timeout time.Duration,
) ([]byte, error) {
	sourceCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return fetcher.Fetch(sourceCtx, sourceURL)
}

// buildASNRegistrySnapshot merges parsed delegated stats documents into a lookup snapshot.
func buildASNRegistrySnapshot(contents [][]byte) (*asnRegistrySnapshot, error) {
	ranges := make([]asnRegistryRange, 0)

	for index, raw := range contents {
		parsed, err := parseASNRegistryDelegatedStats(raw)
		if err != nil {
			return nil, fmt.Errorf("parse ASN registry source %d: %w", index, err)
		}

		ranges = append(ranges, parsed...)
	}

	if len(ranges) == 0 {
		return nil, fmt.Errorf("ASN registry data contains no ASN allocations")
	}

	sort.Slice(ranges, func(i int, j int) bool {
		if ranges[i].start == ranges[j].start {
			return ranges[i].end < ranges[j].end
		}

		return ranges[i].start < ranges[j].start
	})

	return &asnRegistrySnapshot{ranges: ranges, loadedAt: time.Now().UTC()}, nil
}

// parseASNRegistryDelegatedStats extracts assigned and allocated ASN ranges from delegated stats data.
func parseASNRegistryDelegatedStats(raw []byte) ([]asnRegistryRange, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	ranges := make([]asnRegistryRange, 0)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++

		line := strings.TrimSpace(scanner.Text())
		if shouldSkipRegistryLine(line) {
			continue
		}

		fields := strings.Split(line, "|")
		if len(fields) < 7 || fields[2] != "asn" || !isActiveASNRegistryStatus(fields[6]) {
			continue
		}

		recordRange, err := parseASNRegistryRange(fields)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}

		ranges = append(ranges, recordRange)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ranges, nil
}

// Lookup returns registry metadata for one ASN.
func (s *asnRegistrySnapshot) Lookup(asn int) (asnRegistryRecord, bool) {
	if s == nil || asn <= 0 {
		return asnRegistryRecord{}, false
	}

	index := sort.Search(len(s.ranges), func(i int) bool {
		return s.ranges[i].start > asn
	}) - 1
	if index < 0 {
		return asnRegistryRecord{}, false
	}

	recordRange := s.ranges[index]
	if asn > recordRange.end {
		return asnRegistryRecord{}, false
	}

	record := recordRange.record
	record.ASN = asn

	return record, true
}

// Records reports how many ASN ranges are available.
func (s *asnRegistrySnapshot) Records() int {
	if s == nil {
		return 0
	}

	return len(s.ranges)
}

// parseASNRegistryRange converts one delegated stats ASN row into a lookup range.
func parseASNRegistryRange(fields []string) (asnRegistryRange, error) {
	start64, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return asnRegistryRange{}, fmt.Errorf("ASN start must be numeric: %w", err)
	}

	count64, err := strconv.ParseInt(fields[4], 10, 64)
	if err != nil {
		return asnRegistryRange{}, fmt.Errorf("ASN count must be numeric: %w", err)
	}

	if start64 <= 0 || count64 <= 0 {
		return asnRegistryRange{}, fmt.Errorf("ASN range must be positive")
	}

	end64 := start64 + count64 - 1
	if end64 < start64 || end64 > math.MaxInt {
		return asnRegistryRange{}, fmt.Errorf("ASN range overflows")
	}

	start := int(start64)
	end := int(end64)

	return asnRegistryRange{
		start: start,
		end:   end,
		record: asnRegistryRecord{
			Registry:   fields[0],
			CountryISO: fields[1],
			Allocated:  fields[5],
			Status:     fields[6],
		},
	}, nil
}

// shouldSkipRegistryLine reports whether a delegated stats line is informational.
func shouldSkipRegistryLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#")
}

// isActiveASNRegistryStatus keeps only registry rows that describe assigned resources.
func isActiveASNRegistryStatus(status string) bool {
	return status == "allocated" || status == "assigned"
}
