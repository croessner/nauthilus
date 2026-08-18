// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command session-keyspace-retirement reports or explicitly deletes allowlisted legacy Redis records.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/redis/go-redis/v9"
)

const legacyIDPFlowSuffix = "idp:flow:"

type retirementReport struct {
	matched    uint64
	expiring   uint64
	persistent uint64
	deleted    uint64
}

func main() {
	address := flag.String("redis-address", "127.0.0.1:6379", "Redis address")
	basePrefix := flag.String("base-prefix", "", "Exact configured Redis prefix before idp:flow:")
	apply := flag.Bool("apply", false, "Delete allowlisted legacy records; default is report-only")

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := redis.NewClient(&redis.Options{Addr: *address})
	defer func() { _ = client.Close() }()

	if err := client.Ping(ctx).Err(); err != nil {
		fmt.Fprintln(os.Stderr, "legacy retirement: Redis unavailable")
		os.Exit(1)
	}

	if err := runRetirement(ctx, client, *basePrefix, *apply, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "legacy retirement: operation failed")
		os.Exit(1)
	}
}

// runRetirement scans only the fixed legacy namespace and reports no key or value material.
func runRetirement(
	ctx context.Context,
	client redis.UniversalClient,
	basePrefix string,
	apply bool,
	output io.Writer,
) error {
	if client == nil || output == nil || !validBasePrefix(basePrefix) {
		return errors.New("invalid retirement configuration")
	}

	report, err := inspectLegacyIDPFlows(ctx, client, basePrefix+legacyIDPFlowSuffix, apply)
	if err != nil {
		return err
	}

	mode := "dry-run"
	if apply {
		mode = "apply"
	}

	_, err = fmt.Fprintf(output,
		"namespace=legacy_idp_flow mode=%s matched=%d expiring=%d persistent=%d deleted=%d\n",
		mode, report.matched, report.expiring, report.persistent, report.deleted,
	)

	return err
}

func validBasePrefix(prefix string) bool {
	if prefix == "" || strings.ContainsAny(prefix, "*?[]\r\n\x00") {
		return false
	}

	return strings.TrimSpace(prefix) == prefix
}

func inspectLegacyIDPFlows(
	ctx context.Context,
	client redis.UniversalClient,
	prefix string,
	apply bool,
) (retirementReport, error) {
	var report retirementReport

	iterator := client.Scan(ctx, 0, prefix+"*", 200).Iterator()

	for iterator.Next(ctx) {
		key := iterator.Val()
		if !strings.HasPrefix(key, prefix) {
			return retirementReport{}, errors.New("legacy retirement allowlist violation")
		}

		report.matched++

		ttl, err := client.PTTL(ctx, key).Result()
		if err != nil {
			return retirementReport{}, errors.New("legacy retirement TTL read failed")
		}

		if ttl < 0 {
			report.persistent++
		} else {
			report.expiring++
		}

		if apply {
			deleted, deleteErr := client.Del(ctx, key).Result()
			if deleteErr != nil {
				return retirementReport{}, errors.New("legacy retirement delete failed")
			}

			report.deleted += uint64(deleted)
		}
	}

	if err := iterator.Err(); err != nil {
		return retirementReport{}, errors.New("legacy retirement scan failed")
	}

	return report, nil
}
