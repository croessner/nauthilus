// Copyright (C) 2024 Christian Rößner
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
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/croessner/nauthilus/contrib/csv2ldap/engine"
)

func main() {
	cfg := engine.DefaultConfig()

	// Paths
	in := flag.String("in", cfg.InCSVPath, "Input CSV path")
	tpl := flag.String("template", cfg.TemplatePath, "LDIF template path")
	out := flag.String("out", cfg.OutLDIFPath, "LDIF output path")

	// CSV column names and filter knobs
	colExp := flag.String("expect-field", cfg.ColExpectedOK, "CSV column used for expectation field")
	expectTrue := flag.String("expect-true", cfg.ExpectTrueValue, "CSV value considered as true (case-insensitive)")
	protos := flag.String("protocols", strings.Join(cfg.AllowedProtocols, ","), "Allowed protocols (comma-separated)")

	// Password formatting flags
	pwFmt := flag.String("pw-format", cfg.PasswordFormat, "Password format: sha|ssha256|ssha512|argon2i|argon2id (default ssha512)")
	pwEnc := flag.String("pw-ssha-encoding", cfg.SSHAEncoding, "SSHA payload encoding: b64|hex (default b64)")
	pwSalt := flag.Int("pw-ssha-salt", 8, "SSHA salt length in bytes")
	argonT := flag.Uint("argon-t", uint(cfg.ArgonTime), "Argon2 iterations (t)")
	argonM := flag.Uint("argon-m", uint(cfg.ArgonMemoryKiB), "Argon2 memory in KiB (m)")
	argonP := flag.Uint("argon-p", uint(cfg.ArgonParallelism), "Argon2 parallelism (p)")
	argonL := flag.Uint("argon-l", uint(cfg.ArgonKeyLen), "Argon2 hash length in bytes")
	argonPrefix := flag.Bool("argon-prefix", cfg.ArgonOpenLDAPPrefix, "Prepend {ARGON2} to PHC string for OpenLDAP")

	flag.Parse()

	// Apply flags to config
	cfg.InCSVPath = *in
	cfg.TemplatePath = *tpl
	cfg.OutLDIFPath = *out
	cfg.ColExpectedOK = *colExp
	cfg.ExpectTrueValue = *expectTrue
	cfg.AllowedProtocols = splitCSV(*protos)
	cfg.PasswordFormat = *pwFmt
	cfg.SSHAEncoding = *pwEnc
	cfg.ArgonTime = uint32(*argonT)
	cfg.ArgonMemoryKiB = uint32(*argonM)
	cfg.ArgonParallelism = uint8(*argonP)
	cfg.ArgonKeyLen = uint32(*argonL)
	cfg.ArgonOpenLDAPPrefix = *argonPrefix

	// Compose engine
	src, err := engine.NewCSVSource(cfg)
	fatalIf(err)

	filter := engine.NewAllowOKProtocols(cfg.AllowedProtocols)

	// Select password encoder per config
	var enc engine.PasswordEncoder
	switch strings.ToLower(strings.TrimSpace(cfg.PasswordFormat)) {
	case "sha", "sha1":
		enc = &engine.SHAEncoder{Encoding: cfg.SSHAEncoding}
	case "", "ssha512", "ssha256":
		e := &engine.SSHAEncoder{Alg: cfg.PasswordFormat, Encoding: cfg.SSHAEncoding, SaltLength: *pwSalt}
		enc = e
	case "argon2i":
		enc = &engine.Argon2Encoder{Variant: engine.Argon2i, Time: cfg.ArgonTime, MemoryKiB: cfg.ArgonMemoryKiB, Parallelism: cfg.ArgonParallelism, KeyLen: cfg.ArgonKeyLen, OpenLDAPPrefix: cfg.ArgonOpenLDAPPrefix}
	case "argon2id":
		enc = &engine.Argon2Encoder{Variant: engine.Argon2id, Time: cfg.ArgonTime, MemoryKiB: cfg.ArgonMemoryKiB, Parallelism: cfg.ArgonParallelism, KeyLen: cfg.ArgonKeyLen, OpenLDAPPrefix: cfg.ArgonOpenLDAPPrefix}
	default:
		fatalIf(fmt.Errorf("unsupported password format: %s", cfg.PasswordFormat))
	}

	renderer, err := engine.NewTemplateRenderer(cfg.TemplatePath, enc)
	fatalIf(err)

	sink, err := engine.NewLDIFFileSink(cfg.OutLDIFPath)
	fatalIf(err)

	app := &engine.App{Source: src, Filter: filter, Render: renderer, Sink: sink}
	n, err := app.Run()
	fatalIf(err)

	fmt.Printf("done. wrote %d entries to %s\n", n, cfg.OutLDIFPath)
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}

	return out
}

func fatalIf(err error) {
	if err != nil {
		// Print a user-friendly error and exit non-zero
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
