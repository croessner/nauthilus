// Copyright (C) 2026 Christian Rößner
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

package flagutil

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestPrintDefaults_UsesDoubleDashForLongFlags(t *testing.T) {
	fs := flag.NewFlagSet("nauthilus", flag.ContinueOnError)
	fs.Bool("config-check", false, "validate configuration and exit")
	fs.Bool("P", false, "print sensitive configuration values")

	out := &bytes.Buffer{}
	PrintDefaults(fs, out)

	rendered := out.String()

	if !strings.Contains(rendered, "--config-check") {
		t.Fatalf("PrintDefaults() missing long-form double dash: %q", rendered)
	}

	if strings.Contains(rendered, "\n  -config-check") {
		t.Fatalf("PrintDefaults() unexpectedly used single dash for long flag: %q", rendered)
	}

	if !strings.Contains(rendered, "\n  -P") && !strings.HasPrefix(rendered, "  -P") {
		t.Fatalf("PrintDefaults() missing single-dash short flag: %q", rendered)
	}
}

func TestPrintDefaultsGrouped_RendersSectionHeaders(t *testing.T) {
	fs := flag.NewFlagSet("nauthilus", flag.ContinueOnError)
	fs.Bool("version", false, "print version and exit")
	fs.String("config", "", "path to configuration file")
	fs.Bool("config-check", false, "validate configuration and exit")
	fs.Bool("debug", false, "enable debug mode")

	out := &bytes.Buffer{}
	PrintDefaultsGrouped(fs, out, []UsageGroup{
		{
			Title: "General",
			Flags: []string{"version", "config"},
		},
		{
			Title: "Validation",
			Flags: []string{"config-check"},
		},
	})

	rendered := out.String()

	for _, expected := range []string{
		"\nGeneral:\n",
		"\nValidation:\n",
		"--version",
		"--config",
		"--config-check",
		"\nOther Options:\n",
		"--debug",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("PrintDefaultsGrouped() = %q, want substring %q", rendered, expected)
		}
	}
}
