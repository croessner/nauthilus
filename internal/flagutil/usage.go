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

// Package flagutil provides shared helpers for CLI flag usage output.
package flagutil

import (
	"flag"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"
)

// UsageGroup defines a logical section in custom flag help output.
type UsageGroup struct {
	Title string
	Flags []string
}

// ApplyDoubleDashUsage installs a custom usage renderer for the provided flag set.
// Long-form flags are shown with a double-dash prefix, while single-letter flags
// keep the traditional single-dash form.
func ApplyDoubleDashUsage(fs *flag.FlagSet, commandName string) {
	ApplyGroupedDoubleDashUsage(fs, commandName, nil)
}

// ApplyGroupedDoubleDashUsage installs a custom usage renderer for the provided
// flag set. Long-form flags are shown with a double-dash prefix, while
// single-letter flags keep the traditional single-dash form. Flags can be
// grouped into titled sections.
func ApplyGroupedDoubleDashUsage(fs *flag.FlagSet, commandName string, groups []UsageGroup) {
	if fs == nil {
		return
	}

	fs.Usage = func() {
		out := fs.Output()
		if commandName != "" {
			_, _ = fmt.Fprintf(out, "Usage of %s:\n", commandName)
		}

		PrintDefaultsGrouped(fs, out, groups)
	}
}

// PrintDefaults writes the default help output for a flag set, but renders
// long-form flags with a double-dash prefix.
func PrintDefaults(fs *flag.FlagSet, out io.Writer) {
	PrintDefaultsGrouped(fs, out, nil)
}

// PrintDefaultsGrouped writes help output for a flag set and optionally
// organizes flags into titled sections.
func PrintDefaultsGrouped(fs *flag.FlagSet, out io.Writer, groups []UsageGroup) {
	if fs == nil || out == nil {
		return
	}

	if len(groups) == 0 {
		printFlagSetSection(fs, out, allFlags(fs))

		return
	}

	flagMap := allFlags(fs)
	printed := make(map[string]struct{}, len(flagMap))

	for _, group := range groups {
		groupFlags := orderedFlags(flagMap, group.Flags)
		if len(groupFlags) == 0 {
			continue
		}

		_, _ = fmt.Fprintf(out, "\n%s:\n", group.Title)
		printFlagSetSection(fs, out, groupFlags)

		for _, current := range groupFlags {
			printed[current.Name] = struct{}{}
		}
	}

	remaining := make(map[string]*flag.Flag, len(flagMap))
	maps.Copy(remaining, flagMap)

	for name := range printed {
		delete(remaining, name)
	}

	if len(remaining) == 0 {
		return
	}

	_, _ = fmt.Fprintln(out, "\nOther Options:")
	printFlagSetSection(fs, out, remaining)
}

func allFlags(fs *flag.FlagSet) map[string]*flag.Flag {
	flags := make(map[string]*flag.Flag)

	fs.VisitAll(func(current *flag.Flag) {
		flags[current.Name] = current
	})

	return flags
}

func orderedFlags(flagMap map[string]*flag.Flag, names []string) map[string]*flag.Flag {
	groupFlags := make(map[string]*flag.Flag, len(names))

	for _, name := range names {
		if current, ok := flagMap[name]; ok {
			groupFlags[name] = current
		}
	}

	return groupFlags
}

func printFlagSetSection(fs *flag.FlagSet, out io.Writer, flags map[string]*flag.Flag) {
	if fs == nil || out == nil || len(flags) == 0 {
		return
	}

	names := slices.Collect(maps.Keys(flags))
	slices.Sort(names)

	for _, name := range names {
		current := flags[name]
		line := "  " + formatFlagName(current.Name)

		parameterName, usage := flag.UnquoteUsage(current)
		if parameterName != "" {
			line += " " + parameterName
		}

		if len(line) <= 4 {
			line += "\t"
		} else {
			line += "\n    \t"
		}

		line += strings.ReplaceAll(usage, "\n", "\n    \t")

		if !isZeroValueFlag(current) {
			if isStringFlag(current) {
				line += fmt.Sprintf(" (default %q)", current.DefValue)
			} else {
				line += fmt.Sprintf(" (default %s)", current.DefValue)
			}
		}

		_, _ = fmt.Fprintln(out, line)
	}
}

func formatFlagName(name string) string {
	if len(name) == 1 {
		return "-" + name
	}

	return "--" + name
}

func isStringFlag(flagDef *flag.Flag) bool {
	if flagDef == nil {
		return false
	}

	getter, ok := flagDef.Value.(flag.Getter)
	if !ok {
		return false
	}

	_, isString := getter.Get().(string)

	return isString
}

func isZeroValueFlag(flagDef *flag.Flag) bool {
	if flagDef == nil {
		return true
	}

	getter, ok := flagDef.Value.(flag.Getter)
	if !ok {
		switch flagDef.DefValue {
		case "", "0", "0s", "false", "<nil>":
			return true
		default:
			return false
		}
	}

	value := getter.Get()
	if value == nil {
		return true
	}

	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return true
	}

	return reflected.IsZero()
}
