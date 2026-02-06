//go:build ignore

// validate-templates.go validates Go HTML templates for syntax errors.
//
// Usage:
//
//	go run scripts/validate-templates.go [file...]
//
// If no files are specified, all templates in static/templates/ are checked.
package main

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

const (
	colorRed    = "\033[0;31m"
	colorGreen  = "\033[0;32m"
	colorYellow = "\033[1;33m"
	colorReset  = "\033[0m"
)

// templateFuncs defines the custom functions used in Nauthilus templates.
// These must match the functions defined in server/core/http.go SetFuncMap.
var templateFuncs = template.FuncMap{
	"int": func(v any) int {
		switch x := v.(type) {
		case int:
			return x
		case int32:
			return int(x)
		case int64:
			return int(x)
		case float32:
			return int(x)
		case float64:
			return int(x)
		default:
			return 0
		}
	},
	"upper": func(s string) string {
		return strings.ToUpper(s)
	},
}

func main() {
	var files []string
	var err error

	if len(os.Args) > 1 {
		files = os.Args[1:]
	} else {
		files, err = filepath.Glob("static/templates/*.html")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError%s: %v\n", colorRed, colorReset, err)
			os.Exit(1)
		}
	}

	if len(files) == 0 {
		fmt.Printf("%sWarning%s: No template files found\n", colorYellow, colorReset)
		os.Exit(0)
	}

	fmt.Println("Validating Go HTML templates...")
	fmt.Println("================================")

	errorsFound := 0

	for _, file := range files {
		if !validateTemplate(file) {
			errorsFound++
		}
	}

	fmt.Println("================================")
	fmt.Printf("Checked %d template(s)\n", len(files))

	if errorsFound > 0 {
		fmt.Printf("%sFound errors in %d template(s)%s\n", colorRed, errorsFound, colorReset)
		os.Exit(1)
	}

	fmt.Printf("%sAll templates are valid%s\n", colorGreen, colorReset)
}

func validateTemplate(file string) bool {
	filename := filepath.Base(file)

	content, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("%s✗%s %s\n", colorRed, colorReset, filename)
		fmt.Printf("  %s→%s Error reading file: %v\n", colorYellow, colorReset, err)

		return false
	}

	var errors []string

	// Check for common corruption patterns that indicate IDE/formatter damage
	lines := strings.Split(string(content), "\n")

	for i, line := range lines {
		lineNum := i + 1

		// Pattern 1: Standalone ".FieldName end" without proper {{ }} wrapping
		// This indicates a corrupted template where {{ if .Field }}...{{ end }}
		// was mangled into separate lines
		if strings.TrimSpace(line) != "" {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) > 1 && trimmed[0] == '.' &&
				strings.HasSuffix(trimmed, " end") &&
				!strings.Contains(line, "{{") {
				errors = append(errors, fmt.Sprintf("Line %d: Corrupted template - standalone '.Field end' found (expected '{{ if .Field }}...{{ end }}')", lineNum))
			}
		}

		// Pattern 2: "if {{ }}" or "if {{}}" - empty/malformed conditional
		if strings.Contains(line, "if {{ }}") || strings.Contains(line, "if {{}}") {
			errors = append(errors, fmt.Sprintf("Line %d: Malformed conditional 'if {{ }}'", lineNum))
		}

		// Pattern 3: Template action broken across attributes
		// e.g., 'hx-target="#modal-container" if {{ }} }}disabled{{>'
		// This pattern detects when "if" appears outside of {{ }} but followed by {{ }}
		if strings.Contains(line, " if ") && !strings.Contains(line, "{{ if") {
			// Check if there's a {{ }} pattern after the bare "if"
			ifIdx := strings.Index(line, " if ")
			restAfterIf := line[ifIdx+4:]
			if strings.Contains(restAfterIf, "{{") && strings.Contains(restAfterIf, "}}") {
				errors = append(errors, fmt.Sprintf("Line %d: Possible corrupted template - bare 'if' outside template braces", lineNum))
			}
		}

		// Pattern 4: Broken closing tag like '{{>' or similar
		if strings.Contains(line, "{{>") || strings.Contains(line, "{{<") {
			errors = append(errors, fmt.Sprintf("Line %d: Malformed template tag '{{>' or '{{<'", lineNum))
		}

		// Pattern 5: Corrupted "end" statement
		// A line with just "}} end" or "end }}" outside of proper {{ }} wrapper
		// indicates the template was broken apart
		trimmed := strings.TrimSpace(line)
		if trimmed == "}} end" || trimmed == "end }}" ||
			strings.HasPrefix(trimmed, "}} end ") ||
			strings.HasSuffix(trimmed, " end }}") && !strings.Contains(trimmed, "{{") {
			errors = append(errors, fmt.Sprintf("Line %d: Corrupted template - 'end' statement appears broken", lineNum))
		}
	}

	// Use Go's template parser for definitive syntax validation
	// Register the custom functions used by Nauthilus templates
	_, err = template.New(filename).Funcs(templateFuncs).Parse(string(content))
	if err != nil {
		errors = append(errors, fmt.Sprintf("Go template parser error: %v", err))
	}

	if len(errors) == 0 {
		fmt.Printf("%s✓%s %s\n", colorGreen, colorReset, filename)

		return true
	}

	fmt.Printf("%s✗%s %s\n", colorRed, colorReset, filename)

	for _, e := range errors {
		fmt.Printf("  %s→%s %s\n", colorYellow, colorReset, e)
	}

	return false
}
