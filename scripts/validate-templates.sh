#!/bin/bash
# validate-templates.sh
# Validates Go HTML templates for syntax errors
#
# This is a wrapper script that runs the Go template validator.
# It checks all HTML templates in static/templates/ for valid
# Go template syntax.
#
# Usage:
#   ./scripts/validate-templates.sh [file...]
#
# If no files are specified, all templates in static/templates/ are checked.
# Exit codes:
#   0 - All templates are valid
#   1 - One or more templates have errors

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$PROJECT_ROOT"

# Run the Go validator
exec go run scripts/validate-templates.go "$@"
