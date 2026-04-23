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

package config

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/go-viper/mapstructure/v2"
)

// ProblemKind classifies a user-facing configuration problem.
type ProblemKind string

const (
	configProblemDecode     ProblemKind = "decode"
	configProblemUnknownKey ProblemKind = "unknown_key"
	configProblemValidation ProblemKind = "validation"
)

// Problem describes a single canonical configuration problem.
type Problem struct {
	Kind    ProblemKind `mapstructure:"-"`
	Path    string      `mapstructure:"-"`
	Message string      `mapstructure:"-"`
}

func formatConfigProblems(problems []Problem) error {
	if len(problems) == 0 {
		return nil
	}

	sort.SliceStable(problems, func(left int, right int) bool {
		if problems[left].Path == problems[right].Path {
			if problems[left].Kind == problems[right].Kind {
				return problems[left].Message < problems[right].Message
			}

			return problems[left].Kind < problems[right].Kind
		}

		return problems[left].Path < problems[right].Path
	})

	parts := make([]string, 0, len(problems))
	for _, problem := range problems {
		if problem.Path == "" {
			parts = append(parts, problem.Message)

			continue
		}

		parts = append(parts, fmt.Sprintf("field '%s' %s", problem.Path, problem.Message))
	}

	if len(parts) == 1 {
		return fmt.Errorf("configuration errors: %s", parts[0])
	}

	return fmt.Errorf("configuration errors:\n- %s", strings.Join(parts, "\n- "))
}

func formatDecodeErrors(err error) error {
	if err == nil {
		return nil
	}

	problems := make([]Problem, 0)

	for _, decodeErr := range collectDecodeErrors(err) {
		problems = append(problems, Problem{
			Kind:    configProblemDecode,
			Path:    decodeErr.Name(),
			Message: decodeErrorMessage(decodeErr.Unwrap()),
		})
	}

	if len(problems) == 0 {
		return err
	}

	return formatConfigProblems(problems)
}

func formatValidationErrors(validationErrors validator.ValidationErrors) error {
	schemaIndex, err := getConfigSchemaIndex()
	if err != nil {
		return err
	}

	problems := make([]Problem, 0, len(validationErrors))

	for _, fieldErr := range validationErrors {
		path := schemaIndex.configPathFromStructNamespace(fieldErr.StructNamespace())
		if path == "" {
			path = fieldErr.StructNamespace()
		}

		message := fmt.Sprintf("failed validation rule '%s'", fieldErr.Tag())
		if fieldErr.Param() != "" {
			message = fmt.Sprintf("%s (parameter: %s)", message, fieldErr.Param())
		}

		problems = append(problems, Problem{
			Kind:    configProblemValidation,
			Path:    path,
			Message: message,
		})
	}

	return formatConfigProblems(problems)
}

func decodeErrorMessage(err error) string {
	switch typed := err.(type) {
	case *mapstructure.ParseError:
		return fmt.Sprintf("cannot parse value as '%s': %s", typed.Expected.Type(), typed.Err)
	case *mapstructure.UnconvertibleTypeError:
		return fmt.Sprintf("expects type '%s', got '%T'", typed.Expected.Type(), typed.Value)
	default:
		return err.Error()
	}
}

func collectDecodeErrors(err error) []*mapstructure.DecodeError {
	if err == nil {
		return nil
	}

	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		problems := make([]*mapstructure.DecodeError, 0)
		for _, nested := range joined.Unwrap() {
			problems = append(problems, collectDecodeErrors(nested)...)
		}

		return problems
	}

	var decodeErr *mapstructure.DecodeError
	if errors.As(err, &decodeErr) {
		return []*mapstructure.DecodeError{decodeErr}
	}

	return nil
}
