// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import "fmt"

// PathError attaches one exact standalone configuration path to an error.
type PathError struct {
	Err     error
	Path    string
	Message string
}

// Error returns the path-bearing validation message.
func (e *PathError) Error() string {
	if e == nil {
		return ""
	}

	if e.Message == "" {
		return fmt.Sprintf("%s: %v", e.Path, e.Err)
	}

	return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

// Unwrap exposes the underlying error category.
func (e *PathError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

// newPathError creates one exact path-bearing contract error.
func newPathError(path string, err error, message string) *PathError {
	return &PathError{Path: path, Err: err, Message: message}
}
