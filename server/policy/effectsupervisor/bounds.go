// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package effectsupervisor

import (
	"errors"
	"reflect"
)

// ErrWorkBounds marks captured adapter data outside host memory limits.
var ErrWorkBounds = errors.New("post-action work exceeds bounded capture limits")

// WorkBounds limits recursively captured adapter values.
type WorkBounds struct {
	MaxBytes    int
	MaxElements int
	MaxDepth    int
}

// DefaultWorkBounds returns the host limits for one accepted effect.
func DefaultWorkBounds() WorkBounds {
	return WorkBounds{MaxBytes: 256 * 1024, MaxElements: 4096, MaxDepth: 16}
}

type workBoundCounter struct {
	limits   WorkBounds
	bytes    int
	elements int
}

// ValidateBoundedValue rejects adapter capture whose recursive size exceeds limits.
func ValidateBoundedValue(value any, limits WorkBounds) error {
	if limits.MaxBytes <= 0 || limits.MaxElements <= 0 || limits.MaxDepth <= 0 {
		return ErrWorkBounds
	}

	counter := &workBoundCounter{limits: limits}

	return counter.visit(reflect.ValueOf(value), 0)
}

// visit accounts for one recursively captured value without retaining it.
func (c *workBoundCounter) visit(value reflect.Value, depth int) error {
	if err := c.reserve(value, depth); err != nil || !value.IsValid() {
		return err
	}

	if err := c.visitValue(value, depth); err != nil {
		return err
	}

	return c.checkBytes()
}

// reserve enforces recursion and element limits before descending.
func (c *workBoundCounter) reserve(value reflect.Value, depth int) error {
	if !value.IsValid() {
		return nil
	}

	if depth > c.limits.MaxDepth {
		return ErrWorkBounds
	}

	c.elements++
	if c.elements > c.limits.MaxElements {
		return ErrWorkBounds
	}

	return nil
}

// visitValue accounts for one value kind and delegates composite traversal.
func (c *workBoundCounter) visitValue(value reflect.Value, depth int) error {
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return nil
		}

		return c.visit(value.Elem(), depth+1)
	case reflect.String:
		c.bytes += value.Len()
	case reflect.Slice, reflect.Array:
		return c.visitSlice(value, depth)
	case reflect.Map:
		return c.visitMap(value, depth)
	case reflect.Struct:
		return c.visitStruct(value, depth)
	default:
		c.bytes += int(value.Type().Size())
	}

	return nil
}

// visitSlice accounts for bytes directly and recursively visits other elements.
func (c *workBoundCounter) visitSlice(value reflect.Value, depth int) error {
	if value.Type().Elem().Kind() == reflect.Uint8 {
		c.bytes += value.Len()

		return nil
	}

	for index := range value.Len() {
		if err := c.visit(value.Index(index), depth+1); err != nil {
			return err
		}
	}

	return nil
}

// visitMap accounts for every captured key and value.
func (c *workBoundCounter) visitMap(value reflect.Value, depth int) error {
	iterator := value.MapRange()
	for iterator.Next() {
		if err := c.visit(iterator.Key(), depth+1); err != nil {
			return err
		}

		if err := c.visit(iterator.Value(), depth+1); err != nil {
			return err
		}
	}

	return nil
}

// visitStruct accounts for captured fields without converting private values.
func (c *workBoundCounter) visitStruct(value reflect.Value, depth int) error {
	for index := range value.NumField() {
		if err := c.visit(value.Field(index), depth+1); err != nil {
			return err
		}
	}

	return nil
}

// checkBytes enforces the accumulated byte budget.
func (c *workBoundCounter) checkBytes() error {
	if c.bytes > c.limits.MaxBytes {
		return ErrWorkBounds
	}

	return nil
}
