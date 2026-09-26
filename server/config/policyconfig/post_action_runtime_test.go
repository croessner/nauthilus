// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"errors"
	"testing"
)

func TestNormalizeSuppliesPostActionRuntimeDefaults(t *testing.T) {
	postActions := Normalize(Document{}).Policy.Runtime.PostActions

	if postActions.Workers != defaultPostActionWorkers || postActions.QueueCapacity != defaultPostActionQueueCapacity {
		t.Fatalf("post-action defaults = %+v", postActions)
	}

	configured := Document{Policy: PolicyConfig{Runtime: RuntimeConfig{
		PostActions: PostActionRuntimeConfig{Workers: 32, QueueCapacity: 4096},
	}}}

	postActions = Normalize(configured).Policy.Runtime.PostActions
	if postActions.Workers != 32 || postActions.QueueCapacity != 4096 {
		t.Fatalf("configured post-action runtime was replaced: %+v", postActions)
	}
}

func TestValidatePostActionRuntimeBounds(t *testing.T) {
	cases := []struct {
		name        string
		postActions PostActionRuntimeConfig
		path        string
	}{
		{"negative workers", PostActionRuntimeConfig{Workers: -1}, "policy.runtime.post_actions.workers"},
		{"negative capacity", PostActionRuntimeConfig{QueueCapacity: -1}, "policy.runtime.post_actions.queue_capacity"},
		{"too many workers", PostActionRuntimeConfig{Workers: maximumPostActionWorkers + 1, QueueCapacity: maximumPostActionQueueCapacity}, "policy.runtime.post_actions.workers"},
		{"too large queue", PostActionRuntimeConfig{QueueCapacity: maximumPostActionQueueCapacity + 1}, "policy.runtime.post_actions.queue_capacity"},
		{"workers above queue", PostActionRuntimeConfig{Workers: 64, QueueCapacity: 32}, "policy.runtime.post_actions.workers"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(Document{Policy: PolicyConfig{Runtime: RuntimeConfig{PostActions: tc.postActions}}})

			var pathError *PathError
			if !errors.As(err, &pathError) || !errors.Is(err, ErrValidation) || pathError.Path != tc.path {
				t.Fatalf("Validate() error = %v, want path %s", err, tc.path)
			}
		})
	}

	valid := Document{Policy: PolicyConfig{Runtime: RuntimeConfig{
		PostActions: PostActionRuntimeConfig{Workers: 64, QueueCapacity: 8192},
	}}}
	if err := Validate(valid); err != nil {
		t.Fatalf("Validate() rejected bounded post-action runtime: %v", err)
	}
}
