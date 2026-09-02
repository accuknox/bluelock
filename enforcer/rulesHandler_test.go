// SPDX-License-Identifier: MIT
// Copyright 2026 Authors of Bluelock

package enforcer

import "testing"

func TestDirToMap(t *testing.T) {
	tests := []struct {
		name     string
		dirKey   InnerKey
		val      RuleConfig
		expected map[InnerKey]RuleConfig
	}{
		{
			name: "recursive block directory without source",
			dirKey: InnerKey{
				Path:   "/etc/ssl/",
				Source: "",
			},
			val: RuleConfig{
				Recursive: true,
				Deny:      true,
				Allow:     false,
			},
			expected: map[InnerKey]RuleConfig{
				{
					Path:   "/etc/ssl",
					Source: "",
				}: {
					Recursive: true,
					Deny:      true,
					Allow:     false,
					Dir:       false,
					Hint:      false,
				},
				{
					Path:   "/etc/ssl/",
					Source: "",
				}: {
					Recursive: true,
					Deny:      true,
					Allow:     false,
					Dir:       true,
					Hint:      false,
				},
				{
					Path:   "/",
					Source: "",
				}: {
					Recursive: true,
					Deny:      true,
					Allow:     false,
					Dir:       false,
					Hint:      true,
				},
				{
					Path:   "/etc/",
					Source: "",
				}: {
					Recursive: true,
					Deny:      true,
					Allow:     false,
					Dir:       false,
					Hint:      true,
				},
			},
		},
		{
			name: "recursive allow directory without source",
			dirKey: InnerKey{
				Path:   "/var/lib/app/",
				Source: "",
			},
			val: RuleConfig{
				Recursive: true,
				Allow:     true,
				Deny:      false,
			},
			expected: map[InnerKey]RuleConfig{
				{
					Path:   "/var/lib/app",
					Source: "",
				}: {
					Recursive: true,
					Allow:     true,
					Deny:      false,
					Dir:       false,
					Hint:      false,
				},
				{
					Path:   "/var/lib/app/",
					Source: "",
				}: {
					Recursive: true,
					Allow:     true,
					Deny:      false,
					Dir:       true,
					Hint:      false,
				},
				{
					Path:   "/",
					Source: "",
				}: {
					Recursive: true,
					Allow:     true,
					Deny:      false,
					Dir:       false,
					Hint:      true,
				},
				{
					Path:   "/var/",
					Source: "",
				}: {
					Recursive: true,
					Allow:     true,
					Deny:      false,
					Dir:       false,
					Hint:      true,
				},
				{
					Path:   "/var/lib/",
					Source: "",
				}: {
					Recursive: true,
					Allow:     true,
					Deny:      false,
					Dir:       false,
					Hint:      true,
				},
			},
		},
		{
			name: "directory rule with source",
			dirKey: InnerKey{
				Path:   "/etc/ssl/",
				Source: "/usr/bin/bash",
			},
			val: RuleConfig{
				Recursive: true,
				Deny:      true,
				Allow:     false,
			},
			expected: map[InnerKey]RuleConfig{
				{
					Path:   "/etc/ssl",
					Source: "/usr/bin/bash",
				}: {
					Recursive: true,
					Deny:      true,
					Allow:     false,
					Dir:       false,
					Hint:      false,
				},
				{
					Path:   "/etc/ssl/",
					Source: "/usr/bin/bash",
				}: {
					Recursive: true,
					Deny:      true,
					Allow:     false,
					Dir:       true,
					Hint:      false,
				},
				{
					Path:   "/",
					Source: "",
				}: {
					Recursive: true,
					Deny:      true,
					Allow:     false,
					Dir:       false,
					Hint:      true,
				},
				{
					Path:   "/etc/",
					Source: "",
				}: {
					Recursive: true,
					Deny:      true,
					Allow:     false,
					Dir:       false,
					Hint:      true,
				},
			},
		},
		{
			name: "directory rule preserves owner and read-only flags",
			dirKey: InnerKey{
				Path:   "/opt/app/config/",
				Source: "",
			},
			val: RuleConfig{
				Recursive: true,
				ReadOnly:  true,
				OwnerOnly: true,
				Deny:      true,
			},
			expected: map[InnerKey]RuleConfig{
				{
					Path:   "/opt/app/config",
					Source: "",
				}: {
					Recursive: true,
					ReadOnly:  true,
					OwnerOnly: true,
					Deny:      true,
					Dir:       false,
					Hint:      false,
				},
				{
					Path:   "/opt/app/config/",
					Source: "",
				}: {
					Recursive: true,
					ReadOnly:  true,
					OwnerOnly: true,
					Deny:      true,
					Dir:       true,
					Hint:      false,
				},
				{
					Path:   "/",
					Source: "",
				}: {
					Recursive: true,
					ReadOnly:  true,
					OwnerOnly: true,
					Deny:      true,
					Dir:       false,
					Hint:      true,
				},
				{
					Path:   "/opt/",
					Source: "",
				}: {
					Recursive: true,
					ReadOnly:  true,
					OwnerOnly: true,
					Deny:      true,
					Dir:       false,
					Hint:      true,
				},
				{
					Path:   "/opt/app/",
					Source: "",
				}: {
					Recursive: true,
					ReadOnly:  true,
					OwnerOnly: true,
					Deny:      true,
					Dir:       false,
					Hint:      true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := make(map[InnerKey]RuleConfig)

			dirtoMap(tt.dirKey, got, tt.val)

			if len(got) != len(tt.expected) {
				t.Fatalf(
					"unexpected number of rules: got %d, want %d\nGot: %#v",
					len(got),
					len(tt.expected),
					got,
				)
			}

			for key, want := range tt.expected {
				gotValue, ok := got[key]
				if !ok {
					t.Fatalf("expected key %+v to exist", key)
				}

				if gotValue != want {
					t.Errorf(
						"unexpected RuleConfig for key %+v:\n got:  %#v\n want: %#v",
						key,
						gotValue,
						want,
					)
				}
			}
		})
	}
}

func TestDirToMapExistingHintPreservesHint(t *testing.T) {
	rules := map[InnerKey]RuleConfig{
		{
			Path:   "/etc/ssl/",
			Source: "",
		}: {
			Dir:  false,
			Hint: true,
		},
	}

	val := RuleConfig{
		Recursive: true,
		Deny:      true,
	}

	dirtoMap(
		InnerKey{
			Path:   "/etc/ssl/",
			Source: "",
		},
		rules,
		val,
	)

	got, ok := rules[InnerKey{
		Path:   "/etc/ssl/",
		Source: "",
	}]
	if !ok {
		t.Fatal("expected /etc/ssl/ rule to exist")
	}

	if !got.Dir {
		t.Error("expected Dir=true for the resulting directory entry")
	}

	if !got.Hint {
		t.Error("expected existing Hint=true to be preserved")
	}

	if !got.Recursive {
		t.Error("expected Recursive=true")
	}

	if !got.Deny {
		t.Error("expected Deny=true")
	}
}
