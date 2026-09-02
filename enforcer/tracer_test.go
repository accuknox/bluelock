// SPDX-License-Identifier: MIT
// Copyright 2026 Authors of Bluelock

package enforcer

import "testing"

func TestMatchProcAndFileRules(t *testing.T) {
	rules := make(map[InnerKey]RuleConfig)

	dirtoMap(
		InnerKey{
			Path:   "/etc/ssl/",
			Source: "",
		},
		rules,
		RuleConfig{
			Recursive: true,
			Deny:      true,
			Allow:     false,
		},
	)

	tests := []struct {
		name         string
		path         string
		source       string
		wantMatch    bool
		wantRule     RuleConfig
		wantRulePath string
	}{
		{
			name:      "root hint must not match",
			path:      "/",
			source:    "/usr/bin/bash",
			wantMatch: false,
		},
		{
			name:      "etc hint must not match",
			path:      "/etc",
			source:    "/usr/bin/bash",
			wantMatch: false,
		},
		{
			name:         "exact directory file-style path matches",
			path:         "/etc/ssl",
			source:       "/usr/bin/bash",
			wantMatch:    true,
			wantRulePath: "/etc/ssl",
			wantRule: RuleConfig{
				Recursive: true,
				Deny:      true,
				Allow:     false,
				Dir:       false,
				Hint:      false,
			},
		},
		{
			name:         "exact directory path matches",
			path:         "/etc/ssl/",
			source:       "/usr/bin/bash",
			wantMatch:    true,
			wantRulePath: "/etc/ssl/",
			wantRule: RuleConfig{
				Recursive: true,
				Deny:      true,
				Allow:     false,
				Dir:       true,
				Hint:      false,
			},
		},
		{
			name:         "recursive child matches",
			path:         "/etc/ssl/certs",
			source:       "/usr/bin/bash",
			wantMatch:    true,
			wantRulePath: "/etc/ssl/",
			wantRule: RuleConfig{
				Recursive: true,
				Deny:      true,
				Allow:     false,
				Dir:       true,
				Hint:      false,
			},
		},
		{
			name:         "recursive deep child matches",
			path:         "/etc/ssl/certs/example.pem",
			source:       "/usr/bin/bash",
			wantMatch:    true,
			wantRulePath: "/etc/ssl/",
			wantRule: RuleConfig{
				Recursive: true,
				Deny:      true,
				Allow:     false,
				Dir:       true,
				Hint:      false,
			},
		},
		{
			name:         "recursive private key path matches",
			path:         "/etc/ssl/private/server.key",
			source:       "/usr/bin/bash",
			wantMatch:    true,
			wantRulePath: "/etc/ssl/",
			wantRule: RuleConfig{
				Recursive: true,
				Deny:      true,
				Allow:     false,
				Dir:       true,
				Hint:      false,
			},
		},
		{
			name:      "parent directory does not match",
			path:      "/etc",
			source:    "/usr/bin/bash",
			wantMatch: false,
		},
		{
			name:      "unrelated directory does not match",
			path:      "/usr/local",
			source:    "/usr/bin/bash",
			wantMatch: false,
		},
		{
			name:      "unrelated file does not match",
			path:      "/home/test.txt",
			source:    "/usr/bin/bash",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotRule := matchProcAndFileRules(
				tt.path,
				tt.source,
				rules,
			)

			if gotMatch != tt.wantMatch {
				t.Fatalf(
					"matchProcAndFileRules(%q, %q) match = %v, want %v; rule = %#v",
					tt.path,
					tt.source,
					gotMatch,
					tt.wantMatch,
					gotRule,
				)
			}

			if !tt.wantMatch {
				return
			}

			if gotRule != tt.wantRule {
				t.Errorf(
					"matchProcAndFileRules(%q, %q) returned unexpected rule:\n got:  %#v\n want: %#v",
					tt.path,
					tt.source,
					gotRule,
					tt.wantRule,
				)
			}
		})
	}

	_ = rules
}

func TestMatchProcAndFileRulesSourceSpecific(t *testing.T) {
	rules := make(map[InnerKey]RuleConfig)

	source := "/usr/bin/bash"

	dirtoMap(
		InnerKey{
			Path:   "/etc/ssl/",
			Source: source,
		},
		rules,
		RuleConfig{
			Recursive: true,
			Deny:      true,
			Allow:     false,
		},
	)

	tests := []struct {
		name      string
		path      string
		source    string
		wantMatch bool
	}{
		{
			name:      "matching source gets directory rule",
			path:      "/etc/ssl/certs/ca.pem",
			source:    source,
			wantMatch: true,
		},
		{
			name:      "matching source gets exact rule",
			path:      "/etc/ssl",
			source:    source,
			wantMatch: true,
		},
		{
			name:      "matching source does not treat root hint as rule",
			path:      "/",
			source:    source,
			wantMatch: false,
		},
		{
			name:      "different source does not use source-specific rule",
			path:      "/etc/ssl/certs/ca.pem",
			source:    "/usr/bin/python",
			wantMatch: false,
		},
		{
			name:      "different source does not use source-specific root hint",
			path:      "/",
			source:    "/usr/bin/python",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, _ := matchProcAndFileRules(
				tt.path,
				tt.source,
				rules,
			)

			if gotMatch != tt.wantMatch {
				t.Errorf(
					"matchProcAndFileRules(%q, %q) = %v, want %v",
					tt.path,
					tt.source,
					gotMatch,
					tt.wantMatch,
				)
			}
		})
	}
}

func TestMatchProcAndFileRulesExactRuleTakesPriority(t *testing.T) {
	rules := map[InnerKey]RuleConfig{
		{
			Path:   "/etc/ssl",
			Source: "",
		}: {
			Allow: true,
			Deny:  false,
		},
		{
			Path:   "/etc/ssl/",
			Source: "",
		}: {
			Dir:       true,
			Recursive: true,
			Deny:      true,
			Allow:     false,
		},
		{
			Path:   "/",
			Source: "",
		}: {
			Hint:      true,
			Recursive: true,
			Deny:      true,
		},
	}

	match, matchedRule := matchProcAndFileRules(
		"/etc/ssl",
		"/usr/bin/bash",
		rules,
	)

	if !match {
		t.Fatal("expected exact /etc/ssl rule to match")
	}

	want := RuleConfig{
		Allow: true,
		Deny:  false,
	}

	if matchedRule != want {
		t.Fatalf(
			"expected exact rule to win:\n got:  %#v\n want: %#v",
			matchedRule,
			want,
		)
	}
}

func TestMatchProcAndFileRulesHintRegression(t *testing.T) {
	/*
		This is the regression test for the bug we fixed.

		Policy:
		    /etc/ssl/
		    recursive: true
		    action: Block

		dirtoMap() creates these parent hints:

		    /
		    /etc/

		The hints must never be treated as actual matching
		rules by an exact lookup.
	*/
	rules := make(map[InnerKey]RuleConfig)

	dirtoMap(
		InnerKey{Path: "/etc/ssl/"},
		rules,
		RuleConfig{
			Recursive: true,
			Deny:      true,
		},
	)

	pathsThatMustNotMatch := []string{
		"/",
		"/etc",
		"/usr",
		"/usr/local",
		"/home",
	}

	for _, path := range pathsThatMustNotMatch {
		t.Run("must not match "+path, func(t *testing.T) {
			match, rule := matchProcAndFileRules(
				path,
				"/usr/bin/bash",
				rules,
			)

			if match {
				t.Fatalf(
					"path %q incorrectly matched a hint rule: %#v",
					path,
					rule,
				)
			}
		})
	}

	pathsThatMustMatch := []string{
		"/etc/ssl",
		"/etc/ssl/",
		"/etc/ssl/certs",
		"/etc/ssl/certs/ca.pem",
		"/etc/ssl/private/server.key",
	}

	for _, path := range pathsThatMustMatch {
		t.Run("must match "+path, func(t *testing.T) {
			match, rule := matchProcAndFileRules(
				path,
				"/usr/bin/bash",
				rules,
			)

			if !match {
				t.Fatalf(
					"path %q should have matched /etc/ssl/ rule",
					path,
				)
			}

			if !rule.Deny {
				t.Fatalf(
					"path %q matched, but returned rule is not Deny: %#v",
					path,
					rule,
				)
			}
		})
	}
}
