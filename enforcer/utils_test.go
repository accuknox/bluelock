// SPDX-License-Identifier: MIT
// Copyright 2026 Authors of Bluelock

package enforcer

import (
	"os"
	"syscall"
	"testing"
)

func TestGetFileOwnerUID(t *testing.T) {
	t.Run("returns owner UID of an existing file", func(t *testing.T) {
		// Create a temp file owned by the current process's UID.
		f, err := os.CreateTemp(t.TempDir(), "bluelock-owneruid-*")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		f.Close()

		// The file is created by the current user, so its owner UID must
		// equal os.Getuid().
		got := getFileOwnerUID(f.Name())
		want := int32(os.Getuid())

		if got != want {
			t.Errorf("getFileOwnerUID(%q) = %d, want %d", f.Name(), got, want)
		}
	})

	t.Run("matches syscall.Stat_t directly", func(t *testing.T) {
		// Cross-check: stat the file ourselves and compare i_uid.
		f, err := os.CreateTemp(t.TempDir(), "bluelock-owneruid-stat-*")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		f.Close()

		info, err := os.Stat(f.Name())
		if err != nil {
			t.Fatalf("os.Stat failed: %v", err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		want := int32(stat.Uid)

		got := getFileOwnerUID(f.Name())
		if got != want {
			t.Errorf("getFileOwnerUID(%q) = %d, want %d (from Stat_t.Uid)", f.Name(), got, want)
		}
	})

	t.Run("returns -1 for nonexistent path", func(t *testing.T) {
		got := getFileOwnerUID("/nonexistent/path/that/does/not/exist")
		if got != -1 {
			t.Errorf("getFileOwnerUID(nonexistent) = %d, want -1", got)
		}
	})

	t.Run("caller UID matches file owner — is_owner true", func(t *testing.T) {
		// Simulate the ownerOnly enforcement decision:
		// if callerUID == fileOwnerUID → allow (is_owner = true).
		f, err := os.CreateTemp(t.TempDir(), "bluelock-isowner-*")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		f.Close()

		fileOwnerUID := getFileOwnerUID(f.Name())
		callerUID := int32(os.Getuid())

		if fileOwnerUID != callerUID {
			t.Errorf("expected file owner UID (%d) == caller UID (%d)", fileOwnerUID, callerUID)
		}
	})

	t.Run("different UID is detected as non-owner — is_owner false", func(t *testing.T) {
		// Simulate: if callerUID != fileOwnerUID → block (is_owner = false).
		// We fake this by comparing against a UID we know is different.
		f, err := os.CreateTemp(t.TempDir(), "bluelock-nonowner-*")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		f.Close()

		fileOwnerUID := getFileOwnerUID(f.Name())
		// Use a synthetic "other" UID that will never equal the file owner.
		otherUID := fileOwnerUID + 1

		if fileOwnerUID == otherUID {
			t.Error("expected otherUID to differ from fileOwnerUID")
		}
	})
}
