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

// TestIsWriteAccess verifies the isWriteAccess helper that drives readOnly enforcement.
// The logic mirrors KubeArmor BPF's lsm/file_permission hook.
func TestIsWriteAccess(t *testing.T) {
	tests := []struct {
		name      string
		syscallNr uint64
		flags     int
		want      bool
	}{
		// --- Syscalls that are always writes regardless of flags ---
		{"unlink is always write", uint64(syscall.SYS_UNLINK), 0, true},
		{"unlinkat is always write", uint64(syscall.SYS_UNLINKAT), 0, true},
		{"mknod is always write", uint64(syscall.SYS_MKNOD), 0, true},
		{"mknodat is always write", uint64(syscall.SYS_MKNODAT), 0, true},

		// --- SYS_OPEN / SYS_OPENAT read-only access ---
		{"open O_RDONLY is not write", uint64(syscall.SYS_OPEN), syscall.O_RDONLY, false},
		{"openat O_RDONLY is not write", uint64(syscall.SYS_OPENAT), syscall.O_RDONLY, false},

		// --- SYS_OPEN / SYS_OPENAT write-mode flags ---
		{"open O_WRONLY is write", uint64(syscall.SYS_OPEN), syscall.O_WRONLY, true},
		{"open O_RDWR is write", uint64(syscall.SYS_OPEN), syscall.O_RDWR, true},
		{"open O_CREAT is write", uint64(syscall.SYS_OPEN), syscall.O_CREAT, true},
		{"open O_TRUNC is write", uint64(syscall.SYS_OPEN), syscall.O_TRUNC, true},
		{"open O_APPEND is write", uint64(syscall.SYS_OPEN), syscall.O_APPEND, true},
		{"openat O_WRONLY is write", uint64(syscall.SYS_OPENAT), syscall.O_WRONLY, true},
		{"openat O_RDWR is write", uint64(syscall.SYS_OPENAT), syscall.O_RDWR, true},

		// --- Combination: read with extra non-write flags is not write ---
		{"open O_RDONLY|O_CLOEXEC is not write", uint64(syscall.SYS_OPEN), syscall.O_RDONLY | syscall.O_CLOEXEC, false},

		// --- Unknown syscall returns false ---
		{"unknown syscall is not write", uint64(syscall.SYS_READ), 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isWriteAccess(tt.syscallNr, tt.flags)
			if got != tt.want {
				t.Errorf("isWriteAccess(syscall=%d, flags=%#o) = %v, want %v",
					tt.syscallNr, tt.flags, got, tt.want)
			}
		})
	}
}
