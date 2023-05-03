package enforcer

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func extractProcData(pid int) (string, int32, int32, string, error) {
	// read exe symlink
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", 0, 0, "", err
	}

	// read status file
	statusBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return exePath, 0, 0, "", err
	}

	// extract ppid and uid from status
	statusLines := strings.Split(string(statusBytes), "\n")
	var ppid int
	var uid int
	for _, line := range statusLines {
		if strings.HasPrefix(line, "PPid:") {
			ppid, err = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			if err != nil {
				return "", 0, 0, "", err
			}
		} else if strings.HasPrefix(line, "Uid:") {
			uidParts := strings.Split(strings.TrimSpace(strings.TrimPrefix(line, "Uid:")), "\t")
			uid, err = strconv.Atoi(uidParts[0])
			if err != nil {
				return "", 0, 0, "", err
			}
		}
	}

	// read ppid exe symlink
	pExePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", ppid))
	if err != nil {
		return "", 0, 0, "", err
	}

	return exePath, int32(ppid), int32(uid), pExePath, nil
}

func getString(pid int, addr uintptr) string {
	buff := make([]byte, syscall.PathMax)
	syscall.PtracePeekData(pid, addr, buff)
	return string(buff[:clen(buff)])
}

// getProcCwd gets the process CWD
func getProcCwd(pid int) string {
	fileName := "/proc/self/cwd"
	if pid > 0 {
		fileName = fmt.Sprintf("/proc/%d/cwd", pid)
	}
	s, err := os.Readlink(fileName)
	if err != nil {
		return ""
	}
	return s
}

// absPath calculates the absolute path for a process
// built-in function did the dirty works to resolve relative paths
func absPath(pid int, p string) string {
	// if relative path
	if !path.IsAbs(p) {
		return path.Join(getProcCwd(pid), p)
	}
	return path.Clean(p)
}

func clen(b []byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			return i
		}
	}
	return len(b) + 1
}

// set Ptrace option that set up seccomp, exit kill and all mult-process actions
func setPtraceOption(pid int) error {
	const ptraceFlags = unix.PTRACE_O_TRACESECCOMP | unix.PTRACE_O_EXITKILL | unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_TRACEVFORK
	return unix.PtraceSetOptions(pid, ptraceFlags)
}
