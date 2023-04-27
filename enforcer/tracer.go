package enforcer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daemon1024/bluelock/feeder"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

func (pe *PtraceEnforcer) StartSystemTracer() {
	var err error
	var regs syscall.PtraceRegs

	// Create a seccomp filter to trace open and openat calls in the ptrace
	// child process.
	filter, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		panic(err)
	}
	defer filter.Release()

	// // // Trace only open and openat syscalls
	// // nropen, _ := seccomp.GetSyscallFromName("open")
	// // err = filter.AddRule(nropen, seccomp.ActTrace)
	// // if err != nil {
	// // 	panic(err)
	// // }
	nropenat, _ := seccomp.GetSyscallFromName("openat")
	_ = filter.AddRule(nropenat, seccomp.ActTrace)

	// // // Set no new prriliges bit
	// // _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 39, 1, 0, 0, 0, 0)
	// // if errno != 0 {
	// // 	panic(errno)
	// // }

	// Load the filter
	err = filter.Load()
	if err != nil {
		panic(err)
	}

	fmt.Println("Run: ", os.Args[1:])

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	// Extract Container Name
	// Extract Container ID
	// pid/ppid  from status
	// pname from exe
	// ppname  from ppid/exe

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err = cmd.Start()
	// err = cmd.Wait()
	if err != nil {
		fmt.Printf("Wait err %v \n", err)
	}

	pgid := cmd.Process.Pid

	setPtraceOption(pgid)

	execved := false
	traced := make(map[int]bool)

	// TODO:
	// handle processes which won't create a chlid process which leads to execve to be always false
	// make signals sent to child process work

	for {
		var pid int
		var wstatus unix.WaitStatus

		if execved {
			// Wait for all child in the process group
			pid, err = unix.Wait4(-1, &wstatus, unix.WALL, nil)
		} else {
			// Ensure the process have called setpgid
			pid, err = unix.Wait4(pgid, &wstatus, unix.WALL, nil)
		}
		fmt.Println("pid: ", pid, " wstatus: ", wstatus, " err: ", err, "")

		switch {
		case wstatus.Exited():
			delete(traced, pid)
			if pid == pgid {
				if execved {
					break
				}
			}

		case wstatus.Signaled():
			sig := wstatus.Signal()
			// if pid == pgid {
			// 	delete(traced, pid)
			// 	break
			// }
			unix.PtraceCont(pid, int(sig))

		case wstatus.Stopped():
			// Set option if the process is newly forked
			if !traced[pid] {
				traced[pid] = true
				// Ptrace set option valid if the tracee is stopped
				if err := setPtraceOption(pid); err != nil {
					break
				}
			}

			stopSig := wstatus.StopSignal()
			// Check stop signal, if trap then check seccomp
			switch stopSig {
			case unix.SIGTRAP:
				switch trapCause := wstatus.TrapCause(); trapCause {
				case unix.PTRACE_EVENT_SECCOMP:
					// syscall tracee have successfully called seccomp
					fmt.Println("syscall tracee have successfully called seccomp")
					if execved {
						err = syscall.PtraceGetRegs(pid, &regs)
						if err != nil {
							break
						}
						log := tp.Log{}
						if regs.Orig_rax == 257 {
							log.PID = int32(pid)
							log.Timestamp = time.Now().UTC().Unix()
							log.Resource = absPath(pid, getString(pid, uintptr(regs.Rsi)))
							log.Operation = "File"
							log.ProcessName, log.PPID, log.UID, log.ParentProcessName, err = extractProcData(pid)
							if err != nil {
								kg.Warnf("Error extracting process data %v \n", err)
							}
							log.Source = log.ProcessName
							log.Data = "syscall=openat fd=" + strconv.Itoa(int(regs.Rdi)) + " flags=" + strconv.Itoa(int(regs.Rdx)) + " mode=" + strconv.Itoa(int(regs.R10))

							// Enforcement Logic
							if val, ok := pe.Rules.FilePaths[InnerKey{
								Path:   log.Resource,
								Source: "",
							}]; ok {
								if val.Deny {
									regs.Orig_rax = ^uint64(0)
									regs.Rax = ^uint64(syscall.EPERM)
									_ = syscall.PtraceSetRegs(pid, &regs)
									kg.Warnf("Denied %s %s \n", log.Operation, log.Resource)
									log.Action = "Block"
								}
							}
							if val, ok := pe.Rules.FilePaths[InnerKey{
								Path:   log.Resource,
								Source: log.Source,
							}]; ok {
								if val.Deny {
									regs.Orig_rax = ^uint64(0)
									regs.Rax = ^uint64(syscall.EPERM)
									_ = syscall.PtraceSetRegs(pid, &regs)
									kg.Warnf("Denied %s % from source %s \n", log.Operation, log.Resource, log.Source)
									log.Action = "Block"

								}
							}

							b, _ := json.MarshalIndent(log, "", "  ")
							fmt.Print(string(b))

							feeder.PushLogSidekick(log)
						}
					}

				case unix.PTRACE_EVENT_EXEC:
					// forked tracee have successfully called execve
					fmt.Println("execve")
					if !execved {
						execved = true
					}
				case unix.PTRACE_EVENT_VFORK:
					fmt.Println("vfork")
					if !execved {
						execved = true
					}
				case unix.PTRACE_EVENT_CLONE:
					fmt.Println("clone")
					if !execved {
						execved = true
					}
				case unix.PTRACE_EVENT_EXIT:
					fmt.Println("exit")
				case unix.PTRACE_EVENT_FORK:
					fmt.Println("fork")
					if !execved {
						execved = true
					}
				default:
					fmt.Println("ptrace unexpected trap cause: ", trapCause)

				}
				//unix.PtraceCont(pid, 0)

			default:
				fmt.Println("syscall stop signal: ", stopSig)
			}
			unix.PtraceCont(pid, 0)
			//default:
			//	fmt.Println("DEFAULT wstatus:", wstatus)
		}
	}
}

func extractProcData(pid int) (string, int32, int32, string, error) {
	// read exe symlink
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", 0, 0, "", err
	}

	// read status file
	statusBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "", 0, 0, "", err
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
