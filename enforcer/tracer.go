package enforcer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/pkg/seccomp"
	"github.com/criyle/go-sandbox/pkg/seccomp/libseccomp"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"golang.org/x/sys/unix"
)

type Tracer struct {
	*PtraceEnforcer
	pgid    int
	traced  map[int]bool
	execved bool
}

func (pe *PtraceEnforcer) StartSystemTracer() {
	var err error

	builder := libseccomp.Builder{
		Trace: []string{
			"openat",
		},
		Default: libseccomp.ActionAllow,
	}
	var filter seccomp.Filter
	filter, err = builder.Build()
	if err != nil {
		kg.Errf("Failed to build seccomp filter: %v", err)
	}
	fmt.Println("Run: ", os.Args[1:])

	execPath, _ := exec.LookPath(os.Args[1])
	bin, err := os.Open(execPath)
	if err != nil {
		kg.Errf("Failed to open exec file: %v", err)
	}
	defer bin.Close()
	cmd := forkexec.Runner{
		Args:     os.Args[1:],
		ExecFile: bin.Fd(),
		Seccomp:  filter.SockFprog(),
		Ptrace:   true,
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pgid, err := cmd.Start()
	// err = cmd.Wait()
	if err != nil {
		fmt.Printf("Wait err %v \n", err)
	}
	setPtraceOption(pgid)

	tracer := Tracer{pe, pgid, make(map[int]bool), false}

	tracer.trace()
}

func (t *Tracer) trace() {

	// TODO:
	// handle processes which won't create a chlid process which leads to execve to be always false
	// make signals sent to child process work

	for {
		var pid int
		var err error
		var wstatus unix.WaitStatus

		if t.execved {
			// Wait for all child in the process group
			pid, err = unix.Wait4(-1, &wstatus, unix.WALL, nil)
		} else {
			// Ensure the process have called setpgid
			pid, err = unix.Wait4(t.pgid, &wstatus, unix.WALL, nil)
		}
		if err != nil {
			kg.Warnf("Couldn't wait for PID: %d. WaitStatus: %d, Error: %s", pid, &wstatus, err)
		}
		//fmt.Println("pid: ", pid, " wstatus: ", wstatus, " err: ", err, "")

		switch {
		case wstatus.Exited():
			delete(t.traced, pid)
			if pid == t.pgid {
				if t.execved {
					break
				}
			}

		case wstatus.Signaled():
			sig := wstatus.Signal()
			// if pid == t.pgid {
			// 	delete(t.traced, pid)
			// 	break
			// }
			unix.PtraceCont(pid, int(sig))

		case wstatus.Stopped():
			// Set option if the process is newly forked
			if !t.traced[pid] {
				t.traced[pid] = true
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
					if t.execved {
						t.handle(pid)
					}

				case unix.PTRACE_EVENT_EXEC:
					// forked tracee have successfully called execve
					if !t.execved {
						t.execved = true
					}
				case unix.PTRACE_EVENT_VFORK:
					if !t.execved {
						t.execved = true
					}
				case unix.PTRACE_EVENT_CLONE:
					if !t.execved {
						t.execved = true
					}
				case unix.PTRACE_EVENT_FORK:
					if !t.execved {
						t.execved = true
					}
				case unix.PTRACE_EVENT_EXIT:
					fmt.Println("exit")
				default:
					fmt.Println("ptrace unexpected trap cause: ", trapCause)

				}

			default:
				fmt.Println("syscall stop signal: ", stopSig)
			}
			unix.PtraceCont(pid, 0)
		}
	}
}

func (t *Tracer) handle(pid int) {
	var regs syscall.PtraceRegs
	err := syscall.PtraceGetRegs(pid, &regs)
	if err != nil {
		return
	}
	log := t.NewBaseLog()
	if regs.Orig_rax == 257 {
		log.PID = int32(pid)
		log.Resource = absPath(pid, getString(pid, uintptr(regs.Rsi)))
		log.Operation = "File"
		log.ProcessName, log.PPID, log.UID, log.ParentProcessName, err = extractProcData(pid)
		if err != nil {
			kg.Warnf("Error extracting process data %v \n", err)
		}
		log.Source = log.ProcessName
		log.Data = "syscall=openat fd=" + strconv.Itoa(int(regs.Rdi)) + " flags=" + strconv.Itoa(int(regs.Rdx)) + " mode=" + strconv.Itoa(int(regs.R10))

		// Enforcement Logic
		if val, ok := t.Rules.FilePaths[InnerKey{
			Path:   log.Resource,
			Source: "",
		}]; ok {
			if val.Deny {
				regs.Orig_rax = ^uint64(0)
				regs.Rax = ^uint64(syscall.EPERM)
				_ = syscall.PtraceSetRegs(pid, &regs)
				kg.Warnf("Denied %s %s \n", log.Operation, log.Resource)
				log.Action = "Block"
				log.Result = "Permission denied"
			}
		}
		if val, ok := t.Rules.FilePaths[InnerKey{
			Path:   log.Resource,
			Source: log.Source,
		}]; ok {
			if val.Deny {
				regs.Orig_rax = ^uint64(0)
				regs.Rax = ^uint64(syscall.EPERM)
				_ = syscall.PtraceSetRegs(pid, &regs)
				kg.Warnf("Denied %s % from source %s \n", log.Operation, log.Resource, log.Source)
				log.Action = "Block"
				log.Result = "Permission denied"

			}
		}

		b, _ := json.MarshalIndent(log, "", "  ")
		fmt.Print(string(b))

		// feeder.PushLogSidekick(log)
		t.Logger.PushLogRelay(log)
	}
}
