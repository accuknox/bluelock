package enforcer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/criyle/go-sandbox/pkg/forkexec"
	"github.com/criyle/go-sandbox/pkg/seccomp"
	"github.com/criyle/go-sandbox/pkg/seccomp/libseccomp"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"golang.org/x/exp/slices"
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
			"open",
			"openat",
			"socket",
			"execve",
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
	log.PID = int32(pid)
	log.Timestamp = time.Now().UTC().Unix()
	log.ProcessName, log.PPID, log.UID, log.ParentProcessName, err = extractProcData(pid)
	if err != nil {
		kg.Warnf("Error extracting process data %v \n", err)
	}

	if slices.Contains([]int{syscall.SYS_EXECVE}, int(regs.Orig_rax)) {
		log.Operation = "Process"
		log.Source = log.ProcessName
		log.Resource = absPath(pid, getString(pid, uintptr(regs.Rdi)))
		log.Data = "syscall=execve"

		// Enforcement Logic
		if val, ok := t.Rules.ProcessRules[InnerKey{
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
		if val, ok := t.Rules.ProcessRules[InnerKey{
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
	}

	if slices.Contains([]int{syscall.SYS_OPEN, syscall.SYS_OPENAT, syscall.SYS_MKNOD, syscall.SYS_MKNODAT, syscall.SYS_UNLINK, syscall.SYS_UNLINKAT}, int(regs.Orig_rax)) {

		log.Operation = "File"
		log.Source = log.ProcessName

		switch regs.Orig_rax {
		case syscall.SYS_OPEN:
			log.Resource = absPath(pid, getString(pid, uintptr(regs.Rdi)))
			log.Data = "syscall=open flags=" + strconv.Itoa(int(regs.Rsi)) + " mode=" + strconv.Itoa(int(regs.Rdx))
		case syscall.SYS_OPENAT:
			log.Resource = absPath(pid, getString(pid, uintptr(regs.Rsi)))
			log.Data = "syscall=openat fd=" + strconv.Itoa(int(regs.Rdi)) + " flags=" + strconv.Itoa(int(regs.Rdx)) + " mode=" + strconv.Itoa(int(regs.R10))
		case syscall.SYS_MKNOD:
			log.Resource = absPath(pid, getString(pid, uintptr(regs.Rdi)))
			log.Data = "syscall=mknod mode=" + strconv.Itoa(int(regs.Rsi)) + " dev=" + strconv.Itoa(int(regs.Rdx))
		case syscall.SYS_MKNODAT:
			log.Resource = absPath(pid, getString(pid, uintptr(regs.Rsi)))
			log.Data = "syscall=mknodat fd=" + strconv.Itoa(int(regs.Rdi)) + " mode=" + strconv.Itoa(int(regs.Rdx)) + " dev=" + strconv.Itoa(int(regs.R10))
		case syscall.SYS_UNLINK:
			log.Resource = absPath(pid, getString(pid, uintptr(regs.Rdi)))
			log.Data = "syscall=unlink"
		case syscall.SYS_UNLINKAT:
			log.Resource = absPath(pid, getString(pid, uintptr(regs.Rsi)))
			log.Data = "syscall=unlinkat fd=" + strconv.Itoa(int(regs.Rdi)) + " flags=" + strconv.Itoa(int(regs.Rdx))
		}

		// Enforcement Logic
		if val, ok := t.Rules.FileRules[InnerKey{
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
		if val, ok := t.Rules.FileRules[InnerKey{
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
	}

	if regs.Orig_rax == syscall.SYS_SOCKET {
		log.Operation = "Network"
		log.Source = log.ProcessName

		sdomain := getSocketDomain(uint32(regs.Rdi))
		stype := getSocketType(uint32(regs.Rsi))
		sprotocol := getProtocol(int32(regs.Rdx))

		log.Resource = "domain=" + sdomain + " type=" + stype + " protocol=" + sprotocol
		log.Data = "syscall=SYS_SOCKET"

		// extract rule from Resource
		netrule := ""
		if strings.Contains(stype, "SOCK_STREAM") && strings.Contains(sprotocol, "TCP") {
			netrule = "tcp"
		} else if strings.Contains(stype, "SOCK_DGRAM") && (strings.Contains(sprotocol, "UDP") || strings.Contains(sprotocol, "0")) {
			netrule = "udp"
		} else if strings.Contains(sprotocol, "ICMP") && (strings.Contains(stype, "SOCK_DGRAM") || strings.Contains(stype, "SOCK_RAW")) {
			netrule = "icmp"
		} else if strings.Contains(stype, "SOCK_RAW") {
			netrule = "raw"
		}

		// Enforcement Logic
		if val, ok := t.Rules.NetworkRules[InnerKey{
			Path:   netrule,
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
		if val, ok := t.Rules.NetworkRules[InnerKey{
			Path:   netrule,
			Source: log.Source,
		}]; ok {
			if val.Deny {
				regs.Orig_rax = ^uint64(0)
				regs.Rax = ^uint64(syscall.EPERM)
				_ = syscall.PtraceSetRegs(pid, &regs)
				kg.Warnf("Denied %s %s from source %s \n", log.Operation, log.Resource, log.Source)
				log.Action = "Block"
			}
		}

	}

	// if slices.Contains([]int{syscall.SYS_BIND, syscall.SYS_CONNECT, syscall.SYS_ACCEPT, syscall.SYS_ACCEPT4}, int(regs.Orig_rax)) {

	// 	log.Operation = "Network"
	// 	log.Source = log.ProcessName

	// 	// Read Family and protocol from sockaddr pointer
	// 	family := uint16(getUint16(pid, uintptr(regs.Rsi)))
	// 	fd := regs.Rdi
	// 	stype, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
	// 	var protocolStr string

	// 	if err != nil {
	// 		kg.Warnf("Error getting socket info", err)
	// 	}

	// 	switch stype {
	// 	case syscall.SOCK_STREAM:
	// 		protocolStr = "TCP/STREAM"
	// 	case syscall.SOCK_DGRAM:
	// 		protocolStr = "UDP/DGRAM"
	// 	case syscall.SOCK_RAW:
	// 		protocolStr = "RAW/RAW"
	// 	}

	// 	switch regs.Orig_rax {
	// 	case syscall.SYS_BIND:
	// 		log.Data = "syscall=bind"
	// 	case syscall.SYS_CONNECT:
	// 		log.Data = "syscall=connect"
	// 	case syscall.SYS_ACCEPT:
	// 		log.Data = "syscall=accept"
	// 	case syscall.SYS_ACCEPT4:
	// 		log.Data = "syscall=accept4"
	// 	}

	// 	// Convert Family and protocol to string
	// 	var familyStr string
	// 	switch family {
	// 	case syscall.AF_INET:
	// 		familyStr = "AF_INET"
	// 	case syscall.AF_INET6:
	// 		familyStr = "AF_INET6"
	// 	case syscall.AF_UNIX:
	// 		familyStr = "AF_UNIX"
	// 	case syscall.AF_UNSPEC:
	// 		familyStr = "AF_UNSPEC"
	// 	}

	// 	log.Resource = "Family=" + familyStr + " Protocol=" + protocolStr
	// }
	b, _ := json.MarshalIndent(log, "", "  ")
	fmt.Print(string(b))

	// feeder.PushLogSidekick(log)
	// feeder.P(log)
}

// define getUint16 and getUint8
func getUint16(pid int, addr uintptr) uint16 {
	var buff [2]byte
	syscall.PtracePeekData(pid, addr, buff[:])
	return uint16(buff[0]) | uint16(buff[1])<<8
}

func getUint8(pid int, addr uintptr) uint8 {
	var buff [1]byte
	syscall.PtracePeekData(pid, addr, buff[:])
	return uint8(buff[0])
}
