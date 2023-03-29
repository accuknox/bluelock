//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	seccomp "github.com/seccomp/libseccomp-golang"
)

func main() {
	var err error
	var regs syscall.PtraceRegs
	var ss syscallCounter
	ss = ss.init()

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
	// nropenat, _ := seccomp.GetSyscallFromName("openat")
	// _ = filter.AddRule(nropenat, seccomp.ActTrace)

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

	cmd.Start()
	err = cmd.Wait()
	if err != nil {
		fmt.Printf("Wait err %v \n", err)
	}

	pid := cmd.Process.Pid
	exit := true

	for {
		if exit {
			err = syscall.PtraceGetRegs(pid, &regs)
			if err != nil {
				break
			}
			// name := ss.getName(regs.Orig_rax)
			// fmt.Printf("name: %s, id: %d \n", name, regs.Orig_rax)
			ss.inc(regs.Orig_rax)
		}
		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			panic(err)
		}
		_, err = syscall.Wait4(pid, nil, 0, nil)
		if err != nil {
			panic(err)
		}

		exit = !exit
	}

	ss.print()
}
