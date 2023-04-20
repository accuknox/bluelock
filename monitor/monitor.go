package monitor

import (
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
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	seccomp "github.com/seccomp/libseccomp-golang"
)

func StartSystemMonitor() {
	var err error
	var regs syscall.PtraceRegs

	//var ss syscallCounter
	//ss = ss.init()

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

	// Extract Container Name
	// Extract Container ID
	// pid/ppid  from status
	// pname from exe
	// ppname  from ppid/exe

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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
			//ss.inc(regs.Orig_rax)
			log := tp.Log{}
			if regs.Orig_rax == 257 {
				log.PID = int32(pid)
				log.Timestamp = time.Now().UTC().Unix()
				log.Resource = absPath(pid, getString(pid, uintptr(regs.Rsi)))
				log.Operation = "File"
				log.ProcessName, log.PPID, log.UID, log.ParentProcessName, _ = extractProcData(pid)
				log.Source = log.ProcessName
				log.Data = "syscall=openat fd=" + strconv.Itoa(int(regs.Rdi)) + " flags=" + strconv.Itoa(int(regs.Rdx)) + " mode=" + strconv.Itoa(int(regs.R10))

				// TODO: find a mechanism which works with all cgroup versions
				// https://docs.docker.com/config/containers/runmetrics/#find-the-cgroup-for-a-given-container
				//log.ContainerID = containerID

				feeder.PushLogSidekick(log)

				//s, _ := json.MarshalIndent(log, "", "\t")
				//fmt.Print(string(s))
			}
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

	//ss.print()
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
