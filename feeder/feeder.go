package feeder

import (
	"os"
	"path/filepath"
	"sync"

	cfg "github.com/daemon1024/bluelock/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

var (
	PtraceEnforcer = "Ptrace enforcer"
	PtraceTracer = "Ptrace tracer"
)

type Feeder struct {
	Output string
	LogFile *os.File

	SecurityPolicy tp.MatchPolicies
	SecurityPolicyLock *sync.RWMutex

	DefaultPosture tp.DefaultPosture

	EnableSidekick bool
	EnableKubearmorRelay bool

	RelayServerURL string

	HostName string
}

func NewFeeder() *Feeder {
	fd := &Feeder{}

	// output
	fd.Output = cfg.GlobalCfg.LogPath

	// output mode
	if fd.Output != "stdout" && fd.Output != "none" {
		// #nosec
		logFile, err := os.OpenFile(filepath.Clean(fd.Output), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			kg.Errf("Failed to open %s", fd.Output)
			return nil
		}
		fd.LogFile = logFile
	}

	fd.SecurityPolicy = tp.MatchPolicies{}
	fd.DefaultPosture = tp.DefaultPosture{}

	fd.RelayServerURL = cfg.GlobalCfg.RelayServerURL

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "none"
	}
	fd.HostName = hostname

	return fd
}
