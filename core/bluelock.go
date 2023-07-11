package core

import (
	"fmt"
	"sync"

	cfg "github.com/daemon1024/bluelock/config"
	"github.com/daemon1024/bluelock/enforcer"
	"github.com/daemon1024/bluelock/feeder"
	"github.com/kubearmor/KubeArmor/KubeArmor/core"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type BlueLockDaemon struct {
	// K8s specific
	// whether running in K8s cluster
	K8sEnabled bool

	// K8s pod being monitored
	K8sPod tp.K8sPod

	// K8s EndPoint
	EndPoint tp.EndPoint

	// The container in which KubeArmor is running
	Container tp.Container

	// Security policies for the container
	SecurityPolicies     []tp.SecurityPolicy
	SecurityPoliciesLock *sync.RWMutex

	// DefaultPosture
	DefaultPosture tp.DefaultPosture

	// Logger
	Logger *feeder.Feeder

	// Enforcer
	RuntimeEnforcer *enforcer.PtraceEnforcer
}

func NewBlueLockDaemon() *BlueLockDaemon {
	dm := new(BlueLockDaemon)

	dm.K8sEnabled = false
	dm.K8sPod = tp.K8sPod{}
	dm.EndPoint = tp.EndPoint{}
	dm.Container = tp.Container{}
	dm.SecurityPolicies = []tp.SecurityPolicy{}
	dm.SecurityPoliciesLock = new(sync.RWMutex)
	dm.Logger = nil
	dm.RuntimeEnforcer = nil

	return dm
}

// StopChan Channel
var StopChan chan struct{}

func BlueLock() {
	dm := NewBlueLockDaemon()

	if err := cfg.LoadConfig(); err != nil {
		kg.Err(err.Error())
		return
	}

	if cfg.GlobalCfg.K8sEnv {
		dm.K8sEnabled = true
		if !K8s.InitK8sClient() {
			kg.Err("Failed to initialize Kubernetes client")
			return
		}

		kg.Print("Initialized Kubernetes client")
	}

	dm.DefaultPosture = tp.DefaultPosture{
		FileAction:    cfg.GlobalCfg.DefaultFilePosture,
		NetworkAction: cfg.GlobalCfg.DefaultNetworkPosture,
	}

	containerID, err := GetContainerID()
	//fmt.Println(containerID)
	if err != nil {
		kg.Errf("Unable to get container ID: %s", err.Error())
	}

	if containerID != "" {
		dm.Container.ContainerID = containerID
		kg.Printf("Using container ID: %s", containerID)

		// if k8s
		if cfg.GlobalCfg.K8sEnv {
			dm.GetPod()

			dm.CreateEndpointWithPod()

			// watch security policies
			go dm.WatchSecurityPolicies()
			kg.Printf("Started to monitor security policies")
		} else {
			// ECS/unorchestrated
			kg.Printf("Started to monitor unorchestrated containers")
		}
	} else {
		// host mode
		kg.Printf("Not running inside container")
	}

	dm.Logger = feeder.NewFeeder()

	dm.RuntimeEnforcer = enforcer.NewPtraceEnforcer(&dm.Container, dm.Logger)
	go dm.RuntimeEnforcer.StartSystemTracer()

	// watch default posture
	/*
		go dm.WatchDefaultPosture()
		dm.Logger.Print("Started to monitor per-namespace default posture")

		// watch kubearmor configmap
		go dm.WatchConfigMap()
		dm.Logger.Print("Watching for posture changes")
	*/

	// listen for interrupt signals
	sigChan := core.GetOSSigChannel()
	<-sigChan

	// extra line for clean log
	fmt.Println()
	kg.Printf("Quitting Kubearmor")
	//close(StopChan)

	// destroy the daemon
	//dm.DestroyKubeArmorDaemon()
}
