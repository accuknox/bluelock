package core

import (
	"fmt"
	"sync"

	"github.com/daemon1024/bluelock/enforcer"
	"github.com/daemon1024/bluelock/feeder"
	"github.com/daemon1024/bluelock/monitor"
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
	SecurityPolicies []tp.SecurityPolicy
	SecurityPoliciesLock *sync.RWMutex

	// Sidekick logger
	Logger *feeder.Logger

	// Enforcer
	RuntimeEnforcer *enforcer.PtraceEnforcer

	// Monitor

}

func NewBlueLockDaemon() *BlueLockDaemon {
	dm := new(BlueLockDaemon)

	dm.K8sEnabled = false
	dm.K8sPod = tp.K8sPod{}
	dm.EndPoint = tp.EndPoint{}
	dm.Container = tp.Container{}
	dm.SecurityPolicies = []tp.SecurityPolicy{}
	dm.SecurityPoliciesLock = new(sync.RWMutex)
	dm.Logger = feeder.SidekickLogger
	dm.RuntimeEnforcer = nil

	return dm
}

// StopChan Channel
var StopChan chan struct{}

func BlueLock() {
	dm := NewBlueLockDaemon()
	dm.K8sEnabled = true
	if !K8s.InitK8sClient() {
		kg.Err("Failed to initialize Kubernetes client")

		// destroy the daemon
		// dm.DestroyKubeArmorDaemon()

		return
	}

	kg.Print("Initialized Kubernetes client")

	containerID, err := GetContainerID()
	//fmt.Println(containerID)
	if err != nil {
		kg.Errf("Unable to get container ID: %s", err.Error())
	}

	if containerID != "" {
		dm.Container.ContainerID = containerID
		kg.Printf("Using container ID: %s", containerID)

		// if k8s
		dm.CreateNewPod()
		fmt.Println(dm.K8sPod)
	}

	// watch security policies
	go dm.WatchSecurityPolicies()
	kg.Printf("Started to monitor security policies")

	go monitor.StartSystemMonitor()

	dm.RuntimeEnforcer = enforcer.NewPtraceEnforcer()

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
	//dm.Logger.Print("Got a signal to terminate KubeArmor")
	close(StopChan)

	// destroy the daemon
	//dm.DestroyKubeArmorDaemon()
}
