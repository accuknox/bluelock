package core

import (
	"fmt"
	"os"
	"path/filepath"
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

	// PolicyListener - receives policies
	//PolicyListener *grpc.Server
	PolicyClient *PolicyStreamerClient
	PolicyDir    string

	CmdExecutableName string

	// Enforcer
	RuntimeEnforcer *enforcer.PtraceEnforcer

	// WgDaemon Handler
	WgDaemon sync.WaitGroup

	Running bool
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
	dm.Running = true

	return dm
}

// StopChan Channel
var StopChan chan struct{}

// Logger

// InitLogger Function
func (dm *BlueLockDaemon) InitLogger() bool {
	dm.Logger = feeder.NewFeeder()
	return dm.Logger != nil
}

// ServeLogFeeds Function
func (dm *BlueLockDaemon) ServeLogFeeds() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	go dm.Logger.StreamLogFeeds()
}

// CloseLogger Function
func (dm *BlueLockDaemon) CloseLogger() bool {
	if err := dm.Logger.DestroyFeeder(); err != nil {
		kg.Errf("Failed to destroy KubeArmor Logger (%s)", err.Error())
		return false
	}
	return true
}

// CloseLogger Function
func (dm *BlueLockDaemon) ClosePolicyStream() bool {
	if dm.PolicyClient != nil {
		if err := dm.PolicyClient.DestroyClient(); err != nil {
			kg.Errf("Failed to destroy KubeArmor Policy Client (%s)", err.Error())
			return false
		}
	}
	return true
}

func BlueLock() {
	if err := cfg.LoadConfig(); err != nil {
		kg.Err(err.Error())
		return
	}

	dm := NewBlueLockDaemon()

	dm.CmdExecutableName = os.Args[1]

	if cfg.GlobalCfg.K8sEnv {
		dm.K8sEnabled = true
		K8s = NewK8sHandler()
		if !K8s.InitK8sClient() {
			kg.Err("Failed to initialize Kubernetes client")
			return
		}

		kg.Print("Initialized Kubernetes client")
	}

	if !dm.InitLogger() {
		kg.Err("Failed to intialize KubeArmor Logger")
		return
	}
	kg.Print("Initialized KubeArmor Logger")

	dm.DefaultPosture = tp.DefaultPosture{
		FileAction:    cfg.GlobalCfg.DefaultFilePosture,
		NetworkAction: cfg.GlobalCfg.DefaultNetworkPosture,
	}

	containerID, err := GetContainerID()
	if err != nil {
		kg.Errf("Unable to get container ID: %s", err.Error())
	}

	if containerID != "" {
		dm.Container.ContainerID = containerID
		kg.Printf("Using container ID: %s", containerID)

		// if k8s
		if cfg.GlobalCfg.K8sEnv {
			kg.Printf("Detected Kubernetes environment")
			dm.GetPod()

			dm.CreateEndpointWithPod()

			// watch security policies
			go dm.WatchSecurityPolicies()
			kg.Printf("Started to monitor security policies")

		} else {
			kg.Printf("Detected Non-Kubernetes container environment")

			if cfg.GlobalCfg.ContainerName == "" {
				kg.Errf("Environment variable CONTAINERNAME must be set in non-k8s container environments")
				return
			}

			dm.Container.ContainerName = cfg.GlobalCfg.ContainerName

			// Policy dir
			dm.PolicyDir = filepath.Join("/opt/kubearmor/policies", fmt.Sprintf("kubearmor-%s-%s", containerID, dm.CmdExecutableName))

			go dm.StreamPolicies()
		}

	} else {
		// host mode
		kg.Printf("Detected non-container environment. Only visibility.")
	}

	// serve log feeds
	go dm.ServeLogFeeds()
	kg.Printf("Started to serve gRPC-based log feeds")

	dm.RuntimeEnforcer = enforcer.NewPtraceEnforcer(&dm.Container, dm.Logger)
	go dm.RuntimeEnforcer.StartSystemTracer()

	// watch default posture in k8s env
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

	dm.CloseLogger()
	dm.ClosePolicyStream()

	// extra line for clean log
	fmt.Println()
	kg.Printf("Quitting Kubearmor")
	//close(StopChan)

	// destroy the daemon
	//dm.DestroyKubeArmorDaemon()
}
