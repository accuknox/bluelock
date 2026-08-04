package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	cfg "github.com/daemon1024/bluelock/config"
	"github.com/daemon1024/bluelock/enforcer"
	"github.com/daemon1024/bluelock/feeder"
	"github.com/daemon1024/bluelock/state"
	"github.com/kubearmor/KubeArmor/KubeArmor/core"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

type BlueLockDaemon struct {
	// node
	Node     tp.Node
	NodeLock *sync.RWMutex

	// containers (from docker)
	Containers     map[string]tp.Container
	ContainersLock *sync.RWMutex

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

	//PolicyListener *grpc.Server
	PolicyDir string

	CmdExecutableName string

	// Enforcer
	RuntimeEnforcer *enforcer.PtraceEnforcer

	// State Agent
	StateAgent *state.StateAgent

	// health-server
	GRPCHealthServer *health.Server

	// WgDaemon Handler
	WgDaemon sync.WaitGroup

	Running bool
}

func NewBlueLockDaemon() *BlueLockDaemon {
	dm := new(BlueLockDaemon)

	dm.Node = tp.Node{}
	dm.NodeLock = new(sync.RWMutex)

	dm.Containers = map[string]tp.Container{}
	dm.ContainersLock = new(sync.RWMutex)

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

	go dm.Logger.ServeLogFeeds()
}

// CloseLogger Function
func (dm *BlueLockDaemon) CloseLogger() bool {
	if err := dm.Logger.DestroyFeeder(); err != nil {
		kg.Errf("Failed to destroy KubeArmor Logger (%s)", err.Error())
		return false
	}
	return true
}

func (dm *BlueLockDaemon) SetHealthStatus(serviceName string, healthStatus grpc_health_v1.HealthCheckResponse_ServingStatus) error {
	if dm.GRPCHealthServer != nil {
		dm.GRPCHealthServer.SetServingStatus(serviceName, healthStatus)
		return nil
	}

	return fmt.Errorf("GRPC health server is not initialized")
}

func (dm *BlueLockDaemon) InitStateAgent() error {
	dm.StateAgent = state.NewStateAgent(&dm.Node, dm.NodeLock, dm.Containers, dm.ContainersLock)
	if dm.StateAgent == nil {
		return fmt.Errorf("failed to create state agent")
	}
	return nil
}

// CloseStateAgent Function
func (dm *BlueLockDaemon) CloseStateAgent() error {
	if err := dm.StateAgent.DestroyStateAgent(); err != nil {
		return fmt.Errorf("failed to destroy State Agent: %w", err)
	}
	return nil
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

	// health server
	if dm.Logger.LogServer != nil {
		dm.GRPCHealthServer = health.NewServer()
		grpc_health_v1.RegisterHealthServer(dm.Logger.LogServer, dm.GRPCHealthServer)
	}

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

			nodeData, containers, err := GetFargateMetadata()
			if err == nil {
				kg.Printf("Fetched node info NAME=%s", nodeData.NodeName)
				dm.NodeLock.Lock()
				dm.Node = nodeData
				dm.NodeLock.Unlock()

				kg.Printf("Fetched %d containers", len(containers))
				dm.ContainersLock.Lock()
				dm.Containers = containers
				dm.ContainersLock.Unlock()
			} else {
				kg.Errf("Error fetching Fargate metadata: %v", err.Error())
				dm.ContainersLock.Lock()
				dm.Container.NamespaceName = "container_namespace"
				dm.Containers[containerID] = dm.Container
				dm.ContainersLock.Unlock()
			}

			// Policy dir
			dm.PolicyDir = filepath.Join("/opt/kubearmor/policies", fmt.Sprintf("kubearmor-%s-%s", containerID, dm.CmdExecutableName))

			policyService := &PolicyServer{
				ContainerPolicyEnabled: true,
				UpdateContainerPolicy:  dm.ParseAndUpdateContainerSecurityPolicy,
			}
			pb.RegisterPolicyServiceServer(dm.Logger.LogServer, policyService)

			if err := dm.SetHealthStatus(pb.PolicyService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING); err != nil {
				kg.Errf("Failed to set health status for PolicyService: %v", err)
			}

			if !dm.K8sEnabled && cfg.GlobalCfg.StateAgent {
				// initialize state agent
				if err := dm.InitStateAgent(); err != nil {
					kg.Errf("Failed to initialize State Agent Server: %s", err.Error())

					// destroy the daemon
					// dm.DestroyKubeArmorDaemon()

					return
				}
				kg.Print("Initialized State Agent Server")

				pb.RegisterStateAgentServer(dm.Logger.LogServer, dm.StateAgent)
				if err := dm.SetHealthStatus(pb.StateAgent_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING); err != nil {
					kg.Warnf("Failed to set health status for StateAgent: %v", err)
				}
			}

			if dm.StateAgent != nil {
				go dm.StateAgent.PushNodeEvent(dm.Node, state.EventAdded)

				for _, c := range containers {
					dm.StateAgent.PushContainerEvent(c, state.EventAdded)
				}
			}
		}

	} else {
		// host mode
		kg.Printf("Detected non-container environment. Only visibility.")
	}

	reflection.Register(dm.Logger.LogServer)

	// serve log feeds
	go dm.ServeLogFeeds()
	kg.Printf("Started to serve gRPC-based log feeds")
	if err := dm.SetHealthStatus(pb.LogService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING); err != nil {
		kg.Warnf("Failed to set health status for LogService: %v", err)
	}

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

	// extra line for clean log
	fmt.Println()
	kg.Printf("Quitting Kubearmor")
	//close(StopChan)

	// destroy the daemon
	//dm.DestroyKubeArmorDaemon()
}
