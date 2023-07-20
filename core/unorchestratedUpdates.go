package core

import (
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/daemon1024/bluelock/common"
	kl "github.com/daemon1024/bluelock/common"
	cfg "github.com/daemon1024/bluelock/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type PolicyStreamerClient struct {
	Running bool
	RelayServerURL string
	Conn *grpc.ClientConn
	Client pb.PolicyStreamServiceClient

	ContainerPolicyClient pb.PolicyStreamService_ContainerPolicyClient
}

func NewPolicyStreamer() *PolicyStreamerClient {
	return &PolicyStreamerClient{
		Running: true,
	}
}

func (dm *BlueLockDaemon) StreamPolicies() {
	dm.PolicyClient = NewPolicyStreamer()

	address, err := common.GetURL(cfg.GlobalCfg.RelayServerURL)
	if err != nil {
		kg.Errf("Failed to parse Relay Server URL: %s", err.Error())
		return
	}

	dm.PolicyClient.RelayServerURL = address

	for dm.PolicyClient.Running {
		dm.PolicyClient.connectWithRelay()
		if dm.PolicyClient == nil {
			kg.Errf("Error while connecting with relay for streaming policies")
			return
		}

		kg.Printf("Connected with Relay server for streaming policies")

		dm.WgDaemon.Add(1)
		go dm.GetPolicies()
		kg.Printf("Started to stream policies")

		dm.WgDaemon.Wait()

		if err := dm.PolicyClient.Conn.Close(); err != nil {
			kg.Warnf("Failed to delete PolicyClient: %s", err.Error())
		}
		kg.Printf("Closed policy client for %s", address)

		dm.PolicyClient.Client = nil

		/*
		if err := dm.PolicyClient.DestroyClient(); err != nil {
			kg.Warnf("Failed to destroy the policy streamer client")
		}*/
	}

	return
}

// DoHealthCheck Function
func (ps *PolicyStreamerClient) DoHealthCheck() bool {
	// #nosec
	randNum := rand.Int31()

	// send a nonce
	nonce := pb.HealthCheckReq{Nonce: randNum}
	res, err := ps.Client.HealthCheck(context.Background(), &nonce)
	if err != nil {
		kg.Warnf("Relay server health check failed. %s", err)
		return false
	}

	// check nonce
	if randNum != res.Retval {
		return false
	}

	return true
}

func (ps *PolicyStreamerClient) DestroyClient() error {
	ps.Running = false

	if ps.Conn != nil {
		if err := ps.Conn.Close(); err != nil {
			return err
		}
	}

	return nil
}

// TODO: use single gRPC connection for both the clients
func (ps *PolicyStreamerClient) connectWithRelay() {
	var err error

	kacp := keepalive.ClientParameters{
		Time:    1 * time.Second,
		Timeout: 5 * time.Second,
		PermitWithoutStream: true,
	}

	address := ps.RelayServerURL
	for ps.Running {
		conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithKeepaliveParams(kacp), grpc.WithBlock())
		if err != nil {
			kg.Warnf("Failed to connect to relay's gRPC listener. %s", err.Error())
			time.Sleep(time.Second * 5)
			conn.Close()
			continue
		}

		ps.Conn = conn

		client := pb.NewPolicyStreamServiceClient(conn)

		ps.Client = client

		if ok := ps.DoHealthCheck(); !ok {
			kg.Warnf("ContainerPolicy server is unhealthy")
			time.Sleep(time.Second * 5)
			conn.Close()
			continue
		}

		break
	}

	ps.ContainerPolicyClient, err = ps.Client.ContainerPolicy(context.Background())
	if err != nil {
		kg.Warnf("Failed to start ContainerPolicy stream reader err=%s", err.Error())
	}

	return
}

func (dm *BlueLockDaemon) GetPolicies() {
	defer dm.WgDaemon.Done()
	pc := dm.PolicyClient
	var err error
	for pc.Running {
		var res *pb.Policy

		if res, err = pc.ContainerPolicyClient.Recv(); err != nil {
			kg.Warnf("Failed to receive a policy %s", err)
			break
		}

		policyEvent := tp.K8sKubeArmorPolicyEvent{}

		//if err := kl.Clone(res.Policy, &policyEvent); err != nil {
		if err := json.Unmarshal(res.Policy, &policyEvent); err != nil {
			kg.Warnf("GetPolicies: Failed to clone a policy: %s", err)
			continue
		}

		go dm.ParseAndUpdateContainerSecurityPolicy(policyEvent)
	}

	return
}

// ParseAndUpdateContainerSecurityPolicy Function
func (dm *BlueLockDaemon) ParseAndUpdateContainerSecurityPolicy(event tp.K8sKubeArmorPolicyEvent) {
	// create a container security policy
	secPolicy := tp.SecurityPolicy{}

	secPolicy.Metadata = map[string]string{}
	secPolicy.Metadata["namespaceName"] = "container_namespace" //event.Object.Metadata.Namespace
	secPolicy.Metadata["policyName"] = event.Object.Metadata.Name

	if err := kl.Clone(event.Object.Spec, &secPolicy.Spec); err != nil {
		kg.Errf("Failed to clone a spec (%s)", err.Error())
		return
	}

	// return if current policy is not for this container
	if secPolicy.Spec.Selector.MatchLabels["kubearmor.io/container.name"] != dm.Container.ContainerName && secPolicy.Spec.Selector.MatchLabels["kubearmor.io/container.name"] != "*" {
		return
	}

	newPoint := dm.EndPoint

	kl.ObjCommaExpandFirstDupOthers(&secPolicy.Spec.Network.MatchProtocols)

	if secPolicy.Spec.Severity == 0 {
		secPolicy.Spec.Severity = 1 // the lowest severity, by default
	}

	switch secPolicy.Spec.Action {
	case "allow":
		secPolicy.Spec.Action = "Allow"
	case "audit":
		secPolicy.Spec.Action = "Audit"
	case "block":
		secPolicy.Spec.Action = "Block"
	case "":
		secPolicy.Spec.Action = "Block" // by default
	}

	// add identities

	secPolicy.Spec.Selector.Identities = []string{"namespaceName=" + event.Object.Metadata.Namespace}
	//containername := dm.Container.ContainerName
	for k, v := range secPolicy.Spec.Selector.MatchLabels {
		secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, k+"="+v)
		if k == "kubearmor.io/container.name" {
			//containername = v
		} else {
			kg.Warnf("Fail to apply policy. The MatchLabels container name key should be `kubearmor.io/container.name` ")
			return
		}
	}

	sort.Slice(secPolicy.Spec.Selector.Identities, func(i, j int) bool {
		return secPolicy.Spec.Selector.Identities[i] < secPolicy.Spec.Selector.Identities[j]
	})

	// add severities, tags, messages, and actions

	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for idx, path := range secPolicy.Spec.Process.MatchPaths {
			if path.Severity == 0 {
				if secPolicy.Spec.Process.Severity != 0 {
					secPolicy.Spec.Process.MatchPaths[idx].Severity = secPolicy.Spec.Process.Severity
				} else {
					secPolicy.Spec.Process.MatchPaths[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(path.Tags) == 0 {
				if len(secPolicy.Spec.Process.Tags) > 0 {
					secPolicy.Spec.Process.MatchPaths[idx].Tags = secPolicy.Spec.Process.Tags
				} else {
					secPolicy.Spec.Process.MatchPaths[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(path.Message) == 0 {
				if len(secPolicy.Spec.Process.Message) > 0 {
					secPolicy.Spec.Process.MatchPaths[idx].Message = secPolicy.Spec.Process.Message
				} else {
					secPolicy.Spec.Process.MatchPaths[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(path.Action) == 0 {
				if len(secPolicy.Spec.Process.Action) > 0 {
					secPolicy.Spec.Process.MatchPaths[idx].Action = secPolicy.Spec.Process.Action
				} else {
					secPolicy.Spec.Process.MatchPaths[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for idx, dir := range secPolicy.Spec.Process.MatchDirectories {
			if dir.Severity == 0 {
				if secPolicy.Spec.Process.Severity != 0 {
					secPolicy.Spec.Process.MatchDirectories[idx].Severity = secPolicy.Spec.Process.Severity
				} else {
					secPolicy.Spec.Process.MatchDirectories[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(dir.Tags) == 0 {
				if len(secPolicy.Spec.Process.Tags) > 0 {
					secPolicy.Spec.Process.MatchDirectories[idx].Tags = secPolicy.Spec.Process.Tags
				} else {
					secPolicy.Spec.Process.MatchDirectories[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(dir.Message) == 0 {
				if len(secPolicy.Spec.Process.Message) > 0 {
					secPolicy.Spec.Process.MatchDirectories[idx].Message = secPolicy.Spec.Process.Message
				} else {
					secPolicy.Spec.Process.MatchDirectories[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(dir.Action) == 0 {
				if len(secPolicy.Spec.Process.Action) > 0 {
					secPolicy.Spec.Process.MatchDirectories[idx].Action = secPolicy.Spec.Process.Action
				} else {
					secPolicy.Spec.Process.MatchDirectories[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for idx, pat := range secPolicy.Spec.Process.MatchPatterns {
			if pat.Severity == 0 {
				if secPolicy.Spec.Process.Severity != 0 {
					secPolicy.Spec.Process.MatchPatterns[idx].Severity = secPolicy.Spec.Process.Severity
				} else {
					secPolicy.Spec.Process.MatchPatterns[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(pat.Tags) == 0 {
				if len(secPolicy.Spec.Process.Tags) > 0 {
					secPolicy.Spec.Process.MatchPatterns[idx].Tags = secPolicy.Spec.Process.Tags
				} else {
					secPolicy.Spec.Process.MatchPatterns[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(pat.Message) == 0 {
				if len(secPolicy.Spec.Process.Message) > 0 {
					secPolicy.Spec.Process.MatchPatterns[idx].Message = secPolicy.Spec.Process.Message
				} else {
					secPolicy.Spec.Process.MatchPatterns[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(pat.Action) == 0 {
				if len(secPolicy.Spec.Process.Action) > 0 {
					secPolicy.Spec.Process.MatchPatterns[idx].Action = secPolicy.Spec.Process.Action
				} else {
					secPolicy.Spec.Process.MatchPatterns[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for idx, path := range secPolicy.Spec.File.MatchPaths {
			if path.Severity == 0 {
				if secPolicy.Spec.File.Severity != 0 {
					secPolicy.Spec.File.MatchPaths[idx].Severity = secPolicy.Spec.File.Severity
				} else {
					secPolicy.Spec.File.MatchPaths[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(path.Tags) == 0 {
				if len(secPolicy.Spec.File.Tags) > 0 {
					secPolicy.Spec.File.MatchPaths[idx].Tags = secPolicy.Spec.File.Tags
				} else {
					secPolicy.Spec.File.MatchPaths[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(path.Message) == 0 {
				if len(secPolicy.Spec.File.Message) > 0 {
					secPolicy.Spec.File.MatchPaths[idx].Message = secPolicy.Spec.File.Message
				} else {
					secPolicy.Spec.File.MatchPaths[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(path.Action) == 0 {
				if len(secPolicy.Spec.File.Action) > 0 {
					secPolicy.Spec.File.MatchPaths[idx].Action = secPolicy.Spec.File.Action
				} else {
					secPolicy.Spec.File.MatchPaths[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for idx, dir := range secPolicy.Spec.File.MatchDirectories {
			if dir.Severity == 0 {
				if secPolicy.Spec.File.Severity != 0 {
					secPolicy.Spec.File.MatchDirectories[idx].Severity = secPolicy.Spec.File.Severity
				} else {
					secPolicy.Spec.File.MatchDirectories[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(dir.Tags) == 0 {
				if len(secPolicy.Spec.File.Tags) > 0 {
					secPolicy.Spec.File.MatchDirectories[idx].Tags = secPolicy.Spec.File.Tags
				} else {
					secPolicy.Spec.File.MatchDirectories[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(dir.Message) == 0 {
				if len(secPolicy.Spec.File.Message) > 0 {
					secPolicy.Spec.File.MatchDirectories[idx].Message = secPolicy.Spec.File.Message
				} else {
					secPolicy.Spec.File.MatchDirectories[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(dir.Action) == 0 {
				if len(secPolicy.Spec.File.Action) > 0 {
					secPolicy.Spec.File.MatchDirectories[idx].Action = secPolicy.Spec.File.Action
				} else {
					secPolicy.Spec.File.MatchDirectories[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for idx, pat := range secPolicy.Spec.File.MatchPatterns {
			if pat.Severity == 0 {
				if secPolicy.Spec.File.Severity != 0 {
					secPolicy.Spec.File.MatchPatterns[idx].Severity = secPolicy.Spec.File.Severity
				} else {
					secPolicy.Spec.File.MatchPatterns[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(pat.Tags) == 0 {
				if len(secPolicy.Spec.File.Tags) > 0 {
					secPolicy.Spec.File.MatchPatterns[idx].Tags = secPolicy.Spec.File.Tags
				} else {
					secPolicy.Spec.File.MatchPatterns[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(pat.Message) == 0 {
				if len(secPolicy.Spec.File.Message) > 0 {
					secPolicy.Spec.File.MatchPatterns[idx].Message = secPolicy.Spec.File.Message
				} else {
					secPolicy.Spec.File.MatchPatterns[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(pat.Action) == 0 {
				if len(secPolicy.Spec.File.Action) > 0 {
					secPolicy.Spec.File.MatchPatterns[idx].Action = secPolicy.Spec.File.Action
				} else {
					secPolicy.Spec.File.MatchPatterns[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
		for idx, proto := range secPolicy.Spec.Network.MatchProtocols {
			if proto.Severity == 0 {
				if secPolicy.Spec.Network.Severity != 0 {
					secPolicy.Spec.Network.MatchProtocols[idx].Severity = secPolicy.Spec.Network.Severity
				} else {
					secPolicy.Spec.Network.MatchProtocols[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(proto.Tags) == 0 {
				if len(secPolicy.Spec.Network.Tags) > 0 {
					secPolicy.Spec.Network.MatchProtocols[idx].Tags = secPolicy.Spec.Network.Tags
				} else {
					secPolicy.Spec.Network.MatchProtocols[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(proto.Message) == 0 {
				if len(secPolicy.Spec.Network.Message) > 0 {
					secPolicy.Spec.Network.MatchProtocols[idx].Message = secPolicy.Spec.Network.Message
				} else {
					secPolicy.Spec.Network.MatchProtocols[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(proto.Action) == 0 {
				if len(secPolicy.Spec.Network.Action) > 0 {
					secPolicy.Spec.Network.MatchProtocols[idx].Action = secPolicy.Spec.Network.Action
				} else {
					secPolicy.Spec.Network.MatchProtocols[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	kg.Printf("Detected a Container Security Policy (%s/%s/%s)", strings.ToLower(event.Type), secPolicy.Metadata["namespaceName"], secPolicy.Metadata["policyName"])

	globalDefaultPosture := tp.DefaultPosture{
		FileAction:         cfg.GlobalCfg.DefaultFilePosture,
		NetworkAction:      cfg.GlobalCfg.DefaultNetworkPosture,
	}
	newPoint.DefaultPosture = globalDefaultPosture

	// check that a security policy should exist before performing delete operation
	policymatch := 0
	for _, policy := range newPoint.SecurityPolicies {
		// check if policy exist
		if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
			policymatch = 1 // policy exists
		}
	}

	// policy doesn't exist and the policy is being removed
	if policymatch == 0 && event.Type == "DELETED" {
		kg.Warnf("Failed to delete security policy. Policy doesn't exist")
		return
	}

	for idx, policy := range newPoint.SecurityPolicies {
		if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
			if event.Type == "DELETED" {
				newPoint.SecurityPolicies = append(newPoint.SecurityPolicies[:idx], newPoint.SecurityPolicies[idx+1:]...)
				break
			} else {
				event.Type = "MODIFIED"
				// Policy already exists so modify
				newPoint.SecurityPolicies[idx] = secPolicy
			}
		}
	}

	if event.Type == "ADDED" {
		newPoint.SecurityPolicies = append(newPoint.SecurityPolicies, secPolicy)
		dm.EndPoint = newPoint
		//if dm.EndPoint.EndPointName == "" {
		//	// Create new EndPoint
		//	newPoint.NamespaceName = secPolicy.Metadata["namespaceName"]
		//	newPoint.EndPointName = containername
		//	newPoint.PolicyEnabled = tp.KubeArmorPolicyEnabled
		//	newPoint.Identities = secPolicy.Spec.Selector.Identities

		//	newPoint.ProcessVisibilityEnabled = true
		//	newPoint.FileVisibilityEnabled = true
		//	newPoint.NetworkVisibilityEnabled = true
		//	newPoint.Containers = []string{}

		//	for idx, ctr := range dm.Containers {
		//		if ctr.ContainerName == containername {
		//			newPoint.Containers = append(newPoint.Containers, ctr.ContainerID)
		//			ctr.NamespaceName = newPoint.NamespaceName
		//			ctr.EndPointName = newPoint.EndPointName
		//			dm.Containers[idx] = ctr
		//		}
		//	}

		//	// add the endpoint into the endpoint list
		//	dm.EndPoints = append(dm.EndPoints, newPoint)
		//} else {
		//	dm.EndPoints[i] = newPoint
		//}

		// update security policies
		dm.Logger.UpdateSecurityPolicy("ADDED", newPoint)

		if dm.RuntimeEnforcer != nil {
			// enforce security policies
			dm.RuntimeEnforcer.UpdateRules(newPoint.SecurityPolicies, dm.DefaultPosture)
		}

	} else if event.Type == "MODIFIED" {
		dm.EndPoint = newPoint

		dm.Logger.UpdateSecurityPolicy("MODIFIED", newPoint)

		if dm.RuntimeEnforcer != nil {
			// enforce security policies
			dm.RuntimeEnforcer.UpdateRules(newPoint.SecurityPolicies, dm.DefaultPosture)
		}

	} else { // DELETED
		// update security policies after policy deletion
		dm.Logger.UpdateSecurityPolicy("DELETED", newPoint)
		dm.EndPoint = newPoint
		if dm.RuntimeEnforcer != nil {
			// enforce security policies
			dm.RuntimeEnforcer.UpdateRules(newPoint.SecurityPolicies, dm.DefaultPosture)
		}
	}

	// backup/remove container policies
	if !dm.K8sEnabled {
		if event.Type == "ADDED" || event.Type == "MODIFIED" {
			// backup SecurityPolicy to file
			dm.backupKubeArmorContainerPolicy(secPolicy)
		} else if event.Type == "DELETED" {
			dm.removeBackUpPolicy(secPolicy.Metadata["policyName"])
		}
	}
}

// Back up KubeArmor container policies in /opt/kubearmor/policies
func (dm *BlueLockDaemon) backupKubeArmorContainerPolicy(policy tp.SecurityPolicy) {
	// Check for "/opt/kubearmor/policies" path. If dir not found, create the same
	policyDir := dm.PolicyDir
	if _, err := os.Stat(policyDir); err != nil {
		if err = os.MkdirAll(policyDir, 0700); err != nil {
			kg.Warnf("Dir creation failed for [%v]", policyDir)
			return
		}
	}

	var file *os.File
	var err error

	if file, err = os.Create(filepath.Join(policyDir, policy.Metadata["policyName"] + ".yaml")); err == nil {
		if policyBytes, err := json.Marshal(policy); err == nil {
			if _, err = file.Write(policyBytes); err == nil {
				if err := file.Close(); err != nil {
					kg.Errf(err.Error())
				}
			}
		}
	}
}

// removeBackUpPolicy Function
func (dm *BlueLockDaemon) removeBackUpPolicy(name string) {

	fname := filepath.Join(dm.PolicyDir, name + ".yaml")
	// Check for "/opt/kubearmor/policies" path. If dir not found, create the same
	if _, err := os.Stat(fname); err != nil {
		kg.Printf("Backup policy [%v] not exist", fname)
		return
	}

	if err := os.Remove(fname); err != nil {
		kg.Errf("unable to delete file:%s err=%s", fname, err.Error())
	}
}

func (dm *BlueLockDaemon) restoreKubeArmorPolicies() {
	if _, err := os.Stat(dm.PolicyDir); err != nil {
		kg.Warn("Policies dir not found for restoration")
		return
	}

	if policyFiles, err := os.ReadDir(dm.PolicyDir); err == nil {
		for _, file := range policyFiles {
			if data, err := os.ReadFile(filepath.Join(dm.PolicyDir + file.Name())); err == nil {

				var k struct {
					Metadata map[string]string `json:"metadata"`
				}

				err := json.Unmarshal(data, &k)
				if err != nil {
					kg.Errf("Failed to unmarshal policy: %v", err)
					continue
				}

				var containerPolicy tp.K8sKubeArmorPolicy
				if err := json.Unmarshal(data, &containerPolicy); err == nil {
					containerPolicy.Metadata.Name = k.Metadata["policyName"]
					dm.ParseAndUpdateContainerSecurityPolicy(tp.K8sKubeArmorPolicyEvent{
						Type:   "ADDED",
						Object: containerPolicy,
					})
				}
			}
		}

		if len(policyFiles) != 0 {
			kg.Warn("No policies found for restoration")
		}
	}
}
