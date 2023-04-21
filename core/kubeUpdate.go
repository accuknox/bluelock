package core

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	ksp "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	kspinformer "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/informers/externalversions"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
)

const PodNotFoundErr = "Matching pod not found"

// Use downwards API
func (dm *BlueLockDaemon) CreateNewPod() {
	backoff := wait.Backoff{
		Steps: 4,
		Duration: 1 * time.Second,
		Factor: 5.0,
		Jitter: 0.1,
	}

	// get pod info
	err := retry.OnError(backoff, func(err error) bool {
		if strings.Contains(err.Error(), PodNotFoundErr){
			kg.Printf("Re-trying to get pod info: %s", err.Error())
			return true
		}
		return false
	}, dm.getPod)

	if err != nil {
		kg.Errf("Failed to get pod data: %s", err.Error())
		return
	}

	dm.CreateEndpointWithPod()

	return
}

func (dm *BlueLockDaemon) getPod() error {
	k8sPod := tp.K8sPod{}

	podList, err := K8s.K8sClient.CoreV1().Pods(corev1.NamespaceAll).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, p := range podList.Items {
		for _, container := range p.Status.ContainerStatuses {
			if len(container.ContainerID) > 0 {
				id := strings.SplitAfter(container.ContainerID, "://")[1]

				if id == dm.Container.ContainerID {

					k8sPod.Metadata = map[string]string{}
					k8sPod.Metadata["namespaceName"] = p.Namespace
					k8sPod.Metadata["podName"] = p.Name

					k8sPod.Annotations = map[string]string{}
					for k, v := range p.Annotations {
						k8sPod.Annotations[k] = v
					}

					k8sPod.Labels = map[string]string{}
					for k, v := range p.Labels {
						if k == "pod-template-hash" {
							continue
						}

						if k == "pod-template-generation" {
							continue
						}

						if k == "controller-revision-hash" {
							continue
						}
						k8sPod.Labels[k] = v
					}

					k8sPod.Containers = map[string]string{}
					k8sPod.ContainerImages = map[string]string{}

					k8sPod.Containers[container.ContainerID] = container.Name
					k8sPod.ContainerImages[container.ContainerID] = container.Image + kl.GetSHA256ofImage(container.ImageID)

					dm.K8sPod = k8sPod

					return nil
				}
			}
		}
	}

	return fmt.Errorf(PodNotFoundErr)
}

//func (dm *BlueLockDaemon) GetPodInfoWithRetry() (tp.K8sPod, error) {
//	pod := corev1.Pod{}
//	k8sPod := tp.K8sPod{}
//	retry := true
//	attempt := 1
//
//	for retry {
//		podList, err := K8s.K8sClient.CoreV1().Pods(corev1.NamespaceAll).List(context.Background(), metav1.ListOptions{})
//		if err != nil {
//			kg.Errf("Failed to get pod data: ", err.Error())
//			return tp.K8sPod{}, nil
//		}
//
//		for _, p := range podList.Items {
//			for _, container := range p.Status.ContainerStatuses {
//				if len(container.ContainerID) > 0 {
//					id := strings.SplitAfter(container.ContainerID, "://")[1]
//
//					// if pod and container ID matched
//					if id == dm.Container.ContainerID {
//						retry = false
//						pod = p
//						k8sPod.Containers[container.ContainerID] = container.Name
//						k8sPod.ContainerImages[container.ContainerID] = container.Image + kl.GetSHA256ofImage(container.ImageID)
//
//		k8sPod.Metadata = map[string]string{}
//		k8sPod.Metadata["namespaceName"] = pod.Namespace
//		k8sPod.Metadata["podName"] = pod.Name
//
//		k8sPod.Annotations = map[string]string{}
//		for k, v := range pod.Annotations {
//			k8sPod.Annotations[k] = v
//		}
//
//		k8sPod.Labels = map[string]string{}
//		for k, v := range pod.Labels {
//			if k == "pod-template-hash" {
//				continue
//			}
//
//			if k == "pod-template-generation" {
//				continue
//			}
//
//			if k == "controller-revision-hash" {
//				continue
//			}
//			k8sPod.Labels[k] = v
//		}
//		k8sPod.Containers = map[string]string{}
//		k8sPod.ContainerImages = map[string]string{}
//	}
//
//	return k8sPod, nil
//}

func (dm *BlueLockDaemon) CreateEndpointWithPod() {
	pod := dm.K8sPod
	newPoint := tp.EndPoint{}

	newPoint.NamespaceName = pod.Metadata["namespaceName"]
	newPoint.EndPointName = pod.Metadata["podName"]

	newPoint.Labels = map[string]string{}
	newPoint.Identities = []string{"namespaceName=" + pod.Metadata["namespaceName"]}

	// update labels and identities
	for k, v := range pod.Labels {
		newPoint.Labels[k] = v
		newPoint.Identities = append(newPoint.Identities, k+"="+v)
	}

	sort.Slice(newPoint.Identities, func(i, j int) bool {
		return newPoint.Identities[i] < newPoint.Identities[j]
	})

	// update policy flag
	if pod.Annotations["kubearmor-policy"] == "enabled" {
		newPoint.PolicyEnabled = tp.KubeArmorPolicyEnabled
	} else if pod.Annotations["kubearmor-policy"] == "audited" {
		newPoint.PolicyEnabled = tp.KubeArmorPolicyAudited
	} else { // disabled
		newPoint.PolicyEnabled = tp.KubeArmorPolicyDisabled
	}

	// parse annotations and update visibility flags
	for _, visibility := range strings.Split(pod.Annotations["kubearmor-visibility"], ",") {
		if visibility == "process" {
			newPoint.ProcessVisibilityEnabled = true
		} else if visibility == "file" {
			newPoint.FileVisibilityEnabled = true
		} else if visibility == "network" {
			newPoint.NetworkVisibilityEnabled = true
		} else if visibility == "capabilities" {
			newPoint.CapabilitiesVisibilityEnabled = true
		}
	}

	newPoint.Containers = []string{}

	// update containers
	for k := range pod.Containers {
		newPoint.Containers = append(newPoint.Containers, k)
	}

	// update containers
	for _, containerID := range newPoint.Containers {
		container := dm.Container

		container.NamespaceName = newPoint.NamespaceName
		container.EndPointName = newPoint.EndPointName

		labels := []string{}
		for k, v := range newPoint.Labels {
			labels = append(labels, k+"="+v)
		}
		container.Labels = strings.Join(labels, ",")

		container.ContainerName = pod.Containers[containerID]
		container.ContainerImage = pod.ContainerImages[containerID]

		container.PolicyEnabled = newPoint.PolicyEnabled

		container.ProcessVisibilityEnabled = newPoint.ProcessVisibilityEnabled
		container.FileVisibilityEnabled = newPoint.FileVisibilityEnabled
		container.NetworkVisibilityEnabled = newPoint.NetworkVisibilityEnabled
		container.CapabilitiesVisibilityEnabled = newPoint.CapabilitiesVisibilityEnabled

		dm.Container = container
	}

	//dm.DefaultPosturesLock.Lock()
	//if val, ok := dm.DefaultPostures[newPoint.NamespaceName]; ok {
	//	newPoint.DefaultPosture = val
	//} else {
	//	globalDefaultPosture := tp.DefaultPosture{
	//		FileAction:         cfg.GlobalCfg.DefaultFilePosture,
	//		NetworkAction:      cfg.GlobalCfg.DefaultNetworkPosture,
	//		CapabilitiesAction: cfg.GlobalCfg.DefaultCapabilitiesPosture,
	//	}
	//	newPoint.DefaultPosture = globalDefaultPosture
	//}
	//dm.DefaultPosturesLock.Unlock()

	// update security policies with the identities
	newPoint.SecurityPolicies = dm.GetSecurityPolicies(newPoint.Identities)

	//dm.Logger.UpdateSecurityPolicies(action, endpoint)
	//if dm.RuntimeEnforcer != nil {
	//	// enforce security policies
	//	dm.RuntimeEnforcer.UpdateRules()
	//}
}

func (dm *BlueLockDaemon) GetSecurityPolicies(identities []string) []tp.SecurityPolicy {
	dm.SecurityPoliciesLock.Lock()
	defer dm.SecurityPoliciesLock.Unlock()

	secPolicies := []tp.SecurityPolicy{}

	for _, policy := range dm.SecurityPolicies {
		if kl.MatchIdentities(policy.Spec.Selector.Identities, identities) {
			secPolicy := tp.SecurityPolicy{}
			if err := kl.Clone(policy, &secPolicy); err != nil {
				kg.Errf("Failed to clone a policy (%s)", err.Error())
			}
			secPolicies = append(secPolicies, secPolicy)
		}
	}

	return secPolicies
}

func (dm *BlueLockDaemon) CreateSecurityPolicy(policy ksp.KubeArmorPolicy) (secPolicy tp.SecurityPolicy, err error) {
	secPolicy.Metadata = map[string]string{}
	secPolicy.Metadata["namespaceName"] = policy.Namespace
	secPolicy.Metadata["policyName"] = policy.Name

	if err := kl.Clone(policy.Spec, &secPolicy.Spec); err != nil {
		//dm.Logger.Errf("Failed to clone a spec (%s)", err.Error())
		return tp.SecurityPolicy{}, err
	}

	kl.ObjCommaExpandFirstDupOthers(&secPolicy.Spec.Network.MatchProtocols)
	kl.ObjCommaExpandFirstDupOthers(&secPolicy.Spec.Capabilities.MatchCapabilities)

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
	secPolicy.Spec.Selector.Identities = []string{"namespaceName=" + policy.Namespace}

	for k, v := range secPolicy.Spec.Selector.MatchLabels {
		if k == "kubearmor.io/container.name" {
			if len(v) > 2 {
				containerArray := v[1 : len(v)-1]
				containers := strings.Split(containerArray, ",")
				for _, container := range containers {
					if len(container) > 0 {
						secPolicy.Spec.Selector.Containers = append(secPolicy.Spec.Selector.Containers, strings.TrimSpace(container))
					}

				}
			}
		} else {
			secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, k+"="+v)
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

	if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
		for idx, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			if cap.Severity == 0 {
				if secPolicy.Spec.Capabilities.Severity != 0 {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Severity = secPolicy.Spec.Capabilities.Severity
				} else {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(cap.Tags) == 0 {
				if len(secPolicy.Spec.Capabilities.Tags) > 0 {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Tags = secPolicy.Spec.Capabilities.Tags
				} else {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(cap.Message) == 0 {
				if len(secPolicy.Spec.Capabilities.Message) > 0 {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Message = secPolicy.Spec.Capabilities.Message
				} else {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(cap.Action) == 0 {
				if len(secPolicy.Spec.Capabilities.Action) > 0 {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Action = secPolicy.Spec.Capabilities.Action
				} else {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.Syscalls.MatchSyscalls) > 0 {
		for idx, syscall := range secPolicy.Spec.Syscalls.MatchSyscalls {
			if syscall.Severity == 0 {
				if secPolicy.Spec.Syscalls.Severity != 0 {
					secPolicy.Spec.Syscalls.MatchSyscalls[idx].Severity = secPolicy.Spec.Syscalls.Severity
				} else {
					secPolicy.Spec.Syscalls.MatchSyscalls[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(syscall.Tags) == 0 {
				if len(secPolicy.Spec.Syscalls.Tags) > 0 {
					secPolicy.Spec.Syscalls.MatchSyscalls[idx].Tags = secPolicy.Spec.Syscalls.Tags
				} else {
					secPolicy.Spec.Syscalls.MatchSyscalls[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(syscall.Message) == 0 {
				if len(secPolicy.Spec.Syscalls.Message) > 0 {
					secPolicy.Spec.Syscalls.MatchSyscalls[idx].Message = secPolicy.Spec.Syscalls.Message
				} else {
					secPolicy.Spec.Syscalls.MatchSyscalls[idx].Message = secPolicy.Spec.Message
				}
			}

		}
	}

	if len(secPolicy.Spec.Syscalls.MatchPaths) > 0 {
		for idx, syscall := range secPolicy.Spec.Syscalls.MatchPaths {
			if syscall.Severity == 0 {
				if secPolicy.Spec.Syscalls.Severity != 0 {
					secPolicy.Spec.Syscalls.MatchPaths[idx].Severity = secPolicy.Spec.Syscalls.Severity
				} else {
					secPolicy.Spec.Syscalls.MatchPaths[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(syscall.Tags) == 0 {
				if len(secPolicy.Spec.Syscalls.Tags) > 0 {
					secPolicy.Spec.Syscalls.MatchPaths[idx].Tags = secPolicy.Spec.Syscalls.Tags
				} else {
					secPolicy.Spec.Syscalls.MatchPaths[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(syscall.Message) == 0 {
				if len(secPolicy.Spec.Syscalls.Message) > 0 {
					secPolicy.Spec.Syscalls.MatchPaths[idx].Message = secPolicy.Spec.Syscalls.Message
				} else {
					secPolicy.Spec.Syscalls.MatchPaths[idx].Message = secPolicy.Spec.Message
				}
			}

		}
	}
	return
}

// UpdateSecurityPolicy Function
func (dm *BlueLockDaemon) UpdateSecurityPolicy(action string, secPolicy tp.SecurityPolicy) {
	//dm.EndPointsLock.Lock()
	//defer dm.EndPointsLock.Unlock()
	endPoint := dm.EndPoint
	if action == "ADDED" {
		// add a new security policy if it doesn't exist
		new := true
		for _, policy := range endPoint.SecurityPolicies {
			if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
				new = false
				break
			}
		}
		if new {
			dm.EndPoint.SecurityPolicies = append(dm.EndPoint.SecurityPolicies, secPolicy)
		}
	} else if action == "MODIFIED" {
		for idxP, policy := range endPoint.SecurityPolicies {
			if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
				dm.EndPoint.SecurityPolicies[idxP] = secPolicy
				break
			}
		}
	} else if action == "DELETED" {
		// remove the given policy from the security policy list of this endpoint
		for idxP, policy := range endPoint.SecurityPolicies {
			if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
				dm.EndPoint.SecurityPolicies = append(dm.EndPoint.SecurityPolicies[:idxP], dm.EndPoint.SecurityPolicies[idxP+1:]...)
				break
			}
		}
	}
	
	dm.RuntimeEnforcer.UpdateRules(dm.EndPoint.SecurityPolicies)


	/* feeder
	if cfg.GlobalCfg.Policy {
		// update security policies
		dm.Logger.UpdateSecurityPolicies("UPDATED", dm.EndPoints[idx])

		if dm.RuntimeEnforcer != nil {
			if dm.EndPoints[idx].PolicyEnabled == tp.KubeArmorPolicyEnabled {
				// enforce security policies
				dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.EndPoints[idx])
			}
		}
	}
	*/

	//for idx, endPoint := range dm.EndPoints {
	//	// update a security policy
	//	if kl.MatchIdentities(secPolicy.Spec.Selector.Identities, endPoint.Identities) && (len(secPolicy.Spec.Selector.Containers) == 0 || kl.ContainsElement(secPolicy.Spec.Selector.Containers, endPoint.ContainerName)) {
	//	}
	//}
}

// watches security policies only for a particular pod
func (dm *BlueLockDaemon) WatchSecurityPolicies() *http.Response {
	for {
		if !K8s.CheckCustomResourceDefinition("kubearmorpolicies") {
			time.Sleep(time.Second * 1)
			continue
		} else {
			break
		}
	}

	// TODO: minimize the no. of updates received here by using informe with options
	// based on resource fields because we want updates only for policies of this pod

	//labelOptions := kspinformer.WithTweakListOptions(func(opts *metav1.ListOptions) {
	//	//opts.LabelSelector = fmt.Sprintf("kubearmor.io/container.name=%s", dm.Container.ContainerID)
	//	 //= "kubearmor.io/container.name=reader-app"
	//})
	//factory := kspinformer.NewSharedInformerFactoryWithOptions(K8s.KSPClient, 0, labelOptions)

	factory := kspinformer.NewSharedInformerFactory(K8s.KSPClient, 0)

	informer := factory.Security().V1().KubeArmorPolicies().Informer()
	if _, err := informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				// create a security policy
				if policy, ok := obj.(*ksp.KubeArmorPolicy); ok {

					secPolicy, err := dm.CreateSecurityPolicy(*policy)
					if err != nil {
						fmt.Printf("Error ADD, %s", err)
						//dm.Logger.Warnf("Error ADD, %s", err)
						return
					}
					if secPolicy.Spec.Selector.MatchLabels["kubearmor.io/container.name"] == dm.Container.ContainerName {
						//dm.SecurityPoliciesLock.Lock()
						new := true
						for _, policy := range dm.SecurityPolicies {
							// only for the pod
							if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
								new = false
								break
							}
						}
						if new {
							dm.SecurityPolicies = append(dm.SecurityPolicies, secPolicy)
						}
						//dm.SecurityPoliciesLock.Unlock()
						//dm.Logger.Printf("Detected a Security Policy (added/%s/%s)", secPolicy.Metadata["namespaceName"], secPolicy.Metadata["policyName"])

						// apply security policies to pods
						dm.UpdateSecurityPolicy("ADDED", secPolicy)
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if policy, ok := newObj.(*ksp.KubeArmorPolicy); ok {
					secPolicy, err := dm.CreateSecurityPolicy(*policy)
					if err != nil {
						return
					}

					//dm.SecurityPoliciesLock.Lock()
					if secPolicy.Spec.Selector.MatchLabels["kubearmor.io/container.name"] == dm.Container.ContainerName {
						for idx, policy := range dm.SecurityPolicies {
							if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
								dm.SecurityPolicies[idx] = secPolicy
								break
							}
						}
						//dm.SecurityPoliciesLock.Unlock()

						//dm.Logger.Printf("Detected a Security Policy (modified/%s/%s)", secPolicy.Metadata["namespaceName"], secPolicy.Metadata["policyName"])

						// apply security policies to pods
						dm.UpdateSecurityPolicy("MODIFIED", secPolicy)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				if policy, ok := obj.(*ksp.KubeArmorPolicy); ok {
					secPolicy, err := dm.CreateSecurityPolicy(*policy)
					if err != nil {
						return
					}
					//dm.SecurityPoliciesLock.Lock()
					if secPolicy.Spec.Selector.MatchLabels["kubearmor.io/container.name"] == dm.Container.ContainerName {
						for idx, policy := range dm.SecurityPolicies {
							if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
								dm.SecurityPolicies = append(dm.SecurityPolicies[:idx], dm.SecurityPolicies[idx+1:]...)
								break
							}
						}
						//dm.SecurityPoliciesLock.Unlock()

						//dm.Logger.Printf("Detected a Security Policy (deleted/%s/%s)", secPolicy.Metadata["namespaceName"], secPolicy.Metadata["policyName"])

						// apply security policies to pods
						dm.UpdateSecurityPolicy("DELETED", secPolicy)
					}
				}
			},
		},
	); err != nil {
		//dm.Logger.Err("Couldn't start watching KubeArmor Security Policies")
		return nil
	}


	go factory.Start(wait.NeverStop)
	factory.WaitForCacheSync(wait.NeverStop)
	return nil
}
