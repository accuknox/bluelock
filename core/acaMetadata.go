// SPDX-License-Identifier: MIT
// Copyright 2026 Authors of Bluelock

package core

import (
	"fmt"
	"os"
	"strings"
	"time"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// GetACAMetadata fetches the Hostname and Replica info and maps it to KubeArmor types
func GetACAMetadata(containerID string) (tp.Node, map[string]tp.Container, error) {
	envDNSSuffix := os.Getenv("CONTAINER_APP_ENV_DNS_SUFFIX")
	if envDNSSuffix == "" {
		return tp.Node{}, nil, fmt.Errorf("CONTAINER_APP_ENV_DNS_SUFFIX is not set; not running in Azure Container Apps")
	}

	// Extract default hostname
	suffixParts := strings.Split(envDNSSuffix, ".")
	hostname := suffixParts[0]

	// Map Default Hostname to "Node"
	// Azure Container Apps has managed nodes and containers run inside pods, so we treat the Hostname as the Node
	mockNode := tp.Node{
		NodeName: hostname, // Unique identifier for this specific task
		NodeIP:   "",       // Filled below if a network exists
		// Annotations and Labels can be left empty or populated with Cluster info
	}

	// Map ACA Container to KubeArmor Container
	kaContainers := make(map[string]tp.Container)

	containerName := os.Getenv("CONTAINERNAME")
	containerImage := os.Getenv("CONTAINERIMAGE")
	containerAppName := os.Getenv("CONTAINER_APP_NAME")
	containerAppReplicaName := os.Getenv("CONTAINER_APP_REPLICA_NAME")

	kaContainer := tp.Container{
		ContainerID:    containerID, // we don't have a DockerId in ACA, so we use the containerID fetched from cgroup
		ContainerName:  containerName,
		ContainerImage: containerImage,
		Labels:         "",

		// Map Cluster to Namespace so policies can target the whole ECS cluster
		NamespaceName: "container_namespace",
		EndPointName:  containerAppReplicaName,

		Status:        "RUNNING",
		ContainerIP:   "",
		LastUpdatedAt: time.Now().UTC().Format(time.RFC3339),

		Privileged:      false,
		AppArmorProfile: "unconfined",
		PolicyEnabled:   1,
	}

	// Insert into the map using DockerId as the key
	kaContainers[containerID] = kaContainer

	kg.Printf("Successfully mapped %d Azure Container App containers in Container App %s", len(kaContainers), containerAppName)

	return mockNode, kaContainers, nil
}
