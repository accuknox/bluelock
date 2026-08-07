// SPDX-License-Identifier: MIT
// Copyright 2026 Authors of Bluelock

package core

import (
	"fmt"
	"os"
	"time"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// GetACAMetadata fetches the Hostname and Replica info and maps it to KubeArmor types
func GetACAMetadata(containerID string) (tp.Node, map[string]tp.Container, error) {

	// container app env - boundary for container apps which defines hardware (CPU, memory etc.) and networking resources.
	// container app revision - a specific version of the container app that is deployed and running in the container app env.
	// container app - like a replicaset defined by a container app revision that is running in the container app env.
	// container app replica - a specific instance (pod) of the container app revision that is running in the container app env.

	// we treat a replica as a node here, so node name will be replica name which is running the containers.

	containerAppReplicaName := os.Getenv("CONTAINER_APP_REPLICA_NAME")
	if containerAppReplicaName == "" {
		return tp.Node{}, nil, fmt.Errorf("CONTAINER_APP_REPLICA_NAME is not set; not running in Azure Container Apps")
	}

	// Map Replica Name to "Node"
	mockNode := tp.Node{
		NodeName: containerAppReplicaName, // Unique identifier for this specific replica
		NodeIP:   "",                      // Filled below if a network exists
		// Annotations and Labels can be left empty or populated with Cluster info
	}

	// Map ACA Container to KubeArmor Container
	kaContainers := make(map[string]tp.Container)

	containerName := os.Getenv("CONTAINERNAME")
	containerImage := os.Getenv("CONTAINERIMAGE")
	containerAppName := os.Getenv("CONTAINER_APP_NAME")

	kaContainer := tp.Container{
		ContainerID:    containerID, // we don't have a DockerId in ACA, so we use the containerID fetched from cgroup
		ContainerName:  containerName,
		ContainerImage: containerImage,
		Labels:         "",

		// Map Cluster to Namespace so policies can target the whole ECS cluster
		NamespaceName: "container_namespace",
		EndPointName:  containerAppName,

		Status:        "RUNNING",
		ContainerIP:   "",
		LastUpdatedAt: time.Now().UTC().Format(time.RFC3339),

		Privileged:      false,
		AppArmorProfile: "unconfined",
		PolicyEnabled:   1,
	}

	// Insert into the map using DockerId as the key
	kaContainers[containerID] = kaContainer

	kg.Printf("Successfully mapped %d Azure Container App containers in Container App Replica %s", len(kaContainers), containerAppReplicaName)

	return mockNode, kaContainers, nil
}
