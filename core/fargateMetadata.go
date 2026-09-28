// SPDX-License-Identifier: MIT
// Copyright 2026 Authors of Bluelock

package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ECSTaskMetadata represents the V4 Metadata payload from AWS
type ECSTaskMetadata struct {
	Cluster    string `json:"Cluster"`
	TaskARN    string `json:"TaskARN"`
	Family     string `json:"Family"`
	Revision   string `json:"Revision"`
	Containers []struct {
		DockerId    string            `json:"DockerId"`
		Name        string            `json:"Name"`
		Image       string            `json:"Image"`
		Labels      map[string]string `json:"Labels"`
		KnownStatus string            `json:"KnownStatus"`
		Networks    []struct {
			IPv4Addresses []string `json:"IPv4Addresses"`
		} `json:"Networks"`
	} `json:"Containers"`
}

// GetFargateMetadata fetches the Task and Container info and maps it to KubeArmor types
func GetFargateMetadata() (tp.Node, map[string]tp.Container, error) {
	metadataURI := os.Getenv("ECS_CONTAINER_METADATA_URI_V4")
	if metadataURI == "" {
		return tp.Node{}, nil, fmt.Errorf("ECS_CONTAINER_METADATA_URI_V4 is not set; not running in Fargate")
	}

	// Hit the /task endpoint to get metadata for the "Node" and ALL containers
	taskEndpoint := fmt.Sprintf("%s/task", metadataURI)
	resp, err := http.Get(taskEndpoint)
	if err != nil {
		return tp.Node{}, nil, fmt.Errorf("failed to fetch ECS Task Metadata: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tp.Node{}, nil, fmt.Errorf("failed to read metadata response: %v", err)
	}

	var metadata ECSTaskMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return tp.Node{}, nil, fmt.Errorf("failed to parse ECS Metadata JSON: %v", err)
	}

	// 1. Extract clean Cluster Name (AWS returns the full ARN)
	clusterParts := strings.Split(metadata.Cluster, "/")
	clusterName := clusterParts[len(clusterParts)-1]

	// 2. Map Fargate Task to a KubeArmor "Node"
	// Fargate has no physical nodes, so we treat the Task as the Node
	mockNode := tp.Node{
		NodeName: metadata.TaskARN, // Unique identifier for this specific task
		NodeIP:   "",               // Filled below if a network exists
		// Annotations and Labels can be left empty or populated with Cluster info
	}

	// 3. Map ECS Containers to KubeArmor Containers
	kaContainers := make(map[string]tp.Container)

	for _, c := range metadata.Containers {

		// Flatten Fargate labels into a comma-separated string
		var labelPairs []string
		for k, v := range c.Labels {
			labelPairs = append(labelPairs, fmt.Sprintf("%s=%s", k, v))
		}
		labelString := strings.Join(labelPairs, ",")

		// Get the Container IP if available
		containerIP := ""
		if len(c.Networks) > 0 && len(c.Networks[0].IPv4Addresses) > 0 {
			containerIP = c.Networks[0].IPv4Addresses[0]
			// Assume the Task IP is the IP of the first container
			if mockNode.NodeIP == "" {
				mockNode.NodeIP = containerIP
			}
		}

		kaContainer := tp.Container{
			ContainerID:    c.DockerId,
			ContainerName:  c.Name,
			ContainerImage: c.Image,
			Labels:         labelString,

			// Map Cluster to Namespace so policies can target the whole ECS cluster
			NamespaceName: "container_namespace",
			EndPointName:  metadata.Family,

			Status:        c.KnownStatus,
			ContainerIP:   containerIP,
			LastUpdatedAt: time.Now().UTC().Format(time.RFC3339),

			Privileged:      false,
			AppArmorProfile: "unconfined",
			PolicyEnabled:   1,
		}

		// Insert into the map using DockerId as the key
		kaContainers[c.DockerId] = kaContainer
	}

	kg.Printf("Successfully mapped %d Fargate containers in Cluster %s", len(kaContainers), clusterName)

	return mockNode, kaContainers, nil
}
