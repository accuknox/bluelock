package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	types "github.com/falcosecurity/falcosidekick/types"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

var SidekickURL, Hostname string

func init () {
	var ok bool
	if SidekickURL, ok = os.LookupEnv("SIDEKICK_URL"); !ok {
		SidekickURL = "http://localhost:2801/"
	}
	var err error
	Hostname, err = os.Hostname()
	if err != nil {
		Hostname = "none"
	}
}

func PushLogSidekick(kubearmorLog tp.Log) {
	if kubearmorLog.Source == "" {
		return
	}

	// remove MergedDir
	kubearmorLog.MergedDir = ""

	// remove flags
	kubearmorLog.PolicyEnabled = 0
	kubearmorLog.ProcessVisibilityEnabled = false
	kubearmorLog.FileVisibilityEnabled = false
	kubearmorLog.NetworkVisibilityEnabled = false
	kubearmorLog.CapabilitiesVisibilityEnabled = false

	payload := types.FalcoPayload{}

	//payload.Hostname = Hostname

	timestamp, err := time.Parse(time.RFC3339, kubearmorLog.UpdatedTime)
	if err != nil {
		timestamp = time.Now().UTC()
	}
	payload.Time = timestamp

	// syscall, file, network
	payload.Source = kubearmorLog.Operation

	outputFields := map[string]interface{}{
		// Data not available in fargate
		//"ClusterName": kubearmorLog.ClusterName,
		//"NamespaceName": kubearmorLog.NamespaceName,
		//"PodName": kubearmorLog.PodName,
		//"Labels": kubearmorLog.Labels,

		//"ContainerImage": kubearmorLog.ContainerImage,

		"ContainerID": kubearmorLog.ContainerID,

		"ContainerName": Hostname,

		// HACKS: sidekick will only send logs of type string
		"HostPPID": fmt.Sprintf("%v", kubearmorLog.HostPPID),
		"HostPID": fmt.Sprintf("%v", kubearmorLog.HostPID),

		"PPID": fmt.Sprintf("%v", kubearmorLog.PPID),
		"PID": fmt.Sprintf("%v", kubearmorLog.PID),
		"UID": fmt.Sprintf("%v", kubearmorLog.UID),

		"ParentProcessName": kubearmorLog.ParentProcessName,
		"ProcessName": kubearmorLog.ProcessName,
	}

	outputFields["Type"] = "ContainerLog"

	outputFields["Resource"] = strings.ToValidUTF8(kubearmorLog.Resource, "")

	if len(kubearmorLog.Data) > 0 {
		outputFields["Data"] = kubearmorLog.Data
	}

	payload.Output = kubearmorLog.Result
	payload.Rule = "None"
	payload.Priority = types.Informational
	payload.OutputFields = outputFields

	// extra to make sidekick work
	payload.Hostname = Hostname

	SendPayload(payload)
}

func SendPayload(payload types.FalcoPayload) {
	body, err := json.MarshalIndent(payload, "", "\t")
	if err != nil {
		log.Println("ERROR: parsing JSON body:", err)
	}

	resp, err := http.Post(SidekickURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Println("ERROR: pushing log:", err.Error())
		return
	}
	if resp.StatusCode != 200 {
		log.Println("ERROR: sidekick responded with:", resp.StatusCode)
	}
}
