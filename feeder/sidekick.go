package feeder

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

// TODO: improve how it is used globally
type Logger struct {
	URL      string
	Hostname string
}

var SidekickLogger *Logger

func init() {
	var sidekickURL string
	var ok bool

	if sidekickURL, ok = os.LookupEnv("SIDEKICK_URL"); !ok {
		sidekickURL = "http://localhost:2048/"
	}
	var err error
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "none"
	}

	SidekickLogger = &Logger{
		URL:      sidekickURL,
		Hostname: hostname,
	}
}

func PushLogSidekick(kubearmorLog tp.Log) {

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

		"ContainerName": SidekickLogger.Hostname,

		// HACKS: sidekick will only send logs of type string
		//"HostPPID": fmt.Sprintf("%v", kubearmorLog.HostPPID),
		//"HostPID":  fmt.Sprintf("%v", kubearmorLog.HostPID),

		"PPID": fmt.Sprintf("%v", kubearmorLog.PPID),
		"PID":  fmt.Sprintf("%v", kubearmorLog.PID),
		"UID":  fmt.Sprintf("%v", kubearmorLog.UID),

		"ParentProcessName": kubearmorLog.ParentProcessName,
		"ProcessName":       kubearmorLog.ProcessName,
	}

	outputFields["Type"] = "ContainerLog"

	outputFields["Resource"] = strings.ToValidUTF8(kubearmorLog.Resource, "")

	if len(kubearmorLog.Data) > 0 {
		outputFields["Data"] = kubearmorLog.Data
	}

	payload.Output = kubearmorLog.Result
	payload.Rule = "None"

	if kubearmorLog.Action == "Block" {
		payload.Priority = types.Critical
	} else {
		payload.Priority = types.Informational
	}

	payload.OutputFields = outputFields

	// extra to make sidekick work
	payload.Hostname = SidekickLogger.Hostname

	SendPayload(payload)
}

func SendPayload(payload types.FalcoPayload) {
	body, err := json.MarshalIndent(payload, "", "\t")
	if err != nil {
		log.Println("ERROR: parsing JSON body:", err)
	}

	resp, err := http.Post(SidekickLogger.URL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Println("ERROR: pushing log:", err.Error())
		return
	}
	if resp.StatusCode != 200 {
		log.Println("ERROR: sidekick responded with:", resp.StatusCode)
	}
}
