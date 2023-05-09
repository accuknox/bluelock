package feeder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

func (fd *Feeder) PushLogRelay(kubearmorLog tp.Log) {
	kubearmorLog = fd.UpdateMatchedPolicy(kubearmorLog)
	//if kubearmorLog.Source == "" {
	//	return
	//}

	var payload []byte
	var err error

	kubearmorLog.HostName = fd.HostName

	kubearmorLog.PolicyEnabled = 0
	kubearmorLog.ProcessVisibilityEnabled = false
	kubearmorLog.FileVisibilityEnabled = false
	kubearmorLog.NetworkVisibilityEnabled = false
	kubearmorLog.CapabilitiesVisibilityEnabled = false

	if fd.Output == "stdout" {
		arr, _ := json.Marshal(kubearmorLog)
		fmt.Println(string(arr))
	} else if fd.Output != "none" {
		//arr, _ := json.Marshal(kubearmorLog)
		//fd.StrToFile(string(arr))
	}

	if kubearmorLog.Type == "MatchedPolicy" {
		pbAlert := pb.Alert{}

		pbAlert.Timestamp = kubearmorLog.Timestamp
		pbAlert.UpdatedTime = kubearmorLog.UpdatedTime

		pbAlert.HostName = kubearmorLog.HostName

		pbAlert.NamespaceName = kubearmorLog.NamespaceName

		pbAlert.PodName = kubearmorLog.PodName
		pbAlert.Labels = kubearmorLog.Labels

		pbAlert.ContainerID = kubearmorLog.ContainerID
		pbAlert.ContainerName = kubearmorLog.ContainerName
		pbAlert.ContainerImage = kubearmorLog.ContainerImage

		pbAlert.HostPPID = kubearmorLog.HostPPID
		pbAlert.HostPID = kubearmorLog.HostPID

		pbAlert.PPID = kubearmorLog.PPID
		pbAlert.PID = kubearmorLog.PID
		pbAlert.UID = kubearmorLog.UID

		pbAlert.ParentProcessName = kubearmorLog.ParentProcessName
		pbAlert.ProcessName = kubearmorLog.ProcessName

		if len(kubearmorLog.Enforcer) > 0 {
			pbAlert.Enforcer = kubearmorLog.Enforcer
		}

		if len(kubearmorLog.PolicyName) > 0 {
			pbAlert.PolicyName = kubearmorLog.PolicyName
		}

		if len(kubearmorLog.Severity) > 0 {
			pbAlert.Severity = kubearmorLog.Severity
		}

		if len(kubearmorLog.Tags) > 0 {
			pbAlert.Tags = kubearmorLog.Tags
			pbAlert.ATags = strings.Split(kubearmorLog.Tags, ",")
		}

		if len(kubearmorLog.Message) > 0 {
			pbAlert.Message = kubearmorLog.Message
		}

		pbAlert.Type = kubearmorLog.Type
		pbAlert.Source = kubearmorLog.Source
		pbAlert.Operation = kubearmorLog.Operation
		pbAlert.Resource = strings.ToValidUTF8(kubearmorLog.Resource, "")

		if len(kubearmorLog.Data) > 0 {
			pbAlert.Data = kubearmorLog.Data
		}

		if len(kubearmorLog.Action) > 0 {
			pbAlert.Action = kubearmorLog.Action
		}

		pbAlert.Result = kubearmorLog.Result
		payload, err = json.MarshalIndent(pbAlert, "", "\t")
		if err != nil {
			log.Println("ERROR: parsing JSON body:", err)
		}
	} else {
		pbLog := pb.Log{}

		pbLog.Timestamp = kubearmorLog.Timestamp
		pbLog.UpdatedTime = kubearmorLog.UpdatedTime

		pbLog.HostName = kubearmorLog.HostName

		pbLog.NamespaceName = kubearmorLog.NamespaceName

		pbLog.PodName = kubearmorLog.PodName
		pbLog.Labels = kubearmorLog.Labels

		pbLog.ContainerID = kubearmorLog.ContainerID
		pbLog.ContainerName = kubearmorLog.ContainerName
		pbLog.ContainerImage = kubearmorLog.ContainerImage

		pbLog.HostPPID = kubearmorLog.HostPPID
		pbLog.HostPID = kubearmorLog.HostPID

		pbLog.PPID = kubearmorLog.PPID
		pbLog.PID = kubearmorLog.PID
		pbLog.UID = kubearmorLog.UID

		pbLog.ParentProcessName = kubearmorLog.ParentProcessName
		pbLog.ProcessName = kubearmorLog.ProcessName

		pbLog.Type = kubearmorLog.Type
		pbLog.Source = kubearmorLog.Source
		pbLog.Operation = kubearmorLog.Operation
		pbLog.Resource = strings.ToValidUTF8(kubearmorLog.Resource, "")

		if len(kubearmorLog.Data) > 0 {
			pbLog.Data = kubearmorLog.Data
		}

		pbLog.Result = kubearmorLog.Result
		payload, err = json.MarshalIndent(pbLog, "", "\t")
		if err != nil {
			log.Println("ERROR: parsing JSON body:", err)
		}
	}

	/*
	if kubearmorLog.Action == "Block" {
		pbAlert := pb.Alert{}
		pbAlert.ContainerID = kubearmorLog.ContainerID
		pbAlert.ContainerName = SidekickLogger.Hostname

		pbAlert.PPID = kubearmorLog.PPID
		pbAlert.PID = kubearmorLog.PID
		pbAlert.UID = kubearmorLog.UID

		pbAlert.ParentProcessName = kubearmorLog.ParentProcessName
		pbAlert.ProcessName = kubearmorLog.ProcessName

		pbAlert.Source = kubearmorLog.Source
		pbAlert.Operation = kubearmorLog.Operation
		pbAlert.Resource = strings.ToValidUTF8(kubearmorLog.Resource, "")
		pbAlert.Action = "Block"
		pbAlert.Result = kubearmorLog.Result
		if len(kubearmorLog.Data) > 0 {
			pbAlert.Data = kubearmorLog.Data
		}
		payload, err = json.MarshalIndent(pbAlert, "", "\t")
		if err != nil {
			log.Println("ERROR: parsing JSON body:", err)
		}
	} else {
		pbLog := pb.Log{}
		pbLog.ContainerID = kubearmorLog.ContainerID
		pbLog.ContainerName = SidekickLogger.Hostname

		pbLog.PPID = kubearmorLog.PPID
		pbLog.PID = kubearmorLog.PID
		pbLog.UID = kubearmorLog.UID

		pbLog.ParentProcessName = kubearmorLog.ParentProcessName
		pbLog.ProcessName = kubearmorLog.ProcessName

		pbLog.Source = kubearmorLog.Source
		pbLog.Operation = kubearmorLog.Operation
		pbLog.Resource = strings.ToValidUTF8(kubearmorLog.Resource, "")
		pbLog.Result = kubearmorLog.Result
		if len(kubearmorLog.Data) > 0 {
			pbLog.Data = kubearmorLog.Data
		}
		payload, err = json.MarshalIndent(pbLog, "", "\t")
		if err != nil {
			log.Println("ERROR: parsing JSON body:", err)
		}
	}*/

	fmt.Println(string(payload))
	req, err := http.NewRequest("POST", SidekickLogger.URL, bytes.NewBuffer(payload))
	if err != nil {
		log.Println("ERROR: pushing log:", err.Error())
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if kubearmorLog.Action == "Block" {
		req.Header.Set("Telemetry", "Alert")
	} else {
		req.Header.Set("Telemetry", "Log")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("ERROR: pushing log:", err.Error())
		return
	}
	if resp.StatusCode != 200 {
		log.Println("ERROR: sidekick responded with:", resp.StatusCode)
	}

	defer resp.Body.Close()
}
