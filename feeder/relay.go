package feeder

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

func PushLogRelay(kubearmorLog tp.Log) {

	var payload []byte
	var err error

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
	}

	req, err := http.NewRequest("POST", SidekickLogger.URL, bytes.NewBuffer(payload))
	if err != nil {
		panic(err)
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
		panic(err)
	}
	defer resp.Body.Close()

}
