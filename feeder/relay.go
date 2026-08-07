// SPDX-License-Identifier: MIT
// Copyright 2026 Authors of Bluelock

package feeder

import (
	"encoding/json"
	"fmt"
	"strings"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

func (fd *Feeder) PushLogRelay(kubearmorLog tp.Log) {
	kubearmorLog = fd.UpdateMatchedPolicy(kubearmorLog)
	if kubearmorLog.Source == "" {
		return
	}

	//http
	//var payload []byte
	//var err error

	kubearmorLog.HostName = fd.HostName

	kubearmorLog.PolicyEnabled = 0
	kubearmorLog.ProcessVisibilityEnabled = false
	kubearmorLog.FileVisibilityEnabled = false
	kubearmorLog.NetworkVisibilityEnabled = false

	if fd.Output == "stdout" {
		arr, _ := json.Marshal(kubearmorLog)
		fmt.Println(string(arr))
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

		fd.EventStructs.AlertLock.Lock()
		defer fd.EventStructs.AlertLock.Unlock()

		for uid := range fd.EventStructs.AlertStructs {
			select {
			case fd.EventStructs.AlertStructs[uid].Broadcast <- &pbAlert:
			default:
			}
		}

		/* http
		payload, err = json.MarshalIndent(pbAlert, "", "\t")
		if err != nil {
			log.Println("ERROR: parsing JSON body:", err)
		}
		*/
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

		fd.EventStructs.LogLock.Lock()
		defer fd.EventStructs.LogLock.Unlock()

		for uid := range fd.EventStructs.LogStructs {
			select {
			case fd.EventStructs.LogStructs[uid].Broadcast <- &pbLog:
			default:
			}
		}
	}
}
