// SPDX-License-Identifier: MIT
// Copyright 2026 Authors of Bluelock

package common

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Time Format
const (
	TimeFormUTC string = "2006-01-02T15:04:05.000000Z"
)

// GetDateTimeNow Function
func GetDateTimeNow() (int64, string) {
	utc := time.Now().UTC()
	ret := utc.Format(TimeFormUTC)
	return utc.Unix(), ret
}

func IsK8sLocal() bool {
	k8sConfig := os.Getenv("KUBECONFIG")
	if k8sConfig != "" {
		if _, err := os.Stat(filepath.Clean(k8sConfig)); err == nil {
			return true
		}
	}

	home := os.Getenv("HOME")
	if _, err := os.Stat(filepath.Clean(home + "/.kube/config")); err == nil {
		return true
	}

	return false
}

// IsInK8sCluster Function
func IsInK8sCluster() bool {
	if _, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); ok {
		return true
	}

	if _, err := os.Stat(filepath.Clean("/run/secrets/kubernetes.io")); err == nil {
		return true
	}

	return false
}

// IsK8sEnv Function
func IsK8sEnv() bool {
	// local
	if IsK8sLocal() {
		return true
	}

	// in-cluster
	if IsInK8sCluster() {
		return true
	}

	return false
}

// Clone Function
func Clone(src, dst interface{}) error {
	arr, _ := json.Marshal(src)
	return json.Unmarshal(arr, dst)
}

// ObjCommaExpand Function
func ObjCommaExpand(v reflect.Value) []string {
	return strings.Split(v.Field(0).Interface().(string), ",")
}

// ObjCommaExpandFirstDupOthers Function
func ObjCommaExpandFirstDupOthers(objptr interface{}) {
	if ObjCommaCanBeExpanded(objptr) {
		old := reflect.ValueOf(objptr).Elem()
		new := reflect.New(reflect.TypeOf(objptr).Elem()).Elem()

		for i := 0; i < old.Len(); i++ {
			for _, f := range ObjCommaExpand(old.Index(i)) {
				field := strings.ReplaceAll(f, " ", "")
				new.Set(reflect.Append(new, old.Index(i)))
				new.Index(new.Len() - 1).Field(0).SetString(field)
			}
		}

		reflect.ValueOf(objptr).Elem().Set(new)
	}
}

// ObjCommaCanBeExpanded Function
func ObjCommaCanBeExpanded(objptr interface{}) bool {
	ovptr := reflect.ValueOf(objptr)
	if ovptr.Kind() != reflect.Ptr {
		return false
	}

	ov := ovptr.Elem()
	if ov.Kind() != reflect.Slice {
		return false
	}

	if ov.Len() == 0 {
		return false
	}

	ovelm := ov.Index(0)
	if ovelm.Kind() != reflect.Struct {
		return false
	}

	field0 := ovelm.Field(0)
	if field0.Kind() != reflect.String {
		return false
	}

	value := field0.Interface().(string)
	return strings.Split(value, ",")[0] != value
}

// MatchIdentities Function
func MatchIdentities(identities []string, superIdentities []string) bool {
	matched := true

	// if nothing in identities, skip it
	if len(identities) == 0 {
		return false
	}

	// if super identities not include identity, return false
	for _, identity := range identities {
		if !ContainsElement(superIdentities, identity) {
			matched = false
			break
		}
	}

	// otherwise, return true
	return matched
}

// ContainsElement Function
func ContainsElement(slice interface{}, element interface{}) bool {
	switch reflect.TypeOf(slice).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(slice)

		for i := 0; i < s.Len(); i++ {
			val := s.Index(i).Interface()
			if reflect.DeepEqual(val, element) {
				return true
			}
		}
	}
	return false
}

func GetURL(address string) (string, error) {
	var host string
	addr, err := url.Parse(address)
	if err != nil || addr.Host == "" {
		u, repErr := url.ParseRequestURI("http://" + address)
		if repErr != nil {
			return "", fmt.Errorf("Error while parsing URL: %s", err)
		}

		host = u.Host
		if u.Port() == "" {
			return fmt.Sprintf("%s:80", host), nil
		}
	} else {
		host = addr.Host
		if addr.Port() == "" {
			return fmt.Sprintf("%s:80", host), nil
		}
	}

	return host, nil
}

// handle gRPC errors
func HandleGRPCErrors(err error) error {
	if err == nil {
		return nil
	}

	if status, ok := status.FromError(err); ok {
		switch status.Code() {
		case codes.OK:
			// noop
			return nil
		//case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
		//	return status.Err()
		default:
			return status.Err()
		}
	}

	return nil
}

// GetCommandOutputWithErr Function
func GetCommandOutputWithErr(cmd string, args []string) (string, error) {
	// #nosec
	res := exec.Command(cmd, args...)
	stdin, err := res.StdinPipe()
	if err != nil {
		return "", err
	}

	go func() {
		defer func() {
			if err = stdin.Close(); err != nil {
				kg.Warnf("Error closing stdin %s\n", err)
			}
		}()
		_, err = io.WriteString(stdin, "values written to stdin are passed to cmd's standard input")
	}()

	out, err := res.CombinedOutput()
	if err != nil {
		return string(out), err
	}

	return string(out), nil
}

// GetSHA256ofImage of the image
func GetSHA256ofImage(s string) string {
	if idx := strings.Index(s, "@"); idx != -1 {
		return s[idx:]
	}
	return s
}

// GetCommandOutputWithoutErr Function
func GetCommandOutputWithoutErr(cmd string, args []string) string {
	// #nosec
	res := exec.Command(cmd, args...)
	stdin, err := res.StdinPipe()
	if err != nil {
		return ""
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer func() {
			if err = stdin.Close(); err != nil {
				kg.Warnf("Error closing stdin %s\n", err)
			}
		}()
		_, _ = io.WriteString(stdin, "values written to stdin are passed to cmd's standard input")
	}()

	// Wait for the stdin writing to complete
	wg.Wait()

	out, err := res.CombinedOutput()
	if err != nil {
		return ""
	}

	return string(out)
}

// RunCommandAndWaitWithErr Function
func RunCommandAndWaitWithErr(cmd string, args []string) error {
	// #nosec
	res := exec.Command(cmd, args...)
	if err := res.Start(); err != nil {
		return err
	}
	if err := res.Wait(); err != nil {
		return err
	}
	return nil
}

// GetExternalInterface Function
func GetExternalInterface() string {
	route := GetCommandOutputWithoutErr("ip", []string{"route"})
	routeData := strings.Split(strings.Split(route, "\n")[0], " ")
	for idx, word := range routeData {
		if word == "dev" {
			return routeData[idx+1]
		}
	}
	return ""
}

// GetIPAddr Function
func GetIPAddr(ifname string) string {
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			if iface.Name == ifname {
				if addrs, err := iface.Addrs(); err == nil {
					ipaddr := strings.Split(addrs[0].String(), "/")[0]
					return ipaddr
				}
				return ""
			}
		}
	}
	return ""
}

// GetExternalIPAddr Function
func GetExternalIPAddr() string {
	iface := GetExternalInterface()
	return GetIPAddr(iface)
}
