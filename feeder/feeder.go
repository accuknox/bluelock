// SPDX-License-Identifier: MIT
// Copyright 2026 Authors of Bluelock

package feeder

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	cfg "github.com/accuknox/bluelock/config"
	"github.com/google/uuid"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// EventStruct Structure
type EventStruct[T any] struct {
	Filter    string
	Broadcast chan *T
}

type EventStructs struct {
	MsgStructs map[string]EventStruct[pb.Message]
	MsgLock    sync.RWMutex

	AlertStructs map[string]EventStruct[pb.Alert]
	AlertLock    sync.RWMutex

	LogStructs map[string]EventStruct[pb.Log]
	LogLock    sync.RWMutex
}

// AddMsgStruct Function
func (es *EventStructs) AddMsgStruct(filter string, queueSize int) (string, chan *pb.Message) {
	es.MsgLock.Lock()
	defer es.MsgLock.Unlock()

	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.Message, queueSize)

	msgStruct := EventStruct[pb.Message]{
		Filter:    filter,
		Broadcast: conn,
	}

	es.MsgStructs[uid] = msgStruct

	return uid, conn
}

// RemoveMsgStruct Function
func (es *EventStructs) RemoveMsgStruct(uid string) {
	es.MsgLock.Lock()
	defer es.MsgLock.Unlock()

	delete(es.MsgStructs, uid)
}

// AddAlertStruct Function
func (es *EventStructs) AddAlertStruct(filter string, queueSize int) (string, chan *pb.Alert) {
	es.AlertLock.Lock()
	defer es.AlertLock.Unlock()

	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.Alert, queueSize)

	alertStruct := EventStruct[pb.Alert]{
		Filter:    filter,
		Broadcast: conn,
	}

	es.AlertStructs[uid] = alertStruct

	return uid, conn
}

// removeAlertStruct Function
func (es *EventStructs) RemoveAlertStruct(uid string) {
	es.AlertLock.Lock()
	defer es.AlertLock.Unlock()

	delete(es.AlertStructs, uid)
}

// addLogStruct Function
func (es *EventStructs) AddLogStruct(filter string, queueSize int) (string, chan *pb.Log) {
	es.LogLock.Lock()
	defer es.LogLock.Unlock()

	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.Log, queueSize)

	logStruct := EventStruct[pb.Log]{
		Filter:    filter,
		Broadcast: conn,
	}

	es.LogStructs[uid] = logStruct

	return uid, conn
}

// removeLogStruct Function
func (es *EventStructs) RemoveLogStruct(uid string) {
	es.LogLock.Lock()
	defer es.LogLock.Unlock()

	delete(es.LogStructs, uid)
}

var (
	PtraceEnforcer = "Ptrace enforcer"
	PtraceTracer   = "Ptrace tracer"
)

type FeederInterface interface {
	// Methods

	// How does the feeder pushes logs and messages
	PushLog(tp.Log)
	PushMessage(string, string)

	// How does this feeder match log with policy
	UpdateMatchedPolicy(tp.Log)

	// How this feeder serves log feeds
	ServeLogFeeds()
}

type Feeder struct {
	Output  string
	LogFile *os.File

	SecurityPolicy     tp.MatchPolicies
	SecurityPolicyLock *sync.RWMutex

	DefaultPosture     tp.DefaultPosture
	DefaultPostureLock *sync.RWMutex

	HostName string

	EventStructs *EventStructs

	// wait group
	WgServer sync.WaitGroup

	Running bool

	// port
	Port string

	// gRPC listener
	Listener net.Listener

	// log server
	LogServer *grpc.Server
}

func NewFeeder() *Feeder {
	fd := &Feeder{}

	// output
	fd.Output = cfg.GlobalCfg.LogPath

	// output mode
	if fd.Output != "stdout" && fd.Output != "none" {
		// #nosec
		logFile, err := os.OpenFile(filepath.Clean(fd.Output), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			kg.Errf("Failed to open %s", fd.Output)
			return nil
		}
		fd.LogFile = logFile
	}

	fd.SecurityPolicy = tp.MatchPolicies{}
	fd.SecurityPolicyLock = new(sync.RWMutex)

	fd.DefaultPosture = tp.DefaultPosture{}
	fd.DefaultPostureLock = new(sync.RWMutex)

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "none"
	}
	fd.HostName = hostname

	// set wait group
	fd.WgServer = sync.WaitGroup{}

	// initialize msg structs
	fd.EventStructs = &EventStructs{
		MsgStructs: make(map[string]EventStruct[pb.Message]),
		MsgLock:    sync.RWMutex{},

		// initialize alert structs
		AlertStructs: make(map[string]EventStruct[pb.Alert]),
		AlertLock:    sync.RWMutex{},

		// initialize log structs
		LogStructs: make(map[string]EventStruct[pb.Log]),
		LogLock:    sync.RWMutex{},
	}

	fd.Running = true

	// gRPC configuration
	fd.Port = fmt.Sprintf(":%s", "32767")

	// listen to gRPC port
	listener, err := net.Listen("tcp", fd.Port)
	if err != nil {
		kg.Errf("Failed to listen a port (%s, %s)", fd.Port, err.Error())
		return nil
	}
	fd.Listener = listener

	port := fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
	fd.Port = fmt.Sprintf(":%s", port)

	// create a log server

	logService := &LogService{
		QueueSize:    1000,
		Running:      &fd.Running,
		EventStructs: fd.EventStructs,
	}

	kaep := keepalive.EnforcementPolicy{
		PermitWithoutStream: true,
	}
	kasp := keepalive.ServerParameters{
		Time:    1 * time.Second,
		Timeout: 5 * time.Second,
	}

	fd.LogServer = grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))

	pb.RegisterLogServiceServer(fd.LogServer, logService)

	return fd
}

func (fd *Feeder) DestroyFeeder() error {
	fd.Running = false

	// wait for a while
	time.Sleep(time.Second * 1)

	// close listener
	if fd.Listener != nil {
		if err := fd.Listener.Close(); err != nil {
			kg.Err(err.Error())
		}
		fd.Listener = nil
	}

	// wait for other routines
	fd.WgServer.Wait()

	return nil
}

// StreamLogFeeds Function
func (fd *Feeder) ServeLogFeeds() {
	fd.WgServer.Add(1)
	defer fd.WgServer.Done()

	// feed logs
	if err := fd.LogServer.Serve(fd.Listener); err != nil {
		kg.Print("Terminated the gRPC service")
	}
}
