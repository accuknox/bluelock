package feeder

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/daemon1024/bluelock/common"
	cfg "github.com/daemon1024/bluelock/config"
	"github.com/google/uuid"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

var (
	PtraceEnforcer = "Ptrace enforcer"
	PtraceTracer   = "Ptrace tracer"
	//LogModeHTTP = "http"
	//LogModeGRPC = "grpc"

	// LogStructs Map
	LogStructs map[string]LogStruct
	// LogLock Lock
	LogLock *sync.RWMutex

	// AlertStructs Map
	AlertStructs map[string]AlertStruct
	// AlertLock Lock
	AlertLock *sync.RWMutex

	// MessageStructs Map
	MessageStructs map[string]MessageStruct
	// MessageLock Lock
	MessageLock *sync.RWMutex
)

// LogStruct Structure
type LogStruct struct {
	Broadcast chan *pb.Log
}

// AlertStruct Structure
type AlertStruct struct {
	Broadcast chan *pb.Alert
}

// MessageStruct Structure
type MessageStruct struct {
	Broadcast chan *pb.Message
}

type Feeder struct {
	Output  string
	LogFile *os.File

	SecurityPolicy     tp.MatchPolicies
	SecurityPolicyLock *sync.RWMutex

	DefaultPosture tp.DefaultPosture

	EnableSidekick       bool
	EnableKubearmorRelay bool

	RelayServerURL string

	LogClient *LogStreamerClient

	HostName string

	// wait group
	WgServer sync.WaitGroup

	Running bool
}

type LogStreamerClient struct {
	Conn   *grpc.ClientConn
	Client pb.PushLogServiceClient

	PushLogClient     pb.PushLogService_PushLogsClient
	PushAlertClient   pb.PushLogService_PushAlertsClient
	PushMessageClient pb.PushLogService_PushMessagesClient
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
	fd.DefaultPosture = tp.DefaultPosture{}

	address, err := common.GetURL(cfg.GlobalCfg.RelayServerURL)
	if err != nil {
		kg.Errf("Failed to parse Relay Server URL: %s", err.Error())
		return nil
	}
	fd.RelayServerURL = address

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "none"
	}
	fd.HostName = hostname

	// set wait group
	fd.WgServer = sync.WaitGroup{}

	fd.Running = true

	// initialize log structs
	LogStructs = make(map[string]LogStruct)
	LogLock = &sync.RWMutex{}

	// initialize alert structs
	AlertStructs = make(map[string]AlertStruct)
	AlertLock = &sync.RWMutex{}

	// initialize message structs
	MessageStructs = make(map[string]MessageStruct)
	MessageLock = &sync.RWMutex{}

	// gRPC by default
	//fd.LogMode = LogModeGRPC

	return fd
}

func (fd *Feeder) DestroyFeeder() error {
	fd.Running = false

	if fd.LogClient != nil {
		if fd.LogClient.Conn != nil {
			err := fd.LogClient.Conn.Close()
			if err != nil {
				return err
			}
		}
	}
	fd.LogClient = nil

	return nil
}

// StreamLogFeeds Function
func (fd *Feeder) StreamLogFeeds() {
	for fd.Running {
		fd.connectWithRelay()
		if fd.LogClient == nil {
			kg.Errf("Failed to connect with relay for streaming logs")
			return
		}

		kg.Printf("Connected with relay server for pushing logs", fd.RelayServerURL)

		// destroy

		fd.WgServer.Add(1)
		go fd.PushLogs()
		kg.Printf("Started to PushLogs")

		fd.WgServer.Add(1)
		go fd.PushAlerts()
		kg.Printf("Started to PushAlerts")

		fd.WgServer.Add(1)
		go fd.PushMessages()
		kg.Printf("Started to PushMessages")

		time.Sleep(time.Second * 1)

		// wait for other routines to terminate before creating a new connection
		fd.WgServer.Wait()

		// destroy client
		if err := fd.LogClient.Conn.Close(); err != nil {
			kg.Warnf("Failed to delete LogClient: %s", err.Error())
		}
		kg.Printf("Closed log client for %s", fd.RelayServerURL)

		fd.LogClient = nil
	}

	return
}

func (fd *Feeder) PushLogs() {
	defer fd.WgServer.Done()

	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.Log, 1)
	closeChan := make(chan *pb.ReplyMessage, 1)
	defer close(conn)

	// add a new log struct
	logStruct := LogStruct{}
	logStruct.Broadcast = conn

	LogLock.Lock()
	LogStructs[uid] = logStruct
	LogLock.Unlock()

	kg.Printf("Added a new connection (%s) for PushLogs", uid)
	defer removeLogStruct(uid)

	lc := fd.LogClient

	go func() {
		resp, err := lc.PushLogClient.Recv()
		if status, ok := status.FromError(err); ok {
			switch status.Code() {
			case codes.OK:
				closeChan <- resp
			default:
				kg.Warnf("Error while receiving ReplyMessage from relay", err)
				return
			}
		}
	}()

	for fd.Running {
		select {
		case <-lc.PushLogClient.Context().Done():
			return
		case <-closeChan:
			kg.Printf("Relay closed connection for Logs")
			return
		case resp := <-conn:
			if status, ok := status.FromError(lc.PushLogClient.Send(resp)); ok {
				switch status.Code() {
				case codes.OK:
					// noop
				default:
					kg.Warnf("failed to push a log=[%+v] err=[%s]", resp, status.Err().Error())
					return
				}
			}
		}
	}

	kg.Printf("Stopped pushing logs to client (%s)", uid)

	return
}

func (fd *Feeder) PushAlerts() {
	defer fd.WgServer.Done()

	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.Alert, 1)
	closeChan := make(chan *pb.ReplyMessage, 1)
	defer close(conn)

	// add a new alert struct
	alertStruct := AlertStruct{}
	alertStruct.Broadcast = conn

	AlertLock.Lock()
	AlertStructs[uid] = alertStruct
	AlertLock.Unlock()

	kg.Printf("Added a new connection (%s) for PushAlerts", uid)
	defer removeAlertStruct(uid)

	lc := fd.LogClient

	go func() {
		resp, err := lc.PushAlertClient.Recv()
		if status, ok := status.FromError(err); ok {
			switch status.Code() {
			case codes.OK:
				closeChan <- resp
			default:
				kg.Warnf("Error while receiving ReplyMessage from relay", err)
				return
			}
		}
	}()

	for fd.Running {
		select {
		case <-lc.PushAlertClient.Context().Done():
			return
		case <-closeChan:
			kg.Printf("Relay closed connection for Alerts")
			return
		case resp := <-conn:
			if status, ok := status.FromError(lc.PushAlertClient.Send(resp)); ok {
				switch status.Code() {
				case codes.OK:
					// noop
				default:
					kg.Warnf("feeder failed to push an alert=[%+v] err=[%s]", resp, status.Err().Error())
					return
				}
			}
		}
	}

	kg.Printf("Stopped pushing alerts to client (%s)", uid)

	return
}

func (fd *Feeder) PushMessages() {
	defer fd.WgServer.Done()

	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.Message, 1)
	closeChan := make(chan *pb.ReplyMessage, 1)
	defer close(conn)

	// add a new message struct
	messageStruct := MessageStruct{}
	messageStruct.Broadcast = conn

	MessageLock.Lock()
	MessageStructs[uid] = messageStruct
	MessageLock.Unlock()

	kg.Printf("Added a new connection (%s) for PushMessages", uid)
	defer removeMessageStruct(uid)

	lc := fd.LogClient

	go func() {
		resp, err := lc.PushMessageClient.Recv()
		if status, ok := status.FromError(err); ok {
			switch status.Code() {
			case codes.OK:
				closeChan <- resp
			default:
				kg.Warnf("Error while receiving ReplyMessage from relay", err)
				return
			}
		}
	}()

	for fd.Running {
		select {
		case <-lc.PushMessageClient.Context().Done():
			return
		case <-closeChan:
			kg.Printf("Relay closed connection for Messages")
			return
		case resp := <-conn:
			if status, ok := status.FromError(lc.PushMessageClient.Send(resp)); ok {
				switch status.Code() {
				case codes.OK:
					// noop
				default: // otherwise, close the connection
					kg.Warnf("feeder failed to send a message=[%+v] err=[%s]", resp, status.Err().Error())
					return
				}
			}
		}
	}

	kg.Printf("Stopped pushing messages to client (%s)", uid)

	return
}

// connectWithRelay attemtps to establish a connection with kubearmor-relay
// until the relay is healthy
func (fd *Feeder) connectWithRelay() {
	var err error
	lc := &LogStreamerClient{}

	kacp := keepalive.ClientParameters{
		Time:                1 * time.Second,
		Timeout:             5 * time.Second,
		PermitWithoutStream: true,
	}

	address := fd.RelayServerURL
	for fd.Running {
		conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithKeepaliveParams(kacp), grpc.WithBlock())
		if err != nil {
			time.Sleep(time.Second * 5)
			conn.Close()
			continue
		}

		lc.Conn = conn

		client := pb.NewPushLogServiceClient(conn)

		lc.Client = client

		if ok := lc.doHealthCheck(); !ok {
			kg.Warnf("PushLogClient is unhealthy")
			time.Sleep(time.Second * 5)
			conn.Close()
			continue
		}

		break
	}

	lc.PushLogClient, err = lc.Client.PushLogs(context.Background())
	if err != nil {
		kg.Warnf("Failed to create PushLogs (%s) err=%s", address, err.Error())
	}

	lc.PushAlertClient, err = lc.Client.PushAlerts(context.Background())
	if err != nil {
		kg.Warnf("Failed to create PushAlerts (%s) err=%s", address, err.Error())
	}

	lc.PushMessageClient, err = lc.Client.PushMessages(context.Background())
	if err != nil {
		kg.Warnf("Failed to create PushMessages (%s) err=%s", address, err.Error())
	}

	fd.LogClient = lc
	return
}

// doHealthCheck Function
func (lc *LogStreamerClient) doHealthCheck() bool {
	// #nosec
	randNum := rand.Int31()

	// send a nonce
	nonce := pb.NonceMessage{Nonce: randNum}
	res, err := lc.Client.HealthCheck(context.Background(), &nonce)
	if err != nil {
		kg.Warnf("Relay server health check failed. %s", err)
		return false
	}

	// check nonce
	if randNum != res.Retval {
		return false
	}

	return true
}

// removeLogStruct Function
func removeLogStruct(uid string) {
	LogLock.Lock()
	defer LogLock.Unlock()

	delete(LogStructs, uid)

	kg.Printf("Deleted connection (%s) for PushLogs", uid)
}

// removeAlertStruct Function
func removeAlertStruct(uid string) {
	AlertLock.Lock()
	defer AlertLock.Unlock()

	delete(AlertStructs, uid)

	kg.Printf("Deleted connection (%s) for PushAlerts", uid)
}

// removeMessageStruct Function
func removeMessageStruct(uid string) {
	MessageLock.Lock()
	defer MessageLock.Unlock()

	delete(MessageStructs, uid)

	kg.Printf("Deleted connection (%s) for PushMessages", uid)
}
