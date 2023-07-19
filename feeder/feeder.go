package feeder

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	cfg "github.com/daemon1024/bluelock/config"
	"github.com/google/uuid"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	Running bool
	PtraceEnforcer = "Ptrace enforcer"
	PtraceTracer = "Ptrace tracer"
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

func init() {
	Running = true
}

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
	Output string
	LogFile *os.File

	SecurityPolicy tp.MatchPolicies
	SecurityPolicyLock *sync.RWMutex

	DefaultPosture tp.DefaultPosture

	EnableSidekick bool
	EnableKubearmorRelay bool

	RelayServerURL string

	LogClient *LogStreamerClient

	HostName string

	// wait group
	WgServer sync.WaitGroup
}

type LogStreamerClient struct {
	Conn *grpc.ClientConn
	Client pb.PushLogServiceClient

	PushLogClient pb.PushLogService_PushLogsClient
	PushAlertClient pb.PushLogService_PushAlertsClient
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

	fd.RelayServerURL = cfg.GlobalCfg.RelayServerURL

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "none"
	}
	fd.HostName = hostname

	// set wait group
	fd.WgServer = sync.WaitGroup{}

	// initialize log structs
	LogStructs = make(map[string]LogStruct)
	LogLock = &sync.RWMutex{}

	// gRPC by default
	//fd.LogMode = LogModeGRPC

	return fd
}

// StreamLogFeeds Function
func (fd *Feeder) StreamLogFeeds() {
	fd.WgServer.Add(1)
	defer fd.WgServer.Done()

	lc := connectWithRelay(fd.RelayServerURL)
	if lc == nil {
		kg.Errf("Error while connecting with relay")
		return
	}

	fd.LogClient = lc
	kg.Printf("Connected with Relay server for pushing logs")

	// destroy

	fd.WgServer.Add(1)
	go lc.PushLogs()
	kg.Printf("Started to push logs")

	fd.WgServer.Add(1)
	go lc.PushAlerts()
	kg.Printf("Started to push alerts")

	fd.WgServer.Add(1)
	go lc.PushAlerts()
	kg.Printf("Started to push messages")

	time.Sleep(time.Second * 1)
	// wait for other routines
	fd.WgServer.Wait()
}

// DoHealthCheck Function
func (lc *LogStreamerClient) DoHealthCheck() bool {
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

func (lc *LogStreamerClient) PushLogs() error {
	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.Log, 1)
	defer close(conn)

	// add a new log struct
	logStruct := LogStruct{}
	logStruct.Broadcast = conn

	LogLock.Lock()
	LogStructs[uid] = logStruct
	LogLock.Unlock()

	kg.Printf("Added a new connection (%s) for PushLogs", uid)
	defer removeLogStruct(uid)

	for Running {
		select {
		case resp := <-conn:
			if status, ok := status.FromError(lc.PushLogClient.Send(resp)); ok {
				switch status.Code() {
				case codes.OK:
					// noop
				case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
					kg.Warnf("relay failed to send a log=[%+v] err=[%s]", resp, status.Err().Error())
					return status.Err()
				default:
					return nil
				}
			}
		}
	}

	return nil
}

func (lc *LogStreamerClient) PushAlerts() error {
	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.Alert, 1)
	defer close(conn)

	// add a new alert struct
	alertStruct := AlertStruct{}
	alertStruct.Broadcast = conn

	AlertLock.Lock()
	AlertStructs[uid] = alertStruct
	AlertLock.Unlock()

	kg.Printf("Added a new connection (%s) for PushAlerts", uid)
	defer removeAlertStruct(uid)

	for Running {
		select {
		case resp := <-conn:
			if status, ok := status.FromError(lc.PushAlertClient.Send(resp)); ok {
				switch status.Code() {
				case codes.OK:
					// noop
				case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
					kg.Warnf("relay failed to send a alert=[%+v] err=[%s]", resp, status.Err().Error())
					return status.Err()
				default:
					return nil
				}
			}
		}
	}

	return nil
}

func (lc *LogStreamerClient) PushMessages() error {
	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.Message, 1)
	defer close(conn)

	// add a new message struct
	messageStruct := MessageStruct{}
	messageStruct.Broadcast = conn

	MessageLock.Lock()
	MessageStructs[uid] = messageStruct
	MessageLock.Unlock()

	kg.Printf("Added a new connection (%s) for PushMessages", uid)
	defer removeMessageStruct(uid)

	for Running {
		select {
		case resp := <-conn:
			if status, ok := status.FromError(lc.PushMessageClient.Send(resp)); ok {
				switch status.Code() {
				case codes.OK:
					// noop
				case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
					kg.Warnf("relay failed to send a message=[%+v] err=[%s]", resp, status.Err().Error())
					return status.Err()
				default:
					return nil
				}
			}
		}
	}

	return nil
}

func connectWithRelay(address string) *LogStreamerClient {
	var err error
	lc := &LogStreamerClient{}

	for Running {
		conn, err := grpc.Dial(address, grpc.WithInsecure())
		if err != nil {
			kg.Warnf("Failed to connect to relay's gRPC listener. %s", err.Error())
			time.Sleep(time.Second * 5)
			conn.Close()
			continue
		}

		lc.Conn = conn

		client := pb.NewPushLogServiceClient(conn)

		lc.Client = client

		if ok := lc.DoHealthCheck(); !ok {
			time.Sleep(time.Second * 5)
			conn.Close()
			continue
		}

		break
	}

	lc.PushLogClient, err = lc.Client.PushLogs(context.Background())
	if err != nil {
		kg.Warnf("Failed to PushLogs (%s) err=%s", address, err.Error())
	}

	return lc
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
