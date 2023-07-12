package config

import (
	"flag"
	"net/url"
	"os"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/spf13/viper"
)

type BluelockConfig struct {
	ContainerName string // Container name needed for unorchestrated containers

	DefaultFilePosture         string // Default Enforcement Action in Global File Context
	DefaultNetworkPosture      string // Default Enforcement Action in Global Network Context

	GRPC string // Port that policy listener will receive policies on

	K8sEnv bool

	LogPath           string // Log file to use

	RelayServerURL string // RelayServerURL to which logs will be pushed
}

var GlobalCfg BluelockConfig

// ConfigContainerName key
const ConfigContainerName string = "containerName"

// ConfigDefaultFilePosture KubeArmor Default Global File Posture key
const ConfigDefaultFilePosture string = "defaultFilePosture"

// ConfigDefaultNetworkPosture KubeArmor Default Global Network Posture key
const ConfigDefaultNetworkPosture string = "defaultNetworkPosture"

// ConfigGRPC GRPC port
const ConfigGRPC string = "gRPC"

// ConfigK8sEnv VM key
const ConfigK8sEnv string = "k8s"

// ConfigLogPath Log Path key
const ConfigLogPath string = "logPath"

// ConfigRelayServerURL Path key
const ConfigRelayServerURL string = "relayServerURL"

func readCmdLineParameters() {
	containerName := flag.String(ConfigContainerName, "", "container/service name to match policies. only needed in case of unorchestrated containers")

	defaultFilePosture := flag.String(ConfigDefaultFilePosture, "block", "configuring default enforcement action in global file context {allow|audit|block}")
	defaultNetworkPosture := flag.String(ConfigDefaultNetworkPosture, "block", "configuring default enforcement action in global network context {allow|audit|block}")

	grpc := flag.String(ConfigGRPC, "32767", "gRPC port which will be listening for broadcasted policies")

	k8sEnvB := flag.Bool(ConfigK8sEnv, true, "is running with Kubernetes env?")

	logStr := flag.String(ConfigLogPath, "none", "log file path, {path|stdout|none}")

	relayServerURLStr := flag.String(ConfigRelayServerURL, "http://localhost:2801/", "relay-server http URL listening for logs")

	flag.Parse()

	viper.SetDefault(ConfigContainerName, *containerName)

	viper.SetDefault(ConfigDefaultFilePosture, *defaultFilePosture)
	viper.SetDefault(ConfigDefaultNetworkPosture, *defaultNetworkPosture)

	viper.SetDefault(ConfigGRPC, *grpc)

	viper.SetDefault(ConfigK8sEnv, *k8sEnvB)

	viper.SetDefault(ConfigLogPath, *logStr)

	viper.SetDefault(ConfigRelayServerURL, *relayServerURLStr)

}

func LoadConfig() error {
	readCmdLineParameters()

	viper.AutomaticEnv()

	cfgfile := os.Getenv("KUBEARMOR_CFG")
	if cfgfile == "" {
		cfgfile = "kubearmor.yaml"
	}
	if _, err := os.Stat(cfgfile); err == nil {
		kg.Printf("setting config from file [%s]", cfgfile)
		viper.SetConfigFile(cfgfile)
		err := viper.ReadInConfig()
		if err != nil {
			return err
		}
	}

	relayURL, err := url.Parse(viper.GetString(ConfigRelayServerURL))
	if err != nil {
		return err
	}

	GlobalCfg = BluelockConfig {
		ContainerName: viper.GetString(ConfigContainerName),
		DefaultFilePosture: viper.GetString(ConfigDefaultFilePosture),
		DefaultNetworkPosture: viper.GetString(ConfigDefaultNetworkPosture),
		GRPC: viper.GetString(ConfigGRPC),
		K8sEnv: viper.GetBool(ConfigK8sEnv),
		LogPath: viper.GetString(ConfigLogPath),
		RelayServerURL: relayURL.String(),
	}

	kg.Printf("Final Configuration [%+v]", GlobalCfg)

	return nil
}
