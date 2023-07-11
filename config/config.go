package config

import (
	"flag"
	"os"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/spf13/viper"
)

type BluelockConfig struct {
	DefaultFilePosture         string // Default Enforcement Action in Global File Context
	DefaultNetworkPosture      string // Default Enforcement Action in Global Network Context

	K8sEnv bool

	LogPath           string // Log file to use

	RelayURL string
}

var GlobalCfg BluelockConfig

// ConfigDefaultFilePosture KubeArmor Default Global File Posture key
const ConfigDefaultFilePosture string = "defaultFilePosture"

// ConfigDefaultNetworkPosture KubeArmor Default Global Network Posture key
const ConfigDefaultNetworkPosture string = "defaultNetworkPosture"

// ConfigK8sEnv VM key
const ConfigK8sEnv string = "k8s"

// ConfigLogPath Log Path key
const ConfigLogPath string = "logPath"

const ConfigRelayURL string = "relayURL"

func readCmdLineParameters() {
	defaultFilePosture := flag.String(ConfigDefaultFilePosture, "block", "configuring default enforcement action in global file context {allow|audit|block}")
	defaultNetworkPosture := flag.String(ConfigDefaultNetworkPosture, "block", "configuring default enforcement action in global network context {allow|audit|block}")

	k8sEnvB := flag.Bool(ConfigK8sEnv, true, "is running with Kubernetes env?")

	logStr := flag.String(ConfigLogPath, "none", "log file path, {path|stdout|none}")

	relayURLStr := flag.String(ConfigRelayURL, "http://localhost:2801/", "relay server URL")

	flag.Parse()

	viper.SetDefault(ConfigDefaultFilePosture, *defaultFilePosture)
	viper.SetDefault(ConfigDefaultNetworkPosture, *defaultNetworkPosture)

	viper.SetDefault(ConfigK8sEnv, *k8sEnvB)

	viper.SetDefault(ConfigLogPath, *logStr)

	viper.SetDefault(ConfigRelayURL, *relayURLStr)

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

	GlobalCfg.DefaultFilePosture = viper.GetString(ConfigDefaultFilePosture)
	GlobalCfg.DefaultNetworkPosture = viper.GetString(ConfigDefaultNetworkPosture)

	GlobalCfg.K8sEnv = viper.GetBool(ConfigK8sEnv)

	GlobalCfg.LogPath = viper.GetString(ConfigLogPath)

	GlobalCfg.RelayURL = viper.GetString(ConfigRelayURL)

	kg.Printf("Final Configuration [%+v]", GlobalCfg)

	return nil
}
