package config

import (
	"flag"
	"os"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/spf13/viper"
)

type BluelockConfig struct {
	LogPath           string // Log file to use

	DefaultFilePosture         string // Default Enforcement Action in Global File Context
	DefaultNetworkPosture      string // Default Enforcement Action in Global Network Context
	DefaultCapabilitiesPosture string // Default Enforcement Action in Global Capabilities Context
}

var GlobalCfg BluelockConfig

// ConfigDefaultFilePosture KubeArmor Default Global File Posture key
const ConfigDefaultFilePosture string = "defaultFilePosture"

// ConfigDefaultNetworkPosture KubeArmor Default Global Network Posture key
const ConfigDefaultNetworkPosture string = "defaultNetworkPosture"

// ConfigDefaultCapabilitiesPosture KubeArmor Default Global Capabilities Posture key
const ConfigDefaultCapabilitiesPosture string = "defaultCapabilitiesPosture"

// ConfigLogPath Log Path key
const ConfigLogPath string = "logPath"

func readCmdLineParameters() {
	logStr := flag.String(ConfigLogPath, "none", "log file path, {path|stdout|none}")

	defaultFilePosture := flag.String(ConfigDefaultFilePosture, "audit", "configuring default enforcement action in global file context {allow|audit|block}")
	defaultNetworkPosture := flag.String(ConfigDefaultNetworkPosture, "audit", "configuring default enforcement action in global network context {allow|audit|block}")
	defaultCapabilitiesPosture := flag.String(ConfigDefaultCapabilitiesPosture, "audit", "configuring default enforcement action in global capability context {allow|audit|block}")

	viper.SetDefault(ConfigLogPath, *logStr)

	viper.SetDefault(ConfigDefaultFilePosture, *defaultFilePosture)
	viper.SetDefault(ConfigDefaultNetworkPosture, *defaultNetworkPosture)
	viper.SetDefault(ConfigDefaultCapabilitiesPosture, *defaultCapabilitiesPosture)
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

	GlobalCfg.LogPath = viper.GetString(ConfigLogPath)

	GlobalCfg.DefaultFilePosture = viper.GetString(ConfigDefaultFilePosture)
	GlobalCfg.DefaultNetworkPosture = viper.GetString(ConfigDefaultNetworkPosture)
	GlobalCfg.DefaultCapabilitiesPosture = viper.GetString(ConfigDefaultCapabilitiesPosture)

	kg.Printf("Final Configuration [%+v]", GlobalCfg)

	return nil
}
