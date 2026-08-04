//go:build linux
// +build linux

package main

import (
	"os"

	"github.com/daemon1024/bluelock/core"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

func main() {
	core.BlueLock()

	if len(os.Args) <= 1 {
		kg.Errf("No command found to execute")
		os.Exit(1)
	}
}
