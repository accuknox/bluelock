// SPDX-License-Identifier: MIT
// Copyright 2026 Authors of Bluelock

//go:build linux
// +build linux

package main

import (
	"os"

	"github.com/accuknox/bluelock/core"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

func main() {
	core.BlueLock()

	if len(os.Args) <= 1 {
		kg.Errf("No command found to execute")
		os.Exit(1)
	}
}
