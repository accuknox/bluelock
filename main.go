//go:build linux
// +build linux

package main

import (
	"github.com/daemon1024/bluelock/core"
)

func main() {
	core.BlueLock()
}
