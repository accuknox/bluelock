package core

import (
	"bufio"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
)

// Inspired from opentelemetry go sdk:
// https://github.com/open-telemetry/opentelemetry-go/pull/3508/

type containerIDProvider func() (string, error)

var (
	cgroupV1ContainerIDRe = regexp.MustCompile(`^.*/(?:.*-)?([0-9a-f]+)(?:\.|\s*$)`)
	cgroupV2ContainerIDRe = regexp.MustCompile(`^.*/.+/([\w+-.]{64})/.*$`)
)

const (
	cgroupFsPath   = "/sys/fs/cgroup"
	cgroupV1Path   = "/proc/self/cgroup"
	cgroupV2Path   = "/proc/self/mountinfo"
	cgroupV1Output = "tmpfs"
	cgroupV2Output = "cgroup2fs"
)

// getContainerIDFromCGroup returns the ID of the container from the cgroup file.
// If cgroup v1 container ID provider fails, then fall back to cgroup v2 container ID provider.
// If no container ID found, an empty string will be returned.
func GetContainerID() (string, error) {
	containerID, err := getContainerIDFromCGroupFile(cgroupV1Path, getContainerIDFromCgroupV1Line)
	if err != nil {
		return "", err
	}

	if containerID == "" {
		// Fallback to cgroup v2
		containerID, err = getContainerIDFromCGroupFile(cgroupV2Path, getContainerIDFromCgroupV2Line)
		if err != nil {
			return "", err
		}
	}

	return containerID, nil
}

func getContainerIDFromCGroupFile(cgroupPath string, extractor func(string) string) (string, error) {
	if _, err := os.Stat(cgroupPath); errors.Is(err, os.ErrNotExist) {
		// File does not exist, skip
		return "", nil
	}

	file, err := os.Open(cgroupPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	return getContainerIDFromReader(file, extractor), nil
}

// getContainerIDFromReader returns the ID of the container from reader.
func getContainerIDFromReader(reader io.Reader, extractor func(string) string) string {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		if id := extractor(line); id != "" {
			return id
		}
	}
	return ""
}

// getContainerIDFromCgroupV1Line returns the ID of the container from one string line.
func getContainerIDFromCgroupV1Line(line string) string {
	// Only match line contains "cpuset"
	if !strings.Contains(line, "cpuset") {
		return ""
	}

	matches := cgroupV1ContainerIDRe.FindStringSubmatch(line)
	if len(matches) <= 1 {
		return ""
	}
	return matches[1]
}

// getContainerIDFromCgroupV2Line returns the ID of the container from one string line.
func getContainerIDFromCgroupV2Line(line string) string {
	// Only match line contains "hostname"
	if !strings.Contains(line, "hostname") {
		return ""
	}

	matches := cgroupV2ContainerIDRe.FindStringSubmatch(line)
	if len(matches) <= 1 {
		return ""
	}
	return matches[1]
}
