package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"regexp"
)

var (
	cgroupContainerIDRe = regexp.MustCompile(`^.*/(?:.*-)?([0-9a-f]+)(?:\.|\s*$)`)
)

type cgroupContainerIDDetector struct{}

const cgroupPath = "/proc/self/cgroup"

// getContainerIDFromCGroup returns the id of the container from the cgroup file.
// If no container id found, an empty string will be returned.
func getContainerIDFromCGroup() (string, error) {
	if _, err := os.Stat(cgroupPath); errors.Is(err, os.ErrNotExist) {
		// File does not exist, skip
		return "", nil
	}

	file, err := os.Open(cgroupPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	return getContainerIDFromReader(file), nil
}

// getContainerIDFromReader returns the id of the container from reader.
func getContainerIDFromReader(reader io.Reader) string {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		if id := getContainerIDFromLine(line); id != "" {
			return id
		}
	}
	return ""
}

// getContainerIDFromLine returns the id of the container from one string line.
func getContainerIDFromLine(line string) string {
	matches := cgroupContainerIDRe.FindStringSubmatch(line)
	if len(matches) <= 1 {
		return ""
	}
	return matches[1]
}
