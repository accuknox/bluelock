# SPDX-License-Identifier: Apache-2.0
# Copyright 2023 Authors of KubeArmor

GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

.PHONY: run
run: build
	K8S=false RELAYSERVERURL="http://localhost:2801/" ./bluelock bash

.PHONY: run-container
run-container:
	docker compose up --build

.PHONY: build
build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -o bluelock .

.PHONY: docker-build
docker-build:
	docker build -t bluelock:latest .
