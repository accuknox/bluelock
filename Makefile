# SPDX-License-Identifier: MIT
# Copyright 2026 Authors of Bluelock

GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

.PHONY: run
run: build
	K8S=false RELAYSERVERURL="http://localhost:32767/" ./bluelock bash

.PHONY: run-container
run-container:
	docker compose -f examples/unorhcestrated/docker-compose.yaml --project-directory . up --build

.PHONY: build
build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -o bluelock .

.PHONY: docker-build
docker-build:
	docker build -t bluelock:latest .
