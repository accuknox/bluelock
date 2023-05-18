# SPDX-License-Identifier: Apache-2.0
# Copyright 2023 Authors of KubeArmor

.PHONY: build
build:
	docker build -t bluelock:latest .
