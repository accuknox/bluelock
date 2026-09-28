// SPDX-License-Identifier: MIT
// Copyright 2026 Authors of Bluelock

package enforcer

import (
	"github.com/accuknox/bluelock/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type PtraceEnforcer struct {
	Container *tp.Container
	Logger    *feeder.Feeder
	Rules     *RuleSet
}

func NewPtraceEnforcer(container *tp.Container, logger *feeder.Feeder) *PtraceEnforcer {
	return &PtraceEnforcer{
		Container: container,
		Logger:    logger,
		Rules:     CreateNewRuleSet(),
	}
}
