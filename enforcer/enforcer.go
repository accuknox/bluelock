package enforcer

import (
	"github.com/daemon1024/bluelock/feeder"
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
