package enforcer

import "github.com/daemon1024/bluelock/feeder"

type PtraceEnforcer struct {
	ContainerID string
	Logger *feeder.Logger
	Rules  *RuleSet
}

func NewPtraceEnforcer(cid string) *PtraceEnforcer {
	return &PtraceEnforcer{
		ContainerID: cid,
		Logger: feeder.SidekickLogger,
		Rules:  CreateNewRuleSet(),
	}
}
