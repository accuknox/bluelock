package enforcer

import "github.com/daemon1024/bluelock/feeder"

type PtraceEnforcer struct {
	Logger *feeder.Logger
	Rules  *RuleSet
}

func NewPtraceEnforcer() *PtraceEnforcer {
	return &PtraceEnforcer{
		Logger: feeder.SidekickLogger,
		Rules:  CreateNewRuleSet(),
	}
}
