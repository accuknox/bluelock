package enforcer

import (
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type RuleSet struct {
	ProcessPaths         map[InnerKey]RuleConfig
	FilePaths            map[InnerKey]RuleConfig
	NetworkRules         map[InnerKey]RuleConfig
	ProcWhiteListPosture bool
	FileWhiteListPosture bool
	NetWhiteListPosture  bool
}

type InnerKey struct {
	Path   string
	Source string
}

type RuleConfig struct {
	Dir, Recursive, ReadOnly, OwnerOnly, Deny, Allow bool
}

func CreateNewRuleSet() (r *RuleSet) {
	r = new(RuleSet)
	r.ProcessPaths = make(map[InnerKey]RuleConfig)
	r.FilePaths = make(map[InnerKey]RuleConfig)
	r.NetworkRules = make(map[InnerKey]RuleConfig)
	return r
}

func (pe *PtraceEnforcer) UpdateRules(securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture) {
	newRules := CreateNewRuleSet()

	for _, secPolicy := range securityPolicies {

		// parse file rules
		for _, path := range secPolicy.Spec.File.MatchPaths {
			var rc RuleConfig

			rc.OwnerOnly = path.OwnerOnly
			rc.ReadOnly = path.ReadOnly

			if len(path.FromSource) == 0 {
				if path.Action == "Allow" {
					if defaultPosture.FileAction == "block" {
						newRules.FileWhiteListPosture = true
					}
					rc.Allow = true
					rc.Deny = false
				} else if path.Action == "Block" {
					rc.Allow = false
					rc.Deny = true
				}
				key := InnerKey{
					Path:   path.Path,
					Source: "",
				}
				newRules.FilePaths[key] = rc
			} else {
				for _, src := range path.FromSource {
					if path.Action == "Allow" {
						if defaultPosture.FileAction == "block" {
							newRules.FileWhiteListPosture = true
						}
						rc.Allow = true
						rc.Deny = false
					} else if path.Action == "Block" {
						rc.Allow = false
						rc.Deny = true
					}
					key := InnerKey{
						Path:   path.Path,
						Source: src.Path,
					}
					newRules.FilePaths[key] = rc
				}
			}
		}
	}

	pe.Rules = newRules
}
